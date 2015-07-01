###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################
'''
Created on Jun 5, 2013

Install and configure warning banners, to be displayed at startup.

@author: Breen Malmberg
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Replaced old style CI implementation with new.
    Fixed bug where fix() method did not check CI before performing actions.
@change: 2014/08/26 dkennel - fixed typo in method name. Changed print
    statements to debug messages.
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..ruleKVEditor import RuleKVEditor
from ..localize import WARNINGBANNER
from ..localize import OSXSHORTWARNINGBANNER
from ..stonixutilityfunctions import iterate, createFile, writeFile
from ..stonixutilityfunctions import checkPerms, setPerms, readFile, resetsecon


class InstallBanners(RuleKVEditor):
    '''
    Install and configure warning banners, to be displayed at startup.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        RuleKVEditor.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.commandhelper = CommandHelper(logger)
        self.rulenumber = 51
        self.rulename = 'InstallBanners'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = "Install and configure warning banners, to be " + \
        "displayed when logging into this system."
        self.rootrequired = True
        self.compliant = False
        self.guidance = ['CIS', 'NSA 2.3.7.2', 'CCE 4188-9', 'CCE 4431-3',
                         'CCE 3717-6', 'CCE 4554-2', 'CCE 4603-7',
                         'CCE 4760-5', 'CCE 4301-8', 'CCE 4698-7',
                         'CCE 4222-6', 'CCE 4103-8', 'CCE 4870-2',
                         'CCE 4896-7']
        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}
        # init CIs
        datatype = 'bool'
        key = 'InstallBanners'
        instructions = "To prevent the installation of a warning banner, " + \
        "set the value of InstallBanners to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        # list of known possible banner text file names/paths in *nix
        self.bannerfilelist = ["/etc/banners/in.ftpd",
                               "/etc/banners/in.rlogind",
                               "/etc/banners/in.rshd",
                               "/etc/banners/in.telnetd",
                               "/etc/issue",
                               "/etc/issue.net",
                               "/etc/motd"]

        self.macbannerfiledict = {'/Library/Security/PolicyBanner.txt':
                                  WARNINGBANNER,
                                  '/etc/motd': WARNINGBANNER,
                                  '/etc/ftpwelcome': WARNINGBANNER}

        # list of known possible display manager file names/paths in *nix
        self.displaymgrconfiglist = ["/etc/X11/gdm/gdm.conf",
                                    "/etc/X11/xdm/kdmrc",
                                    "/etc/kde/kdm/kdmrc",
                                    "/etc/kde4/kdm/kdmrc",
                                    "/etc/gdm/custom.conf",
                                    "/etc/gdm/gdm.conf-custom",
                                    "/etc/sshd_config",
                                    "/usr/share/config/kdm/kdmrc"]

        # used to keep track of the number of changes made (for fix/undo)
        self.iterator = 1

        self.addKVEditor("FileServerBannerText", "defaults",
                         "/Library/Preferences/com.apple.AppleFileServer", "",
                         {"loginGreeting": [re.escape(WARNINGBANNER),
                                            "'\"" + WARNINGBANNER + "\"'"]},
                         "present", "",
                         "To prevent the installation of a warning banner," + \
                         " set the value of InstallBanners to False",
                         self.ci)
        self.addKVEditor("loginwindowBannerText", "defaults",
                         "/Library/Preferences/com.apple.loginwindow", "",
                         {"LoginWindowText": [re.escape(OSXSHORTWARNINGBANNER),
                                              '"' + OSXSHORTWARNINGBANNER + \
                                              '"']},
                         "present", "",
                         "To prevent the installation of a warning banner," + \
                         " set the value of InstallBanners to False",
                         self.ci)

###############################################################################

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return bool
        @author Breen Malmberg
        '''

        compliant = True
        self.detailedresults = ""

        try:

            self.detailedresults = ""
            if os.path.exists('/etc/dconf/db/gdm.d'):
                self.compliant = self.reportr7()
                return self.compliant
            # if mac, run separate reportmac() method instead
            elif self.environ.getosfamily() == 'darwin':
                self.compliant = self.reportmac()

            else:
                if not os.path.exists("/etc/banners"):
                    compliant = False
                # check if the banner files are properly configured
                for banner in self.bannerfilelist:
                    if os.path.exists(banner):
                        contents = readFile(banner, self.logger)
                        string = ""
                        for line in contents:
                            string += line
                        if not re.search(re.escape(WARNINGBANNER), string):
                            compliant = False
                            self.detailedresults += self.rulename + ' is ' + \
                            ' not compliant because WARNINGBANNER text ' + \
                            ' was not found in ' + str(banner) + '\n'
                        if not checkPerms(banner, [0, 0, 420], self.logger):
                            self.detailedresults += "Permissions not " + \
                            "correct on " + banner + "\n"
                            compliant = False
                    else:
                        compliant = False
                        self.detailedresults += self.rulename + ' is not' + \
                        ' compliant because ' + banner + ' file was not ' + \
                        ' found\n'
                self.compliant = compliant

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def reportr7(self):
        '''
        rhel7 fork fork fork fork fork fork...
        a different report structure is needed for dconf-based systems to
        check warning banner compliancy
        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:

            path = '/etc/dconf/db/gdm.d/01-banner-message'
            confstr = '[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'' + OSXSHORTWARNINGBANNER + '\'\n'

            path2 = '/etc/dconf/db/gdm.d/00-login-screen'
            confstr2 = '[org/gnome/login-screen]\ndisable-user-list=true\n'

            if os.path.exists(path):
                f = open(path, 'r')
                contents = f.read()
                f.close()
                if contents != confstr:
                    retval = False
                    self.detailedresults += '\nconf file configuration text is incorrect'
            else:
                retval = False
                self.detailedresults += '\nconf file not found: ' + str(path)

            if os.path.exists(path2):
                f = open(path2, 'r')
                contents = f.read()
                f.close()
                if contents != confstr2:
                    retval = False
                    self.detailedresults += '\nconf file configuration text is incorrect'
            else:
                retval = False
                self.detailedresults += '\nconf file not found: ' + str(path2)

        except Exception:
            raise
        return retval

###############################################################################

    def reportmac(self):
        '''
        Check content of sshd_config, if it exists
        Check content of com.apple.loginwindow.plist, if it exists
        Check content of com.apple.AppleFileServer.plist

        @return bool
        @author Breen Malmberg
        '''

        # defaults
        compliant = True
        motdfound = False

        try:
            for item in self.macbannerfiledict:
                if os.path.exists(item):
                    contents = readFile(item, self.logger)
                    tempstring = ""
                    for line in contents:
                        tempstring += line
                    if not re.search(re.escape(self.macbannerfiledict[item]),
                                                                   tempstring):
                        compliant = False
                        msg = "bannertext was not found in " + item + " in report\n"
                        self.resultAppend(msg)
                    #644
                    if not checkPerms(item, [0, 0, 420], self.logger):
                        msg = "permissions on " + item + " aren't correct\n"
                        self.resultAppend(msg)
                        compliant = False
                else:
                    compliant = False

            sshfile = "/private/etc/sshd_config"
            if os.path.exists(sshfile):
                contents = readFile(sshfile, self.logger)

                for line in contents:
                    if re.search('^Banner[ \t]+/etc/motd', line.strip()):
                        motdfound = True

                if not motdfound:
                    compliant = False
                    msg = sshfile + " does not have /etc/motd in it in report\n"
                    self.resultAppend(msg)

                if not checkPerms(sshfile, [0, 0, 420], self.logger):
                    msg = sshfile + " Permissions aren't correct on " + \
                    sshfile + "\n"
                    self.resultAppend(msg)
                    compliant = False
            else:
                compliant = False
                msg = sshfile + " does not exist\n"
                self.resultAppend(msg)
            if not RuleKVEditor.report(self, True):
                compliant = False

            return compliant

        except OSError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
            return False

###############################################################################

    def fix(self):
        '''
        Install warning banners, set the warning text and configure the
        file permissions for the warning banner files.

        @author Breen Malmberg
        '''

        success = True
        self.detailedresults = ""

        try:

            if os.path.exists('/etc/dconf/db/gdm.d'):
                self.rulesuccess = self.fixr7()
                return self.rulesuccess
            # if system is mac, run fixmac instead
            elif self.environ.getosfamily() == 'darwin':
                self.rulesuccess = self.fixmac()
            else:
                if not self.ci.getcurrvalue():
                    return
                #clear out event history so only the latest fix is recorded
                eventlist = self.statechglogger.findrulechanges(self.rulenumber)
                for event in eventlist:
                    self.statechglogger.deleteentry(event)

                # if banners dir does not exist, create it
                if not os.path.exists('/etc/banners'):
                    os.mkdir('/etc/banners')
                    os.chmod('/etc/banners', 0755)
                    os.chown('/etc/banners', 0, 0)

                # fix warning banner files
                for banner in self.bannerfilelist:
                    if os.path.exists(banner):
                        if not checkPerms(banner, [0, 0, 420], self.logger):
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            if not setPerms(banner, [0, 0, 420], self.logger,
                                                    self.statechglogger, myid):
                                success = False
                        contents = readFile(banner, self.logger)
                        string = ""
                        for line in contents:
                            string += line
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['InstallBanners.fix',
                                              "string: " + string + "\n"])
                        if not re.search(re.escape(WARNINGBANNER), string):
                            tmpfile = banner + ".tmp"
                            if writeFile(tmpfile, WARNINGBANNER, self.logger):

                                event = {'eventtype': 'conf',
                                         'filepath': banner}
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                self.statechglogger.recordchgevent(myid, event)
                                self.statechglogger.recordfilechange(banner,
                                                            tmpfile, myid)
                                os.rename(tmpfile, banner)
                                os.chmod(banner, 420)
                                os.chown(banner, 0, 0)
                            else:
                                success = False
                    else:
                        createFile(banner, self.logger)
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": banner}
                        self.statechglogger.recordchgevent(myid, event)
                        if not writeFile(banner, WARNINGBANNER, self.logger):
                            success = False
                        os.chmod(banner, 420)
                        os.chown(banner, 0, 0)

                # fix display manager config files
                for conffile in self.displaymgrconfiglist:
                    if os.path.exists(conffile):
                        if re.search('kdm', conffile):
                            if not self.fixkdm(conffile):
                                success = False
                        elif re.search('gdm', conffile):
                            if not self.fixgdm(conffile):
                                success = False
            self.rulesuccess = success
            if self.rulesuccess:
                debug = "InstallBanners fix has run to completion\n"
                self.logger.log(LogPriority.DEBUG, debug)
            else:
                debug = "InstallBanners fix has not run to completion\n"
                self.logger.log(LogPriority.DEBUG, debug)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def fixr7(self):
        '''
        rhel7 sets up warning banners differently than even other linuces
        it uses a new dconf database, and you must run a command after
        setting up the warning banner file and text
        '''

        retval = True

        try:

            path = '/etc/dconf/db/gdm.d/01-banner-message'
            confstr = '[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'' + OSXSHORTWARNINGBANNER + '\'\n'
            cmd = '/usr/bin/dconf update'

            path2 = '/etc/dconf/db/gdm.d/00-login-screen'
            confstr2 = '[org/gnome/login-screen]\ndisable-user-list=true\n'

            pathsplit = os.path.split(path)
            if not os.path.exists(pathsplit[0]):
                os.makedirs(pathsplit[0], 0755)
            pathsplit2 = os.path.split(path2)
            if not os.path.exists(pathsplit2[0]):
                os.makedirs(pathsplit2[0], 0755)

            f = open(path, 'w')
            f.write(confstr)
            f.close()

            f = open(path2, 'w')
            f.write(confstr2)
            f.close()

            self.commandhelper.executeCommand(cmd)
            errout = self.commandhelper.getErrorString()

            if errout:
                retval = False
                self.detailedresults += '\ncould not execute command: ' + str(cmd)
                self.logger.log(LogPriority.DEBUG, str(errout))

        except Exception:
            raise
        return retval

###############################################################################

    def fixmac(self):
        '''
        Fix mac os x mavericks banner files

        @author Breen Malmberg
        @change: dwalker - implemented methods found in stonixutilityfunctions
            that does the same thing but with less code.
        '''

        # defaults
        motdfound = False
        RuleKVEditor.fix(self, True)
        success = True
        for banner in self.macbannerfiledict:
            if os.path.exists(banner):
                # if it is a com.apple.whatever.plist file,
                # RuleKVEditor.fix() should take care of it with the
                # defaults write command
                if re.search(re.escape('com.apple.'), banner):
                    os.chmod(banner, 420)
                    os.chown(banner, 0, 0)
                    pass
                tmpfile = banner + ".tmp"
                if writeFile(tmpfile, self.macbannerfiledict[banner],
                                                              self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": banner}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(banner, tmpfile, myid)
                    os.rename(tmpfile, banner)
                    os.chown(banner, 0, 0)
                    os.chmod(banner, 420)
                    resetsecon(banner)
                else:
                    success = False
            else:
                if createFile(banner, self.logger):
                    event = {'eventtype': 'creation',
                             'filename': banner}
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.statechglogger.recordchgevent(myid, event)
                    writeFile(banner, self.macbannerfiledict[banner],
                              self.logger)
                    os.chmod(banner, 420)
                    os.chown(banner, 0, 0)
                    resetsecon(banner)
                else:
                    success = False
        sshfile = "/private/etc/sshd_config"
        if os.path.exists(sshfile):
            contents = readFile(sshfile, self.logger)

            for line in contents:
                if re.search('^Banner[ \t]+/etc/motd', line.strip()):
                    motdfound = True
            if not motdfound:
                tempstring = ""
                for line in contents:
                    tempstring += line
                tempstring += "Banner /etc/motd\n"
                tmpfile = sshfile + ".tmp"
                if writeFile(tmpfile, tempstring, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': sshfile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(sshfile, tmpfile,
                                                         myid)
                    os.rename(tmpfile, sshfile)
                    os.chmod(sshfile, 420)
                    os.chown(sshfile, 0, 0)
                    resetsecon(sshfile)
                else:
                    success = False
        else:
            if createFile(sshfile, self.logger):
                event = {'eventtype': 'creation',
                         'filepath': sshfile}
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.statechglogger.recordchgevent(myid, event)
                writeFile(sshfile, "Banner /etc/motd\n", self.logger)
                os.chmod(sshfile, 420)
                os.chown(sshfile, 0, 0)
                resetsecon(sshfile)
            else:
                success = False
        return success
###############################################################################
    # kdm display manager config files have proprietary parameters

    def fixkdm(self, conffile):
        '''
        perform kdm-specific config changes to the given conffile
        this method is called/used by fix()

        @param conffile str the filename/path string to operate on
        @author Breen Malmberg
        '''
        success = True
        if os.path.exists(conffile):
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['InstallBanners.fixkdm', "fixing kde files"])
            changed = False
            if not checkPerms(conffile, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(conffile, [0, 0, 420], self.logger,
                                                    self.statechglogger, myid):
                    success = False
            contents = readFile(conffile, self.logger)
            tempstring = ""
            found = False
            for line in contents:
                if re.search('^GreetString', line):
                    if re.search("=", line):
                        temp = line.split("=")
                        try:
                            if temp[1] == WARNINGBANNER:
                                if found:
                                    continue
                                found = True
                                tempstring += line
                        except IndexError:
                            continue
                    else:
                        continue
                else:
                    tempstring += line
            if not found:
                tempstring += "GreetString=" + WARNINGBANNER + "\n"
                changed = True
            if changed:
                tmpfile = conffile + ".tmp"
                if writeFile(tmpfile, tempstring, self.logger):
                    event = {'eventtype': 'conf',
                             'filepath': conffile}
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(conffile, tmpfile,
                                                         myid)
                    os.rename(tmpfile, conffile)
                    os.chmod(conffile, 420)
                    os.chown(conffile, 0, 0)
                    resetsecon(conffile)
                else:
                    success = False
        return success
###############################################################################
    # gdm display manager config files have proprietary parameters

    def fixgdm(self, conffile):
        '''
        perform gdm-specific config changes to the given conffile
        this method is called/used by fix()

        @param conffile str the filename/path string to operate on
        @author Breen Malmberg
        '''
        success = True
        if os.path.exists(conffile):
            if not checkPerms(conffile, [0, 0, 420], self.logger):
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if not setPerms(conffile, [0, 0, 420], self.logger,
                                                    self.statechglogger, myid):
                    success = False
            contents = readFile(conffile, self.logger)
            data = {"Greeter": "/usr/libexec/gdmlogin",
                    "DefaultWelcome": "false",
                    "Welcome": WARNINGBANNER,
                    "RemoteWelcome": WARNINGBANNER}
            tempstring1 = ""
            tempstring2 = ""
            changed = False
            for item in data:
                found = False
                for line in contents:
                    if re.search("^" + item, line):
                        if re.search("=", line):
                            temp = line.split("=")
                            try:
                                if temp[1] == data[item]:
                                    if found:
                                        continue
                                    found = True
                                    tempstring1 += line
                            except IndexError:
                                continue
                        else:
                            continue
                    else:
                        tempstring1 += line
                if not found:
                    tempstring1 += item + "=" + data[item]
                    changed = True
                tempstring2 = tempstring1
                tempstring1 = ""
            if changed:
                tmpfile = conffile + ".tmp"
                if writeFile(tmpfile, tempstring2, self.logger):
                    event = {"eventtype": "conf",
                             "filepath": conffile}
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(conffile, tmpfile,
                                                         myid)
                    os.rename(tmpfile, conffile)
                    os.chmod(conffile, 420)
                    os.chown(conffile, 0, 0)
                    resetsecon(conffile)
                else:
                    success = False
        return success
###############################################################################
