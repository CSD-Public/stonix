###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
@change: 2015/05/11 breen complete re-write
@change: 2016/08/10 eball Added "dbus-launch" to gsettings commands, major PEP8
    cleanup.
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 1/17/2019 dwalker  - hotfix to correct issue with configuration
    file changes in the reportcommon and fixcommon methods
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..ruleKVEditor import RuleKVEditor
from ..KVEditorStonix import KVEditorStonix
from ..pkghelper import Pkghelper
from ..localize import WARNINGBANNER
from ..localize import GDMWARNINGBANNER
from ..localize import GDM3WARNINGBANNER
from ..localize import ALTWARNINGBANNER
from ..localize import OSXSHORTWARNINGBANNER
from ..stonixutilityfunctions import fixInflation, iterate, createFile
from ..stonixutilityfunctions import setPerms, readFile, writeFile


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
        self.rulenumber = 51
        self.rulename = 'InstallBanners'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
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
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        # init CIs
        datatype = 'bool'
        key = 'INSTALLBANNERS'
        instructions = "To prevent the installation of warning banners, " + \
            "set the value of InstallBanners to False.\n\n!DEBIAN USERS! Due to " + \
            "a bug in gdm3 (gnome 3) which has not been patched on debian, we are forced to " + \
            "change the user's display manager to something else in order to be compliant " + \
            "with the login banner requirement. As a result, the login banner changes will " + \
            "only take effect after a system reboot."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        # Initial setup and deterministic resolution of variables
        constlist = [WARNINGBANNER, GDMWARNINGBANNER, GDM3WARNINGBANNER, ALTWARNINGBANNER, OSXSHORTWARNINGBANNER]
        if not self.checkConsts(constlist):
            self.applicable = {'type': 'white',
                               'family': []}
            return

        self.initobjs()
        self.setcommon()
        self.islinux()
        self.ismac()

    def initobjs(self):
        '''
        '''

        try:

            self.ph = Pkghelper(self.logger, self.environ)
            self.ch = CommandHelper(self.logger)
            self.linux = False
            self.mac = False
            self.gnome2 = False
            self.gnome3 = False
            self.kde = False
            self.lightdm = False
            self.badline = False

        except Exception:
            raise

    def setgnome2(self):
        '''
        set up all variables for use with gnome2-based systems

        @author: Breen Malmberg
        '''

        self.gnome2 = True
        self.bannertext = GDMWARNINGBANNER

    def forcelightdm(self):
        '''
        force debian systems using gdm3 to
        change to the lightdm display manager
        in order to comply with login/display
        banner requirements

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        self.logger.log(LogPriority.DEBUG, "Forcing display manager to be lightdm...")

        if self.gnome2:
            cmd = '/usr/sbin/dpkg-reconfigure --frontend=noninteractive gdm'
        elif self.gnome3:
            cmd = '/usr/sbin/dpkg-reconfigure --frontend=noninteractive gdm3'
        else:
            cmd = '/usr/sbin/dpkg-reconfigure --frontend=noninteractive lightdm'

        cmd2 = "/usr/sbin/dpkg --configure lightdm"

        self.lightdm = True
        path = '/etc/X11/default-display-manager'
        opt = '/usr/sbin/lightdm\n'
        mode = 0644
        uid = 0
        gid = 0

        try:

            if not self.setFileContents(path, opt, [uid, gid, mode]):
                retval = False

            if not self.ph.check('lightdm'):
                self.logger.log(LogPriority.DEBUG, "Package: lightdm not installed yet. Installing lightdm...")
                if not self.ph.install('lightdm'):
                    retval = False
                    self.detailedresults += "\nFailed to install lightdm"

            if not self.ch.executeCommand(cmd):
                retval = False
                self.detailedresults += "\nFailed to set lightdm as default display manager"

            self.ch.executeCommand(cmd2)

            if retval:
                self.detailedresults += "\nThe display manager has been changed to lightdm. These changes will only take effect once the system has been restarted."
            else:
                self.detailedresults += "\nFailed to change default display manager to lightdm. Login banner may not display."

        except Exception:
            raise
        return retval

    def setgnome3(self):
        '''
        set up all variables for use with gnome3-based systems

        @author: Breen Malmberg
        '''

        self.gnome3 = True
        self.bannertext = GDM3WARNINGBANNER

    def setkde(self):
        '''
        set up all variables for use with kde-based systems

        @author: Breen Malmberg
        '''

        self.kde = True
        self.bannertext = ALTWARNINGBANNER
        self.kdelocs = ['/etc/kde/kdm/kdmrc',
                        '/etc/kde3/kdm/kdmrc',
                        '/etc/kde4/kdm/kdmrc',
                        '/usr/share/config/kdm/kdmrc',
                        '/usr/share/kde4/config/kdm/kdmrc']
        self.kdefile = '/usr/share/kde4/config/kdm/kdmrc'
        for loc in self.kdelocs:
            if os.path.exists(loc):
                self.kdefile = str(loc)
        tmpfile = self.kdefile + '.stonixtmp'

        key1 = 'GreetString'
        val1 = '"' + self.bannertext + '"'
        self.greetbanner = [key1, val1]
        key2 = 'UserList'
        val2 = 'false'
        key3 = 'UseTheme'
        val3 = 'false'
        key4 = 'PreselectUser'
        val4 = 'None'
        key5 = 'LogoArea'
        val5 = 'None'
        key6 = 'GreeterPos'
        val6 = '45,45'
        key7 = 'AntiAliasing'
        val7 = 'false'
        key8 = 'SortUsers'
        val8 = 'false'
        key9 = 'GreetFont'
        val9 = 'Serif,20,-1,5,50,0,0,0,0,0'
        key10 = 'FailFont'
        val10 = 'Sans Serif,10,-1,5,75,0,0,0,0,0'
        bkey1 = 'PreselectUser'
        bval1 = 'None'
        self.kdedict = {"X-*-Greeter": {key2: val2,
                        key3: val3,
                        key4: val4,
                        key5: val5,
                        key6: val6,
                        key7: val7,
                        key8: val8,
                        key9: val9,
                        key10: val10},
                        "X-:*-Greeter": {bkey1: bval1}}

        self.kdeditor = KVEditorStonix(self.statechglogger, self.logger,
                                       "tagconf", self.kdefile, tmpfile,
                                       self.kdedict, "present", "closedeq")

    def setlightdm(self):
        '''
        set up all variables for use with lightdm-based systems

        @author: Breen Malmberg
        '''

        self.lightdm = True
        self.bannertext = ALTWARNINGBANNER
        key1 = '/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf'
        val1 = ['[SeatDefaults]',
                'allow-guest=false',
                'greeter-hide-users=true',
                'greeter-show-manual-login=true',
                'autologin-user=']
        key2 = self.loginbannerfile
        val2 = WARNINGBANNER
        key3 = '/etc/lightdm/lightdm.conf.d/stonixlightdm.conf'
        val3 = ['[SeatDefaults]',
                'greeter-setup-script=/bin/sh -c "until /usr/bin/zenity ' +
                '--width=600 --height=400 --title=WARNING --text-info ' +
                '--filename=' + str(self.loginbannerfile) + '; do :; done"']
        self.lightdmdict = {key1: val1,
                            key2: val2,
                            key3: val3}

    def setlinuxcommon(self):
        '''
        set up all variables for use with linux-based systems

        @author: Breen Malmberg
        '''

        if not self.sshdfile:
            self.sshdfile = '/etc/ssh/sshd_config'
        self.bannerfiles = ["/etc/banners/in.ftpd",
                            "/etc/banners/in.rlogind",
                            "/etc/banners/in.rshd",
                            "/etc/banners/in.telnetd",
                            "/etc/banner"]

    def setcommon(self):
        '''
        set up all variables for use with all systems

        @author: Breen Malmberg
        '''

        self.loginbannerfile = "/etc/issue"
        self.sshbannerfile = "/etc/banner"

        self.sshdfile = ""
        self.sshdlocs = ["/etc/sshd_config",
                         "/etc/ssh/sshd_config",
                         "/private/etc/ssh/sshd_config",
                         "/private/etc/sshd_config"]
        for loc in self.sshdlocs:
            if os.path.exists(loc):
                self.sshdfile = str(loc)

        self.sshbannerdict = {"Banner": self.sshbannerfile}

    def setmac(self):
        '''
        set up all variables for use with darwin-based systems

        @author: Breen Malmberg
        '''

        self.mac = True
        self.bannertext = WARNINGBANNER

        if not self.sshdfile:
            self.sshdfile = '/private/etc/sshd_config'
        self.ftpwelcomelocs = ["/etc/ftpwelcome", "/private/etc/ftpwelcome"]
        self.ftpwelcomefile = '/private/etc/ftpwelcome'
        for loc in self.ftpwelcomelocs:
            if os.path.exists(loc):
                self.ftpwelcomefile = str(loc)
        self.policybanner = "/Library/Security/PolicyBanner.txt"

        self.addKVEditor("FileServerBannerText", "defaults",
                         "/Library/Preferences/com.apple.AppleFileServer", "",
                         {"loginGreeting": [re.escape(WARNINGBANNER),
                                            "'\"" + WARNINGBANNER + "\"'"]},
                         "present", "",
                         "To prevent the installation of a warning banner," +
                         " set the value of InstallBanners to False",
                         self.ci)
        self.addKVEditor("loginwindowBannerText", "defaults",
                         "/Library/Preferences/com.apple.loginwindow", "",
                         {"LoginwindowText": [re.escape(OSXSHORTWARNINGBANNER),
                                              '"' + OSXSHORTWARNINGBANNER +
                                              '"']},
                         "present", "",
                         "To prevent the installation of a warning banner," +
                         " set the value of InstallBanners to False",
                         self.ci)

    def ismac(self):
        '''
        determine whether the current system is macintosh, or darwin-based

        @author: Breen Malmberg
        '''

        try:
            if self.environ.getosfamily() == 'darwin':
                self.setmac()
                self.logger.log(LogPriority.DEBUG, "System is Mac OS. Configuring Mac banners...")
        except Exception:
            raise

    def islinux(self):
        '''
        determine whether the current system is linux-based, and set all
        distro-specific variables

        @author: Breen Malmberg
        '''

        try:

            if self.environ.getosfamily() == 'linux':
                self.linux = True

                self.setlinuxcommon()

                if os.path.exists("/usr/sbin/gdm3"):
                    self.setgnome3()
                elif os.path.exists("/usr/sbin/gdm"):
                    self.ch.executeCommand("/usr/sbin/gdm --version")
                    gnomeversionstring = self.ch.getOutputString()
                    if re.search("GDM\s+3\.", gnomeversionstring, re.IGNORECASE):
                        self.setgnome3()
                    else:
                        self.setgnome2()
                elif os.path.exists("/usr/sbin/lightdm"):
                    self.setlightdm()
                elif os.path.exists("/usr/bin/startkde"):
                    self.setkde()

        except Exception:
            raise

    def getFileContents(self, filepath, returntype='list'):
        '''
        Retrieve and return file contents (in list format) of a given file path

        @param filepath: string full path to file to read
        @param returntype: string valid values: 'list', 'string'

        @return filecontents
        @rtype: list
        @author: Breen Malmberg
        '''

        self.logger.log(LogPriority.DEBUG, "Retrieving contents of file " + filepath)

        try:
            if returntype == 'list':
                filecontents = []
            elif returntype == 'string':
                filecontents = ''
            else:
                filecontents = ''
                self.detailedresults += "\nReturntype parameter must be " + \
                    "either 'list' or 'string!'"
            if os.path.exists(filepath):
                f = open(filepath, 'r')
                if returntype == 'list':
                    filecontents = f.readlines()
                elif returntype == 'string':
                    filecontents = f.read()
                f.close()
            else:
                self.detailedresults += '\nCould not find specified file: ' + \
                    str(filepath) + '. Returning empty value...'
        except Exception:
            raise
        return filecontents

    def setFileContents(self, filepath, contents, perms=[0, 0, 0644]):
        '''
        write (or append) specified contents to specified file

        @param filepath: string full path to file
        @param contents: list/string object to write to file (can be either
            list or string)
        @param mode: string indicates the IO method to use to open the file.
            Valid values are 'w' for write, and 'a' for append
        @param perms: integer-list of size 3. first index/position in list
            indicates octal permissions flag; second indicates uid; third
            indicates gid

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True
        tmpPath = filepath + ".stonixtmp"

        self.logger.log(LogPriority.DEBUG, "Writing changes to file " + filepath)

        try:

            if os.path.exists(filepath):
                f = open(tmpPath, "w")
                if isinstance(contents, list):
                    f.writelines(contents)
                else:
                    f.write(contents)
                f.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': filepath}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(filepath, tmpPath, myid)
                os.rename(tmpPath, filepath)
                os.chmod(filepath, perms[2])
                os.chown(filepath, perms[0], perms[1])
            else:
                # get the parent directory of filepath
                basepath = ("/").join(filepath.split("/")[:-1])
                # create parent directory if it doesn't exist
                if not os.path.exists(basepath):
                    os.makedirs(basepath, 0755)
                # then create the file
                f = open(filepath, "w")
                if isinstance(contents, list):
                    f.writelines(contents)
                else:
                    f.write(contents)
                f.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'creation',
                         'filepath': filepath}
                self.statechglogger.recordchgevent(myid, event)
                os.chmod(filepath, perms[2])
                os.chown(filepath, perms[0], perms[1])

            if not fixInflation(filepath, self.logger, perms[2], [perms[0], perms[1]]):
                retval = False

        except Exception:
            retval = False
            raise
        return retval

    def replaceFileContents(self, filepath, contentdict):
        '''
        replace key from contentdict with value from contentdict, in filepath

        @param filepath: string full path to file
        @param contentdict: dictionary of strings

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True
        appends = []

        self.logger.log(LogPriority.DEBUG, "Replacing any existing, incorrect configurations...")

        try:

            contentlines = self.getFileContents(filepath)
            for line in contentlines:
                for key in contentdict:
                    if any((re.search("\*", key), re.search("\*", line))):
                        if re.search("^" + re.escape(key), re.escape(line)):
                            contentlines = [c.replace(line, key + contentdict[key]) for c in contentlines]
                    else:
                        if re.search("^" + key, line):
                            contentlines = [c.replace(line, key + contentdict[key]) for c in contentlines]

            for key in contentdict:
                if key.strip() not in contentlines:
                    appends.append(key + contentdict[key])
            self.appendFileContents(filepath, contentlines, appends)

        except Exception:
            self.rulesuccess = False
            raise
        return retval

    def appendFileContents(self, filepath, contents, appends):
        '''

        @return:
        '''

        self.logger.log(LogPriority.DEBUG, "Appending missing configuration lines...")

        for a in appends:
            contents.append(a + "\n")

        self.setFileContents(filepath, contents)

    def reportFileContents(self, filepath, searchparams):
        '''
        verify that the give key:value pairs in contentdict exist in filepath

        @param filepath: string full path to file
        @param searchparams: list or string to search in file contents

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True
        foundDict = {}
        findresult = 999
        foundstring = False

        try:

            if not os.path.exists(filepath):
                retval = False
                self.detailedresults += "\nRequired configuration file " + filepath + " does not exist"
                return retval

            if isinstance(searchparams, basestring):
                contents = self.getFileContents(filepath, "string")
                findresult = contents.find(searchparams)
                if findresult != -1:
                    foundstring = True
                if not foundstring:
                    retval = False
                    self.logger.log(LogPriority.DEBUG, "str.find() return code = " + str(findresult))
                    self.detailedresults += "\nSearch parameter:\n" + searchparams + "\nis missing from " + filepath
            elif isinstance(searchparams, list):
                for p in searchparams:
                    foundDict[p] = False
                contentlines = self.getFileContents(filepath)
                for line in contentlines:
                    for p in searchparams:
                        if line.find(p) != -1:
                            foundDict[p] = True
                for i in foundDict:
                    if not foundDict[i]:
                        retval = False
                        self.detailedresults += "\nSearch parameter:\n" + i + "\nis missing from " + filepath
        except Exception:
            raise
        return retval

    def checkCommand(self, cmd, val="", regex=True):
        '''
        check the output of a given command to see if it matches given value

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        retval = True

        try:

            self.ch.executeCommand(cmd)
            retcode = self.ch.getReturnCode()
            # gconftool-2 returns either 0 or -1 on error
            if re.search("gconftool-2", cmd):
                if retcode == -1:
                    retval = False
                    errstr = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += "\nCommand:\n" + cmd + "\nFailed"
            else:
                # all other programs return 0 on success
                if retcode != 0:
                    retval = False
                    errstr = self.ch.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
            if val:
                outputstr = self.ch.getOutputString()
                if not regex:
                    # outputstr = outputstr.strip()
                    # val = val.strip()
                    if outputstr.find(val) == -1:
                        retval = False
                        self.detailedresults += "\nDesired output:\n"
                        self.detailedresults += val
                        self.detailedresults += "\n\nActual output:\n"
                        self.detailedresults += outputstr
                else:
                    if not re.search(val, outputstr, re.IGNORECASE):
                        retval = False
                        self.logger.log(LogPriority.DEBUG, "Could not find search regex:\n" + val + "\nin command output")

        except Exception:
            raise
        return retval

    def report(self):
        '''
        The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.

        @return self.compliant
        @rtype: boolean

        @author Breen Malmberg
        '''

        self.compliant = True
        self.detailedresults = ""

        try:

            if self.linux:
                if not self.reportlinux():
                    self.compliant = False
            elif self.mac:
                if not self.reportmac():
                    self.compliant = False
            else:
                self.compliant = False
                self.detailedresults += '\nCould not identify operating system, or operating system not supported.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def getgnome3version(self):
        '''
        get the gnome3 version as a float

        @return: g3ver
        @rtype: float
        @author: Breen Malmberg
        '''

        g3ver = 0.0
        cmd = '/usr/sbin/gdm3 --version'
        backupcmd = '/usr/bin/gnome-session --version'
        if not any((self.checkCommand(cmd), self.checkCommand(backupcmd))):
            return g3ver
        else:
            outlines = self.ch.getOutput()
            for line in outlines:
                sline = line.split()
                if len(sline) > 1:
                    splitver = sline[1].split('.')
                    combinedver = splitver[0] + '.' + splitver[1]
                    g3ver = float(combinedver)
                else:
                    try:
                        g3ver = float(sline[0])
                    except Exception:
                        return g3ver
        return g3ver

    def reportlinux(self):
        '''
        run report functionality for linux-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        compliant = True

        try:

            if all((self.gnome3, re.search('debian', self.environ.getostype(), re.IGNORECASE))):
                if self.getgnome3version() < 3.15:
                    self.gnome3 = False
                    self.forcelightdm()
                    self.setlightdm()

            if not self.reportlinuxcommon():
                compliant = False
            if self.gnome2:
                if not self.reportgnome2():
                    compliant = False
            elif self.gnome3:
                if not self.reportgnome3():
                    compliant = False
            elif self.lightdm:
                if not self.reportlightdm():
                    compliant = False
            elif self.kde:
                if not self.reportkde():
                    compliant = False

        except Exception:
            raise
        return compliant

    def reportlinuxcommon(self):
        '''
        run report functionality which is common to linux platforms

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        compliant = True

        try:

            for f in self.bannerfiles:
                if not self.reportFileContents(f, WARNINGBANNER):
                    compliant = False

            if not self.reportcommon():
                compliant = False

        except Exception:
            raise
        return compliant

    def reportcommon(self):
        '''
        run report functionality which is common to all platforms

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        compliant = True
        if not os.path.exists(self.sshdfile):
            self.detailedresults += "Required configuration file " + self.ssdhfile + \
                                    " does not exist.\n"
            return False
        contents = readFile(self.sshdfile, self.logger)
        self.commoneditor =  KVEditorStonix(self.statechglogger, self.logger,
                                       "conf", self.sshdfile, self.sshdfile + ".tmp",
                                       self.sshbannerdict, "present", "space")
        if not self.commoneditor.report():
            compliant = False
            self.detailedresults += self.sshdfile + " doesn't contain correct contents\n"
        return compliant


    def reportgnome2(self):
        '''
        run report functionality for gnome2-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        compliant = True

        try:

            gconf = "/usr/bin/gconftool-2"
            confDict = {"/apps/gdm/simple-greeter/disable_user_list": "true",
                        "/apps/gdm/simple-greeter/banner_message_enable": "true",
                        "/apps/gdm/simple-greeter/banner_message_text": ALTWARNINGBANNER} # gdm 2 db cannot reliably store/preserve/interpret newline characters
            gconfcommands = []
            for item in confDict:
                gconfcommands.append(gconf + " -g " + item)

            for gcmd in gconfcommands:
                if not self.checkCommand(gcmd, confDict[gcmd.split()[2]], False):
                    compliant = False

        except Exception:
            raise
        return compliant

    def reportgnome3(self):
        '''
        run report functionality for gnome3-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        compliant = True

        try:

            if not self.checkprofilecfg():
                compliant = False
            if not self.checkkeyfilecfg():
                compliant = False

        except Exception:
            raise
        return compliant

    def checkprofilecfg(self):
        '''

        @return:
        '''

        compliant = True

        profilefile = "/etc/dconf/profile/gdm"
        profileoptslist = ["user-db:user",
                           "system-db:gdm"]
        if not self.reportFileContents(profilefile, profileoptslist):
            compliant = False

        return compliant

    def checkkeyfilecfg(self):
        '''

        @return:
        '''

        compliant = True

        keyfile = "/etc/dconf/db/gdm.d/01-banner-message"
        keyfileoptslist = ["[org/gnome/login-screen]",
                           "banner-message-enable=true",
                           "banner-message-text='" + GDM3WARNINGBANNER + "'",
                           "disable-user-list=true"]

        if not self.reportFileContents(keyfile, keyfileoptslist):
            compliant = False

        return compliant

    def reportlightdm(self):
        '''
        run report functionality for lightdm-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        compliant = True

        try:

            for item in self.lightdmdict:
                if not self.reportFileContents(item, self.lightdmdict[item]):
                    compliant = False
                    self.detailedresults += '\nRequired configuration text not found in: ' + str(item)

        except Exception:
            raise
        return compliant

    def reportkde(self):
        '''
        run report functionality for kde-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if not os.path.exists(self.kdefile):
                retval = False
                self.detailedresults += 'Required configuration file: ' + str(self.kdefile) + ' not found'
            else:
                if not self.kdeditor.report():
                    retval = False
                    if self.kdeditor.fixables:
                        self.detailedresults += '\nThe following required options are missing from ' + \
                            str(self.kdefile) + ':\n' + '\n'.join(str(f) for f in self.kdeditor.fixables) \
                            + '\n'
                else:
                    # Since the warning banner spans multiple lines in the
                    # config file, the KVEditor does not properly detect it.
                    # This is a modified version of the KVATaggedConf algorithm
                    # to find a multi-line value
                    conflines = open(self.kdefile, "r").readlines()
                    tagstart = -1
                    greetlinestart = -1
                    for ind, line in enumerate(conflines):
                        if re.search("^\[X-\*-Greeter\]", line):
                            tagstart = ind + 1
                            break
                    if tagstart > 0:
                        for ind, line in enumerate(conflines[tagstart:]):
                            if re.search("^#", line) or \
                               re.search("^\s*$", line):
                                continue
                            elif re.search("^\[.*?\]\s*$", line):  # New tag
                                retval = False
                                self.detailedresults += "\nCould not find " + \
                                    "required banner in " + self.kdefile
                                break
                            elif re.search("^" + self.greetbanner[0] + "=",
                                           line):
                                greetlinestart = ind
                                break
                    if greetlinestart > 0:
                        banner = self.bannertext
                        bannerlines = banner.splitlines(True)
                        greetlines = []
                        startline = conflines[greetlinestart +
                                              tagstart].replace(self.greetbanner[0]
                                                                + '="', '')
                        greetlines.append(startline)
                        for line in conflines[greetlinestart + tagstart + 1:]:
                            if re.search('^"\s*', line):
                                break
                            greetlines.append(line)
                        if bannerlines != greetlines:
                            retval = False
                            self.detailedresults += "\nDid not find correct " + \
                                "correct warning banner in " + self.kdefile
                            debug = "Current GreetString: " + "".join(greetlines) \
                                + "\nBanner wanted: " + "".join(bannerlines)
                            self.logger.log(LogPriority.DEBUG, debug)
        except Exception:
            raise
        return retval

    def reportmac(self):
        '''
        run report functionality for macintosh, or darwin-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not RuleKVEditor.report(self, True):
                self.detailedresults += '\nEither file server banner text ' + \
                    'or login window banner text is incorrect, or both'
                retval = False
            if os.path.exists(self.ftpwelcomefile):
                if not self.reportFileContents(self.ftpwelcomefile,
                                               self.bannertext):
                    retval = False
                    self.detailedresults += '\nIncorrect configuration ' + \
                        'text in: ' + str(self.ftpwelcomefile)
            else:
                retval = False
                self.detailedresults += '\nRequired configuration file: ' + \
                    str(self.ftpwelcomefile) + ' not found'

            if os.path.exists(self.policybanner):
                if not self.reportFileContents(self.policybanner,
                                               self.bannertext):
                    retval = False
                    self.detailedresults += '\nIncorrect configuration ' + \
                        'text in: ' + str(self.policybanner)
            else:
                retval = False
                self.detailedresults += '\nRequired configuration file: ' + \
                    str(self.policybanner) + ' not found'
            if not self.reportcommon():
                retval = False
        except Exception:
            raise
        return retval

    def fix(self):
        '''
        Install warning banners, set the warning text and configure the
        file permissions for the warning banner files.

        @return: success
        @rtype: boolean

        @author Breen Malmberg
        '''

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

        try:

            if self.ci.getcurrvalue():
                if not self.fixcommon():
                    self.rulesuccess = False
                if self.linux:
                    if not self.fixlinux():
                        self.rulesuccess = False
                elif self.mac:
                    if not self.fixmac():
                        self.rulesuccess = False
                else:
                    self.rulesuccess = False
                    self.detailedresults += '\nCould not identify ' + \
                        'operating system, or operating system not supported.'
            else:
                self.detailedresults += '\nThe configuration item for ' + \
                    'this rule was not enabled so nothing was done.'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixlinux(self):
        '''
        run fix functionality for linux-based systems

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''

        success = True

        try:

            if not self.fixlinuxcommon():
                success = False
            if self.gnome2:
                if not self.fixgnome2():
                    success = False
            elif self.gnome3:
                if not self.fixgnome3():
                    success = False
            elif self.lightdm:
                if not self.fixlightdm():
                    success = False
            elif self.kde:
                if not self.fixkde():
                    success = False

        except Exception:
            raise
        return success

    def fixlinuxcommon(self):
        '''
        run fix functionality which is common to linux platforms

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''

        success = True

        try:

            for f in self.bannerfiles:
                if not self.setFileContents(f, WARNINGBANNER):
                    success = False

        except Exception:
            raise
        return success

    def fixcommon(self):
        '''
        run fix functionlity which is common to all platforms

        @return: success
        @rtype: boolean

        @author: Breen Malmberg
        '''

        success = True

        if self.commoneditor.fixables:
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            self.commoneditor.setEventID(myid)
            if not self.commoneditor.fix():
                debug = self.sshdfile + " editor fix is returning false\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
            elif not self.commoneditor.commit():
                debug = self.sshdfile + " editor commit is returning false\n"
                self.logger.log(LogPriority.DEBUG, debug)
                success = False
            if not success:
                self.detailedresults += "Unable to correct contents of " + \
                    self.sshdfile + "\n"
        return success

    def fixgnome2(self):
        '''
        run fix functionality for gnome2-based systems
        (implementation based on: https://access.redhat.com/solutions/32480)

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''

        success = True
        gconf = "/usr/bin/gconftool-2"
        confDict = {"/apps/gdm/simple-greeter/disable_user_list": "boolean true",
                    "/apps/gdm/simple-greeter/banner_message_enable": "boolean true",
                    "/apps/gdm/simple-greeter/banner_message_text": 'string "$(cat /etc/issue)"'}
        gconfcommands = []
        for item in confDict:
            gconfcommands.append(gconf + " -s " + item + " --config-source=xml:readwrite:/etc/gconf/gconf.xml.system --direct --type " + confDict[item])

        try:

            if not self.setFileContents("/etc/issue", GDMWARNINGBANNER):
                success = False
                self.detailedresults += "\nFailed to properly configure the banner text in file /etc/issue"

            # write configuration options to gnome system-wide database
            for gcmd in gconfcommands:
                if not self.checkCommand(gcmd):
                    success = False

        except Exception:
            raise
        return success

    def fixgnome3(self):
        '''
        run fix functionality for gnome3-based systems

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''

        success = True

        try:

            if not self.setFileContents("/etc/issue", GDM3WARNINGBANNER):
                success = False
                self.detailedresults += "\nFailed to properly configure the banner text in file /etc/issue"

            self.logger.log(LogPriority.DEBUG, "Applying gdm profile configurations...")

            # configure the gdm profile
            greeterdefaults = ""
            gdefaultslocs = ["/usr/share/gdm/greeter-dconf-defaults",
                             "/usr/share/gdm/greeter.dconf-defaults"]
            for loc in gdefaultslocs:
                if os.path.exists(loc):
                    greeterdefaults = loc
            profilebasedir = "/etc/dconf/profile"
            profilepath = profilebasedir + "/gdm"
            profileconflist = ["user-db:user\n",
                               "system-db:gdm\n",
                               "file-db:" + greeterdefaults + "\n"]
            if not os.path.exists(profilebasedir):
                self.logger.log(LogPriority.DEBUG, "gdm profile base directory does not exist. Creating it...")
                os.makedirs(profilebasedir, 0755)
            if not self.setFileContents(profilepath, profileconflist):
                success = False

            self.logger.log(LogPriority.DEBUG, "Applying gdm keyfile configurations...")

            # configure the gdm keyfile
            gdmkeyfilebase = "/etc/dconf/db/gdm.d"
            gdmkeyfile = gdmkeyfilebase + "/01-banner-message"
            gdmkeyfileconflist = ["[org/gnome/login-screen]\n",
                                  "banner-message-enable=true\n",
                                  "banner-message-text='" + GDM3WARNINGBANNER + "'\n",
                                  "disable-user-list=true\n"]
            if not os.path.exists(gdmkeyfilebase):
                self.logger.log(LogPriority.DEBUG, "gdm keyfile base directory does not exist. Creating it...")
                os.makedirs(gdmkeyfilebase, 0755)
            if not self.setFileContents(gdmkeyfile, gdmkeyfileconflist):
                success = False

            self.logger.log(LogPriority.DEBUG, "Updating dconf with new configuration settings...")

            # update dconf
            dconfupdate = "/usr/bin/dconf update"
            if not self.checkCommand(dconfupdate):
                success = False

            if success:
                self.detailedresults += "\nSuccessfully applied new banner configuration settings. On some systems, a reboot may be required to view updated settings"

        except Exception:
            raise
        return success

    def fixlightdm(self):
        '''
        run fix functionality for lightdm-based systems

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''

        success = True
        contentlines = []

        try:

            if not os.path.exists('/etc/lightdm/lightdm.conf.d'):
                os.makedirs('/etc/lightdm/lightdm.conf.d/', 0755)
            for f in self.lightdmdict:
                contentlines = []
                if isinstance(self.lightdmdict[f], list):
                    for opt in self.lightdmdict[f]:
                        contentlines.append(opt + '\n')
                    if not self.setFileContents(f, contentlines):
                        success = False
                else:
                    if not self.setFileContents(f, self.lightdmdict[f]):
                        success = False
        except Exception:
            raise
        return success

    def fixkde(self):
        '''
        run fix functionality for kde-based systems

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        @change: Breen Malmberg - 5/25/2016 - moved the commit calls to ensure
        they are only called if the fix calls completed successfully
        '''

        success = True

        try:
            if not self.kdefile:
                self.logger.log(LogPriority.DEBUG,
                                "Unable to identify kde configuration file. " +
                                "Can not continue with fix")
                self.detailedresults += "Unable to identify kde " + \
                    "configuration file. Can not continue with fix."
                success = False
                return success

            fileCreated = False
            if not os.path.exists(self.kdefile):
                if createFile(self.kdefile, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.kdefile}
                    self.statechglogger.recordchgevent(myid, event)
                    fileCreated = True
                    debug = "kdmrc file successfully created at " + \
                        self.kdefile
                    self.logger.log(LogPriority.DEBUG, debug)
                    setPerms(self.kdefile, [0, 0, 0o644], self.logger)
                    self.reportkde()
                else:
                    self.detailedresults += "\nCould not create kdmrc file " + \
                        "at " + self.kdefile
                    return False

            if not self.kdeditor.fix():
                success = False
                self.detailedresults += "KVEditor fix failed. Fix not applied"
            else:
                if not fileCreated:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.kdeditor.setEventID(myid)
                if not self.kdeditor.commit():
                    success = False
                    self.detailedresults += 'kdeditor commit failed. ' + \
                        'Fix not applied'
            key1 = 'GreetString'
            val1 = '"' + self.bannertext + '"'
            data = {"X-*-Greeter": {key1: val1}}
            tmpfile = self.kdefile + ".stonixtmp2"
            greeteditor = KVEditorStonix(self.statechglogger, self.logger,
                                         "tagconf", self.kdefile, tmpfile,
                                         data, "present", "closedeq")
            if not greeteditor.report():
                if greeteditor.fix():
                    if not greeteditor.commit():
                        if not fileCreated:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            self.kdeditor.setEventID(myid)
                            success = False
                        self.detailedresults += "\nGreetString commit failed"
                else:
                    success = False
                    self.detailedresults += "\nGreetString fix failed"
        except Exception:
            raise
        return success

    def fixmac(self):
        '''
        run fix functionality for macintosh, or darwin-based systems

        @return: success
        @rtype: boolean
        @author: Breen Malmberg
        '''

        success = True

        try:
            if not RuleKVEditor.fix(self, True):
                success = False
            if not self.setFileContents(self.ftpwelcomefile, self.bannertext):
                success = False
                self.detailedresults += '\nUnable to set warning banner text in ' + str(self.ftpwelcomefile)
            if not self.setFileContents(self.policybanner, self.bannertext):
                success = False
                self.detailedresults += '\nUnable to set warning banner text in ' + str(self.policybanner)
        except Exception:
            raise
        return success
