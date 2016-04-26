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
@change: 2015/05/11 breen complete re-write
'''

from __future__ import absolute_import
import os
import re
import traceback

from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..ruleKVEditor import RuleKVEditor
from ..KVEditorStonix import KVEditorStonix
from ..localize import WARNINGBANNER
from ..localize import ALTWARNINGBANNER
from ..localize import OSXSHORTWARNINGBANNER
from ..stonixutilityfunctions import fixInflation
from ..stonixutilityfunctions import iterate


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
                           'os': {'Mac OS X': ['10.9', 'r', '10.11.10']}}
        # init CIs
        datatype = 'bool'
        key = 'InstallBanners'
        instructions = "To prevent the installation of warning banners, " + \
        "set the value of InstallBanners to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.cmdhelper = CommandHelper(self.logger)

        #initial setup and deterministic resolution of variables
        self.setcommon()
        self.islinux()
        self.ismac()

###############################################################################

    def checkCommand(self, cmd, val, regex=True):
        '''
        check the output of a given command to see if it matches given value

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        retval = False

        try:
            self.cmdhelper.executeCommand(cmd)
            output = self.cmdhelper.getOutputString()
            if not regex:
                found = output.find(val)
                if found != -1:
                    retval = True
            else:
                if re.search(val, output):
                    retval = True
        except Exception:
            raise
        return retval

    def islinux(self):
        '''
        determine whether the current system is linux-based, and set all
        distro-specific variables

        @author: Breen Malmberg
        '''

        self.linux = False
        self.gnome2 = False
        self.gnome3 = False
        self.kde = False
        self.lightdm = False

        try:
            if self.environ.getosfamily() == 'linux':
                self.setlinuxcommon()
                self.isgnome2()
                self.isgnome3()
                self.iskde()
                self.islightdm()
        except Exception:
            raise

    def setgnome2(self):
        '''
        set up all variables for use with gnome2-based systems

        @author: Breen Malmberg
        '''

        self.gnome2 = True
        self.gconfpath = '/etc/gconf/gconf.xml.mandatory'
        gconfget = '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get '
        gconfset = '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory '
        opt1type = '--type bool --set '
        opt2type = '--type bool --set '
        opt3type = '--type string --set '
        opt1 = '/apps/gdm/simple-greeter/disable_user_list'
        opt2 = '/apps/gdm/simple-greeter/banner_message_enable'
        opt3 = '/apps/gdm/simple-greeter/banner_message_text'
        rep1 = gconfget + opt1
        rep2 = gconfget + opt2
        rep3 = gconfget + opt3
        val1 = 'true'
        val2 = 'true'
        val3 = '\'' + ALTWARNINGBANNER + '\''
        val3report = "This is a Department of Energy (DOE) computer system. DOE computer"
        fix1 = gconfset + opt1type + opt1 + ' ' + val1
        fix2 = gconfset + opt2type + opt2 + ' ' + val2
        fix3 = gconfset + opt3type + opt3 + ' ' + val3
        self.gnome2reportdict = {rep1: val1,
                                 rep2: val2,
                                 rep3: val3report}
        self.gnome2fixlist = [fix1, fix2, fix3]

    def setgnome3(self):
        '''
        set up all variables for use with gnome3-based systems

        @author: Breen Malmberg
        '''

        self.gnome3 = True

        profiledirs = ['/etc/dconf/profile/', '/var/lib/gdm3/dconf/profile/']
        profiledir = '/etc/dconf/profile/' # default
        for loc in profiledirs:
            if os.path.exists(loc):
                profiledir = loc
        if not profiledir:
            self.logger.log(LogPriority.DEBUG, "Unable to locate the gnome3 profile directory")

        profilefile = 'gdm'

        self.gdmprofile = profiledir + profilefile

        profiledict = {'/etc/dconf/profile/': ['user-db:user\n', 'system-db:gdm\n'],
                       '/var/lib/gdm3/dconf/profile/': ['user\n', 'gdm\n']}
        self.profilelist = profiledict[profiledir]

        gdmdirs = ['/etc/dconf/db/gdm.d/', '/var/lib/gdm3/dconf/db/gdm.d/']
        self.gdmdir = '/etc/dconf/db/gdm.d/' # default
        for loc in gdmdirs:
            if os.path.exists(loc):
                self.gdmdir = loc

        bannermessagefile = '01-banner-message'
        self.bannerfile = self.gdmdir + bannermessagefile

        self.gnome3optlist = ['[org/gnome/login-screen]\n', 'disable-user-list=true\n', 'banner-message-enable=true\n', 'banner-message-text=\'' + OSXSHORTWARNINGBANNER + '\'']
        self.gnome3optdict = {'disable-user-list': 'true',
                            'banner-message-enable': 'true',
                            'banner-message-text': '\'' + OSXSHORTWARNINGBANNER + '\''}
        dconf = '/usr/bin/dconf'
        self.dconfupdate = dconf + ' update'
        gsettings = '/usr/bin/gsettings'
        schema = 'org.gnome.login-screen'
        self.gsettingsget = gsettings + ' get ' + schema + ' '
        self.gsettingsset = gsettings + ' set ' + schema + ' '

    def setkde(self):
        '''
        set up all variables for use with kde-based systems

        @author: Breen Malmberg
        '''

        self.kde = True
        self.kdelocs = ['/etc/kde/kdm/kdmrc',
                        '/etc/kde3/kdm/kdmrc',
                        '/etc/kde4/kdm/kdmrc',
                        '/usr/share/config/kdm/kdmrc',
                        '/usr/share/kde4/config/kdm/kdmrc']
        key1 = 'GreetString'
        val1 = '\"' + ALTWARNINGBANNER + '\"'
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
        self.kdedict = {"X-\*-Greeter": {key1: val1,
                        key2: val2,
                        key3: val3,
                        key4: val4,
                        key5: val5,
                        key6: val6,
                        key7: val7,
                        key8: val8,
                        key9: val9,
                        key10: val10}}
        bkey1 = 'PreselectUser'
        bval1 = 'None'
        self.kdedict2 = {"X-:\*-Greeter": {bkey1: bval1}}
        self.kdefile = '/usr/share/kde4/config/kdm/kdmrc'
        for loc in self.kdelocs:
            if os.path.exists(loc):
                self.kdefile = str(loc)
        tmpfile = self.kdefile + '.tmp'
        self.kdeditor = KVEditorStonix(self.statechglogger, self.logger,
                                          "tagconf", self.kdefile, tmpfile,
                                          self.kdedict, "present",
                                          "closedeq")
        self.kdeditor2 = KVEditorStonix(self.statechglogger, self.logger,
                                        "tagconf", self.kdefile, tmpfile,
                                        self.kdedict2, "present")

    def setlightdm(self):
        '''
        set up all variables for use with lightdm-based systems

        @author: Breen Malmberg
        '''

        self.lightdm = True
        key1 = '/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf'
        val1 = ['[SeatDefaults]',
                'allow-guest=false',
                'greeter-hide-users=true',
                'greeter-show-manual-login=true',
                'autologin-user=']
        key2 = self.motdfile
        val2 = ALTWARNINGBANNER
        key3 = '/etc/lightdm/lightdm.conf.d/stonixlightdm.conf'
        val3 = ['[SeatDefaults]',
                'greeter-setup-script=/bin/sh -c "until /usr/bin/zenity --width=600 --height=400 --title=WARNING --text-info --filename=' + str(self.motdfile) + '; do :; done"']
        self.lightdmdict = {key1: val1,
                            key2: val2,
                            key3: val3}

    def setlinuxcommon(self):
        '''
        set up all variables for use with linux-based systems

        @author: Breen Malmberg
        '''

        self.linux = True
        self.motd = WARNINGBANNER + '\n'
        if not self.sshdfile:
            self.sshdfile = '/etc/ssh/sshd_config'
        self.bannerfiles = ["/etc/banners/in.ftpd",
                            "/etc/banners/in.rlogind",
                            "/etc/banners/in.rshd",
                            "/etc/banners/in.telnetd"]
        self.bannertext = ALTWARNINGBANNER

    def setcommon(self):
        '''
        set up all variables for use with all systems

        @author: Breen Malmberg
        '''

        self.motdfile = '/etc/motd'
        self.sshdlocs = ["/etc/sshd_config",
                         "/etc/ssh/sshd_config",
                         "/private/etc/ssh/sshd_config",
                         "/private/etc/sshd_config"]
        self.sshdfile = ''
        for loc in self.sshdlocs:
            if os.path.exists(loc):
                self.sshdfile = str(loc)
        key1 = 'Banner '
        val1 = 'Banner ' + str(self.motdfile)
        self.sshdopt = val1
        self.sshddict = {key1: val1}

    def setmac(self):
        '''
        set up all variables for use with darwin-based systems

        @author: Breen Malmberg
        '''

        self.mac = True
        self.motd = WARNINGBANNER + '\n'
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
                         "To prevent the installation of a warning banner," + \
                         " set the value of InstallBanners to False",
                         self.ci)
        self.addKVEditor("loginwindowBannerText", "defaults",
                         "/Library/Preferences/com.apple.loginwindow", "",
                         {"LoginwindowText": [re.escape(OSXSHORTWARNINGBANNER),
                                              '"' + OSXSHORTWARNINGBANNER + \
                                              '"']},
                         "present", "",
                         "To prevent the installation of a warning banner," + \
                         " set the value of InstallBanners to False",
                         self.ci)

    def isgnome2(self):
        '''
        determine whether the current system is gnome2-based

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = False

        cmd1 = "ps -ef | grep '/[X]' | grep gdm"
        val1 = '\/gdm\/'
        cmd2 = 'gnome-session --version'
        val2 = '\s2\.'

        try:
            if self.checkCommand(cmd1, val1):
                if self.checkCommand(cmd2, val2):
                    self.setgnome2()
        except Exception:
            raise
        return retval

    def isgnome3(self):
        '''
        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = False

        cmd1 = "ps -ef | grep '/[X]' | grep gdm"
        val1 = '\/gdm\/'
        cmd2 = 'gnome-session --version'
        val2 = '\s3\.'
        cmd3 = 'gdm --version'
        val3 = 'GDM\s*3\.'
        cmd4 = "ps -ef | grep '/[X]' | grep gdm"
        val4 = '\/gdm3\/'

        try:
            if self.checkCommand(cmd1, val1):
                if self.checkCommand(cmd2, val2):
                    self.setgnome3()
            if self.checkCommand(cmd3, val3):
                self.setgnome3()
            if self.checkCommand(cmd4, val4):
                self.setgnome3()
        except Exception:
            raise
        return retval

    def islightdm(self):
        '''
        determine whether the current system is lightdm-based

        @author: Breen Malmberg
        '''

        cmd1 = "ps -ef | grep '/[X]' | grep lightdm"
        val1 = '\/lightdm\/'

        try:
            if self.checkCommand(cmd1, val1):
                self.setlightdm()
        except Exception:
            raise

    def iskde(self):
        '''
        determine whether the current system is kde-based

        @author: Breen Malmberg
        '''

        cmd1 = "ps -ef | grep '/[X]' | grep kdm"
        val1 = '\/kdm\/'

        try:
            if self.checkCommand(cmd1, val1):
                self.setkde()
        except Exception:
            raise

    def ismac(self):
        '''
        determine whether the current system is macintosh, or darwin-based

        @author: Breen Malmberg
        '''

        try:
            if self.environ.getosfamily() == 'darwin':
                self.setmac()
        except Exception:
            raise

    def getFileContents(self, filepath, returntype='list'):
        '''
        retrieve and return file contents (in list format), of a given file path

        @param filepath: string full path to file to read
        @param returntype: string valid values: 'list', 'string'

        @return filecontents
        @rtype: list
        @author: Breen Malmberg
        '''

        try:
            if returntype == 'list':
                filecontents = []
            elif returntype == 'string':
                filecontents = ''
            else:
                filecontents = ''
                self.detailedresults += "\nreturntype parameter must be either 'list' or 'string!'"
            if os.path.exists(filepath):
                f = open(filepath, 'r')
                if returntype == 'list':
                    filecontents = f.readlines()
                elif returntype == 'string':
                    filecontents = f.read()
                f.close()
            else:
                self.detailedresults += '\nCould not find specified file: ' + str(filepath) + '. Returning empty value...'
        except Exception:
            raise
        return filecontents

    def setFileContents(self, filepath, contents, mode='w', perms=[0644, 0, 0]):
        '''
        write (or append) specified contents to specified file

        @param filepath: string full path to file
        @param contents: list/string object to write to file (can be either list or string)
        @param mode: string indicates the IO method to use to open the file. valid values are 'w' for write, and 'a' for append
        @param perms: integer-list of size 3. first index/position in list indicates octal permissions flag; second indicates uid; third indicates gid

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if not mode in ['w', 'a']:
                self.logger.log(LogPriority.DEBUG, "parameter 'mode' must be either 'w' or 'a'")
                self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                retval = False
                return retval

            for item in perms:
                if not isinstance(item, int):
                    self.logger.log(LogPriority.DEBUG, "parameter 'perms' must be a list of exactly size 3, and all elements of the list must be integers")
                    self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                    retval = False
                    return retval
            if len(perms) < 3:
                self.logger.log(LogPriority.DEBUG, "parameter 'perms' must be a list of exactly size 3, and all elements of the list must be integers")
                self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                retval = False
                return retval

            if not filepath:
                self.logger.log(LogPriority.DEBUG, "parameter 'filepath' was blank")
                self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                retval = False
                return retval

            if not contents:
                self.logger.log(LogPriority.DEBUG, "parameter 'contents' was blank")
                self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                retval = False
                return retval

            if not isinstance(contents, (list, basestring)):
                self.logger.log(LogPriority.DEBUG, "parameter 'contents' must be either a list or a string")
                self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                retval = False
                return retval

            pathsplit = os.path.split(filepath)
            if not os.path.exists(pathsplit[0]):
                self.logger.log(LogPriority.DEBUG, "parameter 'filepath' base directory is missing. attempting to create it...")
                try:
                    os.makedirs(pathsplit[0], 0755)
                except Exception:
                    self.logger.log(LogPriority.DEBUG, "failed to create filepath base directory: " + str(pathsplit[0]))
                    self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                    retval = False
                    return retval
                self.logger.log(LogPriority.DEBUG, "base directory: " + str(pathsplit[0]) + " created successfully.")
                #FIXME need to add undo event here after rule.py is updated to correctly handle undo of directory creations

            if not os.path.exists(filepath):
                self.logger.log(LogPriority.DEBUG, "parameter 'filepath' does not exist. attempting to create it...")
                try:
                    f = open(filepath, 'w')
                    f.write('')
                    f.close()
                    os.chmod(filepath, perms[0])
                    os.chown(filepath, perms[1], perms[2])

                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'creation',
                             'filepath': filepath}
                    self.statechglogger.recordchgevent(myid, event)

                except Exception:
                    self.logger.log(LogPriority.DEBUG, "failed to create filepath: " + str(filepath))
                    self.detailedresults += '\nfailed to write to file: ' + str(filepath)
                    retval = False
                    return retval
                self.logger.log(LogPriority.DEBUG, "filepath: " + str(filepath) + " created successfully.")

            tmpfilepath = filepath + '.stonixtmp'

            tf = open(tmpfilepath, mode)
            if isinstance(contents, basestring):
                tf.write(contents)
            elif isinstance(contents, list):
                tf.writelines(contents)
            tf.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'conf',
                     'filepath': filepath}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(tmpfilepath, filepath, myid)

            os.rename(tmpfilepath, filepath)
            os.chmod(filepath, perms[0])
            os.chown(filepath, perms[1], perms[2])

        except Exception:
            self.rulesuccess = False
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
        replacedict = {}

        try:

            if isinstance(contentdict, dict):
                for key in contentdict:
                    replacedict[contentdict[key]] = False
            else:
                self.detailedresults += '\ncontentdict parameter must be of type dictionary. Returning False'
                retval = False
                return retval

            if os.path.exists(filepath):
                contentlines = self.getFileContents(filepath)
                for key in contentdict:
                    for line in contentlines:
                        if re.search(key, line):
                            contentlines = [c.replace(line, contentdict[key] + '\n') for c in contentlines]
                            replacedict[contentdict[key]] = True
                for item in replacedict:
                    if not replacedict[item]:
                        contentlines.append(item)
                if not self.setFileContents(filepath, contentlines):
                    retval = False
            else:
                retval = False
                self.detailedresults += '\nSpecified filepath not found. Returning False'

        except Exception:
            self.rulesuccess = False
            raise
        return retval

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
        booldict = {}

        try:
            if not os.path.exists(filepath):
                retval = False
                return retval
            if not searchparams:
                retval = False
                return retval

            if isinstance(searchparams, list):
                for line in searchparams:
                    booldict[line] = False
                filecontents = self.getFileContents(filepath, 'list')
                for line in filecontents:
                    for opt in searchparams:
                        if re.search(opt, line):
                            booldict[opt] = True
                for opt in booldict:
                    if not booldict[opt]:
                        retval = False
            elif isinstance(searchparams, basestring):
                filecontents = self.getFileContents(filepath, 'string')
                found = filecontents.find(searchparams)
                if found == -1:
                    retval = False
        except Exception:
            raise
        return retval

###############################################################################

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
        self.detailedresults = ''

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
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportlinux(self):
        '''
        run report functionality for linux-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not self.reportlinuxcommon:
                retval = False
            if self.gnome2:
                if not self.reportgnome2():
                    retval = False
            elif self.gnome3:
                if not self.reportgnome3():
                    retval = False
            elif self.lightdm:
                if not self.reportlightdm():
                    retval = False
            elif self.kde:
                if not self.reportkde():
                    retval = False
            else:
                retval = False
                self.detailedresults += '\nCould not identify display manager, or display manager not supported.'
        except Exception:
            raise
        return retval

    def reportlinuxcommon(self):
        '''
        run report functionality which is common to linux platforms

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        retval = True

        try:
            for f in self.bannerfiles:
                if os.path.exists(f):
                    if not self.reportFileContents(f, self.bannertext):
                        retval = False
                        self.detailedresults += '\nrequired banner text not found in file: ' + str(f)
                else:
                    retval = False
                    self.detailedresults += '\nrequired file: ' + str(f) + ' not found.'
            if not self.reportcommon():
                retval = False
        except Exception:
            raise
        return retval

    def reportcommon(self):
        '''
        run report functionality which is common to all platforms

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        retval = True

        try:
            if os.path.exists(self.sshdfile):
                if not self.reportFileContents(self.sshdfile, self.sshdopt):
                    retval = False
                    self.detailedresults += '\nsshd config file does not contain required config line: ' + str(self.sshdopt)
            else:
                retval = False
                self.detailedresults += '\nrequired sshd config file not found.'

            if os.path.exists(self.motdfile):
                if not self.reportFileContents(self.motdfile, self.motd):
                    retval = False
                    self.detailedresults += '\nrequired warning banner text not found in: ' + str(self.motdfile)
            else:
                retval = False
                self.detailedresults += '\nrequired motd config file: ' + str(self.motdfile) + ' not found.'
        except Exception:
            raise
        return retval

    def reportgnome2(self):
        '''
        run report functionality for gnome2-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:

            # set up gnome2 undo commands
            self.gnome2undocmdlist = []
            gconfget = '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get '
            gconfset = '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory '
            gconfremove = '/usr/bin/gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --unset '
            opt1type = '--type bool --set '
            opt2type = '--type bool --set '
            opt3type = '--type string --set '
            opt1 = '/apps/gdm/simple-greeter/disable_user_list'
            opt2 = '/apps/gdm/simple-greeter/banner_message_enable'
            opt3 = '/apps/gdm/simple-greeter/banner_message_text'

            self.cmdhelper.executeCommand(gconfget + opt1)
            undoval1 = self.cmdhelper.getOutputString()
            if not undoval1:
                self.gnome2undocmdlist.append(gconfremove + opt1)
            self.gnome2undocmdlist.append(gconfset + opt1type + ' ' + undoval1)

            self.cmdhelper.executeCommand(gconfget + opt2)
            undoval2 = self.cmdhelper.getOutputString()
            if not undoval2:
                self.gnome2undocmdlist.append(gconfremove + opt2)
            self.gnome2undocmdlist.append(gconfset + opt2type + ' ' + undoval2)

            self.cmdhelper.executeCommand(gconfget + opt3)
            undoval3 = self.cmdhelper.getOutputString()
            if not undoval3:
                self.gnome2undocmdlist.append(gconfremove + opt3)
            self.gnome2undocmdlist.append(gconfset + opt3type + ' ' + undoval3)

            for cmd in self.gnome2reportdict:
                if not self.checkCommand(cmd, self.gnome2reportdict[cmd], False):
                    retval = False
                    self.detailedresults += '\nCommand: ' + str(cmd) + ' did not return the correct output.'
        except Exception:
            raise
        return retval

    def reportgnome3(self):
        '''
        run report functionality for gnome3-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if os.path.exists('/etc/gdm3/greeter.gsettings'):
                foundbannerenable = False
                foundbannermessage = False
                f = open('/etc/gdm3/greeter.gsettings', 'r')
                contentlines = f.readlines()
                f.close()
                for line in contentlines:
                    if re.search('^banner\-message\-enable\=true', line):
                        foundbannerenable = True
                    if re.search('^banner\-message\-text\=\"' + OSXSHORTWARNINGBANNER, line):
                        foundbannermessage = True
                if not foundbannerenable:
                    self.compliant = False
                    self.detailedresults += '\nbanner-message-enable=true was missing from /etc/gdm3/greeter.gsettings'
                if not foundbannermessage:
                    self.compliant = False
                    self.detailedresults += '\nbanner-message-text was not set to the correct value in /etc/gdm3/greeter.gsettings'
            else:
                for opt in self.gnome3optdict:
                    if not self.checkCommand(self.gsettingsget + opt, self.gnome3optdict[opt], False):
                        retval = False
                        self.detailedresults += '\noption: ' + str(opt) + ' did not have the required value of ' + str(self.gnome3optdict[opt])
                if not self.reportFileContents(self.gdmprofile, self.profilelist):
                    retval = False
                    self.detailedresults += '\ncould not locate the required configuration options in ' + str(self.gdmprofile)
                if not self.reportFileContents(self.bannerfile, self.gnome3optlist):
                    retval = False
                    self.detailedresults += '\ncould not locate required configuration options in ' + str(self.bannerfile)

        except Exception:
            raise
        return retval

    def reportlightdm(self):
        '''
        run report functionality for lightdm-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            for item in self.lightdmdict:
                if os.path.exists(item):
                    if not self.reportFileContents(item, self.lightdmdict[item]):
                        retval = False
                        self.detailedresults += '\nrequired configuration text not found in: ' + str(item)
                else:
                    retval = False
                    self.detailedresults += '\nrequired configuration file: ' + str(item) + ' not found.'
        except Exception:
            raise
        return retval

    def reportkde(self):
        '''
        run report functionality for kde-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not self.kdeditor.report():
                retval = False
                self.detailedresults += '\none or more of the required configuration items is missing from ' + str(self.kdefile)
            if not self.kdeditor2.report():
                retval = False
                self.detailedresults += '\none or more of the required configuration items is missing from ' + str(self.kdefile)
            if not os.path.exists(self.kdefile):
                retval = False
                self.detailedresults += '\nrequired configuration file: ' + str(self.kdefile) + ' not found'
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
                self.detailedresults += '\nEither file server banner text or login window banner text is incorrect, or both'
                retval = False
            if os.path.exists(self.ftpwelcomefile):
                if not self.reportFileContents(self.ftpwelcomefile, WARNINGBANNER):
                    retval = False
                    self.detailedresults += '\nincorrect configuration text in: ' + str(self.ftpwelcomefile)
            else:
                retval = False
                self.detailedresults += '\nrequired configuration file: ' + str(self.ftpwelcomefile) + ' not found'

            if os.path.exists(self.policybanner):
                if not self.reportFileContents(self.policybanner, WARNINGBANNER):
                    retval = False
                    self.detailedresults += '\nincorrect configuration text in: ' + str(self.policybanner)
            else:
                retval = False
                self.detailedresults += '\nrequired configuration file: ' + str(self.policybanner) + ' not found'
            if not self.reportcommon():
                retval = False
        except Exception:
            raise
        return retval

###############################################################################

    def fix(self):
        '''
        Install warning banners, set the warning text and configure the
        file permissions for the warning banner files.

        @return: success
        @rtype: boolean

        @author Breen Malmberg
        '''

        success = True
        self.detailedresults = ''

        try:
            if self.ci.getcurrvalue():
                if self.linux:
                    if not self.fixlinux():
                        success = False
                elif self.mac:
                    if not self.fixmac():
                        success = False
                else:
                    success = False
                    self.detailedresults += '\nCould not identify operating system, or operating system not supported.'
            else:
                self.detailedresults += '\nThe configuration item for this rule was not enabled so nothing was done.'
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return success

    def fixlinux(self):
        '''
        run fix functionality for linux-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not self.fixlinuxcommon():
                retval = False
            if self.gnome2:
                if not self.fixgnome2():
                    retval = False
            elif self.gnome3:
                if not self.fixgnome3():
                    retval = False
            elif self.lightdm:
                if not self.fixlightdm():
                    retval = False
            elif self.kde:
                if not self.fixkde():
                    retval = False
            else:
                retval = False
                self.detailedresults += '\nCould not identify display manager, or display manager not supported.'
        except Exception:
            raise
        return retval

    def fixlinuxcommon(self):
        '''
        run fix functionality which is common to linux platforms

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not self.fixcommon():
                retval = False
            for item in self.bannerfiles:
                if not self.setFileContents(item, WARNINGBANNER, 'w'):
                    retval = False
        except Exception:
            raise
        return retval

    def fixcommon(self):
        '''
        run fix functionlity which is common to all platforms

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not self.replaceFileContents(self.sshdfile, self.sshddict):
                retval = False
            if not fixInflation(self.sshdfile, self.logger, 0644, [0, 0]):
                retval = False
            if not self.setFileContents(self.motdfile, self.motd, 'w'):
                retval = False
                self.detailedresults += '\nunable to set warning banner text in ' + str(self.motdfile)
        except Exception:
            raise
        return retval

    def fixgnome2(self):
        '''
        run fix functionality for gnome2-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            for cmd in self.gnome2fixlist:
                self.cmdhelper.executeCommand(cmd)
                errout = self.cmdhelper.getErrorString()
                if errout:
                    retval = False
                    self.detailedresults += "Failed to run command: " + str(cmd)
                    self.logger.log(LogPriority.DEBUG, "Error running command: " + str(cmd) + "\n" + str(errout))
            if retval:
                if self.gnome2undocmdlist:
                    for undocmd in self.gnome2undocmdlist:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {'eventtype': 'commandstring',
                                 'command': undocmd}
                        self.statechglogger.recordchgevent(myid, event)
        except Exception:
            raise
        return retval

    def fixgnome3(self):
        '''
        run fix functionality for gnome3-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:

            # this is special, for debian 7 only
            if os.path.exists('/etc/gdm3/greeter.gsettings'):
                f = open('/etc/gdm3/greeter.gsettings', 'r')
                contentlines = f.readlines()
                f.close()
                replacementline = 'banner-message-enable=true\nbanner-message-text=\"' + OSXSHORTWARNINGBANNER + '\"\n'

                for line in contentlines:
                    if re.search('^banner-message-enable', line):
                        contentlines = [c.replace(line, '') for c in contentlines]
                    if re.search('^banner-message-text', line):
                        contentlines = [c.replace(line, '') for c in contentlines]
                foundorglogin = False
                for line in contentlines:
                    if re.search('^\[org\.gnome\.login\-screen\]', line):
                        foundorglogin = True
                        contentlines = [c.replace(line, line + replacementline) for c in contentlines]
                if not foundorglogin:
                    replacementline = '[org.gnome.login-screen]\n' + replacementline
                    contentlines.append('\n' + replacementline)
                tf = open('/etc/gdm3/greeter.gsettings.stonixtmp', 'w')
                tf.writelines(contentlines)
                tf.close()
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': '/etc/gdm3/greeter.gsettings'}
                self.statechglogger.recordfilechange('/etc/gdm3/greeter.gsettings', '/etc/gdm3/greeter.gsettings.stonixtmp', myid)
                self.statechglogger.recordchgevent(myid, event)
                os.rename('/etc/gdm3/greeter.gsettings.stonixtmp', '/etc/gdm3/greeter.gsettings')
                os.chmod('/etc/gdm3/greeter.gsettings', 0644)
                os.chown('/etc/gdm3/greeter.gsettings', 0, 0)
                self.cmdhelper.executeCommand('dpkg-reconfigure gdm3')
                errout = self.cmdhelper.getErrorString()
                if errout:
                    retval = False
                    self.detailedresults += '\nEncountered a problem trying to run command: dpkg-reconfigure gdm3\nError was: ' + str(errout)
            else:
                for opt in self.gnome3optdict:
                    self.cmdhelper.executeCommand(self.gsettingsset + opt + ' ' + str(self.gnome3optdict[opt]))
                    errout = self.cmdhelper.getErrorString()
                    if errout:
                        retval = False
                        self.detailedresults += '\n' + str(errout)
                if not self.setFileContents(self.gdmprofile, self.profilelist):
                    retval = False
                    self.detailedresults += '\nunable to create gdm profile file: ' + str(self.gdmprofile)
                if not self.setFileContents(self.bannerfile, self.gnome3optlist):
                    retval = False
                    self.detailedresults += '\nunable to create gdm banner file: ' + str(self.bannerfile)
                if not self.cmdhelper.executeCommand(self.dconfupdate):
                    retval = False
                    output = self.cmdhelper.getOutputString()
                    self.detailedresults += '\n'+ str(output)
            if os.path.exists('/etc/gdm3/daemon.conf'):
                f = open('/etc/gdm3/daemon.conf', 'r')
                contentlines = f.readlines()
                f.close()
                autologinreplaced = False
                autologindisabled = False
                for line in contentlines:
                    if re.search('^AutomaticLoginEnable\s*=\s*', line):
                        contentlines = [c.replace(line, 'AutomaticLoginEnable = false\n') for c in contentlines]
                        autologinreplaced = True
                if not autologinreplaced:
                    for line in contentlines:
                        if re.search('^\[daemon\]', line):
                            contentlines = [c.replace(line, line + '# disabling auto login; added by STONIX\nAutomaticLoginEnable = false\n') for c in contentlines]
                            autologindisabled = True
                if autologinreplaced or autologindisabled:
                    tf = open('/etc/gdm3/daemon.conf.stonixtmp', 'w')
                    tf.writelines(contentlines)
                    tf.close()
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': '/etc/gdm3/daemon.conf'}
                    self.statechglogger.recordfilechange('/etc/gdm3/daemon.conf', '/etc/gdm3/daemon.conf.stonixtmp', myid)
                    self.statechglogger.recordchgevent(myid, event)
                    os.rename('/etc/gdm3/daemon.conf.stonixtmp', '/etc/gdm3/daemon.conf')
                    os.chmod('/etc/gdm3/daemon.conf', 0644)
                    os.chown('/etc/gdm3/daemon.conf', 0, 0)
                    self.cmdhelper.executeCommand('dpkg-reconfigure gdm3')
                    errout = self.cmdhelper.getErrorString()
                    if errout:
                        retval = False
                        self.detailedresults += '\nEncountered a problem trying to run command: dpkg-reconfigure gdm3\nError was: ' + str(errout)
        except Exception:
            raise
        return retval

    def fixlightdm(self):
        '''
        run fix functionality for lightdm-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True
        contentlines = []

        try:

            if not os.path.exists('/etc/lightdm/lightdm.conf.d'):
                os.makedirs('/etc/lightdm/lightdm.conf.d/', 0755)
            for item in self.lightdmdict:
                contentlines = []
                if isinstance(self.lightdmdict[item], list):
                    for opt in self.lightdmdict[item]:
                        contentlines.append(opt + '\n')
                    if not self.setFileContents(item, contentlines):
                        retval = False
                else:
                    if not self.setFileContents(item, self.lightdmdict[item]):
                        retval = False
        except Exception:
            raise
        return retval

    def fixkde(self):
        '''
        run fix functionality for kde-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not self.kdeditor.fix():
                retval = False
                self.detailedresults += '\nkveditor fix did not complete successfully'
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.kdeditor.setEventID(myid)
            if not self.kdeditor.commit():
                retval = False
                self.detailedresults += '\nkveditor commit did not complete successfully'
            if not self.kdeditor2.fix():
                retval = False
                self.detailedresults += '\nkveditor fix did not complete successfully'
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                self.kdeditor2.setEventID(myid)
            if not self.kdeditor2.commit():
                retval = False
                self.detailedresults += '\nkveditor commit did not complete successfully'
        except Exception:
            raise
        return retval

    def fixmac(self):
        '''
        run fix functionality for macintosh, or darwin-based systems

        @return: retval
        @rtype: boolean
        @author: Breen Malmberg
        '''

        retval = True

        try:
            if not RuleKVEditor.fix(self, True):
                retval = False
            if not self.setFileContents(self.ftpwelcomefile, WARNINGBANNER, 'w'):
                retval = False
                self.detailedresults += '\nunable to set warning banner text in ' + str(self.ftpwelcomefile)
            if not self.setFileContents(self.policybanner, WARNINGBANNER, 'w'):
                retval = False
                self.detailedresults += '\nunable to set warning banner text in ' + str(self.policybanner)
            else:
                os.chmod(self.policybanner, 0644)
            if not self.fixcommon():
                retval = False
        except Exception:
            raise
        return retval
