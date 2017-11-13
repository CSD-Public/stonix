###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
from ..localize import ALTWARNINGBANNER
from ..localize import OSXSHORTWARNINGBANNER
from ..stonixutilityfunctions import fixInflation, iterate, createFile
from ..stonixutilityfunctions import setPerms, resetsecon


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
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}
        # init CIs
        datatype = 'bool'
        key = 'INSTALLBANNERS'
        instructions = "To prevent the installation of warning banners, " + \
            "set the value of InstallBanners to False.\n\n!DEBIAN USERS! Due to " + \
            "a bug in gdm3 (gnome 3) which has not been patched on debian, we are forced to " + \
            "change the user's display manager to something else in order to be compliant " + \
            "with the login banner requirement."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        # Initial setup and deterministic resolution of variables
        self.initobjs()
        self.setcommon()
        self.islinux()
        self.ismac()

###############################################################################

    def initobjs(self):
        '''
        '''

        try:

            self.ph = Pkghelper(self.logger, self.environ)
            self.ch = CommandHelper(self.logger)

        except Exception:
            raise

    def checkCommand(self, cmd, val, regex=True):
        '''
        check the output of a given command to see if it matches given value

        @return: retval
        @rtype: boolean

        @author: Breen Malmberg
        '''

        retval = False

        try:
            self.ch.executeCommand(cmd)
            output = self.ch.getOutputString()
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

        constlist = [WARNINGBANNER, ALTWARNINGBANNER, OSXSHORTWARNINGBANNER]
        if not self.checkConsts(constlist):
            return

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
        gconfget = '/usr/bin/gconftool-2 --direct --config-source ' + \
            'xml:readwrite:/etc/gconf/gconf.xml.mandatory --get '
        gconfset = '/usr/bin/gconftool-2 --direct --config-source ' + \
            'xml:readwrite:/etc/gconf/gconf.xml.mandatory '
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
        val3 = "'" + WARNINGBANNER + "'"
        val3report = WARNINGBANNER
        fix1 = gconfset + opt1type + opt1 + ' ' + val1
        fix2 = gconfset + opt2type + opt2 + ' ' + val2
        fix3 = gconfset + opt3type + opt3 + ' ' + val3
        self.gnome2reportdict = {rep1: val1,
                                 rep2: val2,
                                 rep3: val3report}
        self.gnome2fixlist = [fix1, fix2, fix3]

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

        cmd = '/usr/sbin/dpkg-reconfigure --frontend=noninteractive lightdm'
        path = '/etc/X11/default-display-manager'
        opt = '/usr/sbin/lightdm\n'
        mode = 0644
        uid = 0
        gid = 0
        

        try:

            if not self.ph.check('lightdm'):
                self.logger.log(LogPriority.DEBUG, "Package: lightdm not installed yet. Installing lightdm...")
                if not self.ph.install('lightdm'):
                    retval = False
                    self.detailedresults += "\nFailed to install lightdm"
            if not self.ch.executeCommand(cmd):
                retval = False
                self.detailedresults += "\nFailed to set lightdm as default display manager"

            f = open(path, 'w')
            f.write(opt)
            f.close()

            os.chmod(path, mode)
            os.chown(path, uid, gid)

            self.detailedresults += "\nThe display manager has been changed to lightdm. These changes will only take effect once the system has been restarted."

        except Exception:
            raise
        return retval

    def setgnome3(self):
        '''
        set up all variables for use with gnome3-based systems

        @author: Breen Malmberg
        '''

        self.gnome3 = True

        profiledirs = ['/etc/dconf/profile/', '/var/lib/gdm3/dconf/profile/']
        profiledir = '/etc/dconf/profile/'  # default
        for loc in profiledirs:
            if os.path.exists(loc):
                profiledir = loc
        if not profiledir:
            self.logger.log(LogPriority.DEBUG,
                            "Unable to locate the gnome3 profile directory")

        profilefile = 'gdm'

        self.gdmprofile = profiledir + profilefile

        profiledict = {'/etc/dconf/profile/': ['user-db:user\n',
                                               'system-db:gdm\n'],
                       '/var/lib/gdm3/dconf/profile/': ['user\n', 'gdm\n']}
        self.profilelist = profiledict[profiledir]

        gdmdirs = ['/etc/dconf/db/gdm.d/', '/var/lib/gdm3/dconf/db/gdm.d/']
        self.gdmdir = '/etc/dconf/db/gdm.d/'  # default
        for loc in gdmdirs:
            if os.path.exists(loc):
                self.gdmdir = loc

        self.locksdir = self.gdmdir + 'locks/'
        self.locksfile = self.locksdir + '00-required-locks'
        self.locksettings = {'/org/gnome/login-screen/banner-message-enable':
                             False,
                             '/org/gnome/login-screen/banner-message-text':
                             False,
                             '/org/gnome/login-screen/disable-user-list':
                             False}

        bannermessagefile = '01-banner-message'
        self.bannerfile = self.gdmdir + bannermessagefile

        self.gnome3optlist = ['[org/gnome/login-screen]\n',
                              'disable-user-list=true\n',
                              'banner-message-enable=true\n',
                              'banner-message-text=\'' +
                              OSXSHORTWARNINGBANNER + '\'']
        self.gnome3optdict = {"disable-user-list": "true",
                              "banner-message-enable": "true",
                              "banner-message-text": "'" +
                              OSXSHORTWARNINGBANNER + "'"}
        dconf = '/usr/bin/dconf'
        self.dconfupdate = dconf + ' update'
        gsettings = '/usr/bin/gsettings'
        schema = 'org.gnome.login-screen'
        self.gsettingsget = 'dbus-launch ' + gsettings + ' get ' + schema + ' '
        self.gsettingsset = 'dbus-launch ' + gsettings + ' set ' + schema + ' '

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
        self.kdefile = '/usr/share/kde4/config/kdm/kdmrc'
        for loc in self.kdelocs:
            if os.path.exists(loc):
                self.kdefile = str(loc)
        tmpfile = self.kdefile + '.stonixtmp'

        key1 = 'GreetString'
        val1 = '"' + ALTWARNINGBANNER + '"'
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
                'greeter-setup-script=/bin/sh -c "until /usr/bin/zenity ' +
                '--width=600 --height=400 --title=WARNING --text-info ' +
                '--filename=' + str(self.motdfile) + '; do :; done"']
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

        self.motdfile = '/etc/issue.net'
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

        constlist = [WARNINGBANNER, ALTWARNINGBANNER, OSXSHORTWARNINGBANNER]
        if not self.checkConsts(constlist):
            return

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
                self.kde = True
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
        Retrieve and return file contents (in list format) of a given file path

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

    def setFileContents(self, filepath, contents, mode='w',
                        perms=[0, 0, 0644]):
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

        try:

            if mode not in ['w', 'a']:
                self.logger.log(LogPriority.DEBUG,
                                "Parameter 'mode' must be either 'w' or 'a'")
                self.detailedresults += '\nFailed to write to file: ' + \
                    str(filepath)
                retval = False
                return retval

            for item in perms:
                if not isinstance(item, int):
                    self.logger.log(LogPriority.DEBUG,
                                    "Parameter 'perms' must be a list of " +
                                    "exactly size 3, and all elements of " +
                                    "the list must be integers")
                    self.detailedresults += '\nFailed to write to file: ' + \
                        str(filepath)
                    retval = False
                    return retval
            if len(perms) < 3:
                self.logger.log(LogPriority.DEBUG,
                                "Parameter 'perms' must be a list of " +
                                "exactly size 3, and all elements of the " +
                                "list must be integers")
                self.detailedresults += '\nFailed to write to file: ' + \
                    str(filepath)
                retval = False
                return retval

            # attempt to prevent mixed parameters
            if len(str(perms[0])) > 1:
                perms=[0, 0, 0644]
            if len(str(perms[1])) > 1:
                perms=[0, 0, 0644]
            if len(str(perms[2])) < 3:
                perms=[0, 0, 0644]

            if not filepath:
                self.logger.log(LogPriority.DEBUG,
                                "Parameter 'filepath' was blank")
                self.detailedresults += '\nFailed to write to file: ' + \
                    str(filepath)
                retval = False
                return retval

            if not contents:
                self.logger.log(LogPriority.DEBUG,
                                "Parameter 'contents' was blank")
                self.detailedresults += '\nFailed to write to file: ' + \
                    str(filepath)
                retval = False
                return retval

            if not isinstance(contents, (list, basestring)):
                self.logger.log(LogPriority.DEBUG,
                                "Parameter 'contents' must be either a " +
                                "list or a string")
                self.detailedresults += '\nFailed to write to file: ' + \
                    str(filepath)
                retval = False
                return retval

            fileCreated = False
            if not os.path.exists(filepath):
                self.logger.log(LogPriority.DEBUG,
                                filepath + " does not exist. " +
                                "Attempting to create it...")
                try:
                    createFile(filepath, self.logger)
                    os.chmod(filepath, perms[0])
                    os.chown(filepath, perms[1], perms[2])

                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'creation',
                             'filepath': filepath}
                    self.statechglogger.recordchgevent(myid, event)
                    fileCreated = True
                except Exception:
                    self.logger.log(LogPriority.DEBUG,
                                    "Failed to create filepath: " +
                                    str(filepath))
                    self.detailedresults += '\nFailed to write to file: ' + \
                        str(filepath)
                    retval = False
                    return retval
                self.logger.log(LogPriority.DEBUG, "Filepath: " +
                                str(filepath) + " created successfully.")

            tmpfilepath = filepath + '.stonixtmp'

            if mode == 'a':
                fp = open(filepath, "r")
                if isinstance(contents, basestring):
                    originalContents = fp.read()
                    originalContents += "\n"
                elif isinstance(contents, list):
                    originalContents = fp.readlines()
                    originalContents.append("\n")
                fp.close()
                contents = originalContents + contents

            tf = open(tmpfilepath, mode)
            if isinstance(contents, basestring):
                tf.write(contents)
            elif isinstance(contents, list):
                tf.writelines(contents)
            tf.close()

            if not fileCreated:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': filepath}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(filepath, tmpfilepath,
                                                     myid)
                os.rename(tmpfilepath, filepath)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(filepath, perms, self.logger, self.statechglogger,
                         myid)
            else:
                os.rename(tmpfilepath, filepath)
                setPerms(filepath, perms, self.logger)

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
                self.detailedresults += '\ncontentdict parameter must be ' + \
                    'of type dictionary. Returning False'
                retval = False
                return retval

            if os.path.exists(filepath):
                contentlines = self.getFileContents(filepath)
                for key in contentdict:
                    for line in contentlines:
                        if re.search('^' + key, line):
                            contentlines = [c.replace(line, contentdict[key] + '\n') for c in contentlines]
                            replacedict[contentdict[key]] = True
                for item in replacedict:
                    if not replacedict[item]:
                        contentlines.append(item)
                if not self.setFileContents(filepath, contentlines):
                    retval = False
            else:
                retval = False
                self.detailedresults += '\nSpecified filepath not found. ' + \
                    'Returning False'

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
            else:
                retval = False
                self.detailedresults += "\nFile contents for " + filepath + \
                    "could not be read\n"
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

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [WARNINGBANNER, ALTWARNINGBANNER, OSXSHORTWARNINGBANNER]
        if not self.checkConsts(constlist):
            self.compliant = False
            self.detailedresults = "\nPlease ensure that the constants: WARNINGBANNER, ALTWARNINGBANNER, OSXSHORTWARNINGBANNER, in localize.py, are defined and are not None. This rule will not function without them."
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

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
                self.detailedresults += '\nCould not identify operating ' + \
                    'system, or operating system not supported.'
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

    def getgnome3version(self):
        '''
        get the gnome3 version as a float

        @return: g3ver
        @rtype: float
        @author: Breen Malmberg
        '''

        g3ver = 0.0

        cmd = '/usr/sbin/gdm3 --version'
        self.ch.executeCommand(cmd)
        retcode = self.ch.getReturnCode()
        if retcode != 0|1:
            backupcmd = '/usr/bin/gnome-session --version'
            self.ch.executeCommand(backupcmd)
        outlines = self.ch.getOutput()
        retcode2 = self.ch.getReturnCode()
        if retcode2 != 0:
            self.logger.log(LogPriority.DEBUG, "Failed to get gnome3 version")
            return g3ver
        for line in outlines:
            sline = line.split()
            if len(sline) > 1:
                g3ver = float(sline[1])
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

        retval = True

        try:

            if self.gnome3 and re.search('debian', self.environ.getostype(), re.IGNORECASE):
                if self.getgnome3version() < 3.15:
                    self.gnome3 = False
                    self.forcelightdm()
                    self.setlightdm()

            if not self.reportlinuxcommon():
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
                        self.detailedresults += '\nRequired banner text ' + \
                            'not found in file: ' + str(f)
                else:
                    retval = False
                    self.detailedresults += '\nRequired file: ' + str(f) + \
                        ' not found.'
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
                    self.detailedresults += '\nsshd config file does not ' + \
                        'contain required config line: ' + str(self.sshdopt)
            else:
                if self.ph.check('ssh'):
                    retval = False
                    self.detailedresults += '\nRequired sshd config file not found.'

            if not self.lightdm:
                if os.path.exists(self.motdfile):
                    if not self.reportFileContents(self.motdfile, self.motd):
                        retval = False
                        self.detailedresults += '\nRequired warning banner ' + \
                            'text not found in: ' + str(self.motdfile)
                else:
                    retval = False
                    self.detailedresults += '\nRequired banner message text file: ' + \
                        str(self.motdfile) + ' not found.'
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
            gconfget = '/usr/bin/gconftool-2 --direct --config-source ' + \
                'xml:readwrite:/etc/gconf/gconf.xml.mandatory --get '
            gconfset = '/usr/bin/gconftool-2 --direct --config-source ' + \
                'xml:readwrite:/etc/gconf/gconf.xml.mandatory '
            gconfremove = '/usr/bin/gconftool-2 --direct --config-source ' + \
                'xml:readwrite:/etc/gconf/gconf.xml.mandatory --unset '
            opt1type = '--type bool --set '
            opt2type = '--type bool --set '
            opt3type = '--type string --set '
            opt1 = '/apps/gdm/simple-greeter/disable_user_list'
            opt2 = '/apps/gdm/simple-greeter/banner_message_enable'
            opt3 = '/apps/gdm/simple-greeter/banner_message_text'

            self.ch.executeCommand(gconfget + opt1)
            undoval1 = self.ch.getOutputString()
            if not undoval1:
                self.gnome2undocmdlist.append(gconfremove + opt1)
            self.gnome2undocmdlist.append(gconfset + opt1type + ' ' + undoval1)

            self.ch.executeCommand(gconfget + opt2)
            undoval2 = self.ch.getOutputString()
            if not undoval2:
                self.gnome2undocmdlist.append(gconfremove + opt2)
            self.gnome2undocmdlist.append(gconfset + opt2type + ' ' + undoval2)

            self.ch.executeCommand(gconfget + opt3)
            undoval3 = self.ch.getOutputString()
            if not undoval3:
                self.gnome2undocmdlist.append(gconfremove + opt3)
            self.gnome2undocmdlist.append(gconfset + opt3type + ' ' + undoval3)

            for cmd in self.gnome2reportdict:
                if not self.checkCommand(cmd, self.gnome2reportdict[cmd],
                                         False):
                    retval = False
                    self.detailedresults += '\nCommand: ' + str(cmd) + \
                        ' did not return the correct output.'
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
        foundbannerenable = False
        foundbannermessage = False
        founddisableuserlist = False

        try:

            if os.path.exists('/etc/gdm3/greeter.gsettings'):

                f = open('/etc/gdm3/greeter.gsettings', 'r')
                contentlines = f.readlines()
                f.close()

                for line in contentlines:
                    if re.search('^banner\-message\-enable\=true', line, re.IGNORECASE):
                        foundbannerenable = True
                    if re.search('^banner\-message\-text\=\"' +
                                 OSXSHORTWARNINGBANNER, line, re.IGNORECASE):
                        foundbannermessage = True
                    if re.search('^disable-user-list\=true', line, re.IGNORECASE):
                        founddisableuserlist = True

                if not foundbannerenable:
                    self.compliant = False
                    self.detailedresults += '\nBanner-message-enable=true ' + \
                        'was missing from /etc/gdm3/greeter.gsettings'
                if not foundbannermessage:
                    self.compliant = False
                    self.detailedresults += '\nBanner-message-text was ' + \
                        'not set to the correct value in ' + \
                        '/etc/gdm3/greeter.gsettings'
                if not founddisableuserlist:
                    self.compliant = False
                    self.detailedresults += '\nDisable-user-list=true was missing from /etc/gdm3/greeter.gsettings'
            else:
                for opt in self.gnome3optdict:
                    if not self.checkCommand(self.gsettingsget + opt,
                                             self.gnome3optdict[opt], False):
                        retval = False
                        self.detailedresults += '\nOption: ' + str(opt) + \
                            ' did not have the required value of ' + \
                            str(self.gnome3optdict[opt])
                if not self.reportFileContents(self.gdmprofile,
                                               self.profilelist):
                    retval = False
                    self.detailedresults += '\nCould not locate the ' + \
                        'required configuration options in ' + \
                        str(self.gdmprofile)
                if not self.reportFileContents(self.bannerfile,
                                               self.gnome3optlist):
                    retval = False
                    self.detailedresults += '\nCould not locate required ' + \
                        'configuration options in ' + str(self.bannerfile)

            if not self.reportlocks():
                retval = False

        except Exception:
            raise
        return retval

    def reportlocks(self):
        '''
        report status of configuration settings locks for gnome3

        @return: retval
        @rtype: bool
        @author: Breen Malmberg
        '''

        retval = True

        try:

            if not os.path.exists(self.locksfile):
                retval = False
                self.detailedresults += "\nThe locks file does not exist."
            else:
                f = open(self.locksfile, 'r')
                contentlines = f.readlines()
                f.close()
                for line in contentlines:
                    for item in self.locksettings:
                        if re.search(item.strip(), line):
                            self.locksettings[item] = True

                for item in self.locksettings:
                    if not self.locksettings[item]:
                        retval = False
                        self.detailedresults += "\nRequired lock setting: " + \
                            str(item) + " is missing from the locks file."

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
                    if not self.reportFileContents(item,
                                                   self.lightdmdict[item]):
                        retval = False
                        self.detailedresults += '\nRequired configuration ' + \
                            'text not found in: ' + str(item)
                else:
                    retval = False
                    self.detailedresults += '\nRequired configuration file: ' \
                        + str(item) + ' not found.'
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
        self.setkde()
        try:

            if not os.path.exists(self.kdefile):
                retval = False
                self.detailedresults += 'Required configuration file: ' + \
                    str(self.kdefile) + ' not found'
            else:
                if not self.kdeditor.report():
                    retval = False
                    if self.kdeditor.fixables:
                        self.detailedresults += '\nThe following required ' + \
                            'options are missing from ' + \
                            str(self.kdefile) + ':\n' + \
                            '\n'.join(str(f) for f in self.kdeditor.fixables) \
                            + '\n'
                else:
                    # Since the warner banner spans multiple lines in the
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
                        banner = ALTWARNINGBANNER
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
                                               WARNINGBANNER):
                    retval = False
                    self.detailedresults += '\nIncorrect configuration ' + \
                        'text in: ' + str(self.ftpwelcomefile)
            else:
                retval = False
                self.detailedresults += '\nRequired configuration file: ' + \
                    str(self.ftpwelcomefile) + ' not found'

            if os.path.exists(self.policybanner):
                if not self.reportFileContents(self.policybanner,
                                               WARNINGBANNER):
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

###############################################################################

    def fix(self):
        '''
        Install warning banners, set the warning text and configure the
        file permissions for the warning banner files.

        @return: success
        @rtype: boolean

        @author Breen Malmberg
        '''

        # UPDATE THIS SECTION IF YOU CHANGE THE CONSTANTS BEING USED IN THE RULE
        constlist = [WARNINGBANNER, ALTWARNINGBANNER, OSXSHORTWARNINGBANNER]
        if not self.checkConsts(constlist):
            success = False
            self.formatDetailedResults("fix", success, self.detailedresults)
            return success

        success = True
        self.detailedresults = ''

        self.iditerator = 0
        eventlist = self.statechglogger.findrulechanges(self.rulenumber)
        for event in eventlist:
            self.statechglogger.deleteentry(event)

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
                    self.detailedresults += '\nCould not identify ' + \
                        'operating system, or operating system not supported.'
            else:
                self.detailedresults += '\nThe configuration item for ' + \
                    'this rule was not enabled so nothing was done.'
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
                if not self.setFileContents(item, self.bannertext, 'w'):
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
            if not self.lightdm and \
               not self.setFileContents(self.motdfile, self.motd, 'w'):
                retval = False
                self.detailedresults += '\nUnable to set warning banner ' + \
                    'text in ' + str(self.motdfile)
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
                self.ch.executeCommand(cmd)
                errout = self.ch.getErrorString()
                if self.ch.getReturnCode():
                    retval = False
                    self.detailedresults += "Failed to run command: " + str(cmd)
                    self.logger.log(LogPriority.DEBUG,
                                    "Error running command: " + str(cmd) +
                                    "\n" + str(errout))
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

                orgoptsreplace = 'banner-message-enable=true\nbanner-message-text=\"' + OSXSHORTWARNINGBANNER + '\"\n'
                bannermsgreplace = 'banner-message-text=\"' + OSXSHORTWARNINGBANNER + '\"\n'
                bannerenablereplace = 'banner-message-enable=true\n'
                disableulistreplace = 'disable-user-list=true\n'

                for line in contentlines:
                    if re.search('^banner-message-enable', line):
                        contentlines = [c.replace(line, bannerenablereplace) for c in contentlines]
                    if re.search('^banner-message-text', line):
                        contentlines = [c.replace(line, bannermsgreplace) for c in contentlines]
                    if re.search('disable-user-list', line):
                        contentlines = [c.replace(line, disableulistreplace) for c in contentlines]

                foundorglogin = False

                for line in contentlines:
                    if re.search('^\[org\.gnome\.login\-screen\]', line):
                        foundorglogin = True
                        contentlines = [c.replace(line, line + orgoptsreplace)
                                        for c in contentlines]

                if not foundorglogin:
                    orgoptsreplace = '[org.gnome.login-screen]\n' + \
                        orgoptsreplace
                    contentlines.append('\n' + orgoptsreplace)
                tf = open('/etc/gdm3/greeter.gsettings.stonixtmp', 'w')
                tf.writelines(contentlines)
                tf.close()
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': '/etc/gdm3/greeter.gsettings'}
                self.statechglogger.recordfilechange('/etc/gdm3/greeter.gsettings',
                                                     '/etc/gdm3/greeter.gsettings.stonixtmp',
                                                     myid)
                self.statechglogger.recordchgevent(myid, event)
                os.rename('/etc/gdm3/greeter.gsettings.stonixtmp',
                          '/etc/gdm3/greeter.gsettings')
                os.chmod('/etc/gdm3/greeter.gsettings', 0644)
                os.chown('/etc/gdm3/greeter.gsettings', 0, 0)
                self.ch.executeCommand('dpkg-reconfigure gdm3')
                errout = self.ch.getErrorString()
                if self.ch.getReturnCode():
                    retval = False
                    self.detailedresults += '\nEncountered a problem ' + \
                        'trying to run command: dpkg-reconfigure ' + \
                        'gdm3\nError was: ' + str(errout)

            for opt in self.gnome3optdict:
                value = str(self.gnome3optdict[opt])
                cmd = self.gsettingsget + opt
                self.ch.executeCommand(cmd)
                output = self.ch.getOutputString()
                if not re.search(value, output):
                    self.ch.executeCommand(self.gsettingsset + opt +
                                                  ' ' + value)
                    errout = self.ch.getErrorString()
                    if self.ch.getReturnCode():
                        retval = False
                        self.detailedresults += '\n' + str(errout)
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        undocmd = self.gsettingsset + opt + ' ' + output
                        event = {"eventtype": "comm",
                                 "command": undocmd}
                        self.statechglogger.recordchgevent(myid, event)
            if not self.setFileContents(self.gdmprofile, self.profilelist):
                retval = False
                self.detailedresults += '\nUnable to create gdm ' + \
                    'profile file: ' + str(self.gdmprofile)
            if not self.setFileContents(self.bannerfile,
                                        self.gnome3optlist):
                retval = False
                self.detailedresults += '\nUnable to create gdm ' + \
                    'banner file: ' + str(self.bannerfile)
            if not self.fixlocks():
                retval = False
            if not self.ch.executeCommand(self.dconfupdate):
                retval = False
                output = self.ch.getOutputString()
                self.detailedresults += '\n' + str(output)
            if os.path.exists('/etc/gdm3/daemon.conf'):
                f = open('/etc/gdm3/daemon.conf', 'r')
                contentlines = f.readlines()
                f.close()
                autologinreplaced = False
                autologindisabled = False
                for line in contentlines:
                    if re.search('^AutomaticLoginEnable\s*=\s*', line):
                        contentlines = [c.replace(line,
                                                  'AutomaticLoginEnable = false\n')
                                        for c in contentlines]
                        autologinreplaced = True
                if not autologinreplaced:
                    for line in contentlines:
                        if re.search('^\[daemon\]', line):
                            contentlines = [c.replace(line, line +
                                                      '# disabling auto ' +
                                                      'login; added by ' +
                                                      'STONIX\n' +
                                                      'AutomaticLoginEnable ' +
                                                      '= false\n')
                                            for c in contentlines]
                            autologindisabled = True
                if autologinreplaced or autologindisabled:
                    confpath = '/etc/gdm3/daemon.conf'
                    tmppath = '/etc/gdm3/daemon.conf.stonixtmp'
                    tf = open(tmppath, 'w')
                    tf.writelines(contentlines)
                    tf.close()
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {'eventtype': 'conf',
                             'filepath': confpath}
                    self.statechglogger.recordfilechange(confpath, tmppath,
                                                         myid)
                    self.statechglogger.recordchgevent(myid, event)
                    os.rename(tmppath, confpath)
                    setPerms(confpath, [0, 0, 0o644], self.logger,
                             self.statechglogger, myid)
                    self.ch.executeCommand('dpkg-reconfigure gdm3')
                    errout = self.ch.getErrorString()
                    if self.ch.getReturnCode():
                        retval = False
                        self.detailedresults += '\nEncountered a problem ' + \
                            'trying to run command: dpkg-reconfigure ' + \
                            'gdm3\nError was: ' + str(errout)
        except Exception:
            raise
        return retval

    def fixlocks(self):
        '''
        create and/or configure locks file for gdm3 settings

        @author: Breen Malmberg
        '''

        retval = True
        locksfile = self.locksfile
        lockstmp = locksfile + ".stonixtmp"

        try:
            fileCreated = False
            if not os.path.exists(locksfile):
                if createFile(locksfile, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": locksfile}
                    self.statechglogger.recordchgevent(myid, event)
                    fileCreated = True
                    debug = "Lockfile successfully created at " + locksfile
                    self.logger.log(LogPriority.DEBUG, debug)
                else:
                    retval = False
                    self.detailedresults += "Could not create lockfile at " + \
                        locksfile

            f = open(locksfile, 'r')
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                for item in self.locksettings:
                    if re.search(item.strip(), line):
                        self.locksettings[item] = True

            for item in self.locksettings:
                if not self.locksettings[item]:
                    contentlines.append('\n' + item)

            f = open(lockstmp, 'w')
            f.writelines(contentlines)
            f.close()

            if not fileCreated:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf", "filepath": self.locksfile}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(locksfile, lockstmp, myid)

            os.rename(lockstmp, locksfile)
            resetsecon(locksfile)

            if fileCreated:
                setPerms(locksfile, [0, 0, 0o644], self.logger)
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(locksfile, [0, 0, 0o644], self.logger,
                         self.statechglogger, myid)

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
        @change: Breen Malmberg - 5/25/2016 - moved the commit calls to ensure
        they are only called if the fix calls completed successfully
        '''

        retval = True

        try:
            if not self.kdefile:
                self.logger.log(LogPriority.DEBUG,
                                "Unable to identify kde configuration file. " +
                                "Can not continue with fix")
                self.detailedresults += "Unable to identify kde " + \
                    "configuration file. Can not continue with fix."
                retval = False
                return retval

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
                retval = False
                self.detailedresults += "KVEditor fix failed. Fix not applied"
            else:
                if not fileCreated:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.kdeditor.setEventID(myid)
                if not self.kdeditor.commit():
                    retval = False
                    self.detailedresults += 'kdeditor commit failed. ' + \
                        'Fix not applied'
            key1 = 'GreetString'
            val1 = '"' + ALTWARNINGBANNER + '"'
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
                        retval = False
                        self.detailedresults += "\nGreetString commit failed"
                else:
                    retval = False
                    self.detailedresults += "\nGreetString fix failed"
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
            if not self.setFileContents(self.ftpwelcomefile, WARNINGBANNER,
                                        'w'):
                retval = False
                self.detailedresults += '\nUnable to set warning banner ' + \
                    'text in ' + str(self.ftpwelcomefile)
            if not self.setFileContents(self.policybanner, WARNINGBANNER, 'w'):
                retval = False
                self.detailedresults += '\nUnable to set warning banner ' + \
                    'text in ' + str(self.policybanner)
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                setPerms(self.policybanner, [-1, -1, 0o644], self.logger,
                         self.statechglogger, myid)
            if not self.fixcommon():
                retval = False
        except Exception:
            raise
        return retval
