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
Created on May 31, 2016

@author: dkennel
@change: 2016/10/18 eball Added conditionals so that Gnome and KDE checks will
    only occur if Gnome/KDE are installed. Did PEP8 and detailedresults cleanup.
@change: 2017/7/3 bgonz12 Added check to make sure that gconf2 for Gnome is
    installed before running gconf configuration in fixgnome3
@change: 2017/17/21 bgonz12 Updated fix and report to use KDE Plasma's new
    desktop manager, SDDM.
@change: 2017/10/23 rsn - removed unused service helper
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2017/11/14 bgonz12 - Changed rule to only run in root space
@change: 2018/02/27 bgonz12 - Added tag to geditor in fixgnome3
@change: 2018/12/12 dwalker - Updating rule to properly record change events
    and not override the undo method.
'''
from __future__ import absolute_import

import os
import traceback
import re
import subprocess

from ..KVEditorStonix import KVEditorStonix
from ..CommandHelper import CommandHelper
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import resetsecon, setPerms, iterate, writeFile, readFile, checkPerms, createFile
from ..pkghelper import Pkghelper


class ForceIdleLogout(Rule):
    '''
    The ForceIdleLogout class attempts to configure the system to log out users
    after long periods of inactivity. This control reinforces the protection
    offered by the screen lock by terminating long idle sessions. Note that
    the guidance for this control, AC-2(5) from 800-53, seems to be written
    to the capabilities of Microsoft's active directory product which has the
    ability to establish work schedules in the directory service and limit
    logons to those time windows. *NIX systems typically do not have that type
    of tooling so we rely on a long idle time.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 23
        self.rulename = 'ForceIdleLogout'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''The ForceIdleLogout rule will configure \
the system to log out GUI sessions that have been idle for a long time. This \
helps prevent take over and illicit use of idle sessions and frees system \
resources. Because some environments may rely on the capability of interactive \
sessions to execute long running jobs this control is optional and will need \
to be enabled below for environments that require it. The idle time before \
logout may also be customized. N.B. Please note that most Linux window \
managers will not save work in progress when the logout occurs.
'''
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'family': ['linux'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.11.10']}}
        self.cmdhelper = CommandHelper(self.logger)
        self.guidance = ['NIST 800-53 AC-2(5)']
        self.ph = Pkghelper(self.logger, self.environ)
        myos = self.environ.getostype().lower()
        self.gconf = ""
        if re.search("red hat", myos) or re.search("centos", myos):
            self.gconf = "GConf2"
        else:
            self.gconf = "gconf2"

        datatype = 'bool'
        key = 'FORCEIDLELOGOUT'
        instructions = '''To disable this rule set the value of \
FORCEIDLELOGOUT to False.'''
        default = False
        self.filci = self.initCi(datatype, key, instructions, default)

        datatype2 = 'int'
        key2 = 'FORCEIDLELOGOUTTIMEOUT'
        instructions2 = '''To customize the timeout period set the \
FORCEIDLELOGOUTTIMEOUT to the desired duration in minutes.'''
        default2 = 240
        self.timeoutci = self.initCi(datatype2, key2, instructions2, default2)

        self.gnomesettingpath = "/etc/dconf/db/local.d/00-autologout"
        self.gnomelockpath = "/etc/dconf/db/local.d/locks/autologout"
        self.undotimeout = ""
        self.undoforcelogout = ""
        self.kdesddm = self.ph.check("sddm")

    def report(self):
        """
        Report on whether the Idle Logout settings are correct.

        @return: bool
        @author: D.Kennel
        """

        compliant = True
        self.detailedresults = ""

        try:
            if self.environ.osfamily == 'linux':
                ph = Pkghelper(self.logger, self.environ)
                if ph.check("gdm") or ph.check("gdm3"):
                    if not self.chkgnome3():
                        self.detailedresults += "Gnome GUI environment " + \
                                                "does not appear to be correctly configured " + \
                                                "for automatic logout of idle sessions. This " + \
                                                "guidance is optional in STONIX, check local " + \
                                                "policy to see if it is required.\n"
                        compliant = False
                    else:
                        self.detailedresults += "Gnome GUI environment " + \
                                                "appears to be correctly configured for " + \
                                                "automatic logout of idle sessions.\n"
                else:
                    self.detailedresults += "Gnome not installed.  No need to configure for gnome\n"

                if ph.check("kdm") or ph.check("kde-workspace") or \
                                      ph.check("sddm"):
                    if not self.chkkde4():
                        self.detailedresults += "KDE GUI environment " + \
                                                "does not appear to be correctly configured " + \
                                                "for automatic logout of idle sessions. This " + \
                                                "guidance is optional in STONIX, check local " + \
                                                "policy to see if it is required.\n"
                        compliant = False
                    else:
                        self.detailedresults += "KDE GUI environment " + \
                                                "appears to be correctly configured for " + \
                                                "automatic logout of idle sessions.\n"
                else:
                    self.detailedresults += "KDE not installed.  No need to configure for kde\n"
            elif self.environ.getosfamily() == 'darwin':
                compliant = self.chkosx()
                if not compliant:
                    self.detailedresults += "Idle logout value is not set to " + \
                        str(self.timeoutci.getcurrvalue()) + "\n"
            self.compliant = compliant

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults = 'ForceIdleLogout: '
            self.detailedresults = self.detailedresults + \
                traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def chkgnome3(self):
        """
        Check that the GNOME 3 auto logout settings are set correctly

        @return: boot - true if settings are set to logout
        @author: D. Kennel
        """

        try:
            seconds = self.timeoutci.getcurrvalue() * 60
        except(TypeError):
            self.detailedresults += "FORCEIDLELOGOUTTIMEOUT value is not " + \
                "valid!\n"
            return False

        if not self.environ.geteuid() == 0:
            # Short circuit for user mode run
            # manipulating the GNOME settings requires privilege
            return True
        compliant = True
        self.timeoutwrong = False
        self.logoutwrong = False
        if os.path.exists('/etc/dconf/db/local.d'):
            havedconffile = False
            havelockfile = False
            havetimeout = False
            havetimeoutlock = False
            havelogout = False
            havelogoutlock = False
            if os.path.exists(self.gnomesettingpath):
                havedconffile = True
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.__chkgnome3',
                                      'Found Gnome settings file'])
                contents = readFile(self.gnomesettingpath, self.logger)
                for line in contents:
                    if re.search('sleep-inactive-ac-timeout=' + str(seconds),
                                 line):
                        havetimeout = True
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['ForceIdleLogout.__chkgnome3',
                                              'Found Gnome timeout'])
                    if re.search("sleep-inactive-ac-type='logout'", line):
                        havelogout = True
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['ForceIdleLogout.__chkgnome3',
                                              'Found Gnome logout'])
            if os.path.exists(self.gnomelockpath):
                havelockfile = True
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.__chkgnome3',
                                      'Found Gnome lock file'])
                contents = readFile(self.gnomelockpath, self.logger)
                for line in contents:
                    if re.search('/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout', line):
                        havetimeoutlock = True
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['ForceIdleLogout.__chkgnome3',
                                              'Found Gnome timeout lock'])
                    if re.search("/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type", line):
                        havelogoutlock = True
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['ForceIdleLogout.__chkgnome3',
                                              'Found Gnome logout lock'])
            if not havedconffile:
                self.detailedresults += "GNOME 3 autologout settings " + \
                    "file not found at: " + \
                    "/etc/dconf/db/local.d/00-autologout\n"
                compliant = False

            if not havetimeout:
                self.detailedresults += "GNOME 3 autologout timeout " + \
                    "not found or does not match expected value. Set " + \
                    "sleep-inactive-ac-timeout=" + str(seconds) + \
                    " in /etc/dconf/db/local.d/00-autologout\n"
                compliant = False

            if not havelogout:
                self.detailedresults += "GNOME 3 autologout logout " + \
                    "not found. Set sleep-inactive-ac-type='logout' in " + \
                    "/etc/dconf/db/local.d/00-autologout\n"
                compliant = False

            if not havelockfile:
                self.detailedresults += "GNOME 3 autologout lock " + \
                    "file not found at: " + \
                    "/etc/dconf/db/local.d/locks/autologout\n"
                compliant = False

            if not havetimeoutlock:
                self.detailedresults += "GNOME 3 autologout timeout " + \
                    "lock not found. Set /org/gnome/settings-daemon/" + \
                    "plugins/power/sleep-inactive-ac-timeout in " + \
                    "/etc/dconf/db/local.d/locks/autologout\n"
                compliant = False

            if not havelogoutlock:
                self.detailedresults += "GNOME 3 autologout lock not " + \
                    "found. Set /org/gnome/settings-daemon/plugins/" + \
                    "power/sleep-inactive-ac-type in " + \
                    "/etc/dconf/db/local.d/locks/autologout\n"
                compliant = False

        if self.ph.check(self.gconf):
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['ForceIdleLogout.__chkgnome3',
                                  'Checking GNOME with gconf'])
            prefix = '/usr/bin/gconftool-2 --direct --config-source ' + \
                'xml:readwrite:/etc/gconf/gconf.xml.mandatory --get '
            idletimecmd = prefix + '/desktop/gnome/session/max_idle_time'
            idleactcmd = prefix + '/desktop/gnome/session/max_idle_action'
            self.cmdhelper.executeCommand(idletimecmd)
            output = self.cmdhelper.getOutput()
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['ForceIdleLogout.__chkgnome3',
                                  'Value of idle time ' + str(output)])
            if output:
                try:
                    if not int(output[0].strip()) == self.timeoutci.getcurrvalue():
                        compliant = False
                        self.timeoutwrong = True
                        if re.search("No value set", output[0]):
                            self.detailedresults += "GNOME 3 autologout time not found\n"
                            self.undotimeout = "unset"
                        elif isinstance(output[0], int):
                            self.detailedresults += "GNOME 3 autologout time not correct.\n"
                            self.undotimeout = output[0]
                        else:
                            self.detailedresults += "GNOME 2 autologout time not correct\n"
                            self.undotimeout = "''"
                except(ValueError):
                    # value not found message
                    pass
            self.cmdhelper.executeCommand(idleactcmd)
            output2 = self.cmdhelper.getOutput()
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['ForceIdleLogout.__chkgnome3',
                                  'Value of idle action ' + str(output2)])
            if output2:
                if not re.search('forced-logout', output2[0]):
                    compliant = False
                    self.logoutwrong = True
                    if re.search("No value set", output2[0]):
                        self.detailedresults += "GNOME 3 autologout settings " + \
                                                "not found.\n"
                        self.undoforcelogout = "unset"
                    else:
                        self.detailedresults += "GNOME 3 autologout settings " + \
                                                "not correct.\n"
                        self.undoforcelogout = str(output2[0])

        return compliant

    def chkkde4(self):
        """
        Check that settings are correct for KDE 4 auto logout. Note that this
        setting lives in each user's home folder and is the reason this rule
        has root & non-root components. With root perms we can work on homes
        that are on local storage but user perms are required for NFS mounted
        home directories.

        @return: bool - true if settings are set to logout for inspected users
        @author: D. Kennel
        """

        try:
            seconds = self.timeoutci.getcurrvalue() * 60
            self.kdefix = []
            kdecheck = ""
            rcpath = ""
            # Lines to search for in rc file
            rcdesired = []
            if self.kdesddm:
                kdecheck = ".config/kdeglobals"
                rcpath = ".config/kscreenlockerrc"
                self.kdeprops = ["Timeout=" + str(self.timeoutci.getcurrvalue())]
                #rcdesired = ["Timeout=" + str(self.timeoutci.getcurrvalue()) + "\n"]
            else:
                kdecheck = ".kde"
                rcpath = ".kde/share/config/kscreensaverrc"
                self.kdeprops = ["AutoLogout=true",
                                 "AutoLogoutTimeout=" + str(seconds)]
                #rcdesired = ["AutoLogout=true\n", "AutoLogoutTimeout=" +
                          str(seconds) + "\n"]
            if self.environ.geteuid() == 0:
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.__chkkde4',
                                      'Root user context beginning passwd ' +
                                      ' loop'])
                failed = []
                contents = readFile("/etc/passwd", self.logger)
                for user in contents:
                    user = user.split(':')
                    try:
                        username = user[0]
                        homepath = user[5]
                    except(IndexError):
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['ForceIdleLogout.__chkkde4',
                                              'IndexError processing ' + 
                                              str(user)])
                        continue
                    if not os.path.exists(os.path.join(homepath, kdecheck)):
                        # User does not use KDE
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['ForceIdleLogout.__chkkde4',
                                              kdecheck + ' not found for ' +
                                              str(username)])
                        continue
                    if not os.path.exists(os.path.join(homepath, rcpath)):
                        failed.append(username)
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['ForceIdleLogout.__chkkde4',
                                              rcpath + ' not found for ' +
                                              str(username)])
                    else:
                        contents = readFile(os.path.join(homepath, rcpath), self.logger)
                        for desired in rcdesired:
                            found = False
                            for data in contents:
                                if desired == data:
                                    found = True
                            if not found:
                                failed.append(username)
                                break
                if len(failed) == 0:
                    return True
                else:
                    userlist = ', '.join(failed)
                    self.detailedresults += "The following users have KDE " + \
                        "preference files but are not configured for " + \
                        " automatic logout: " + userlist + "\n"
                    return False
            else:
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.__chkkde4',
                                      'Non root user context starting check'])
                if not os.path.exists(os.path.join(self.environ.geteuidhome(),
                                                   kdecheck)):
                    # User does not use KDE
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['ForceIdleLogout.__chkkde4',
                                          kdecheck + ' not found for ' +
                                          str(username)])
                    return True
                else:
                    if not os.path.exists(os.path.join(
                                            self.environ.geteuidhome(),
                                            rcpath)):
                        self.detailedresults += "Your " + rcpath + \
                                                "file does not exist.\n"
                        return False
                    else:
                        contents = readFile(os.path.join(self.environ.geteuidhome(),
                                                    rcpath), self.logger)
                        compliant = False
                        for desired in rcdesired:
                            compliant = False
                            for data in contents:
                                if desired == data:
                                    compliant = True
                            if not compliant:
                                break
                        if compliant:
                            return True
                        else:
                            self.detailedresults += "Your " + rcpath + \
                                " file is not configured for " + \
                                "automatic logout. It should contain the " + \
                                "lines: "
                            for desired in rcdesired:
                                self.detailedresults += desired
                            return False
        except Exception, err:
            self.detailedresults += str(err)
            raise

    def chkosx(self):
        '''
        '''

        globalprefs = "/Library/Preferences/.GlobalPreferences.plist"
        globalprefstemp = globalprefs + ".stonixtmp"
        timeout = self.timeoutci.getcurrvalue() * 60
        data = {"com.apple.autologout.AutoLogOutDelay":
                [str(timeout), "-int " + str(timeout)]}
        self.editor = KVEditorStonix(self.statechglogger, self.logger,
                                     "defaults", globalprefs, globalprefstemp,
                                     data, "present")
        return self.editor.report()



    def fixgnome3(self):
        """
        Configure GNOME 3 for automatic logout.

        @author: d.kennel
        """

        if not self.environ.geteuid() == 0:
            return
        success = True
        if os.path.exists('/etc/dconf/db/local.d'):
            created1, created2 = False, False
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['ForceIdleLogout.__fixgnome3',
                                  'Working GNOME with dconf'])

            try:
                seconds = self.timeoutci.getcurrvalue() * 60
            except(TypeError):
                self.detailedresults += "FORCEIDLELOGOUTTIMEOUT value is " + \
                    "not valid!\n"
                self.rulesuccess = False
                return False
            if not os.path.exists(self.gnomesettingpath):
                if not createFile(self.gnomesettingpath, self.logger):
                    success = False
                    self.detailedresults += "Unable to create " + self.gnomesettingpath + " file\n"
                else:
                    created1 = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.gnomesettingpath}
                    self.statechglogger.recordchgevent(myid, event)
            if os.path.exists(self.gnomesettingpath):
                gdirectives = {"org.gnome.settings-daemon.plugins.power": {
                                "sleep-inactive-ac-type": "'logout'",
                                'sleep-inactive-ac-timeout': str(seconds)}}
                geditor = KVEditorStonix(self.statechglogger, self.logger, "tagconf",
                                         self.gnomesettingpath,
                                         self.gnomesettingpath + '.tmp',
                                         gdirectives, "present", "closedeq")
                geditor.report()
                if geditor.fixables:
                    if geditor.fix():
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        geditor.setEventID(myid)
                        if geditor.commit():
                            debug = self.gnomesettingpath + "'s contents have been " + \
                                "corrected\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            os.chown(self.gnomesettingpath, 0, 0)
                            os.chmod(self.gnomesettingpath, 0o644)
                            resetsecon(self.gnomesettingpath)

                        else:
                            debug = "kveditor commit not successful\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            self.detailedresults += self.gnomesettingpath + \
                                " properties could not be set\n"
                            succeess = False
                    else:
                        debug = "kveditor fix not successful\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        self.detailedresults += self.gnomesettingpath + \
                                                " properties could not be set\n"
                        succeess = False
                if not checkPerms(self.gnomesettingpath, [0, 0, 644], self.logger):
                    if not created1:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.gnomesettingpath, [0, 0, 644], self.logger,
                                        self.statechglogger, myid):
                            self.detailedresults += "Unable to set permissions on " + \
                                self.gnomesettingpath + " file\n"
                            success = False
                    else:
                        if not setPerms(self.gnomesettingpath, [0, 0, 644], self.logger):
                            self.detailedresults += "Unable to set permissions on " + \
                                                    self.gnomesettingpath + " file\n"
                            success = False
            havetimeoutlock = False
            havelogoutlock = False
            lockdata = []
            if not os.path.exists(self.gnomelockpath):
                if not createFile(self.gnomelockpath, self.logger):
                    success = False
                    self.detailedresults += "Unable to create " + self.gnomelockpath + " file\n"
                else:
                    created2 = True
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "creation",
                             "filepath": self.gnomelockpath}
                    self.statechglogger.recordchgevent(myid, event)
            if os.path.exists(self.gnomelockpath):
                contents = readFile(self.gnomelockpath, self.logger)
                for line in contents:
                    if re.search('/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout',
                                 line):
                        havetimeoutlock = True
                    if re.search("/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type",
                                 line):
                        havelogoutlock = True
                if not havetimeoutlock:
                    lockdata.append('/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout\n')
                if not havelogoutlock:
                    lockdata.append("/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type\n")
                tempfile = self.gnomelockpath + ".tmp"
                if writeFile(tempfile, lockdata, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath", self.gnomelockpath}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.gnomelockpath,
                                                         tempfile, myid)
                    os.rename(tempfile, self.gnomelockpath)
                    os.chown(self.gnomelockpath, 0, 0)
                    os.chmod(self.gnomelockpath, 0o644)
                    resetsecon(self.gnomelockpath)
                else:
                    self.detailedresults += "Unable to write contents to " + \
                        self.gnomelockpath
                    success = False
                if not checkPerms(self.gnomelockpath, [0, 0, 644], self.logger):
                    if not created2:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        if not setPerms(self.gnomelockpath, [0, 0, 644], self.logger,
                                        self.statechglogger, myid):
                            self.detailedresults += "Unable to set permissions on " + \
                                self.gnomelockpath + " file\n"
                            success = False
                    else:
                        if not setPerms(self.gnomelockpath, [0, 0, 644], self.logger):
                            self.detailedresults += "Unable to set permissions on " + \
                                                    self.gnomelockpath + " file\n"
                            success = False

        elif self.ph.check(gconf):
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['ForceIdleLogout.__fixgnome3',
                                  'Working GNOME with gconf'])
            undocmd = ""
            undoprefix = '/usr/bin/gconftool-2 --direct --config-source ' + \
                'xml:readwrite:/etc/gconf/gconf.xml.mandatory '
            setprefix = '/usr/bin/gconftool-2 --direct --config-source ' + \
                'xml:readwrite:/etc/gconf/gconf.xml.mandatory --set '
            settime = setprefix + \
                '--type integer /desktop/gnome/session/max_idle_time ' + \
                str(self.timeoutci.getcurrvalue())
            setlogout = setprefix + \
                '--type string /desktop/gnome/session/' + \
                'max_idle_action forced-logout'
            if self.timeoutwrong:
                self.cmdhelper.executeCommand(settime)
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    errstr = self.cmdhelper.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += 'Failed to configure idle time limit option.\n'
                    success = False
                else:
                    if self.undotimeout == "unset":
                        undocmd = undoprefix + '--unset /desktop/gnome/session/max_idle_time'
                    else:
                        undocmd = setprefix + '--type integer /desktop/gnome/session/max_idle_time ' + \
                            self.undotimeout
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "command"
                             "command": undocmd}
                    self.statechglogger.recordchgevent(myid, event)
                    self.detailedresults += 'Maximum idle time limit configured successfully.\n'
            if self.logoutwrong:
                self.cmdhelper.executeCommand(setlogout)
                retcode = self.cmdhelper.getReturnCode()
                if retcode != 0:
                    errstr = self.cmdhelper.getErrorString()
                    self.logger.log(LogPriority.DEBUG, errstr)
                    self.detailedresults += 'Failed to configure idle forced-logout option.\n'
                    success = False
                else:
                    if self.undoforcelogout == "unset":
                        undocmd = undoprefix + '--unset /desktop/gnome/session/max_idle_action'
                    else:
                        undocmd = setprefix + '--type integer /desktop/gnome/session/max_idle_action ' + \
                            self.undoforcelogout
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "command"
                             "command": undocmd}
                    self.statechglogger.recordchgevent(myid, event)
                    self.detailedresults += 'Idle forced-logout option configured successfully.\n'
        return success
    def fixkde4(self):
        """
        Configure KDE 4 for automatic logout.

        @author: d.kennel
        """

        passwddata = readFile('/etc/passwd', self.logger)

        if self.environ.geteuid() == 0:
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['ForceIdleLogout.__fixkde4',
                                  'Root context starting loop'])
            for user in passwddata:
                user = user.split(':')
                try:
                    uidnum = int(user[2])
                    defgid = int(user[3])
                    homepath = user[5]
                except(IndexError):
                    self.logdispatch.log(LogPriority.DEBUG, \
                                         ['ForceIdleLogout.__fixkde4', \
                                          'IndexError processing ' + str(user)])
                    continue
                self.logdispatch.log(LogPriority.DEBUG, \
                                     ['ForceIdleLogout.__fixkde4', \
                                      'Calling rcfix on ' + str(user)])
                self.kdercfix(uidnum, defgid, homepath)
        else:
            homepath = self.environ.geteuidhome()
            uidnum = int(self.environ.geteuid())
            found = False
            for user in passwddata:
                user = user.split(':')
                try:
                    puidnum = int(user[2])
                    pdefgid = int(user[3])
                except(IndexError):
                    continue
                if puidnum == uidnum:
                    defgid = pdefgid
                    found = True
            if not found:
                defgid = uidnum
            self.kdercfix(uidnum, defgid, homepath)

    def kdercfix(self, uidnum, defgid, homepath):
        """
        Private support method for fixkde4. This actually does the
        settings wrangling

        @param uidnum: UID number of the user being edited
        @param defgid: Default GID of the user being edited
        @param homepath: Home directory path of the user being edited
        @author: d.kennel
        """

        try:
            seconds = self.timeoutci.getcurrvalue() * 60
            kdecheck = ""
            rcpath = ""
            # Lines to add in rc file
            rcdesired = []
            if not os.path.exists(os.path.join(homepath, kdecheck)):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.__kdercfix',
                                      kdecheck + ' not found'])
                # User does not use KDE
                return
            rcpath = os.path.join(homepath, rcpath)
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['ForceIdleLogout.__kdercfix',
                                  'rcpath is ' + str(rcpath)])
            if not os.path.exists(rcpath):
                rcstring = ""
                for desired in rcdesired:
                    rcstring += desired + "\n"
                kwhandle = open(rcpath, 'w')
                kwhandle.write(rcstring)
                os.chmod(rcpath, 0644)
                os.chown(rcpath, uidnum, defgid)
                resetsecon(rcpath)
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.__kdercfix',
                                      'Created kscreensaverrc'])
            else:
                khandle = open(rcpath)
                rcdata = khandle.readlines()
                khandle.close()
                compliant = True
                for desired in rcdesired:
                    linefound = False
                    for data in rcdata:
                        if desired == data:
                            linefound = True
                    if not linefound:
                        compliant = False
                        rcdata.append(desired)
                if not compliant:
                    kwhandle = open(rcpath, 'w')
                    kwhandle.writelines(rcdata)
                    kwhandle.close()
                    os.chmod(rcpath, 0644)
                    os.chown(rcpath, uidnum, defgid)
                    resetsecon(rcpath)
        except Exception, err:
            self.detailedresults += err
            return False

    def fixosx(self):
        if not self.editor.report():
            if self.editor.fix():
                if self.editor.commit():
                    self.rulesuccess = True
                else:
                    self.detailedresults += "KVEditor could not commit " + \
                        "correct configuration\n"
                    self.rulesuccess = False
            else:
                self.detailedresults += "KVEditor could not fix configuration\n"
                self.rulesuccess = False

    def fix(self):
        """
       Configure the system to enforce logout of idle GUI sessions

        @author: D. Kennel
        """

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0
        if self.filci.getcurrvalue() and self.environ.getosfamily() == "linux":
            if self.gnomeInstalled:
                try:
                    self.fixgnome3()
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    self.rulesuccess = False
                    self.detailedresults = 'ForceIdleLogout: '
                    self.detailedresults = self.detailedresults + \
                        traceback.format_exc()
                    self.rulesuccess = False
                    self.logger.log(LogPriority.ERROR,
                                    self.detailedresults)
            if self.kdeInstalled:
                try:
                    self.fixkde4()
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    self.rulesuccess = False
                    self.detailedresults = 'ForceIdleLogout: '
                    self.detailedresults = self.detailedresults + \
                        traceback.format_exc()
                    self.rulesuccess = False
                    self.logger.log(LogPriority.ERROR,
                                    self.detailedresults)
        elif self.filci.getcurrvalue() and \
             self.environ.getosfamily() == "darwin":
            try:
                self.fixosx()
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.rulesuccess = False
                self.detailedresults = 'ForceIdleLogout: '
                self.detailedresults = self.detailedresults + \
                    traceback.format_exc()
                self.rulesuccess = False
                self.logger.log(LogPriority.ERROR,
                                self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def undo(self):
        """
        Undo forced logout settings. Note that due to network mounted home
        directory issues we don't track eventids for the KDE settings. So the
        undo will remove the KDE settings if present in any form.

        @author: dkennel
        """

        self.targetstate = 'notconfigured'

        if self.environ.geteuid() == 0:
            try:
                eventgnomecontent = self.statechglogger.getchgevent('0023001')
                if eventgnomecontent['startstate'] != eventgnomecontent['endstate']:
                    self.statechglogger.revertfilechanges(self.gnomesettingpath,
                                                          '0023001')
            except(IndexError, KeyError):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.undo',
                                      "EventID 0023001 not found"])
            try:
                eventgnomemode = self.statechglogger.getchgevent('0023002')
                if eventgnomemode['startstate'] != eventgnomemode['endstate']:
                    uid = eventgnomemode['startstate'][0]
                    gid = eventgnomemode['startstate'][1]
                    mode = eventgnomemode['startstate'][2]
                    if os.path.exists(self.gnomesettingpath):
                        os.chown(self.gnomesettingpath, uid, gid)
                        os.chmod(self.gnomesettingpath, mode)
                        resetsecon(self.gnomesettingpath)
            except(IndexError, KeyError):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.undo',
                                      "EventID 0023002 not found"])
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self.detailedresults = traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR,
                                     ['ForceIdleLogout.undo',
                                      self.detailedresults])
            try:
                eventlockmode = self.statechglogger.getchgevent('0023003')
                if eventlockmode['startstate'] != eventlockmode['endstate']:
                    uid = eventlockmode['startstate'][0]
                    gid = eventlockmode['startstate'][1]
                    mode = eventlockmode['startstate'][2]
                    if os.path.exists(self.gnomelockpath):
                        os.chown(self.gnomelockpath, uid, gid)
                        os.chmod(self.gnomelockpath, mode)
                        resetsecon(self.gnomelockpath)
            except(IndexError, KeyError):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['ForceIdleLogout.undo',
                                      "EventID 0023003 not found"])
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self.detailedresults = traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR,
                                     ['ForceIdleLogout.undo',
                                      self.detailedresults])
            if not os.path.exists('/etc/dconf/db'):
                setprefix = '/usr/bin/gconftool-2 --direct --config-source ' + \
                    'xml:readwrite:/etc/gconf/gconf.xml.mandatory --set '
                setlogout = setprefix + '--type string ' + \
                    '/desktop/gnome/session/max_idle_action ""'
                self.cmdhelper.executeCommand(setlogout)
            fhandle = open('/etc/passwd', 'r')
            passwddata = fhandle.readlines()
            fhandle.close()
            for user in passwddata:
                user = user.split(':')
                try:
                    homepath = user[5]
                except(IndexError):
                    continue
                rcpath = os.path.join(homepath,
                                      '.kde/share/config/kscreensaverrc')
                if os.path.exists(rcpath):
                    cmd = "/usr/bin/sed -i -e '/AutoLogout=/d' -e " + \
                        "'/AutoLogoutTimeout=/d' " + rcpath
                    subprocess.call(cmd, shell=True, close_fds=True)
            self.currstate = 'notconfigured'
        else:
            homepath = self.environ.geteuidhome()
            rcpath = os.path.join(homepath, '.kde/share/config/kscreensaverrc')
            if os.path.exists(rcpath):
                cmd = "/usr/bin/sed -i -e '/AutoLogout=/d' -e " + \
                    "'/AutoLogoutTimeout=/d' " + rcpath
                subprocess.call(cmd, shell=True, close_fds=True)
                self.currstate = 'notconfigured'

        self.report()
        if self.currstate == self.targetstate:
            self.detailedresults = 'ForceIdleLogout: Changes ' + \
                'successfully reverted'
        return True
