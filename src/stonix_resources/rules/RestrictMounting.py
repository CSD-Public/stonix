###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################


"""
This rule restricts mounting rights and options.

@author: Eric Ball
@change: 2015/07/06 Eric Ball Original implementation
@change: 2016/04/22 Eric Ball Added GNOME 3 method for disabling GNOME mounting
@change: 2016/08/01 Eric Ball Added "dbus-launch" before all gsettings commands,
    and fixed undos that were the same as the fix commands
@change: 2017/10/23 Roy Nielsen - change to new service helper interface
@change: 2018/2/9   Brandon Gonzales - changed fix make sure dbus-x11 is installed
    before disabling gnome automount in gsettings
@change: 2018/4/6   Brandon Gonzales - Initialized variable 'success' in fix
@TODO candidate for rule re-write with focus on modularity, readability, code re-use, command-based approach
@TODO difficult to create good unit tests for this rule as written
"""



import os
import re
import traceback

from ..stonixutilityfunctions import iterate, resetsecon
from ..stonixutilityfunctions import writeFile, readFile
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..CommandHelper import CommandHelper
from ..KVEditorStonix import KVEditorStonix
from ..pkghelper import Pkghelper
from ..ServiceHelper import ServiceHelper


class RestrictMounting(Rule):
    '''Class help text'''

    def __init__(self, config, enviro, logger, statechglogger):
        """
        Constructor
        """

        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 112
        self.rulename = "RestrictMounting"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.sethelptext()

        # Configuration item instantiation
        datatype1 = "bool"
        key1 = "RESTRICTCONSOLEACCESS"
        instructions1 = "To restrict console device access, set " + \
                       "RESTRICTCONSOLEACCESS to True."
        default1 = False
        self.consoleCi = self.initCi(datatype1, key1, instructions1, default1)

        datatype2 = "bool"
        key2 = "DISABLEAUTOFS"
        instructions2 = "To disable dynamic NFS mounting through the " + \
                       "autofs service, set DISABLEAUTOFS to True."
        default2 = False
        self.autofsCi = self.initCi(datatype2, key2, instructions2, default2)

        datatype3 = "bool"
        key3 = "DISABLEGNOMEAUTOMOUNT"
        instructions3 = "To disable the GNOME desktop environment from " + \
                       "automounting devices and removable media, set " + \
                       "DISABLEGNOMEAUTOMOUNT to True."
        default3 = False
        self.gnomeCi = self.initCi(datatype3, key3, instructions3, default3)

        self.guidance = ["NSA 2.2.2.1", "NSA 2.2.2.3", "NSA 2.2.2.4",
                         "CCE 3685-5", "CCE 4072-5", "CCE 4231-7",
                         "CCE-RHEL7-CCE-TBD 2.2.2.6"]
        self.applicable = {"type": "white",
                           "family": ["linux"]}
        self.iditerator = 0
        self.gsettings = "/usr/bin/gsettings"
        self.gconftool = "/usr/bin/gconftool-2"
        self.dbuslaunch = "/usr/bin/dbus-launch"

    def report(self):
        ''' '''

        self.automountMedia = True
        self.automountDrives = True
        self.sec_console_perms1 = "/etc/security/console.perms.d/50-default.perms"
        self.sec_console_perms2 = "/etc/security/console.perms"
        self.console_perms_temppath = self.sec_console_perms2 + ".stonixtmp"
        self.data = {"<console>": "tty[0-9][0-9]* vc/[0-9][0-9]* :0\.[0-9] :0",
                     "<xconsole>": "0\.[0-9] :0"}
        self.autofspkg = "autofs"
        self.autofssvc = "autofs"
        self.ph = Pkghelper(self.logdispatch, self.environ)
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.ch = CommandHelper(self.logdispatch)
        self.compliant = True
        self.detailedresults = ""

        try:

            if os.path.exists(self.sec_console_perms1):
                current_config = readFile(self.sec_console_perms1, self.logger)
                for line in current_config:
                    if re.search("^<[x]?console>", line, re.M):
                        self.compliant = False
                        self.detailedresults += self.sec_console_perms1 + " contains unrestricted device access\n"
                        break

            if os.path.exists(self.sec_console_perms2):
                self.editor2 = KVEditorStonix(self.statechglogger, self.logger, "conf", self.sec_console_perms2, self.console_perms_temppath, self.data, "present", "closedeq")
                if not self.editor2.report():
                    self.compliant = False
                    self.detailedresults += self.sec_console_perms2 + " does not contain the correct values\n"

            if self.ph.check(self.autofspkg):
                if self.sh.auditService(self.autofssvc, _="_"):
                    self.compliant = False
                    self.detailedresults += "autofs is installed and enabled\n"

            if os.path.exists(self.gsettings):
                automountOff = False
                autorunNever = False
                cmd = [self.gsettings, "get", "org.gnome.desktop.media-handling",
                       "automount"]
                self.ch.executeCommand(cmd)
                if re.search("false", self.ch.getOutputString()):
                    automountOff = True

                cmd = [self.gsettings, "get", "org.gnome.desktop.media-handling",
                       "autorun-never"]
                self.ch.executeCommand(cmd)
                if re.search("true", self.ch.getOutputString()):
                    autorunNever = True
                    debug = "autorun-never is enabled"
                    self.logger.log(LogPriority.DEBUG, debug)

                self.automountOff = automountOff
                self.autorunNever = autorunNever

                if not automountOff or not autorunNever:
                    self.compliant = False
                    self.detailedresults += "GNOME automounting is enabled\n"

            # check for gnome automounting
            if os.path.exists(self.gconftool):
                cmd = [self.gconftool, "-R", "/desktop/gnome/volume_manager"]

                if os.path.exists("/desktop/gnome/volume_manager"):
                    self.ch.executeCommand(cmd)
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        self.compliant = False
                        self.detailedresults += "\nFailed to read gnome volume manager config"
    
                    output = self.ch.getOutputString()
    
                    if re.search("automount_media.*false", output):
                        self.automountMedia = False
                    if re.search("automount_drives.*false", output):
                        self.automountDrives = False

                else:
                    self.automountMedia = False
                    self.automountDrives = False
                mylist = [self.automountMedia, self.automountDrives]

                if any(mylist):
                    self.compliant = False
                    self.detailedresults += "GNOME automounting is enabled\n"

            # reset these directories to be owned by their respective users
            dirs = ''
            if os.path.exists('/run/user'):
                dirs = os.listdir('/run/user')

            if dirs:
                for d in dirs:
                    # check if the directory is an integer representing a uid
                    if re.search('^([+-]?[1-9]\d*|0)$', d, re.IGNORECASE):
                        self.logger.log(LogPriority.DEBUG, "Found UID directory")
                        try:
                            os.chown('/run/user/' + d + '/dconf/user', int(d), int(d))
                        except Exception as errmsg:
                            self.logger.log(LogPriority.DEBUG, str(errmsg))
                            continue
            else:
                self.logger.log(LogPriority.DEBUG, "no directories in /run/user")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant

    def fix(self):
        ''' '''

        self.detailedresults = ""
        self.iditerator = 0
        self.rulesuccess = True
        success = True
        consoleaccess = self.consoleCi.getcurrvalue()
        autofs = self.autofsCi.getcurrvalue()
        gnomeautomount = self.gnomeCi.getcurrvalue()
        mylist = [consoleaccess, autofs, gnomeautomount]

        try:

            # if none of the CIs are enabled, skip fix
            if not any(mylist):
                self.detailedresults += "\nNone of the CI's were enabled. Nothing was done."
                self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess

            # clear event list data
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            # if restrict console access CI is enabled, restrict console access
            if self.consoleCi.getcurrvalue():
                if os.path.exists(self.sec_console_perms1):
                    tmpfile = self.sec_console_perms1 + ".stonixtmp"
                    defaultPerms = open(self.sec_console_perms1, "r").read()
                    defaultPerms = re.sub("(<[x]?console>)", r"#\1", defaultPerms)
                    if writeFile(tmpfile, defaultPerms, self.logger):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "conf", "filepath": self.sec_console_perms1}
                        self.statechglogger.recordchgevent(myid, event)
                        self.statechglogger.recordfilechange(self.sec_console_perms1, tmpfile, myid)
                        os.rename(tmpfile, self.sec_console_perms1)
                        resetsecon(self.sec_console_perms1)
                    else:
                        success = False
                        self.detailedresults += "Problem writing new contents to " + \
                                   "temporary file"
                if os.path.exists(self.sec_console_perms2):
                    self.editor = KVEditorStonix(self.statechglogger, self.logger, "conf", self.sec_console_perms2, self.console_perms_temppath, self.data, "present", "closedeq")
                    self.editor.report()
                    if self.editor.fixables:
                        if self.editor.fix():
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            self.editor.setEventID(myid)
                            if self.editor.commit():
                                debug = self.sec_console_perms2 + "'s contents have been " \
                                    + "corrected\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                resetsecon(self.sec_console_perms2)
                            else:
                                debug = "kveditor commit not successful\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                success = False
                                self.detailedresults += self.sec_console_perms2 + \
                                    " properties could not be set\n"
                        else:
                            debug = "kveditor fix not successful\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            success = False
                            self.detailedresults += self.sec_console_perms2 + \
                                " properties could not be set\n"

            # if autofs CI is enabled, disable autofs
            if self.autofsCi.getcurrvalue():
                if self.ph.check(self.autofspkg) and \
                   self.sh.auditService(self.autofssvc, _="_"):
                    if self.sh.disableService(self.autofssvc, _="_"):
                        debug = "autofs service successfully disabled\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "servicehelper", "servicename":
                                 self.autofssvc, "startstate": "enabled",
                                 "endstate": "disabled"}
                        self.statechglogger.recordchgevent(myid, event)
                    else:
                        success = False
                        debug = "Unable to disable autofs service\n"
                        self.logger.log(LogPriority.DEBUG, debug)

            returnCode = 0
            if self.gnomeCi.getcurrvalue():
                if os.path.exists(self.gsettings):
                    # gsettings requires a D-Bus session bus in order to make
                    # any changes. This is because the dconf daemon must be
                    # activated using D-Bus.
                    if not os.path.exists(self.dbuslaunch):
                        self.ph.install("dbus-x11")
                    
                    if os.path.exists(self.dbuslaunch):
                        if not self.automountOff:
                            cmd = [self.dbuslaunch, self.gsettings, "set",
                                   "org.gnome.desktop.media-handling",
                                   "automount", "false"]
                            self.ch.executeCommand(cmd)
                            returnCode = self.ch.getReturnCode()

                            if not returnCode:
                                self.iditerator += 1
                                myid = iterate(self.iditerator, 
                                               self.rulenumber)
                                event = {"eventtype": "comm", "command":
                                        ["dbus-launch", "gsettings", "set",
                                         "org.gnome.desktop.media-handling",
                                         "automount", "true"]}
                                self.statechglogger.recordchgevent(myid, event)

                        if not self.autorunNever:
                            cmd = [self.dbuslaunch, "gsettings", "set",
                                   "org.gnome.desktop.media-handling",
                                   "autorun-never", "true"]
                            self.ch.executeCommand(cmd)
                            returnCode += self.ch.getReturnCode()

                            if not self.ch.getReturnCode():
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                event = {"eventtype": "comm", "command":
                                        [self.dbuslaunch, self.gsettings, "set",
                                         "org.gnome.desktop.media-handling",
                                         "autorun-never", "false"]}
                                self.statechglogger.recordchgevent(myid, event)
                    else:
                        success = False
                        debug = "Unable to disable GNOME automounting: " + \
                                "dbus-x11 is not installed"
                        self.logger.log(LogPriority.DEBUG, debug)

                if os.path.exists(self.gconftool):
                    if self.automountMedia:
                        cmd = [self.gconftool, "--direct", "--config-source",
                               "xml:readwrite:/etc/gconf/gconf.xml.mandatory",
                               "--type", "bool", "--set",
                               "/desktop/gnome/volume_manager/automount_media",
                               "false"]
                        self.ch.executeCommand(cmd)
                        returnCode = self.ch.getReturnCode()

                        if not returnCode:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "comm", "command":
                                     [self.gconftool, "--direct",
                                      "--config-source", "xml:readwrite:" +
                                      "/etc/gconf/gconf.xml.mandatory",
                                      "--type", "bool", "--set",
                                      "/desktop/gnome/volume_manager/" +
                                      "automount_media", "true"]}
                            self.statechglogger.recordchgevent(myid, event)

                    if self.automountDrives:
                        cmd = [self.gconftool, "--direct", "--config-source",
                               "xml:readwrite:/etc/gconf/gconf.xml.mandatory",
                               "--type", "bool", "--set",
                               "/desktop/gnome/volume_manager/automount_drives",
                               "false"]
                        self.ch.executeCommand(cmd)
                        returnCode += self.ch.getReturnCode()

                        if not self.ch.getReturnCode():
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "comm", "command":
                                     [self.gconftool, "--direct",
                                      "--config-source", "xml:readwrite:" +
                                      "/etc/gconf/gconf.xml.mandatory",
                                      "--type", "bool", "--set",
                                      "/desktop/gnome/volume_manager/" +
                                      "automount_drives",
                                      "true"]}
                            self.statechglogger.recordchgevent(myid, event)

                if returnCode:
                    success = False
                    self.detailedresults += "Fix failed to disable GNOME automounting\n"

            # reset these directories to be owned by their respective users
            dirs = ''
            if os.path.exists('/run/user'):
                dirs = os.listdir('/run/user')

            if dirs:
                for d in dirs:
                    # check if the directory is an integer representing a uid
                    if re.search('^([+-]?[1-9]\d*|0)$', d, re.IGNORECASE):
                        self.logger.log(LogPriority.DEBUG, "Found UID directory")
                        try:
                            os.chown('/run/user/' + d + '/dconf/user', int(d), int(d))
                        except Exception as errmsg:
                            self.logger.log(LogPriority.DEBUG, str(errmsg))
                            continue
            else:
                self.logger.log(LogPriority.DEBUG, "no directories in /run/user")

            self.rulesuccess = success

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
