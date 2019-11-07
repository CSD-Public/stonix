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

'''
Created on 2015/07/01

@author: Eric Ball
@change: 2015/12/07 eball Added information about REMOVEX CI to help text
@change: 2016/07/06 eball Separated fix into discrete methods
@change: 2017/06/02 bgonz12 - Change a conditional in reportUbuntu to search for
                    "manual" using regex instead of direct comparison
@change 2017/08/28 rsn Fixing to use new help text methods
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/14 bgonz12 - Fix removeX dependency issue for deb systems
'''


import os
import re
import traceback
from KVEditorStonix import KVEditorStonix
from logdispatcher import LogPriority
from pkghelper import Pkghelper
from rule import Rule
from CommandHelper import CommandHelper
from ServiceHelper import ServiceHelper
from stonixutilityfunctions import iterate, readFile, writeFile, createFile
from stonixutilityfunctions import resetsecon


class DisableGUILogon(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 105
        self.rulename = "DisableGUILogon"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # Configuration item instantiation
        datatype = "bool"
        key = "DISABLEX"
        instructions = "To enable this item, set the value of DISABLEX " + \
            "to True. When enabled, this rule will disable the automatic " + \
            "GUI login, and the system will instead boot to the console " + \
            "(runlevel 3). This will not remove any GUI components, and the " + \
            "GUI can still be started using the \"startx\" command."
        default = False
        self.ci1 = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "LOCKDOWNX"
        instructions = "To enable this item, set the value of LOCKDOWNX " + \
            "to True. When enabled, this item will help secure X Windows by " + \
            "disabling the X Font Server (xfs) service and disabling X " + \
            "Window System Listening. This item should be enabled if X " + \
            "Windows is disabled but will be occasionally started via " + \
            "startx, unless there is a mission-critical need for xfs or " + \
            "a remote display."
        default = False
        self.ci2 = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "REMOVEX"
        instructions = "To enable this item, set the value of REMOVEX " + \
            "to True. When enabled, this item will COMPLETELY remove X " + \
            "Windows from the system, and on most platforms will disable " + \
            "any currently running display manager. It is therefore " + \
            "recommended that this rule be run from a console session " + \
            "rather than from the GUI.\nREMOVEX cannot be undone."
        default = False
        self.ci3 = self.initCi(datatype, key, instructions, default)

        self.guidance = ["NSA 3.6.1.1", "NSA 3.6.1.2", "NSA 3.6.1.3",
                         "CCE 4462-8", "CCE 4422-2", "CCE 4448-7",
                         "CCE 4074-1"]
        self.iditerator = 0
        self.ph = Pkghelper(self.logger, self.environ)
        self.ch = CommandHelper(self.logger)
        self.sh = ServiceHelper(self.environ, self.logger)
        self.myos = self.environ.getostype().lower()
        self.sethelptext()

    def report(self):
        '''@author: Eric Ball

        :param self: essential if you override this definition
        :returns: bool - True if system is compliant, False if it isn't

        '''
        try:
            compliant = True
            results = ""

            if os.path.exists("/bin/systemctl"):
                self.initver = "systemd"
                compliant, results = self.reportSystemd()
            elif re.search("debian", self.myos):
                self.initver = "debian"
                compliant, results = self.reportDebian()
            elif re.search("ubuntu", self.myos):
                self.initver = "ubuntu"
                compliant, results = self.reportUbuntu()
            else:
                self.initver = "inittab"
                compliant, results = self.reportInittab()

            # NSA guidance specifies disabling of X Font Server (xfs),
            # however, this guidance seems to be obsolete as of RHEL 6,
            # and does not apply to the Debian family.
            if self.sh.auditService("xfs", _="_"):
                compliant = False
                results += "xfs is currently enabled\n"

            xremoved = True
            self.xservSecure = True
            if re.search("debian|ubuntu", self.myos):
                if self.ph.check("xserver-xorg-core"):
                    compliant = False
                    xremoved = False
                    results += "Core X11 components are present\n"
            elif re.search("opensuse", self.myos):
                if self.ph.check("xorg-x11-server"):
                    compliant = False
                    xremoved = False
                    results += "Core X11 components are present\n"
            else:
                if self.ph.check("xorg-x11-server-Xorg"):
                    compliant = False
                    xremoved = False
                    results += "Core X11 components are present\n"
            # Removing X will take xserverrc with it. If X is not present, we
            # do not need to check for xserverrc
            if not xremoved:
                self.serverrc = "/etc/X11/xinit/xserverrc"
                self.xservSecure = False
                if os.path.exists(self.serverrc):
                    serverrcText = readFile(self.serverrc, self.logger)
                    if re.search("opensuse", self.myos):
                        for line in serverrcText:
                            reSearch = r'exec (/usr/bin/)?X \$dspnum.*\$args'
                            if re.search(reSearch, line):
                                self.xservSecure = True
                                break
                    else:
                        for line in serverrcText:
                            reSearch = r'^exec (/usr/bin/)?X (:0 )?-nolisten tcp ("$@"|.?\$@)'
                            if re.search(reSearch, line):
                                self.xservSecure = True
                                break
                    if not self.xservSecure:
                        compliant = False
                        results += self.serverrc + " does not contain proper " \
                            + "settings to disable X Window System " + \
                            "Listening/remote display\n"
                else:
                    compliant = False
                    results += self.serverrc + " does not exist; X Window " + \
                        "System Listening/remote display has not " + \
                        "been disabled\n"

            self.detailedresults = results
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults = "\n" + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportInittab(self):
        compliant = False
        results = ""
        inittab = "/etc/inittab"
        if os.path.exists(inittab):
            initData = readFile(inittab, self.logger)
            for line in initData:
                if line.strip() == "id:3:initdefault:":
                    compliant = True
                    break
        else:
            self.logger.log(LogPriority.ERROR, inittab + " not found, init " +
                            "system unknown")
        if not compliant:
            results = "inittab not set to runlevel 3; GUI logon is enabled\n"
        return compliant, results

    def reportSystemd(self):
        compliant = True
        results = ""
        cmd = ["/bin/systemctl", "get-default"]
        self.ch.executeCommand(cmd)
        defaultTarget = self.ch.getOutputString()
        if not re.search("multi-user.target", defaultTarget):
            compliant = False
            results = "systemd default target is not multi-user.target; " + \
                      "GUI logon is enabled\n"
        return compliant, results

    def reportDebian(self):
        compliant = True
        results = ""
        dmlist = ["gdm", "gdm3", "lightdm", "xdm", "kdm"]
        for dm in dmlist:
            if self.sh.auditService(dm, _="_"):
                compliant = False
                results = dm + \
                    " is still in init folders; GUI logon is enabled\n"
        return compliant, results

    def reportUbuntu(self):
        compliant = True
        results = ""
        ldmover = "/etc/init/lightdm.override"
        grub = "/etc/default/grub"
        if os.path.exists(ldmover):
            lightdmText = readFile(ldmover, self.logger)
            if not re.search("manual", lightdmText[0], re.IGNORECASE):
                compliant = False
                results += ldmover + ' exists, but does not contain text ' + \
                                    '"manual". GUI logon is still enabled\n'
        else:
            compliant = False
            results += ldmover + " does not exist; GUI logon is enabled\n"
        if os.path.exists(grub):
            tmppath = grub + ".tmp"
            data = {"GRUB_CMDLINE_LINUX_DEFAULT": '"quiet"'}
            editor = KVEditorStonix(self.statechglogger, self.logger, "conf",
                                    grub, tmppath, data, "present", "closedeq")
            if not editor.report():
                compliant = False
                results += grub + " does not contain the correct values: " + \
                    str(data)
        else:
            compliant = False
            results += "Cannot find file " + grub
        if not compliant:
            results += "/etc/init does not contain proper override file " + \
                      "for lightdm; GUI logon is enabled\n"
        return compliant, results

    def fix(self):
        '''@author: Eric Ball

        :param self: essential if you override this definition
        :returns: bool - True if fix is successful, False if it isn't

        '''
        try:
            if not self.ci1.getcurrvalue() and not self.ci2.getcurrvalue() \
               and not self.ci3.getcurrvalue():
                return
            success = True
            self.detailedresults = ""
            # Delete past state change records from previous fix
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            # If we are doing DISABLEX or REMOVEX, we want to boot to
            # non-graphical multi-user mode.
            if self.ci1.getcurrvalue() or self.ci3.getcurrvalue():
                success &= self.fixBootMode()

            # Since LOCKDOWNX depends on having X installed, and REMOVEX
            # completely removes X from the system, LOCKDOWNX fix will only be
            # executed if REMOVEX is not.
            if self.ci3.getcurrvalue():
                success &= self.fixRemoveX()
            elif self.ci2.getcurrvalue():
                success &= self.fixLockdownX()

            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixBootMode(self):
        success = True
        if self.initver == "systemd":
            cmd = ["/bin/systemctl", "set-default",
                   "multi-user.target"]
            if not self.ch.executeCommand(cmd):
                success = False
                self.detailedresults += '"systemctl set-default ' \
                    + 'multi-user.target" did not succeed\n'
            else:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                commandstring = "/bin/systemctl set-default " + \
                                "graphical.target"
                event = {"eventtype": "commandstring",
                         "command": commandstring}
                self.statechglogger.recordchgevent(myid, event)

        elif self.initver == "debian":
            dmlist = ["gdm", "gdm3", "lightdm", "xdm", "kdm"]
            for dm in dmlist:
                cmd = ["update-rc.d", "-f", dm, "disable"]
                if not self.ch.executeCommand(cmd):
                    self.detailedresults += "Failed to disable desktop " + \
                        "manager " + dm
                else:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "servicehelper",
                             "servicename": dm,
                             "startstate": "enabled",
                             "endstate": "disabled"}
                    self.statechglogger.recordchgevent(myid, event)

        elif self.initver == "ubuntu":
            ldmover = "/etc/init/lightdm.override"
            tmpfile = ldmover + ".tmp"
            created = False
            if not os.path.exists(ldmover):
                createFile(ldmover, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation", "filepath": ldmover}
                self.statechglogger.recordchgevent(myid, event)
                created = True
            writeFile(tmpfile, "manual\n", self.logger)
            if not created:
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "conf", "filepath": ldmover}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(ldmover, tmpfile, myid)
            os.rename(tmpfile, ldmover)
            resetsecon(ldmover)

            grub = "/etc/default/grub"
            if not os.path.exists(grub):
                createFile(grub, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation", "filepath": grub}
                self.statechglogger.recordchgevent(myid, event)
            tmppath = grub + ".tmp"
            data = {"GRUB_CMDLINE_LINUX_DEFAULT": '"quiet"'}
            editor = KVEditorStonix(self.statechglogger, self.logger,
                                    "conf", grub, tmppath, data,
                                    "present", "closedeq")
            editor.report()
            if editor.fixables:
                if editor.fix():
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    editor.setEventID(myid)
                    debug = "kveditor fix ran successfully\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    if editor.commit():
                        debug = "kveditor commit ran successfully\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    else:
                        error = "kveditor commit did not run " + \
                                "successfully\n"
                        self.logger.log(LogPriority.ERROR, error)
                        success = False
                else:
                    error = "kveditor fix did not run successfully\n"
                    self.logger.log(LogPriority.ERROR, error)
                    success = False
            cmd = "update-grub"
            self.ch.executeCommand(cmd)

        else:
            inittab = "/etc/inittab"
            tmpfile = inittab + ".tmp"
            if os.path.exists(inittab):
                initText = open(inittab, "r").read()
                initre = r"id:\d:initdefault:"
                if re.search(initre, initText):
                    initText = re.sub(initre, "id:3:initdefault:",
                                      initText)
                    writeFile(tmpfile, initText, self.logger)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf", "filepath": inittab}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(inittab,
                                                         tmpfile, myid)
                    os.rename(tmpfile, inittab)
                    resetsecon(inittab)
                else:
                    initText += "\nid:3:initdefault:\n"
                    writeFile(tmpfile, initText, self.logger)
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf", "filepath": inittab}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(inittab,
                                                         tmpfile, myid)
                    os.rename(tmpfile, inittab)
                    resetsecon(inittab)
            else:
                self.detailedresults += inittab + " not found, no other " + \
                    "init system found. If you are using a supported " + \
                    "Linux OS, please report this as a bug\n"
        return success

    def fixRemoveX(self):
        success = True
        # Due to automatic removal of dependent packages, the full
        # removal of X and related packages cannot be undone
        if re.search("opensuse", self.myos):
            cmd = ["zypper", "-n", "rm", "-u", "xorg-x11*", "kde*",
                   "xinit*"]
            self.ch.executeCommand(cmd)
        elif re.search("debian|ubuntu", self.myos):
            xpkgs = ["unity.*", "xserver-xorg-video-ati",
                     "xserver-xorg-input-synaptics",
                     "xserver-xorg-input-wacom", "xserver-xorg-core",
                     "xserver-xorg", "lightdm.*", "libx11-data"]
            for xpkg in xpkgs:
                self.ph.remove(xpkg)
        elif re.search("fedora", self.myos):
            # Fedora does not use the same group packages as other
            # RHEL-based OSs. Removing this package will remove the X
            # Windows system, just less efficiently than using a group
            self.ph.remove("xorg-x11-server-Xorg")
            self.ph.remove("xorg-x11-xinit*")
        else:
            cmd = ["yum", "groups", "mark", "convert"]
            self.ch.executeCommand(cmd)
            self.ph.remove("xorg-x11-xinit")
            self.ph.remove("xorg-x11-server-Xorg")
            cmd2 = ["yum", "groupremove", "-y", "X Window System"]
            if not self.ch.executeCommand(cmd2):
                success = False
                self.detailedresults += '"yum groupremove -y X Window System" command failed\n'
        return success

    def fixLockdownX(self):
        success = True
        if self.sh.disableService("xfs", _="_"):
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype":   "servicehelper",
                     "servicename": "xfs",
                     "startstate":  "enabled",
                     "endstate":    "disabled"}
            self.statechglogger.recordchgevent(myid, event)
        else:
            success = False
            self.detailedresults += "STONIX was unable to disable the " + \
                "xfs service\n"

        if not self.xservSecure:
            serverrcString = "exec X :0 -nolisten tcp $@"
            if not os.path.exists(self.serverrc):
                createFile(self.serverrc, self.logger)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {"eventtype": "creation",
                         "filepath": self.serverrc}
                self.statechglogger.recordchgevent(myid, event)
                writeFile(self.serverrc, serverrcString, self.logger)
            else:
                open(self.serverrc, "a").write(serverrcString)
        return success
