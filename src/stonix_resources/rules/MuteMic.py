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
Created on Jul 7, 2014

This class handles muting the microphone input levels.

@author: dkennel
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2014/12/15 dkennel Fix for Macs with no microphones (and ergo no input)
@change: 2015/04/15 dkennel updated for new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2016/03/14 eball Fixed possible casting error, PEP8 cleanup
@change: 2016/07/19 Breen Malmberg added fixmac() and fixlinux() methods;
altered report() and fix() methods to init variables to defaults
and fix() method to use the new fixmac and fixlinux methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/02/16 bgonz12 - change reportLinux() to ignore an amixer error
that occurs when pulseaudio isn't running
@change 2018/02/20 bgonz12 - change reportLinux() to ignore an amixer error
that occurs when system sound card(s) is missing firmware
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/12/07 dwalker - updated rule with more debugging, more recorded
    state change events, removed overriding of undo method, implemented pre-
    written methods for reading file, writing to file, and creating file.
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''

import traceback
import os
import re
import subprocess

from rule import Rule
from logdispatcher import LogPriority
from stonixutilityfunctions import resetsecon, readFile, writeFile, iterate
from stonixutilityfunctions import checkPerms, setPerms, createFile
from CommandHelper import CommandHelper


class MuteMic(Rule):
    '''This class is responsible for muting the microphone input levels to
    help prevent attacks that would attempt to use the system as a listening
    device.
    
    @author: dkennel
    @change: dwalker 11/6/2018 - Updated rule to only check contents of
            protected files inside /etc/ if uid is 0


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 201
        self.rulename = 'MuteMic'
        self.logger = logger
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.sethelptext()
        self.rootrequired = False
        self.mutemicrophone = self.__initializeMuteMicrophone()
        self.guidance = ['CIS']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        self.root = True
        if self.environ.geteuid() != 0:
            self.root = False
        self.setPaths()

    def __initializeMuteMicrophone(self):
        '''
        Private method to initialize the configurationitem object for the
        MUTEMICROPHONE bool.
        @return: configuration object instance
        @author: dkennel
        '''
        datatype = 'bool'
        key = 'MUTEMICROPHONE'
        instructions = 'If set to yes or true the MUTEMICROPHONE action \
will mute the microphone. This rule should always be set to TRUE with few \
valid exceptions.'
        default = True
        myci = self.initCi(datatype, key, instructions, default)
        return myci

    def report(self):
        '''Report method for MuteMic. Uses the platform native method to read
        the input levels. Levels must be zero to pass. Note for Linux the use
        of amixer presumes pulseaudio.
        
        @author: dkennel
        @change: Breen Malmberg - 07/19/2016 - added variable defaults initialization;
        added commandhelper object self.ch


        '''

        # defaults
        self.compliant = True
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)

        try:

            if self.environ.getosfamily() == 'darwin':
                if not self.reportmac():
                    self.compliant = False
            elif os.path.exists(self.amixer):
                if not self.reportlinux():
                    self.compliant = False
            if os.path.exists(self.pulsedefaults):
                if not self.checkpulseaudio():
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportmac(self):
        '''determine the volume level of the input device on a mac


        :returns: retval

        :rtype: bool
@author: Breen Malmberg

        '''

        retval = True
        command = "/usr/bin/osascript -e 'get the input volume of (get volume settings)'"

        try:

            self.ch.executeCommand(command)
            output = self.ch.getOutputString()
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                retval = False
                errmsg = self.ch.getErrorString()
                self.detailedresults += "Error while running command: " + str(command) + " :\n" + str(errmsg) + "\n"
            if re.search("[1-9]+", output.strip(), re.IGNORECASE):
                retval = False
                self.detailedresults += "The microphone is not muted\n"

        except Exception:
            raise
        return retval

    def reportlinux(self):
        '''determine the volume level and mute status of all mic's
        and capture devices, using linux-specific mechanisms and
        commands/paths


        :returns: retval

        :rtype: bool
@author: Breen Malmberg
@change: dwalker 11/6/2018 - Updated rule to only check contents of
    protected files inside /etc/ if uid is 0

        '''
        debug = ""
        retval = True
        getc0Controls = self.amixer + " -c 0 scontrols"
        getgenCap = self.amixer + " sget 'Capture'"
        miccontrols = []
        micbcontrols = []
        c0Capcontrols = []

        try:
            if self.soundDeviceExists():
                self.ch.executeCommand(getc0Controls)
                output = self.ch.getOutput()
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    retval = False
                    errmsg = self.ch.getErrorString()
                    self.detailedresults += "\nError while running command: " + str(getc0Controls) + " :\n" + str(errmsg)
                    debug = getc0Controls + " command returned " + str(retcode) + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                for line in output:
                    if re.search("^Simple\s+mixer\s+control\s+\'.*Mic\'", line, re.IGNORECASE):
                        sline = line.split("'")
                        miccontrols.append("'" + str(sline[1]) + "'")
                    elif re.search("^Simple\s+mixer\s+control\s+\'.*Mic\s+Boost.*\'", line, re.IGNORECASE):
                        sline = line.split("'")
                        micbcontrols.append("'" + str(sline[1]) + "'")
                    elif re.search("^Simple\s+mixer\s+control\s+\'.*Capture.*\'", line, re.IGNORECASE):
                        sline = line.split("'")
                        c0Capcontrols.append("'" + str(sline[1]) + "'")
                for mc in miccontrols:
                    getc0mic = self.amixer + " -c 0 sget " + mc
                    self.ch.executeCommand(getc0mic)
                    output = self.ch.getOutput()
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        retval = False
                        errmsg = self.ch.getErrorString()
                        self.detailedresults += "Error while running command: " + str(getc0mic) + " :\n" + str(errmsg) + "\n"
                        debug = getc0mic + " command returned " + str(retcode) + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    for line in output:
                        if re.search("\[[0-9]+\%\]", line, re.IGNORECASE):
                            if not re.search("\[0\%\]", line, re.IGNORECASE):
                                retval = False
                                self.detailedresults += "The microphone labeled: " + str(mc) + " does not have its volume level set to 0"
                                debug = "Didn't find 0% level for " + line + "\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                for mcb in micbcontrols:
                    getc0micb = self.amixer + " -c 0 sget " + mcb
                    self.ch.executeCommand(getc0micb)
                    output = self.ch.getOutput()
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        retval = False
                        errmsg = self.ch.getErrorString()
                        self.detailedresults += "Error while running command: " + str(getc0micb) + " :\n" + str(errmsg) + "\n"
                        debug = getc0micb + " command returned " + str(retcode) + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    for line in output:
                        if re.search("\[[0-9]+\%\]", line, re.IGNORECASE):
                            if not re.search("\[0\%\]", line, re.IGNORECASE):
                                retval = False
                                self.detailedresults += "The microphone boost labeled: " + str(mcb) + " does not have its volume level set to 0\n"
                                debug = "The microphone boost labeled: " + str(mcb) + " does not have its volume level set to 0\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                        elif re.search("\[on\]|\[off\]", line, re.IGNORECASE):
                            if not re.search("\[off\]", line, re.IGNORECASE):
                                retval = False
                                self.detailedresults += "The microphone boost labeled: " + str(mcb) + " is not turned off\n"
                                debug = "The microphone boost labeled: " + str(mcb) + " is not turned off\n"
                                self.logger.log(LogPriority.DEBUG, debug)
    
                for cap in c0Capcontrols:
                    getc0Cap = self.amixer + " -c 0 sget " + cap
                    self.ch.executeCommand(getc0Cap)
                    output = self.ch.getOutput()
                    retcode = self.ch.getReturnCode()
                    if retcode != 0:
                        retval = False
                        errmsg = self.ch.getErrorString()
                        self.detailedresults += "Error while running command: " + str(getc0Cap) + " :\n" + str(errmsg) + "\n"
                        debug = getc0Cap + " command returned " + str(retcode) + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                    for line in output:
                        if re.search("\[[0-9]+\%\]", line, re.IGNORECASE):
                            if not re.search("\[0\%\]", line, re.IGNORECASE):
                                retval = False
                                self.detailedresults += "Capture control labeled: " + str(cap) + " does not have its volume level set to 0\n"
                                debug = "Capture control labeled: " + str(cap) + " does not have its volume level set to 0\n"
                                self.logger.log(LogPriority.DEBUG, debug)
                                break
                    for line in output:
                        if re.search("\[on\]", line, re.IGNORECASE):
                            retval = False
                            self.detailedresults += "Capture control labeled: " + str(cap) + " is not turned off\n"
                            debug = "Capture control labeled: " + str(cap) + " is not turned off\n"
                            self.logger.log(LogPriority.DEBUG, debug)
                            break
            else:
                self.logger.log(LogPriority.DEBUG, "No capture hardware devices found")
            

            self.ch.executeCommand(getgenCap)
            output = self.ch.getOutput()
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                errmsg = self.ch.getErrorString()
                # if the control does not exist, then there is no problem:
                # we can't mute/unmute/use a non-existent control
                errignore0 = "Unable to find simple control"
                # if pulseaudio isn't running, then there is no problem:
                # the system is likely running in headless mode
                errignore1 = "PulseAudio: Unable to connect: Connection refused"
                # if amixer unable to access devices, then there is no problem
                # capture control devices are likely missing firmware
                errignore2 = "amixer: Mixer attach default error: No such file or directory"
                if not re.search(errignore0, errmsg, re.IGNORECASE) and \
                   not re.search(errignore1, errmsg, re.IGNORECASE) and \
                   not re.search(errignore2, errmsg, re.IGNORECASE):
                    retval = False
                    self.detailedresults += "Error while running command: " + str(getgenCap) + " :\n" + str(errmsg) + "\n"
                    debug = "Error while running command: " + str(getgenCap) + " :\n" + str(errmsg) + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
            for line in output:
                if re.search("\[[0-9]+\%\]", line, re.IGNORECASE):
                    if not re.search("\[0\%\]", line, re.IGNORECASE):
                        retval = False
                        self.detailedresults += "Generic Capture control does not have its volume level set to 0\n"
                        debug = "Generic Capture control does not have its volume level set to 0\n"
                        self.logger.log(LogPriority.DEBUG, debug)
            for line in output:
                if re.search("\[on\]", line, re.IGNORECASE):
                    retval = False
                    self.detailedresults += "Generic Capture control is not turned off\n"
                    debug = "Generic Capture control is not turned off\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    break

            systype = self.getSysType()
            if systype == "systemd":
                if not os.path.exists(self.systemdscriptname):
                    self.detailedresults += "The startup script to mute mics was not found\n"
                    debug = "The startup script to mute mics was not found\n"
                    if not self.root:
                        self.detailedresults += "This is ok as a regular user but needs " + \
                            "to be fixed while running this rule and stonix in root context\n"
                    else:
                        retval = False
                    self.logger.log(LogPriority.DEBUG, debug)
            if systype == "sysvinit":
                if os.path.exists(self.sysvscriptname):
                    contents = readFile(self.sysvscriptname, self.logger)
                    found = False
                    for line in contents:
                        if re.search("amixer", line, re.IGNORECASE):
                            found = True
                    if not found:
                        self.detailedresults += "System not configured to mute mics on startup.\n"
                        if not self.root:
                            self.detailedresults += "This is ok as a regular user but needs " + \
                            "to be fixed while running this rule and stonix in root context\n"
                        else:
                            retval = False
                        

        except Exception:
            raise
        return retval

    def fix(self):
        '''Fix method for MuteMic. Uses platform native methods to set the input
        levels to zero. Note for Linux the use of amixer presumes pulseaudio.


        :returns: self.rulesuccess

        :rtype: bool
@author: dkennel
@change: Breen Malmberg - 07/19/2016 - fixed comment block; init return
value to default and self.detailedresults as well; commands now run
through commandhelper object: self.ch; wrapped entire method in try/except;
added more debugging output

        '''

        # defaults
        self.detailedresults = ""
        success = True

        try:

            if not self.root:
                self.detailedresults += "You are not running STONIX with elevated privileges. Some fix functionality will be disabled for this rule.\n"

            # if the CI is disabled, then don't run the fix
            if not self.mutemicrophone.getcurrvalue():
                self.logger.log(LogPriority.DEBUG, "MUTEMICROPHONE CI was not enabled so nothing will be done!\n\n\n")
                return
            self.iditerator = 0
            self.logger.log(LogPriority.DEBUG, "Attempting to mute all mic's and capture sources...")
            if self.environ.getosfamily() == 'darwin':
                if not self.fixmac():
                    success = False

            if os.path.exists('/usr/bin/amixer'):
                if not self.fixlinux():
                    success = False

            if os.path.exists(self.pulsedefaults) and self.environ.geteuid() == 0:
                if not self.fixPulseAudio():
                    success = False

            self.logger.log(LogPriority.DEBUG, "Finished muting all mic's and capture sources")

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        return success

    def fixmac(self):
        '''run commands to turn off microphones on mac


        :returns: retval

        :rtype: bool
@author: Breen Malmberg

        '''

        # defaults
        retval = True
        command = "/usr/bin/osascript -e 'set volume input volume 0'"
        undocmd = "/usr/bin/osascript -e 'set volume input volume 100'"

        self.logger.log(LogPriority.DEBUG, "System detected as: darwin. Running fixmac()...")

        try:

            self.ch.executeCommand(command)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                retval = False
                errmsg = self.ch.getErrorString()
                self.detailedresults += "Error while running command: " + \
                    str(command) + " :\n" + str(errmsg) + "\n"
                self.logger.log(LogPriority.DEBUG, self.detailedresults)
            else:
                if self.root:
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "commandstring",
                             "command": undocmd}
                    self.statechglogger.recordchgevent(myid, event)
        except Exception:
            raise
        return retval

    def fixlinux(self):
        '''run commands to turn off microphones on linux


        :returns: retval

        :rtype: bool
@author: Breen Malmberg

        '''

        retval = True

        self.systemdcomment = ["# Added by STONIX\n\n"]
        self.systemdunit = ["[Unit]\n", "Description=Mute Mic at system boot\n", "After=basic.target\n\n"]
        self.systemdservice = ["[Service]\n", "Type=oneshot\n"]
        self.systemdinstall = ["\n[Install]\n", "WantedBy=basic.target\n"]
        self.sysvscriptcmds = []
        self.systemdscript = []
        debug = "\n\nSystem detected as: linux. Running fixlinux()...\n\n"
        self.logger.log(LogPriority.DEBUG, debug)

        try:

            devices = self.getDevices()
            debug = "Number of devices on this system is: " + \
                str(len(devices)) + "\n"
            self.logger.log(LogPriority.DEBUG, debug)

            if not devices:
                mics = self.getMics("0")
                for m in mics:
                    mutemiccmd = self.amixer + " -c 0 sset " + m + " 0% nocap mute off"
                    self.systemdservice.append("ExecStart=" + str(mutemiccmd) + "\n")
                    self.sysvscriptcmds.append(str(mutemiccmd) + "\n")
                    self.ch.executeCommand(mutemiccmd)
                mutecapturecmd = self.amixer + " -c 0 sset 'Capture' 0% mute off"
                self.ch.executeCommand(mutecapturecmd)
                self.systemdservice.append("ExecStart=" + str(mutecapturecmd) + "\n")
                self.sysvscriptcmds.append(str(mutecapturecmd) + "\n")

            else:
                for di in devices:
                    mics = self.getMics(di)
                    debug = "Number of mic's on device index " + \
                        str(di) + " is " + str(len(mics)) + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    for m in mics:
                        mutemiccmd = self.amixer + " -c " + di + " sset " + m + " 0% nocap mute off"
                        self.systemdservice.append("ExecStart=" + str(mutemiccmd) + "\n")
                        self.sysvscriptcmds.append(str(mutemiccmd) + "\n")
                        self.ch.executeCommand(mutemiccmd)
                    mutecapturecmd = self.amixer + " -c " + di + " sset 'Capture' 0% mute off"
                    self.ch.executeCommand(mutecapturecmd)
                    self.systemdservice.append("ExecStart=" + str(mutecapturecmd) + "\n")
                    self.sysvscriptcmds.append(str(mutecapturecmd) + "\n")

            # get card 0 Capture control info
            # this is separate from the general Capture
            self.ch.executeCommand(self.amixer + " -c 0 sget Capture")
            output = self.ch.getOutput()
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                retval = False
                errmsg = self.ch.getErrorString()
                self.detailedresults += "Error while running command: " + \
                    str(self.amixer + " -c 0 sget Capture") + " :\n" + \
                    str(errmsg) + "\n"
                debug = "Error while running command: " + \
                    str(self.amixer + " -c 0 sget Capture") + " :\n" + \
                    str(errmsg) + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
            for line in output:
                # toggle the c0 Capture control off (mute it)
                if re.search("\[on\]", line, re.IGNORECASE):
                    self.ch.executeCommand(self.amixer + " -c 0 sset Capture toggle")
                    retcodeB = self.ch.getReturnCode()
                    if retcodeB != 0:
                        retval = False
                        errmsg = self.ch.getErrorString()
                        debug = "Error while running command: " + \
                            str(self.amixer +  " -c 0 sset Capture toggle") + \
                            " :\n" + str(errmsg) + "\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        self.detailedresults += "Error while running command: " + \
                            str(self.amixer +  " -c 0 sset Capture toggle") + \
                            " :\n" + str(errmsg) + "\n"
                    else:
                        if self.root:
                            undocmd = self.amixer + " -c 0 sset Capture toggle"
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "commandstring",
                                     "command": undocmd}
                            self.statechglogger.recordchgevent(myid, event)
                    # again, we don't want to toggle more than once
                    break

            # set card 0 Capture volume to 0
            self.ch.executeCommand(self.amixer + " -c 0 sset Capture 0")
            self.systemdservice.append("ExecStart=" + self.amixer + " -c 0 sset Capture 0\n")
            self.sysvscriptcmds.append(self.amixer + " -c 0 sset Capture 0\n")
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                retval = False
                errmsg = self.ch.getErrorString()
                debug = "Error while running command: " + \
                    str(self.amixer + " -c 0 sset Capture 0") + \
                    " :\n" + str(errmsg)
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "Error while running command: " + \
                    str(self.amixer + " -c 0 sset Capture 0") + \
                    " :\n" + str(errmsg) + "\n"
            else:
                if self.root:
                    undocmd = self.amixer + " -c 0 sset Capture 100"
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "commandstring",
                             "command": undocmd}
                    self.statechglogger.recordchgevent(myid, event)
            setGenCap = self.amixer + " sset 'Capture' 0% nocap off mute"
            self.systemdservice.append("ExecStart=" + str(setGenCap) + "\n")
            self.sysvscriptcmds.append(setGenCap)
            self.ch.executeCommand(setGenCap)
            retcode = self.ch.getReturnCode()
            if retcode != 0:
                retval = False
                errmsg = self.ch.getErrorString()
                debug = "Error while running command: " + \
                    str(setGenCap) + " :\n" + str(errmsg) + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "Error while running command: " + \
                    str(setGenCap) + " :\n" + str(errmsg) + "\n"
            else:
                if self.root:
                    undocmd = self.amixer + ' sset Capture Volume 65536,65536 unmute'
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "commandstring",
                             "command": undocmd}
                    self.statechglogger.recordchgevent(myid, event)
            if self.root:
                systype = self.getSysType()
                script = self.buildScript(systype)
                if script:
                    self.finishScript(systype, script)
                
        except Exception:
            raise
        return retval

    def setPaths(self):
        '''determine the correct paths for each utility,
        based on the current OS distro


        :returns: void
        @author: Breen Malmberg

        '''

        sysvinitscripts = ["/etc/rc.d/rc.local", "/etc/rc.local"]
        self.sysvscriptname = ""
        for loc in sysvinitscripts:
            if os.path.exists(loc):
                self.sysvscriptname = loc

        self.pulsedefaults = "/etc/pulse/default.pa"
        self.amixer = "/usr/bin/amixer"
        self.systemctl = "/usr/bin/systemctl"
        self.systemdbase = "/usr/lib/systemd/system/"
        self.systemdscriptname = self.systemdbase + "stonix-mute-mic.service"
        self.systemdscriptname = "/usr/lib/systemd/system/stonix-mute-mic.service"

    def soundDeviceExists(self):
        '''This method is only meant to be used on linux systems
        This method is used to determine the presence of any
        sound devices on the current system. Return True if
        any are found. Return False if none are found.


        :returns: sdevicefound

        :rtype: bool
@author: Breen Malmberg

        '''

        sdevicefound = False
        procdir = "/proc/asound/cards"
        proccheck = "/usr/bin/cat " + procdir
        procRE = "^[0-9]"
        arecorddir = "/usr/bin/arecord"
        arecordcheck = arecorddir + " -l"
        arecordRE = "^card\s+[0-9]"
        debug = ""

        try:
            if not os.path.exists(procdir):
                debug = "Sound device directory within /proc does not exist."
                self.logger.log(LogPriority.DEBUG, debug)
            else:
                self.ch.executeCommand(proccheck)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    debug = "Command Failed: " + str(proccheck) + \
                        " with return code: " + str(retcode) + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                outputlines = self.ch.getOutput()
                if outputlines:
                    for line in outputlines:
                        if re.search(procRE, line, re.IGNORECASE):
                            sdevicefound = True
                            
            if not os.path.exists(arecorddir):
                debug = "/usr/bin/arecord command not found on this system.\n"
                self.logger.log(LogPriority.DEBUG, debug)
            else:
                self.ch.executeCommand(arecordcheck)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    debug = "Command Failed: " + str(arecordcheck) + \
                        " with return code: " + str(retcode) + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                outputlines = self.ch.getOutput()
                if outputlines:
                    for line in outputlines:
                        if re.search(arecordRE, line, re.IGNORECASE):
                            sdevicefound = True
    
            if sdevicefound:
                debug = "Sound device found on this system... Proceeding to configure it."
                self.logger.log(LogPriority.DEBUG, debug)
            else:
                debug = "No sound devices found on this system.\n"
                self.logger.log(LogPriority.DEBUG, debug)
        except Exception:
            raise
        return sdevicefound

    def findPulseMic(self):
        '''This method will attempt to determine the indexes of the sources that
        contain microphone inputs. It will return a list of strings that are
        index numbers. It is legal for the list to be of zero length in the
        cases where pulse is not running or there are no sources with
        microphones.
        
        @author: dkennel


        :returns: list of numbers in string format

        '''
        indexlist = []
        index = ''
        listcmd = '/usr/bin/pacmd list-sources'
        proc = subprocess.Popen(listcmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)
        pulsesourcelist = proc.stdout.readlines()
        for line in pulsesourcelist:
            if re.search('index:', line):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['MuteMic.findPulseMic',
                                      'Scanning ' + line])
                try:
                    elements = line.split(' ')
                    for element in elements:
                        if re.search('\d', element):
                            index = int(element)
                except (KeyboardInterrupt, SystemExit):
                    # User initiated exit
                    raise
                except ValueError:
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['MuteMic.findPulseMic',
                                          'Oops! Tried to convert non-integer '
                                          + element])
            if re.search('input-microphone', line):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['MuteMic.findPulseMic',
                                      'Found mic at index ' + str(index)])
                index = str(index)
                if index not in indexlist:
                    indexlist.append(index)
        return indexlist

    def checkpulseaudio(self):
        '''Report method for checking the pulse audio configuration to ensure that
        the Microphone defaults to muted. Returns True if the system is
        compliant
        
        @author: dkennel


        :returns: Bool

        '''
        linesfound = 0
        if not os.path.exists(self.pulsedefaults):
            return True
        debug = "Performing checkpulseaudio method\n"
        self.logger.log(LogPriority.DEBUG, debug)
        expectedlines = []
        try:
            debug = ""
            indexlist = self.findPulseMic()
            debug = "Mic devices list: " + str(indexlist) + "\n"
            self.logger.log(LogPriority.DEBUG, debug)
            if len(indexlist) > 0:
                for index in indexlist:
                    line = 'set-source-mute ' + index + ' 1\n'
                    expectedlines.append(line)
                debug = "lines expected to be found in " + \
                    self.pulsedefaults + ":\n"
                debug += str(expectedlines) + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                defaultsdata = readFile(self.pulsedefaults, self.logger)
                for eline in expectedlines:
                    for pulseline in defaultsdata:
                        if re.search(eline, pulseline):
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 ['MuteMic.findPulseMic',
                                                  'Found expected line ' +
                                                  str(pulseline)])
                            linesfound = linesfound + 1
                if linesfound == len(indexlist):
                    return True
                else:
                    debug = "Didn't find all the expected lines inside " + \
                        self.pulsedefaults + "\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    self.detailedresults += "Didn't find all the expected lines inside " + \
                        self.pulsedefaults + "\n"
                    if self.environ.geteuid() != 0:
                        self.detailedresults += "This is ok as a regular user but needs " + \
                            "to be fixed while running this rule and stonix in root context\n"
                        return True
                    else:
                        return False
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults += "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        return True

    def fixPulseAudio(self):
        '''This method adds lines to the end of the pulse audio services default
        settings definitions file to ensure that the microphones are muted by
        default.


        :returns: retval

        :rtype: bool
@author: dkennel
@change: Breen Malmberg - 07/19/2016 - fixed comment block; init default return
param value, retval; made sure method always returns something
@change: Breen Malmberg - 2/15/2017 - made sure method does not run if the rule is
        being run in user mode, because the method writes to a location which requires
        root privileges

        '''

        retval = True

        if not os.path.exists(self.pulsedefaults):
            return retval

        if self.checkpulseaudio():
            return retval

        expectedlines = []

        if not self.root:
            self.detailedresults += "You are currently running this rule " + \
                "as an unprivileged user. This rule requires root " + \
                "privileges to configure pulse audio.\n"
            return

        try:

            indexlist = self.findPulseMic()

            if len(indexlist) > 0:
                for index in indexlist:
                    line = 'set-source-mute ' + index + ' 1\n'
                    expectedlines.append(line)

                defaultsdata = readFile(self.pulsedefaults, self.logger)
                for eline in expectedlines:
                    elinefound = False
                    for pulseline in defaultsdata:
                        if re.search(eline, pulseline):
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 ['fixPulseAudio',
                                                  'Found expected line ' +
                                                  str(pulseline)])
                            elinefound = True
                    if not elinefound:
                        defaultsdata.append(eline)
                        self.logdispatch.log(LogPriority.DEBUG,
                                             ['fixPulseAudio',
                                              'Appended line ' + str(eline)])
                tempstring = ""
                for line in defaultsdata:
                    tempstring += line
                tempfile = self.pulsedefaults + '.tmp'
                if writeFile(tempfile, tempstring, self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": self.pulsedefaults}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.pulsedefaults,
                                                     tempfile, myid)
                    os.rename(tempfile, self.pulsedefaults)
                    if setPerms(self.pulsedefaults, [0, 0, 0o420]):
                        resetsecon(self.pulsedefaults)
                    else:
                        self.detailedresults += "Unable to set permissions " + \
                            "on " + self.pulsedefaults + "file\n"
                        debug = "Unable to set permissions " + \
                            "on " + self.pulsedefaults + "file\n"
                        self.logger.log(LogPriority.DEBUG, debug)
                        retval = False
                else:
                    self.detailedresults += "Unable to write contents to " + \
                        self.pulsedefaults + " file\n"
                    debug = "Unable to write contents to " + \
                        self.pulsedefaults + " file\n"
                    self.logger.log(LogPriority.DEBUG, debug)
                    retval = False

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            retval = False
            self.detailedresults += "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        return retval

    def getDevices(self):
        '''retrieve a list of device indexes


        :returns: indexes

        :rtype: list
@author: Breen Malmberg

        '''

        indexes = []

        cmd = "/usr/bin/pacmd list-sinks"
        debug = ""
        try:

            self.ch.executeCommand(cmd)
            retcode = self.ch.getReturnCode()
            output = self.ch.getOutput()
            if retcode != 0:
                errmsg = self.ch.getErrorString()
                debug = "Error while running command: " + \
                    str(cmd) + " :\n" + str(errmsg) + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "Error while running command: " + \
                    str(cmd) + " :\n" + str(errmsg) + "\n"
                return indexes
            for line in output:
                if re.search("index\:", line, re.IGNORECASE):
                    sline = line.split(":")
                    indexes.append(str(sline[1]).strip())

        except Exception:
            raise
        if not indexes:
            self.logger.log(LogPriority.DEBUG,
                            "Returning a blank list for indexes!")
        return indexes

    def getMics(self, index):
        '''return a list of simple mixer control mics for the
        specified device index

        :param index: 
        :returns: mics
        :rtype: list
@author: Breen Malmberg

        '''

        mics = []
        cmd = self.amixer + " -c " + index + " scontrols"
        debug = ""
        try:

            self.ch.executeCommand(cmd)
            retcode = self.ch.getReturnCode()
            output = self.ch.getOutput()
            if retcode != 0:
                errmsg = self.ch.getErrorString()
                debug = "Error while running command: " + \
                    str(cmd) + " :\n" + str(errmsg) + "\n"
                self.logger.log(LogPriority.DEBUG, debug)
                self.detailedresults += "Error while running command: " + \
                    str(cmd) + " :\n" + str(errmsg) + "\n"
            for line in output:
                if re.search("^Simple\s+mixer\s+control\s+\'.*Mic\'",
                             line, re.IGNORECASE):
                    sline = line.split("'")
                    mics.append("'" + str(sline[1]).strip() + "'")
        except Exception:
            raise
        if not mics:
            self.logger.log(LogPriority.DEBUG,
                            "Returning a blank list for mics!")
        return mics

    def buildScript(self, systype):
        '''dynamically build the boot up script and return
        a list of the lines to be written

        :param systype: 
        :returns: script
        :rtype: list
@author: Breen Malmberg

        '''

        script = []
        exitcodefound = False

        try:

            if systype == "systemd":
                # create the systemdservice script
                for item in self.systemdcomment:
                    script.append(item)
                for item in self.systemdunit:
                    script.append(item)
                for item in self.systemdservice:
                    script.append(item)
                for item in self.systemdinstall:
                    script.append(item)
            if systype == "sysvinit":

                # if the script already exists, put the
                # existing contents at the beginning
                contents = readFile(self.sysvscriptname, self.logger)
                if contents:
                    for line in contents:
                        if re.search("^exit \0", line, re.IGNORECASE):
                            exitcodefound = True
                            contents = [c.replace(line, "") for c in contents]
    
                    for line in contents:
                        script.append(line)
                    script.append("\n")
                    for line in self.sysvscriptcmds:
                        script.append(line)
                    if exitcodefound:
                        script.append("\nexit 0")

        except Exception:
            raise
        return script

    def getSysType(self):
        '''determine whether the os type is
        systemd-based or sysvinit-based


        :returns: systype

        :rtype: string
@author: Breen Malmberg

        '''

        # determine if os is systemd-based or sysvinit
        systemd = False
        sysvinit = False
        checkbasecmd = "pidof systemd && echo 'systemd' || echo 'sysvinit'"
        systype = ""
        debug = ""

        try:

            self.logger.log(LogPriority.DEBUG, 
                            "Detecting whether OS is systemd or sysvinit based...")
            self.ch.executeCommand(checkbasecmd)
            retcode = self.ch.getReturnCode()
            output = self.ch.getOutput()
    
            if retcode != 0:
                errmsg = self.ch.getErrorString()
                self.detailedresults += "Error while running command: " + \
                    str(checkbasecmd) + " :\n" + str(errmsg) + "\n"
            debug = str(output) + ""
            for line in output:
                if re.search("systemd", line, re.IGNORECASE):
                    systemd = True
                    self.logger.log(LogPriority.DEBUG,
                                    "OS detected as systemd based")
                if re.search("sysvinit", line, re.IGNORECASE):
                    sysvinit = True
                    self.logger.log(LogPriority.DEBUG,
                                    "OS detected as sysvinit based")
            if not systemd and not sysvinit:
                debug = "\nDid not detect either systemd or sysvinit in output\n"
                self.logger.log(LogPriority.DEBUG, debug)
            if systemd:
                systype = "systemd"
            if sysvinit:
                systype = "sysvinit"
        except Exception:
            raise
        return systype

    def finishScript(self, systype, script):
        '''write the script to disk and run any
        final needed command(s)

        :param systype: 
        :param script: 
        :returns: void
        @author: Breen Malmberg

        '''
        retval = True
        if not self.root:
            self.detailedresults += "You are currently running this rule " + \
                "as an unprivileged user. This rule requires root " + \
                "privileges to create the startup script.\nWithout the " + \
                "startup script, the mic(s) will not be disabled at boot " + \
                "time, or upon reboot.\n"
            return retval
        
        try:
            created1, created2 = False, False
            if systype == "systemd":
                tempfile = self.systemdscriptname + ".stonixtmp"
                # make sure the base directory exists
                # before we attempt to write a file to it
                if not os.path.exists(self.systemdbase):
                    os.makedirs(self.systemdbase, 0o755)
                #if file doesn't exist, create it and record creation event
                if not os.path.exists(self.systemdscriptname):
                    if not createFile(self.systemdscriptname, self.logger):
                        retval = False
                        self.detailedresults += "Unable to create " + \
                            self.systemdscriptname + " file\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": self.systemdscriptname}
                        self.statechglogger.recordchgevent(myid, event)
                        created1 = True
                #otherwise check permissions, if incorrect, record perm event
                elif not checkPerms(self.systemdscriptname, [0, 0, 0o644],
                                    self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.systemdscriptname, [0, 0, 0o644],
                                    self.logger, self.statechglogger, myid):
                        self.detailedresults += "Unable to set permissions " + \
                            "on " + self.systemdscriptname + "\n"
                        retval = False
                #file should now exist unless there were problems creating it
                if os.path.exists(self.systemdscriptname):
                    tempstring = ""
                    for line in script:
                        tempstring += line
                    #write the script contents to the file
                    if writeFile(tempfile, tempstring, self.logger):
                        if not created1:
                            #if file was created then undo deletes it
                            #otherwise we record the event for the file write
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "conf",
                                     "filepath": self.systemdscriptname}
                            self.statechglogger.recordchgevent(myid, event)
                            self.statechglogger.recordfilechange(self.systemdscriptname,
                                                                 tempfile,
                                                                 myid)
                        os.rename(tempfile, self.systemdscriptname)
                        #do another setPerms call but without the state logger
                        #since we recorded the event earlier if necessary
                        if not setPerms(self.systemdscriptname, [0, 0, 0o644],
                                        self.logger):
                            self.detailedresults += "Unable to set permissions " + \
                            "on " + self.systemdscriptname + "\n"
                            retval = False
                        resetsecon(self.systemdscriptname)
                    else:
                        retval = False
                        self.detailedresults += "Unable to write contents " + \
                            "to " + self.systemdscriptname + "\n"
                else:
                    self.detailedresults += self.systemdscriptname + \
                        "doesn't exist\n"
                    retval = False
        
                # tell systemd to pull in the script unit
                # when starting its target
                enablescript = self.systemctl + " enable " + self.systemdscriptname
                self.ch.executeCommand(enablescript)
                retcode = self.ch.getReturnCode()
                if retcode != 0:
                    errmsg = self.ch.getErrorString()
                    self.detailedresults += "Error while running command: " + \
                        str(enablescript) + " :\n" + str(errmsg) + "\n"
                    retval = False
            #doing essentially the exact same thing we did above for systemd
            if systype == "sysvinit":
    
                tempfile = self.sysvscriptname + ".stonixtmp"
                if not os.path.exists(self.sysvscriptname):
                    if not createFile(self.sysvscriptname, self.logger):
                        retval = False
                        self.detailedresults += "Unable to create " + \
                            self.sysvscriptname + " file\n"
                    else:
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "creation",
                                 "filepath": self.sysvscriptname}
                        self.statechglogger.recordchgevent(myid, event)
                        created2 = True
                elif not checkPerms(self.sysvscriptname, [0, 0, 0o644],
                                    self.logger):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    if not setPerms(self.sysvscriptname, [0, 0, 0o644],
                                    self.logger, self.statechglogger, myid):
                        self.detailedresults += "Unable to set permissions " + \
                            "on " + self.sysvscriptname + "\n"
                        retval = False
                if os.path.exists(self.sysvscriptname):
                    tempstring = ""
                    for line in script:
                        tempstring += line
                    if writeFile(tempfile, tempstring, self.logger):
                        if not created2:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "conf",
                                     "filepath": self.sysvscriptname}
                            self.statechglogger.recordchgevent(myid, event)
                            self.statechglogger.recordfilechange(self.sysvscriptname,
                                                                 tempfile,
                                                                 myid)
                        os.rename(tempfile, self.sysvscriptname)
                        if not setPerms(self.sysvscriptname, [0, 0, 0o755],
                                        self.logger):
                            self.detailedresults += "Unable to set permissions " + \
                            "on " + self.sysvscriptname + "\n"
                            retval = False
                        resetsecon(self.sysvscriptname)
                    else:
                        retval = False
                        self.detailedresults += "Unable to write contents " + \
                            "to " + self.sysvscriptname + "\n"
                else:
                    self.detailedresults += self.sysvscriptname + \
                        "doesn't exist\n"
                    retval = False
            return retval
        except Exception:
            raise