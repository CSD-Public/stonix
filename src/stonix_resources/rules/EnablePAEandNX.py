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
Created on May 2, 2016

Install PAE Kernel on Supported 32-bit x86 Systems. If the system is 32-bit and also supports the PAE
and NX features, the kernel-PAE package should be installed to enable XD or NX support.

@author: Breen Malmberg
@change: 2017/08/28 Breen Malmberg Fixing to use new help text methods
'''


from ..rule import Rule
from ..CommandHelper import CommandHelper
from ..pkghelper import Pkghelper
from ..logdispatcher import LogPriority

import re
import os
import traceback


class EnablePAEandNX(Rule):
    '''Install PAE Kernel on Supported 32-bit x86 Systems. If the system is 32-bit and also supports the PAE
    and NX features, the kernel-PAE package should be installed to enable XD or NX support.


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        # set up constructor and class variables
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.logger = logger
        self.environ = environ
        self.statechglogger = statechglogger
        self.rulenumber = 87
        self.rulename = "EnablePAEandNX"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.rootrequired = True
        self.guidance = ["CCE-RHEL7-CCE-TBD 2.2.4.4.1"]
        self.sethelptext()
        self.applicable = {'type': 'white',
                           'family': 'linux'}

        # set up CI
        datatype = "bool"
        key = "ENABLEPAEANDNX"
        instructions = "If you want to prevent this rule from running, set the value of EnablePAEandNX to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.initobjs()

    def initobjs(self):
        '''initialize helper objects
        @author: Breen Malmberg


        '''

        self.ch = CommandHelper(self.logger)
        self.pkg = Pkghelper(self.logger, self.environ)

    def report(self):
        '''Run report actions for EnablePAEandNX


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        # set default variables for this method
        systemOS = ""
        systemARCH = 0
        self.detailedresults = ""
        self.compliant = True
        self.package = ""

        try:

            # get value of other variables to be used in this method
            systemOS = self.getSystemOS()
            systemARCH = self.getSystemARCH()
            self.package = self.getSysPackage(systemOS)

            # check if required utility exists; log warning if not
            if not os.path.exists("/proc/cpuinfo"):
                self.logger.log(LogPriority.WARNING, "Unable to verify presence of required system utility /proc/cpuinfo")

            # check for presence of pae cpu flag as well as pae kernel package
            if not self.checkPAE(self.package):
                self.compliant = False

            # check for presence of nx cpu flag
            if not self.checkNX():
                self.compliant = False

            # if system architecture is not 32-bit, disregard previous; inform user
            if systemARCH == 64:
                self.compliant = True
                self.detailedresults = "This system is 64-bit and this rule only applies to 32-bit systems."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        return self.compliant

    def getSystemOS(self):
        '''return the name of the OS


        :returns: osname

        :rtype: string
@author: Breen Malmberg

        '''

        return self.environ.getostype()

    def getSystemARCH(self):
        '''return the architecture of the system (32 or 64 bit)


        :returns: sysARCH

        :rtype: int
@author: Breen Malmberg

        '''

        # set default variables for this method
        sysARCH = 0
        command = ["uname", "-a"]

        try:

            self.ch.executeCommand(command)
            output = self.ch.getOutput()

            # check if the system is 64-bit or not
            for line in output:
                if re.search("x86_64", line):
                    sysARCH = 64

            # if x86_64 flag not found, set system arch as 32-bit
            if sysARCH == 0:
                sysARCH = 32

        except Exception:
            raise

        return sysARCH

    def getSysPackage(self, systemos):
        '''return name of pae kernel package for this specific OS

        :param systemos: string The name of the system's operating system
        @author: Breen Malmberg
        :returns: packagename
        :rtype: string

        '''

        packagename = ""

        self.logger.log(LogPriority.DEBUG, "Getting system-specific package name...")

        if not systemos:
            self.logger.log(LogPriority.DEBUG, "Required parameter: systemos was passed as blank")
        if not isinstance(systemos, str):
            self.logger.log(LogPriority.DEBUG, "Required parameter: systemos was passed as incorrect data type. Required data type: string")
        else:
            self.logger.log(LogPriority.DEBUG, "System info was: " + str(systemos))

        # set default variables for this method
        defaultpackagename = "kernel-PAE"
        syspkgdict = {"redhat": "kernel-PAE",
                      "red hat": "kernel-PAE",
                      "centos": "kernel-PAE",
                      "cent os": "kernel-PAE",
                      "fedora": "kernel-PAE",
                      "debian": "linux-image-686-pae",
                      "ubuntu": "linux-generic-pae",
                      "opensuse": "kernel-pae",
                      "suse": "kernel-pae"}

        try:

            self.logger.log(LogPriority.DEBUG, "Determining system os name...")

            for opsys in syspkgdict:
                if re.search(opsys, systemos.lower()):
                    self.logger.log(LogPriority.DEBUG, "System os name is: " + str(opsys))
                    packagename = syspkgdict[opsys]
                    self.logger.log(LogPriority.DEBUG, "System-specific package name is: " + str(packagename))

        except KeyError:
            # if systemos does not exist in syspkgdict, log debug and use default packagename
            packagename = defaultpackagename
            self.logger.log(LogPriority.DEBUG, "Unable to determine system-specific package name. Defaulting to " + str(defaultpackagename))
        except Exception:
            raise

        if not packagename:
            packagename = defaultpackagename

        return packagename

    def checkPAE(self, package):
        '''check for the presence of the kernel-PAE package as well as the CPU pae flag

        :param package: string The name of the kernel PAE package as it appears to this specific system's OS
        @author: Breen Malmberg
        :returns: retval
        :rtype: bool

        '''

        # set default variables for this method
        retval = True
        paeflag = False
        paepkg = False
        command = "cat /proc/cpuinfo | grep flags"
        osname = ""
        osver = ""
        checkpkg = True

        try:

            osname = self.environ.getostype()
            osver = self.environ.getosver()

            # do not check for existence of a pae package
            # on ubuntu 16 32 bit because it is built into
            # the default kernel and as a result there is no
            # separate pae kernel package to install
            if re.search("Ubuntu", osname, re.IGNORECASE):
                if re.search("16\.", osver, re.IGNORECASE):
                    checkpkg = False
                    paepkg = True

            if not package:
                self.detailedresults += "\nNo package was specified. No package check will be performed. Assuming: not installed."
                self.logger.log(LogPriority.DEBUG, "Required parameter: package was empty")
            elif not isinstance(package, str):
                self.logger.log(LogPriority.DEBUG, "Required parameter: package was not passed as the correct data type. Type required: string")
                self.detailedresults += "\nNo package was specified. No package check will be performed. Assuming: not installed."
            else:
                if checkpkg:
                    # check for presence of kernel PAE package
                    if self.pkg.check(package):
                        paepkg = True

            self.ch.executeCommand(command)
            output = self.ch.getOutput()

            # check for presence of CPU pae flag
            for line in output:
                if re.search("pae", line):
                    paeflag = True

            # let the user know what is wrong
            if not paepkg:
                self.detailedresults += "\nThe kernel pae package is not installed."
            if not paeflag:
                self.detailedresults += "\nThe pae CPU flag was not found."

            retval = bool(paeflag and paepkg)

        except Exception:
            raise

        return retval

    def checkNX(self):
        '''check for the presence of the CPU nx flag


        :returns: retval

        :rtype: bool
@author: Breen Malmberg

        '''

        # set default variables for this method
        retval = False
        command = "cat /proc/cpuinfo | grep flags"

        try:

            self.ch.executeCommand(command)
            output = self.ch.getOutput()

            # check for presence of CPU nx flag
            for line in output:
                if re.search("nx", line):
                    retval = True

            # let the user know what is wrong
            if not retval:
                self.detailedresults += "\nThe CPU nx flag was not found."

        except Exception:
            raise

        return retval

    def fix(self):
        '''Run fix actions for EnablePAEandNX


        :returns: success

        :rtype: bool
@author: Breen Malmberg

        '''

        success = True
        self.detailedresults = ""

        try:

            # only run fix actions if the system is 32-bit and the CI is enabled
            if self.ci.getcurrvalue():
                if self.getSystemARCH() == 32:

                    # attempt to install the kernel pae package; inform user if this fails
                    if not self.pkg.install(self.package):
                        success = False
                        self.detailedresults += "\nUnable to install package: " + str(self.package)

                else:
                    # inform the user if the fix actions do not apply because the system is 64-bit
                    self.detailedresults += "\nThis rule only applies to 32-bit systems. This system is 64-bit."

            else:
                # inform the user if the fix actions will not be run because the CI was not enabled
                self.detailedresults += "\nCI for this rule not enabled. Nothing was done."

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        return success
