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
Created on Aug 23, 2016

@author: Derek Walker
@change: 2017/03/30 Dave Kennel Marked as FISMA High
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/10/25 Breen Malmberg - added support for high sierra and mojave;
        refactored rule
@change: Derek Walker - 2/7/2019 - updated method to search for a
            different identifier for security profile on 10.13. Added
            testing paths in setvars method which are commented out. DO
            NOT DELETE THIS SECTION OF COMMENTED CODE.
'''



import traceback
import re

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate
from ..CommandHelper import CommandHelper


class STIGConfigurePasswordPolicy(Rule):
    '''Deploy Passcode Policy configuration profiles for macOS X'''

    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 361
        self.rulename = "STIGConfigurePasswordPolicy"
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12.0', 'r', '10.14.10']},
                           'fisma': 'high'}
        datatype = "bool"
        key = "STIGPWPOLICY"
        instructions = "To disable the installation of the password " + \
            "profile set the value of STIGPWPOLICY to False"
        default = False
        self.pwci = self.initCi(datatype, key, instructions, default)

        datatype = "bool"
        key = "STIGSECPOLICY"
        instructions = "To disable the installation of the security " + \
            "profile set the value of STIGSECPOLICY to False"
        default = True
        self.sci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0
        self.setvars()

    def setvars(self):
        '''set class variables based on os version'''

        self.pwprofile = ""
        self.secprofile = ""
        self.passidentifier = "mil.disa.STIG.passwordpolicy.alacarte"
        self.secidentifier = "mil.disa.STIG.Security_Privacy.alacarte"
        self.os_major_ver = self.environ.getosmajorver()
        self.os_minor_ver = self.environ.getosminorver()
        baseconfigpath = "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/files/"
        self.passprofiledict = {"10.10": baseconfigpath + "U_Apple_OS_X_10-10_Workstation_V1R2_STIG_Passcode_Policy.mobileconfig",
                             "10.11": baseconfigpath + "U_Apple_OS_X_10-11_V1R1_STIG_Passcode_Policy.mobileconfig",
                             "10.12": baseconfigpath + "U_Apple_macOS_10-12_V1R1_STIG_Passcode_Policy.mobileconfig",
                             "10.13": baseconfigpath + "U_Apple_OS_X_10-13_V1R0-1_STIG_Passcode_Policy.mobileconfig",
                             "10.14": baseconfigpath + "stonix4macPasscodeConfigurationProfilemacOSMojave10.14.mobileconfig"}
        self.secprofiledict = {"10.10": baseconfigpath + "U_Apple_OS_X_10-10_Workstation_V1R2_STIG_Security_Privacy_Policy.mobileconfig",
                               "10.11": baseconfigpath + "U_Apple_OS_X_10-11_V1R1_STIG_Security_and_Privacy_Policy.mobileconfig",
                               "10.12": baseconfigpath + "U_Apple_macOS_10-12_V1R1_STIG_Security_and_Privacy_Policy.mobileconfig",
                               "10.13": baseconfigpath + "U_Apple_OS_X_10-13_V1R0-1_STIG_Security_and_Privacy_Policy.mobileconfig",
                               "10.14": baseconfigpath + "stonix4macSecurity\&PrivacymacOSMojave10.14.mobileconfig"}
        #the following path and dictionaries are for testing on local vm's
        #without installing stonix package each time.  DO NOT DELETE
        # basetestpath = "/Users/username/stonix/src/stonix_resources/files/"
        # self.passprofiledict = {
        #     "10.10": basetestpath + "U_Apple_OS_X_10-10_Workstation_V1R2_STIG_Passcode_Policy.mobileconfig",
        #     "10.11": basetestpath + "U_Apple_OS_X_10-11_V1R1_STIG_Passcode_Policy.mobileconfig",
        #     "10.12": basetestpath + "U_Apple_macOS_10-12_V1R1_STIG_Passcode_Policy.mobileconfig",
        #     "10.13": basetestpath + "U_Apple_OS_X_10-13_V1R0-1_STIG_Passcode_Policy.mobileconfig",
        #     "10.14": basetestpath + "stonix4macPasscodeConfigurationProfilemacOSMojave10.14.mobileconfig"}
        # self.secprofiledict = {
        #     "10.10": basetestpath + "U_Apple_OS_X_10-10_Workstation_V1R2_STIG_Security_Privacy_Policy.mobileconfig",
        #     "10.11": basetestpath + "U_Apple_OS_X_10-11_V1R1_STIG_Security_and_Privacy_Policy.mobileconfig",
        #     "10.12": basetestpath + "U_Apple_macOS_10-12_V1R1_STIG_Security_and_Privacy_Policy.mobileconfig",
        #     "10.13": basetestpath + "U_Apple_OS_X_10-13_V1R0-1_STIG_Security_and_Privacy_Policy.mobileconfig",
        #     "10.14": basetestpath + "stonix4macSecurity&PrivacymacOSMojave10.14.mobileconfig"}
        try:
            self.pwprofile = self.passprofiledict[str(self.os_major_ver) + "." + str(self.os_minor_ver)]
        except KeyError:
            self.logger.log(LogPriority.DEBUG, "Could not locate appropriate password policy profile for macOS X version: " + str(self.os_major_ver) + "." + str(self.os_minor_ver))
            self.pwprofile = ""

        try:
            self.secprofile = self.secprofiledict[str(self.os_major_ver) + "." + str(self.os_minor_ver)]
        except KeyError:
            self.logger.log(LogPriority.DEBUG, "Could not locate appropriate privacy and security policy profile for macOS X version: " + str(self.os_major_ver) + "." + str(self.os_minor_ver))
            self.secprofile = ""

        if self.pwprofile == "":
            self.logger.log(LogPriority.DEBUG, "Could not locate the Password policy profile for this version of macOS X")
            self.fall_back_profiles('pass', self.os_minor_ver)
        if self.secprofile == "":
            self.logger.log(LogPriority.DEBUG, "Could not locate the Privacy and Security policy profile for this version of macOS X")
            self.fall_back_profiles('sec', self.os_minor_ver)

    def fall_back_profiles(self, policy, minorver):
        '''if the current system is a new version of mac, for which we do
        not yet have a profile (due to STIG guidance release lag), then
        use the profiles for the previous version of macOS

        :param policy: string; policy to roll back (can be 'pass' or 'sec')
        :param minorver: string; minor revision number to iterate over
        
        @author: Breen Malmberg

        '''

        if int(minorver) < 10:
            self.logger.log(LogPriority.DEBUG, "Failed to find a suitable fall-back profile for this version of macOS X")
            return
        # if both are properly set, then exit recursion
        if bool(self.pwprofile and self.secprofile):
            return

        # set previous version of macOS to use
        rollbackminor = int(minorver) - 1
        rollbackversion = str(self.os_major_ver) + "." + str(rollbackminor)

        try:
            if policy == 'pass':
                self.logger.log(LogPriority.DEBUG, "Attempting to roll back to older Password policy profile, for macOS X version: " + rollbackversion)
                self.pwprofile = self.passprofiledict[rollbackversion]
                if self.pwprofile != "":
                    self.logger.log(LogPriority.DEBUG, "Using Password policy profile for macOS X version: " + rollbackversion)
                else:
                    return self.fall_back_profiles('pass', rollbackminor)
        except KeyError:
            self.pwprofile = ""
            return self.fall_back_profiles('pass', rollbackminor)

        try:
            if policy == 'sec':
                self.logger.log(LogPriority.DEBUG, "Attempting to roll back to older Privacy and Security policy profile, for macOS X version: " + rollbackversion)
                self.secprofile = self.secprofiledict[rollbackversion]
                if self.secprofile != "":
                    self.logger.log(LogPriority.DEBUG, "Using Privacy and Security policy profile for macOS X version: " + rollbackversion)
                else:
                    return self.fall_back_profiles('sec', rollbackminor)
        except KeyError:
            self.secprofile = ""
            return self.fall_back_profiles('sec', rollbackminor)

    def report(self):
        '''report compliance to password policy and
        security and privacy policy


        :returns: self.compliant

        :rtype: bool

@author: Derek Walker
@change: Breen Malmberg - 10/25/2018 - added doc string; refactor
@change: Derek Walker - 2/7/2019 - updated method to search for a
    different identifier for security profile on 10.13

        '''

        self.compliant = True
        self.pwcompliant = False
        self.secompliant = False
        self.detailedresults = ""
        self.ch = CommandHelper(self.logger)
        listprofiles = ["/usr/bin/profiles", "-P"]

        if not self.pwprofile:
            self.detailedresults += "\nCould not determine the appropriate password policy profile for your system."
            self.compliant = False
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return self.compliant
        if not self.secprofile:
            self.detailedresults += "\nCould not determine the appropriate privacy and security policy profile for your system."
            self.compliant = False
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return self.compliant

        try:

            if not self.ch.executeCommand(listprofiles):
                self.compliant = False
                self.detailedresults += "\nFailed to get list of profiles on this system"
            else:
                output = self.ch.getOutput()
                if output:
                    for line in output:
                        if re.search("^There are no configuration profiles installed", line.strip()):
                            self.detailedresults += "There are no configuration profiles installed\n"
                            break
                        if self.os_minor_ver == "14":
                            if re.search("31208FA5-819D-4311-96BF-A88B953876F9", line.strip()):
                                self.pwcompliant = True
                        elif re.search("mil\.disa\.STIG\.passwordpolicy\.alacarte$", line.strip()):
                            self.pwcompliant = True
                        if self.os_minor_ver == "12":
                            if re.search("mil\.disa\.STIG\.Security_Privacy\.alacarte$", line.strip()):
                                self.secompliant = True
                        elif self.os_minor_ver == "13":
                            if re.search("3C05C7B8\-6DE9\-4162\-96A9\-9A4D0507CD01", line.strip()):
                                self.secompliant = True
                        elif self.os_minor_ver == "14":
                            if re.search("A4BF53F7-4060-4BDA-A438-4550CBCB23D2", line.strip()):
                                self.secompliant = True

            if not self.pwcompliant:
                self.detailedresults += "\nPassword policy profile is not installed"
                self.compliant = False
            if not self.secompliant:
                self.detailedresults += "\nPrivacy and Security policy profile is not installed"
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''install the password policy and privacy and security policy profiles


        :returns: self.rulesuccess

        :rtype: bool

@author: Derek Walker
@change: Breen Malmberg - 10/25/2018 - added doc string; refactor

        '''

        self.iditerator = 0
        self.rulesuccess = True
        self.detailedresults = ""
        profiles = "/usr/bin/profiles"
        pinstall = ""
        premove = ""

        # if macOS X is Sierra or previous, then use old
        # profiles command structure
        if int(self.os_minor_ver) <= 12:
            pinstall = profiles + " -I -F "
            premove = profiles + " -R -F "
        # else use newer profiles commands
        else:
            pinstall = profiles + " install -path="
            premove = profiles + " remove -path="

        try:

            # if password policy ci enabled
            if self.pwci.getcurrvalue():
                # install password policy profile
                if not self.pwcompliant:
                    installpwp = pinstall + self.pwprofile
                    self.ch.executeCommand(installpwp)
                    retcode = self.ch.getReturnCode()
                    # if successfull
                    if retcode == 0:
                        # configure undo action
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        undopwp = premove + self.pwprofile
                        event = {"eventtype": "comm",
                                 "command": undopwp}
                        self.statechglogger.recordchgevent(myid, event)
                        self.detailedresults += "\nSuccessfully installed Password policy profile in:\n" + str(self.pwprofile)
                    # if not successful
                    else:
                        self.rulesuccess = False
                        self.detailedresults += "\nFailed to install Password policy profile!"
                        errmsg = self.ch.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errmsg)
                else:
                    self.detailedresults += "\nPassword policy profile was already installed. Nothing to do."

            # if privacy and sec policy ci enabled
            if self.sci.getcurrvalue():
                # install privacy and security profile
                if not self.secompliant:
                    installsecp = pinstall + self.secprofile
                    self.ch.executeCommand(installsecp)
                    retcode = self.ch.getReturnCode()
                    # if successfull
                    if retcode == 0:
                        # configure undo action
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        undosecp = premove + self.secprofile
                        event = {"eventtype": "comm",
                                 "command": undosecp}
                        self.statechglogger.recordchgevent(myid, event)
                        self.detailedresults += "\nSuccessfully installed Privacy and Security policy profile in:\n" + str(self.secprofile)
                    # if not successful
                    else:
                        self.rulesuccess = False
                        self.detailedresults += "\nFailed to install Privacy and Security policy profile!"
                        errmsg = self.ch.getErrorString()
                        self.logger.log(LogPriority.DEBUG, errmsg)
                else:
                    self.detailedresults += "\nPrivacy and Security policy profile was already installed. Nothing to do."

                # sync new profiles with users
                self.ch.executeCommand(profiles + " sync")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
