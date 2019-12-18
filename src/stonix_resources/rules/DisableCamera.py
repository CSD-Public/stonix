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
Created on Dec 10, 2013

@author: dwalker, Breen Malmberg
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 03/26/2014 ekkehard convert to ruleKVEditor
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/14 dkennel updated for new isApplicable
@change: 2015/08/26 ekkehard [artf37771] : DisableCamera(150) - NCAF & Lack of detail in Results - OS X El Capitan 10.11
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
@change: 2017/01/19 Breen Malmberg - minor class doc string edit; minor refactor of report and fix methods;
        got rid of unused code blocks (previously commented out) and unused imports; updated the help text to
        include more detail
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change 2017/08/28 Breen Malmberg Fixing to use new help text methods
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''


from rule import Rule
from logdispatcher import LogPriority
from KVEditorStonix import KVEditorStonix
from stonixutilityfunctions import iterate
import os
import traceback

class DisableCamera(Rule):

    def __init__(self, config, environ, logger, statechglogger):
        '''
        :param config:
        :param environ:
        :param logger:
        :param statechglogger:
        '''

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 150
        self.rulename = "DisableCamera"
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.rulesuccess = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ["CIS 1.2.6"]
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        self.logger = logger
        self.iditerator = 0
        datatype = 'bool'
        key = 'DISABLECAMERA'
        instructions = "To disable the built-in iSight camera, set the value of DISABLECAMERA to True."
        default = False
        self.ci = self.initCi(datatype, key, instructions, default)
        self.setvars()

    def setvars(self):
        self.camprofile = ""
        baseconfigpath = "/Applications/stonix4mac.app/Contents/" + \
                             "Resources/stonix.app/Contents/MacOS/" + \
                             "stonix_resources/files/"
        self.camprofile = baseconfigpath + "stonix4macCameraDisablement.mobileconfig"
        # basetestpath = "/Users/username/stonix/src/stonix_resources/files/"
        # self.camprofile = basetestpath + "stonix4macCameraDisablement.mobileconfig"
        if not os.path.exists(self.camprofile):
            self.logger.log(LogPriority.DEBUG, "Could not locate appropriate camera disablement profile\n")
            self.camprofile = ""

    def report(self):
        '''check for the existence of the AppleCameraInterface driver in the
        output of kexstat. Report non-compliant if found. Report compliant
        if not found.
        :returns: self.compliant
        :rtype: bool
        @author: Breen Malmberg
        @change: dwalker - ??? - ???
        @change: Breen Malmberg - 1/19/2017 - minor doc string edit; minor refactor
        @change: dwalker 10/3/2017 updated to check for a profile value
        '''
        try:
            self.detailedresults = ""
            self.compliant = True
            if not self.camprofile:
                self.detailedresults += "Could not locate the appropriate camera disablement profile for your system.\n"
                self.compliant = False
                self.formatDetailedResults("report", self.compliant, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.compliant
            if os.path.exists(self.camprofile):
                cameradict = {"com.apple.applicationaccess": {"allowCamera": {"val": "0",
                                                                              "type": "bool",
                                                                              "accept": "",
                                                                              "result": False}}}
                self.cameditor = KVEditorStonix(self.statechglogger, self.logger,
                                                "profiles", self.camprofile, "",
                                                cameradict, "", "")
                if not self.cameditor.report():
                    self.detailedresults += "iSight camera is not disabled\n"
                    self.compliant = False
            else:
                self.detailedresults += self.camprofile + " doesn't exist\n"
                self.compliant = False
            self.detailedresults += "Due to a Mac OS issue, having multiple camera profiles " + \
                                    "installed with conflicting values may allow any camera, " + \
                                    "internal or external to still function. If a rule is coming " + \
                                    "back compliant but your camera is still working, check your " + \
                                    "installed profiles and remove any other restriction based profiles.\n"
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                                   " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''run kextunload on the AppleCameraInterface driver to
        unload it and disable the iSight camera.
        return True if the command succeeds. return False if
        the command fails.
        :returns: success
        :rtype: bool
        @author: Breen Malmberg
        @change: dwalker - ??? - ???
        @change: Breen Malmberg - 1/19/2017 - minor doc string edit; minor refactor
        @change: dwalker 10/3/2017 updated to check for a profile value
        '''

        try:
            success = True
            self.detailedresults = ""
            # only run the fix actions if the CI has been enabled
            if not self.ci.getcurrvalue():
                self.detailedresults += "Configuration item was not enabled\n"
                self.rulesuccess = False
                self.formatDetailedResults("report", self.rulesuccess, self.detailedresults)
                self.logdispatch.log(LogPriority.INFO, self.detailedresults)
                return self.rulesuccess
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            if not self.cameditor.report():
                if self.cameditor.fix():
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    self.cameditor.setEventID(myid)
                    if not self.cameditor.commit():
                        success = False
                        self.detailedresults += "Unable to install profile\n"
                        self.logdispatch.log(LogPriority.DEBUG, "Kveditor commit failed")
                else:
                    success = False
                    self.detailedresults += "Unable to install profile\n"
                    self.logdispatch.log(LogPriority.DEBUG, "Kveditor fix failed")
            else:
                self.detailedresults += "Camera disablement profile was already installed.\n"
            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                                   " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", success, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
