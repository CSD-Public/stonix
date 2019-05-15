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

This object is designed to automate rules using the KV Editor paradigm

@version: 1.0.3
@author: ekkehard j. koch
@change: 10/16/2013 Original Implementation
@change: 02/05/2014 Enhanced Error Handeling
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/19/2014 ekkehard added beforereport and afterreport
@change: 02/19/2014 ekkehard added beforefix and afterfix
@change: 04/14/2014 ekkeahrd integrate currenthost option feature
@change: 04/23/2014 ekkeahrd fixed statelogger only records if euid = 0
@change: 09/16/2015 eball Changed fix() so it won't run if report is successful
'''
import traceback
import types
from rule import Rule
from KVEditorStonix import KVEditorStonix
from logdispatcher import LogPriority
from configurationitem import ConfigurationItem


class RuleKVEditor (Rule):
    '''Abstraction of the Rule class for KVEditor Rule classes.
    @author: ekkehard j. koch


    '''
###############################################################################

    def __init__(self, config, environ, logger, statechglogger):
        '''
        This is the constructor for the RuleKVEditor Object. It calls # the
        constructor for it's parent Rule first and then set's up the some
        defaults.
        @author: ekkehard j. koch
        @param self:essential if you override this definition
        @param config:The configuration Object
        @param environ:The environment Object
        @param logger:The Log Dispatcher Object
        @param statechglgger:The State Change Logger Object
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulename = 'KV Editor template class'
        self.helptext = """This is the default help text for the base rule
class. If you are seeing this text it is because the developer for one of the
rules forgot to assign the appropriate help text. Please file a bug against
LANL-stonix."""
        self.formatDetailedResults("initialize")
        self.resetKVEditorValues()
        self.configurationItem = None
        self.kveditorName = ""
        self.kvindex = 0
        self.kvdictionary = {}

###############################################################################

    def setconfigurationitem(self,
                             ci=None,
                             citype="bool",
                             instruction="This should always be enabled."):
        success = True
        if (ci == None):
            self.configurationItem = self.initCi(citype,
                                                 self.kveditorName,
                                                 instruction,
                                                 True)
            self.configurationItemName = self.configurationItem.getkey()
            self.kvconfigurationtype = self.configurationItem.getdatatype()
        else:
# FIXME looks like the type stuff is ugly
            isconfigurationiteminstance = isinstance(ci, ConfigurationItem)
            datatype = type(ci)
            typeexpected = "<class " + \
            "'stonix_resources.configurationitem.ConfigurationItem'>"
            if isconfigurationiteminstance:
                self.configurationItem = ci
                self.configurationItemName = self.configurationItem.getkey()
            else:
                success = False
                self.configurationItem = None
                self.configurationItemName = ""
                raise TypeError("configurationItem with value" + str(ci) + \
                                "is of type " + str(datatype) + " not of " + \
                                "type " + str(typeexpected) + \
                                " as expected!")
        return success

###############################################################################

    def setkvdata(self, value):
        success = True
        datatype = type(value)
        if datatype == types.DictionaryType:
            self.kvdata = value
        else:
            success = False
            self.kvdata = {}
            raise TypeError("kvata with value" + str(value) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.DictionaryType) + \
                            " as expected!")
        return success

###############################################################################

    def setkvdatafixalternate(self, value):
        success = True
        datatype = type(value)
        if datatype == types.DictionaryType:
            self.kvdatafixalternate = value
        else:
            success = False
            self.kvdatafixalternate = {}
            raise TypeError("kvdatafixalternate with value" + str(value) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.DictionaryType) + \
                            " as expected!")
        return success

###############################################################################

    def setkvintent(self, value):
        success = True
        datatype = type(value)
        if datatype == types.StringType:
            self.kvintent = value
        else:
            success = False
            self.kvintent = ""
            raise TypeError("kvintent with value" + str(value) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + " as expected!")
        return success

###############################################################################

    def setkvpath(self, value):
        success = True
        datatype = type(value)
        if datatype == types.StringType:
            self.kvpath = value
        else:
            success = False
            self.kvpath = ""
            raise TypeError("kvpath with value" + str(value) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + " as expected!")
        return success

###############################################################################

    def setkvreportonly(self, value):
        success = True
        datatype = type(value)
        if datatype == types.BooleanType:
            self.kvreportonly = value
        else:
            success = False
            self.kvreportonly = False
            raise TypeError("kvreportonly with value" + str(value) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.BooleanType) + " as expected!")
        return success

###############################################################################

    def setkvtemppath(self, value):
        success = True
        datatype = type(value)
        if datatype == types.StringType:
            self.kvtemppath = value
        else:
            success = False
            self.kvtemppath = ""
            raise TypeError("kvtemppath with value" + str(value) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + " as expected!")
        return success

###############################################################################

    def setkvtype(self, value):
        success = True
        datatype = type(value)
        if datatype == types.StringType:
            self.kvtype = value
        else:
            success = False
            self.kvtype = ""
            raise TypeError("kvtype with value" + str(value) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + " as expected!")
        return success

###############################################################################

    def setkvdefaultscurrenthost(self, value=False):
        success = True
        datatype = type(value)
        if datatype == types.BooleanType:
            self.kvdefaultscurrenthost = value
        else:
            success = False
            self.kvdefaultscurrenthost = False
            raise TypeError("kvdefaultscurrenthost with value" + \
                            str(value) + " is of type " + str(datatype) + \
                            " not of type " + str(types.BooleanType) + \
                            " as expected!")
        return success

###############################################################################

    def fix(self, letcallersetdetailedresults=False):
        '''This is the standard fix routine for a rule. It goes
        though all # the KVEditors and atempts to fix everything. If it
        succeeds it returns true
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        @note: kveditorName is essential
        :param letcallersetdetailedresults:  (Default value = False)

        '''

        try:
            self.logdispatch.log(LogPriority.DEBUG, [self.prefix(),
                                                     "----Begin"])
            fixsuccessful = self.beforefix()
            if fixsuccessful:
                if not letcallersetdetailedresults:
                    self.resultReset()
                keys = sorted(self.kvdictionary.keys())
                for key in keys:
                    self.getKVEditor(key)
                    if (self.kveditorName == ""):
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                             "no kveditorname is blank!"])
                    elif not self.configurationItem == None and \
                    self.configurationItem.getdatatype() == "bool" and \
                    not (self.configurationItem.getcurrvalue()) and \
                    self.kvdatafixalternate == {}:
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              " Configuration Item is False!"])
                        self.resultAppend(str(self.configurationItem.getkey()) + \
                                          " was set to Disabled. No " + \
                                          "action taken!!")
                        success = True
                    # If the report was successful, and there either isn't
                    # alt conf to write or the CI is enabled, skip fix
                    elif (self.kvreportsuccessful and
                          (self.kvdatafixalternate == {} or
                           (self.configurationItem is not None and
                            self.configurationItem.getcurrvalue()))):
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              "Compliant no action taken!"])
                    elif (self.kvreportonly):
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              self.kveditorName +
                                             " is a report only kveditor"])
                    else:
                        success = True
                        if (success and self.kveditorinitialized == False):
                            success = self.kveditorinit()
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 [self.prefix(),
                                                  "kveditorinit() = " + \
                                                  str(success)])
                        if success and not (self.kvdatafixalternate == {}) \
                           and not (self.configurationItem is not None and
                                    self.configurationItem.getcurrvalue()):
                            success = self.kveditor.updatedata(self.kvdatafixalternate)
                        if (success):
                            success = self.kveditor.fix()
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 [self.prefix(),
                                                  "kveditor.fix() = " + \
                                                  str(success)])
                        if (success):
# statlogger only works as root so on set eventid if root
                            if self.environ.geteuid() == 0:
                                self.kveditor.setEventID(self.kveventid)
                                self.logdispatch.log(LogPriority.DEBUG,
                                                     [self.prefix(),
                                                      "environ.geteuid() " + \
                                                      "is 0 so we are " + \
                                                      "setting " + \
                                                      "kveditor.setEventID(" + \
                                                      str(self.kveventid) + \
                                                      ")!"])
                            success = self.kveditor.commit()
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 [self.prefix(),
                                                  "kveditor.commit() = " + \
                                                  str(success)])
                        if not self.configurationItem == None and \
                        self.configurationItem.getdatatype() == "bool" and \
                        not (self.kvdatafixalternate == {}) \
                        and not (self.configurationItem.getcurrvalue()):
                            success = self.kveditor.updatedata(self.kvdata)
                        if (success):
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 [self.prefix(),
                                                  "fix was successful!"])
                            self.resultAppend(self.kveditorName + \
                                              " fix was successful!")
                        else:
                            self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              "Failed!"])
                            self.resultAppend(self.kveditorName + \
                                              " fix failed!")
                            fixsuccessful = False
                self.logdispatch.log(LogPriority.DEBUG, [self.prefix(),
                                                         str(fixsuccessful) + \
                                                         " ----End"])
            if fixsuccessful:
                fixsuccessful = self.afterfix()
        except (KeyboardInterrupt, SystemExit):
            fixsuccessful = False
            raise
        except Exception, err:
            fixsuccessful = False
            self.detailedresults = self.detailedresults + \
            str(traceback.format_exc())
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 [self.prefix(),
                                  "exception - " + str(err) + \
                                  " - " + self.detailedresults])
        if not letcallersetdetailedresults:
            self.formatDetailedResults("fix", fixsuccessful,
                                       self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixsuccessful

###############################################################################

    def beforefix(self):
        beforefixsuccessful = True
        return beforefixsuccessful

###############################################################################

    def afterfix(self):
        afterfixsuccessful = True
        return afterfixsuccessful

###############################################################################

    def report(self, letcallersetdetailedresults=False):
        '''This is the standard report routine for a rule. It goes though all the
        KVEditors and checks if everything is compliant. If everything is
        compliant it returns true.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        @note: kveditorName is essential
        :param letcallersetdetailedresults:  (Default value = False)
        :returns: bool - true if all are compliant, false if one fails

        '''
        self.logdispatch.log(LogPriority.DEBUG,
                             [self.prefix(), "----begin"])
        try:
            self.currstate = "notconfigured"
            if not letcallersetdetailedresults:
                self.resultReset()
            compliant = self.beforereport()
            allcompliant = compliant
            if not letcallersetdetailedresults:
                self.resultReset()
            keys = sorted(self.kvdictionary.keys())
            for key in keys:
                self.getKVEditor(key)
    # FIXME Don't check bool in report mode
                if (self.kveditorName == ""):
                    self.logdispatch.log(LogPriority.DEBUG,
                                         [self.prefix(),
                                          "kveditorname is blank!"])
                else:
                    compliant = False
                    success = True
                    if (success and self.kveditorinitialized == False):
                        success = self.kveditorinit()
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              "kveditorinit() = " +
                                              str(success)])
                    if (success):
                        compliant = self.kveditor.report()
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              "kveditor reports that " +
                                              "compliance = " +
                                              str(compliant)])
                        self.kvvalue = self.formatValue(self.kveditor.getvalue())
                    if (compliant):
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              "kveditor is compliant!"])
                        self.resultAppend(self.kveditorName + \
                                          " is compliant!")
                        self.kvreportsuccessful = True
                    else:
                        allcompliant = False
                        self.resultAppend(self.kveditorName +
                                          " is NOT compliant!")
                        self.logdispatch.log(LogPriority.DEBUG,
                                             [self.prefix(),
                                              "kveditor is not compliant!"])
            compliant = self.afterreport()
            if not compliant:
                allcompliant = False
            self.logdispatch.log(LogPriority.DEBUG,
                                 [self.prefix(),
                                  " ----end" + " Compliant = " +
                                  str(allcompliant)])
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            allcompliant = False
            self.detailedresults = self.detailedresults + \
            str(traceback.format_exc())
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                                 [self.prefix(),
                                  "exception - " + str(err) + \
                                  " - " + self.detailedresults])
        self.compliant = allcompliant
        if not letcallersetdetailedresults:
            self.formatDetailedResults("report", self.compliant,
                                       self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return allcompliant

###############################################################################

    def beforereport(self):
        beforereportsuccessful = True
        return beforereportsuccessful

###############################################################################

    def afterreport(self):
        afterreportsuccessful = True
        return afterreportsuccessful

###############################################################################

    def kveditorinit(self):
        '''Initializes the current kveditor
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true if kveditor is initialized, false if not
        @note: kveditorName is essential

        '''
        if (not self.kveditorinitialized):
            self.kveditor = KVEditorStonix(self.statechglogger,
                                           self.logdispatch,
                                           self.kvtype,
                                           self.kvpath,
                                           self.kvtemppath,
                                           self.kvdata,
                                           self.kvintent,
                                           self.kvconfigurationtype)
            self.kveditor.setCurrentHostbool(self.kvdefaultscurrenthost)
            self.kveditorinitialized = True
            self.logdispatch.log(LogPriority.DEBUG,
                                 [self.prefix(), "kveditor initialized = " +
                                  str(self.kveditorinitialized)])
        else:
            self.logdispatch.log(LogPriority.DEBUG,
                                 [self.prefix(),
                                  "kveditor was alredady initialized!"])
        return self.kveditorinitialized

###############################################################################

    def prefix(self):
        '''Creates a standard prefix used in logging for the rule.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: string - standard prefix for rule
        @note: kveditorName is essential

        '''
        try:
            prefix = str(self.rulename) + "(" + str(self.rulenumber) + \
            ")." + self.kveditorName
        except AttributeError:
            try:
                prefix = str(self.rulename) + "(" + str(self.rulenumber) + ")"
            except AttributeError:
                try:
                    prefix = str(self.rulename)
                except AttributeError:
                    prefix = ""
        return prefix

###############################################################################

    def addKVEditor(self,
                    pKVEditorName,
                    pKvType="",
                    pKvPath="",
                    pKvTempPath="",
                    pKvData={},
                    pKvIntent="present",
                    pKvConfigurationType="",
                    pInstruction='''This should always be enabled.''',
                    pKvConfigurationItem=None,
                    pKVReportOnly=False,
                    pKvDataFixAlternate={}):
        '''set the current kveditor values and adds the new kveditor to the
        dictionary
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pKVEditorName: string - required kveditorname
        :param pKvType: string - type of kveditor to use (blank by default)
        :param pKvPath: string - file path (blank by default)
        :param pKvTempPath: string - file path for temp files (blank by
                            default)
        :param pKvData: dictionary - of command data (empty dictionary by
                        default)
        :param pKvIntent: string - intent of kveditor (present dictionary by
                          default)
        :param pKvConfigurationType: string - type of configuration file for
                                     kveditor (blank by default)
        :param pInstruction: string - instructions for configuraiton item
                             ('This should always be enabled' by default)
        :param pKvConfigurationItem: ConfigurationItem - configuration item to
                                     use for kveditor  (None by default)
        :param pKVReportOnly: boolean set to true if the kveditor in only
                              supposed to run in report mode (False by default)
        :param pKvDataFixAlternate: dictionary - of command data to be used
                                    for alternate fix actions (empty
                                    dictionary by default)
        :returns: pointer to the configuration item
        @note: kveditorName is essential

        '''
        success = True
        if success:
            success = self.saveKVEditor()
        if success:
            success = self.resetKVEditorValues()
        if success:
            self.kveditorinitialized = False
            self.kveditor = None
            self.kvreportsuccessful = False
            datatype = type(pKVEditorName)
            if datatype == types.StringType:
                self.kveditorName = pKVEditorName
            else:
                success = False
                self.kveditorName = ""
                success = False
                raise TypeError("pKVEditorName with value" + \
                                str(pKVEditorName) + "is of type " + \
                                str(datatype) + " not of " + "type " + \
                                str(types.StringType) + " as expected!")
            self.kveventid = str(self.rulenumber).zfill(4) + \
            str(self.kveditorName)
            self.kvindex = self.kvindex + 1
        if success:
            success = self.setkvtype(pKvType)
        if success:
            success = self.setkvpath(pKvPath)
        if success:
            success = self.setkvtemppath(pKvTempPath)
        if success:
            success = self.setkvdata(pKvData)
        if success:
            success = self.setkvintent(pKvIntent)
        if success:
            success = self.setkvreportonly(pKVReportOnly)
        if success and not pKVReportOnly:
            if pKvConfigurationType == "":
                configurationType = "bool"
            else:
                configurationType = pKvConfigurationType
            success = self.setconfigurationitem(pKvConfigurationItem,
                                                configurationType,
                                                pInstruction)
        if success:
            success = self.setkvdatafixalternate(pKvDataFixAlternate)
        self.saveKVEditor()
        self.logdispatch.log(LogPriority.DEBUG,
                             [self.prefix(),
                              "kveditor dictionary entry added!"])
        return success

###############################################################################

    def getKVEditor(self, pKVEditorName):
        '''gets a kveditor by name and loads it into the current kveditor values
        of the object.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pKVEditorName: string - required kveditorname
        :returns: boolean - true
        @note: kveditorName is essential

        '''
        self.saveKVEditor()
        self.kveditorName = pKVEditorName
        item = self.kvdictionary[self.kveditorName]
        if not (item == None):
            self.kveventid = item["kveventid"]
            self.kvtype = item["kvtype"]
            self.kvpath = item["kvpath"]
            self.kvtemppath = item["kvtemppath"]
            self.kvdata = item["kvdata"]
            self.kvintent = item["kvintent"]
            self.kvconfigurationtype = item["kvconfigurationtype"]
            self.kveditorinitialized = item["kveditorinitialized"]
            self.kvdefaultscurrenthost = item["kvdefaultscurrenthost"]
            self.kveditor = item["kveditor"]
            self.kvreportsuccessful = item["kvreportsuccessful"]
            self.configurationItemName = item["configurationItemName"]
            self.kvreportonly = item["kvreportonly"]
            self.kvdatafixalternate = item["kvdatafixalternate"]
            self.kvvalue = item["kvvalue"]
            if not self.configurationItemName == "":
                self.configurationItem = self.getConfigurationByName(self.configurationItemName)
            else:
                self.configurationItem = None
            self.logdispatch.log(LogPriority.DEBUG,
                                 [self.prefix(),
                                  "kveditor dictionary entry retrieved " + \
                                  "and object values set!"])
        else:
            self.resetKVEditorValues()
        return True

###############################################################################

    def saveKVEditor(self):
        '''saves the current kveditor values into the dictionary.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pKVEditorName: string - required kveditorname
        :returns: boolean - true
        @note: kveditorName is essential

        '''
        if not (self.kveditorName == ""):
            item = {"kveventid": self.kveventid,
                    "kvtype": self.kvtype,
                    "kvpath": self.kvpath,
                    "kvtemppath": self.kvtemppath,
                    "kvdata": self.kvdata,
                    "kvintent": self.kvintent,
                    "kvconfigurationtype": self.kvconfigurationtype,
                    "kveditorinitialized": self.kveditorinitialized,
                    "kvdefaultscurrenthost": self.kvdefaultscurrenthost,
                    "kveditor": self.kveditor,
                    "kvreportsuccessful": self.kvreportsuccessful,
                    "configurationItemName": self.configurationItemName,
                    "kvreportonly": self.kvreportonly,
                    "kvdatafixalternate": self.kvdatafixalternate,
                    "kvvalue": self.kvvalue}
            self.kvdictionary[self.kveditorName] = item
            self.logdispatch.log(LogPriority.DEBUG,
                                 [self.prefix(),
                                  "kveditor dictionary entry saved!"])
        else:
            self.resetKVEditorValues()
        return True

###############################################################################

    def resetKVEditorValues(self):
        '''reset the current kveditor values to their defaults.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true
        @note: kveditorName is essential

        '''
        success = True
        self.kveditorName = ""
        self.kveventid = ""
        self.kvtype = ""
        self.kvpath = ""
        self.kvtemppath = ""
        self.kvdata = {}
        self.kvintent = ""
        self.kvconfigurationtype = ""
        self.kveditorinitialized = False
        self.kveditor = None
        self.kvreportsuccessful = False
        self.configurationItemName = ""
        self.configurationItem = None
        self.kvreportonly = False
        self.kvdatafixalternate = {}
        self.kvvalue = ""
        self.kvdefaultscurrenthost = False
        self.logdispatch.log(LogPriority.DEBUG,
                             [self.prefix(),
                              "kveditor object value entry sReset!"])
        return success

###############################################################################

    def resultAppend(self, pMessage=""):
        '''reset the current kveditor values to their defaults.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :param pMessage:  (Default value = "")
        :returns: boolean - true
        @note: kveditorName is essential

        '''
        datatype = type(pMessage)
        if datatype == types.StringType:
            if not (pMessage == ""):
                messagestring = pMessage
                if (self.detailedresults == ""):
                    self.detailedresults = messagestring + "\n"
                else:
                    self.detailedresults += messagestring + "\n"
        elif datatype == types.ListType:
            if not (pMessage == []):
                for item in pMessage:
                    messagestring = item
                    if (self.detailedresults == ""):
                        self.detailedresults = messagestring + "\n"
                    else:
                        self.detailedresults += messagestring + "\n"
        else:
            raise TypeError("pMessage with value" + str(pMessage) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + \
                            " or type " + str(types.ListType) + \
                            " as expected!")

###############################################################################

    def resultReset(self):
        '''reset the current kveditor values to their defaults.
        @author: ekkehard j. koch

        :param self: essential if you override this definition
        :returns: boolean - true
        @note: kveditorName is essential

        '''
        self.detailedresults = ""

###############################################################################

    def formatValue(self, pValue):
        return pValue

###############################################################################

    def getConfigurationByName(self, pCIName=""):
        configurationItemObject = None
        datatype = type(pCIName)
        if datatype == types.StringType:
            ciName = pCIName
        else:
            ciName = ""
            raise TypeError("pCIName with value" + str(pCIName) + \
                            "is of type " + str(datatype) + " not of " + \
                            "type " + str(types.StringType) + \
                            " as expected!")
        for ci in self.confitems:
            if ci.getkey() == ciName:
                configurationItemObject = ci
                break
        if configurationItemObject == None:
            raise ValueError("No confiuration item found for pCIName = " + \
                             str(pCIName) + \
                            "!")
        return configurationItemObject
