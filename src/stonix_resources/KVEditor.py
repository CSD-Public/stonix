'''
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
Created on Apr 5, 2013

@author: dwalker
'''

import KVADefault
import KVAConf
import KVATaggedConf
import KVAProfiles
import os
from CommandHelper import CommandHelper
from logdispatcher import LogPriority


class KVEditor(object):
    '''The main parent class for The Key Value Editor Class group.  Call the
    validate def to see if the specified values are either present or not based
    on the intent desired, "present" or "notpresent", where, "present" means
    the values you set are desired in the configuration file and "notpresent"
    means the values you set are not desired in the configuration file.  If you
    have a mixture of desired key-values and undesired key-values you must set
    intent for each time you change intents then setData with the new data.  Do
    not run commit until all'''

    def __init__(self, stchlgr, logger, kvtype, path, tmpPath, data, intent="",
                 configType="", output=""):
        '''
        KVEditor constructor
        @param stchlgr: StateChgLogger object
        @param logger: logger object
        @param kvtype: Type of key-value file.
                       Valid values: "tagconf", "conf", "defaults", "profiles"
        @param path: Path to key-value file
        @param tmpPath: Path to temp file for key-value list
        @param data: Dict of key-value data
        @param intent: "present" or "notpresent"
        @param configType: Specify how the config options are separated.
                           Valid values: "space", "openeq", "closedeq"
        @param output: Output of profiler command, used only by KVAProfiles
        '''
        self.kvtype = kvtype
        self.path = path
        self.tmpPath = tmpPath
        self.logger = logger
        self.configType = configType
        self.data = data
        self.output = output
        self.detailedresults = ""
        self.missing = []
        self.fixables = {}
        self.fixlist = []
        self.removeables = {}
        self.intent = intent
        self.container = {}
        self.iditerator = 0
        self.idcontainer = []
        if self.kvtype == "tagconf":
            if not self.getPath:
                return None
            self.editor = KVATaggedConf.KVATaggedConf(self.path, self.tmpPath,
                                                      self.intent,
                                                      self.configType,
                                                      self.logger)
        elif self.kvtype == "conf":
            if not self.getPath:
                return None
            self.editor = KVAConf.KVAConf(self.path, self.tmpPath, self.intent,
                                          self.configType, self.logger)
        elif self.kvtype == "defaults":
            self.editor = KVADefault.KVADefault(self.path, self.logger,
                                                self.data)
        elif self.kvtype == "profiles":
            self.editor = KVAProfiles.KVAProfiles(self.logger, self.path)
        else:
            self.detailedresults = "Not one of the supported kveditor types"
            self.logger.log(LogPriority.DEBUG,
                            ["KVEditor.__init__", self.detailedresults])
            return None

    def setData(self, data):
        if data is None:
            return False
        elif data == "":
            return False
        else:
            self.data = data
            return True

    def getData(self):
        return self.data

    def updateData(self, data):
        self.data = data

    def setIntent(self, intent):
        if intent == "present" or intent == "notpresent":
            self.intent = intent
            self.editor.setIntent(intent)
            return True
        else:
            return False

    def getIntent(self):
        return self.intent

    def setPath(self, path):
        if not os.path.exists(path):
            self.detailedresults = "File path does not exist"
            self.logger.log(LogPriority.INFO,
                            ["KVEditor", self.detailedresults])
            return False
        else:
            self.path = path
            self.editor.setPath(path)
            return True

    def getPath(self):
        if not os.path.exists(self.path):
            debug = "File path does not exist\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False
        else:
            return self.path

    def setTmpPath(self, tmpPath):
        self.tmpPath = tmpPath
        self.editor.setTmpPath(tmpPath)
        return True

    def getTmpPath(self):
        return self.tmpPath

    def getType(self):
        return self.kvtype

    def setConfigType(self, configType):
        self.configType = configType
        self.editor.setConfigType(configType)
        return True

    def getConfigType(self):
        return self.configType

    def validate(self):
        try:
            status = False
            if self.kvtype == "defaults":
                status = self.validateDefaults()
            elif self.kvtype == "plist":
                status = self.validatePlist()
            elif self.kvtype == "conf":
                status = self.validateConf()
            elif self.kvtype == "tagconf":
                status = self.validateTag()
            elif self.kvtype == "profiles":
                status = self.validateProfiles()
            else:
                status = "invalid"
            debug = "KVEditor is returning " + str(status) + " back to " + \
                "KVEditorStonix.report()\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return status
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise

    def update(self):
        try:
            status = False
            if self.kvtype == "defaults":
                status = self.updateDefaults()
            elif self.kvtype == "plist":
                status = self.updatePlist()
            elif self.kvtype == "conf":
                status = self.updateConf()
            elif self.kvtype == "tagconf":
                status = self.updateTag()
            elif self.kvtype == "profiles":
                status = self.updateProfiles()
            else:
                status = False
            debug = "KVEditor is returning " + str(status) + " back to " + \
                "KVEditorStonix.fix()\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return status
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise

    def validateDefaults(self):
        if isinstance(self.data, dict):
            if not self.checkDefaults(self.data):
                return False
        else:
            return False
        if self.editor.validate():
            return True
        else:
            return False

    def updateDefaults(self):
        if self.editor.update():
            debug = "KVEditor.updateDefaults() is returning True to " + \
                "KVEditor.update()\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return True
        else:
            debug = "KVEditor.updateDefaults() is returning False to " + \
                "KVEditor.update()\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False

    def checkDefaults(self, data):
        for k, v in data.iteritems():
            if isinstance(v, dict):
                retval = self.checkDefaults(v)
                return retval
            elif isinstance(v, list):
                if len(v) == 2 or len(v) == 3:
                    return True
                else:
                    return False
            else:
                return False

    def setCurrentHostbool(self, val):
        self.editor.currentHost = val

    def validateConf(self):
        validate = True
        if not self.checkConf():
            return False
        if self.intent == "present":
            for k, v in self.data.iteritems():
                retval = self.editor.validate(k, v)
                if retval == "invalid":
                    validate = "invalid"
                elif isinstance(retval, list):
                    self.fixables[k] = retval
                    validate = False
                elif not retval:
                    validate = False
                    self.fixables[k] = v
        if self.intent == "notpresent":
            for k, v in self.data.iteritems():
                retval = self.editor.validate(k, v)
                if retval == "invalid":
                    validate = "invalid"
                elif isinstance(retval, list):
                    self.removeables[k] = retval
                    validate = False
                elif retval is True:
                    validate = False
                    self.removeables[k] = v
        if validate == "invalid":
            debug = "KVEditor.validateConf() is returning invalid to " + \
                "KVEditor.validate()\n"
        elif validate:
            debug = "KVEditor.validateConf() is returning True to " + \
                "KVEditor.validate()\n"
        else:
            debug = "KVEditor.validateConf() is returning False to " + \
                "KVEditor.validate()\n"
        self.logger.log(LogPriority.DEBUG, debug)
        return validate

    def updateConf(self):
        if self.fixables or self.removeables:
            if self.editor.update(self.fixables, self.removeables):
                debug = "KVEditor.updateConf() is returning True to " + \
                    "KVEditor.update()\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return True
            else:
                debug = "KVEditor.updateConf() is returning False to " + \
                    "KVEditor.update()\n"
                self.logger.log(LogPriority.DEBUG, debug)
                return False

    def checkConf(self):
        if isinstance(self.data, dict):
            return True
        else:
            return False

    def validateTag(self):
        validate = True
        keyvals = {}
        if not self.checkTag():
            return False
        if self.intent == "present":
            for tag in self.data:
                keyvals = self.editor.getValue(tag, self.data[tag])
                if keyvals == "invalid":
                    validate = "invalid"
                elif isinstance(keyvals, dict):
                    self.fixables[tag] = keyvals
                    validate = False
        if self.intent == "notpresent":
            for tag in self.data:
                keyvals = self.editor.getValue(tag, self.data[tag])
                if keyvals == "invalid":
                    validate = "invalid"
                elif isinstance(keyvals, dict):
                    self.removeables[tag] = keyvals
                    validate = False
        if validate == "invalid":
            debug = "KVEditor.validateTag() is returning invalid to " + \
                "KVEditor.validate()\n"
        elif validate:
            debug = "KVEditor.validateTag() is returning True to " + \
                "KVEditor.validate()\n"
        else:
            debug = "KVEditor.validateTag() is returning False to " + \
                "KVEditor.validate()\n"
        self.logger.log(LogPriority.DEBUG, debug)
        return validate

    def updateTag(self):
        if self.editor.setValue(self.fixables, self.removeables):
            debug = "KVEditor.updateTag() is returning True to " + \
                "KVEditor.update()\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return True
        else:
            debug = "KVEditor.updateTag() is returning False to " + \
                "KVEditor.update()\n"
            self.logger.log(LogPriority.DEBUG, debug)
            return False

    def checkTag(self):
        if isinstance(self.data, dict):
            for tag in self.data:
                if not isinstance(self.data[tag], dict):
                        return False
            return True
        else:
            return False

    def validateProfiles(self):
        '''
        @since: 3/10/2016
        @author: dwalker
        @var self.data: A dictionary in the form of {k: {v: ["numberValue",
                                                             "datatype",
                                                             "acceptableDeviation"(optional)],
                                                        v: ["", "", ""],
                                                        v: ["", "", ""],
                                                        .
                                                        .
                                                        .}}
        @var: k: The profile sub-identifier e.g.
            com.apple.mobiledevice.passwordpolicy
        @var v: The profile data key-value pairs in a dictionary e.g.
            allowSimple that will appear in the output of the system_profiler
            command within the first opening brace after the profile
            sub-identifier.  v also contains an associated list containing:
            [a,b,c]
            a) the value on the other side of the = sign
            b) whether that value is an integer(int) or a boolean(bool)
            c) (optional) whether the value present after the = sign(a),
                if an int, can be lower(less) or higher(more) in order to
                detect and represent stringency (see self.data description
                above).
        @return: Value returned from validate method in factory sub-class
        @rtype: bool
        '''
        cmd = ["/usr/sbin/system_profiler", "SPConfigurationProfileDataType"]
        self.ch = CommandHelper(self.logger)
        if self.ch.executeCommand(cmd):
            self.output = self.ch.getOutput()
            retval = True
            if self.output:
                for k, v in self.data.iteritems():
                    retval = self.editor.validate(self.output, k, v)
                    if not retval:
                        return False
            else:
                debug = "There are no profiles installed"
                self.logger.log(LogPriority.DEBUG, debug)
                return False
        return True

    def updateProfiles(self):
        retval = self.editor.update()
        return retval
    def commit(self):
        if self.kvtype == "defaults" or self.kvtype == "profiles":
            retval = self.editor.commit()
            return retval
        else:
            retval = self.editor.commit()
            self.fixables = {}
            self.removeables = {}
            return retval

    def removekey(self, d, key):
        r = dict(d)
        del r[key]
        return r
