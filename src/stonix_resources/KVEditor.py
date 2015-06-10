'''
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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
import os
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
###############################################################################
    def __init__(self,stchlgr,logger,kvtype,path,tmpPath,data,intent="",
                                                                configType=""):
        self.kvtype = kvtype
        self.path = path
        self.tmpPath = tmpPath
        self.logger = logger
        self.configType = configType
        self.data = data
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
                return False
            self.editor = KVATaggedConf.KVATaggedConf(self.path,self.tmpPath,
                                       self.intent,self.configType,self.logger)
            return True
        elif self.kvtype == "conf":
            if not self.getPath:
                return False
            self.editor = KVAConf.KVAConf(self.path,self.tmpPath,self.intent,
                                                   self.configType,self.logger)
            return True
        elif self.kvtype == "defaults":
            self.editor = KVADefault.KVADefault(self.path,self.logger,self.data)
            return True
        else:
            self.detailedresults = "Not one of the supported kveditor types"
            self.logger.log(LogPriority.DEBUG,
                                    ["KVEditor.__init__",self.detailedresults])
            return False
###############################################################################
    def setData(self,data):
        if data == None:
            return False
        elif data == "":
            return False
        else:
            self.data = data
            return True
###############################################################################
    def getData(self):
        return self.data
###############################################################################
    def updateData(self,data):
        self.data = data
###############################################################################
    def setIntent(self,intent):
        if intent == "present":
            self.intent = intent
            self.editor.setIntent(intent)
            return True
        elif intent == "notpresent":
            self.intent = intent
            self.editor.setIntent(intent)
            return True
        else:
            return False
###############################################################################
    def getIntent(self):
        return self.intent
###############################################################################
    def setPath(self,path):
        if not os.path.exists(path):
            self.detailedresults = "File path does not exist"
            self.logger.log(LogPriority.INFO,["KVEditor",self.detailedresults])
            return False
        else:
            self.path = path
            return True
###############################################################################
    def getPath(self):
        if not os.path.exists(self.path):
            self.detailedresults = "File path does not exist"
            self.logger.log(LogPriority.INFO,["KVEditor",self.detailedresults])
            return False
        else:
            return self.path
###############################################################################
    def setTmpPath(self,tmpPath):
        self.tmpPath = tmpPath
        return True
###############################################################################
    def getTmpPath(self):
        return self.tmpPath
###############################################################################
    def setType(self,kvtype):
        '''implementer must use one of the following four strings to 
        instantiate the corresponding class: tagconf,conf,plist,defaults'''
        self.kvtype = kvtype
        return True
###############################################################################
    def validate(self):
        try: 
            if self.kvtype == "defaults":
                status = self.validateDefaults()
            elif self.kvtype == "plist":
                status = self.validatePlist()
            elif self.kvtype == "conf":
                status = self.validateConf()
            elif self.kvtype == "tagconf":
                status = self.validateTag()
            else:
                status = "invalid"
            return status
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
###############################################################################
    def update(self):
        try:
            if self.kvtype == "defaults":
                status = self.updateDefaults()
            elif self.kvtype == "plist":
                status = self.updatePlist()
            elif self.kvtype == "conf":
                status = self.updateConf()
            elif self.kvtype == "tagconf":
                status = self.updateTag()
            else:
                return False
            return status
        except(KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
###############################################################################
    def validateDefaults(self):
        if isinstance(self.data,dict):
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
            return True
        else:
            return False
    
    def checkDefaults(self,data):
        for k, v in data.iteritems():  
            if isinstance(v, dict):
                retval = self.checkDefaults(v)
                return retval
            elif isinstance(v,list):
                if len(v) == 2 or len(v) == 3:
                    return True
                else:
                    return False
            else:
                return False
    def setCurrentHostbool(self,val):
        self.editor.currentHost = val
###############################################################################
    def validateConf(self):
        validate = True
        if not self.checkConf():
            return False
        if self.intent == "present":
            for k, v in self.data.iteritems():
                retval = self.editor.validate(k, v)
                if isinstance(retval, list):
                    self.fixables[k] = retval
                    validate = False
                elif not self.editor.validate(k, v):
                    validate = False
                    self.fixables[k] = v
        if self.intent == "notpresent":
            for k, v in self.data.iteritems():
                retval = self.editor.validate(k, v)
                if isinstance(retval, list):
                    self.removeables[k] = retval
                    validate = False
                elif retval is True:
                    validate = False
                    self.removeables[k] = v
        return validate
###############################################################################
    def updateConf(self):
        if self.fixables or self.removeables:
            if self.editor.update(self.fixables,self.removeables):
                return True
###############################################################################
    def checkConf(self):
        if isinstance(self.data,dict):
            return True
        else:
            return False
###############################################################################
    def validateTag(self):
        validate = True
        self.fixables = {}
        keyvals = {}
        if not self.checkTag():
            return False
        if self.intent == "present":
            for tag in self.data:
                #self.editor.getTagValue(tag, self.data[tag])
                keyvals = self.editor.getValue(tag, self.data[tag])
                if keyvals == "invalid":
                    return "invalid"
                elif keyvals:
                    self.fixables[tag] = keyvals
                    validate = False
        if self.intent == "notpresent":
            for tag in self.data:
                keyvals = self.editor.getValue(tag,self.data[tag])
                if keyvals == "invalid":
                    return "invalid"
                elif keyvals:
                    self.removeables[tag] = keyvals
                    validate = False
        return validate
            
    def updateTag(self):
        if self.editor.setValue(self.fixables,self.removeables):
            return True
        
    def checkTag(self):
        if isinstance(self.data,dict):
            for tag in self.data:
                if not isinstance(self.data[tag],dict):
                        return False
            return True
        else:
            return False
###############################################################################
    def commit(self):
        if self.kvtype == "defaults":
            retval = self.editor.commit()
            return retval
        else:
            retval = self.editor.commit()
            self.fixables = {}
            self.removeables = {}
            return retval
###############################################################################
    def removekey(self,d, key):
        r = dict(d)
        del r[key]
        return r
