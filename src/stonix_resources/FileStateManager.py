import os
import re
import sys
import time
import shutil
import difflib
import filecmp
import optparse
import traceback

from distutils.version import LooseVersion

from logdispatcher import LogPriority as lp

class FileStateManager(object):
    '''
    Handles state management of files based on directory path.

    Directory path is based on:

    <prefix>/<version>/<state>/<map>

    prefix: root of location to look for file states
    version: version of the software managing the state
    state: Name of state to compare against
    map: In the case of this state manager, is the file
         path to the file relative to the root oirectory of
         tile to compare against.

    each of the above variables  is based on a 'mode' or
    recipe provided by the class for building that 
    variable.  For instance, the <state> variable may contain
    both an OS version and an actual state to check.

    please see the setMode method for more information on
    this class's building of these variables.

    '''

    def __init__(self, environ, logger):
        '''
        Initialization method

        '''
        self.environ = environ
        self.logger = logger
        self.mode = None
        self.version = None

    def setMode(self, mode=''):
        '''
        Setter for the mode of differential checking
        '''
        modes = ["unified", "ndiff", "filecmp"]
        if isinstance(mode, basestring) and mode in modes:
            self.mode = mode

    def setPrefix(self, prefix=''):
        '''
        Setter for the prefix used in building the compare path.
        '''
        if isinstance(prefix, basestring):
            self.prefix = prefix

    def setVersion(self, version=""):
        '''
        Setter for the version to check against)
        '''
        success = False
        lv = LooseVersion()
        if isinstance(version, basestring) and lv.component_re.match(version):
            self.version = version
            success = True
        return success
    
    def isSaneFilePath(self, filepath):
        """
        Check for a good file path in the passed in string.
        
        @author: Roy Nielsen
        """
        sane = False
        if isinstance(filepath, basestring):
            if re.match("^[A-Za-z0-9./][A-Za-z0-9/_.\-]*", filepath):
                sane = True
        return sane

    def warnOfMissMatch(self, message=''):
        '''
        Build a warning string for reporting purposes.
        '''
        pass

    def isKnownStateMatch(self, metaState='', fileName=''):
        '''
        Checks the state of filename (full path to a file) against 
        <metaState>/<filename>, where metaState is the path to a mirror
        of the full path file name provided.  The metaState is described below.
        
        @param: metaState - Instead of where the description of the file path 
        is as in the header for the class:
            Directory path is based on:

            <prefix>/<version>/<state>/<map>

        the metaState must equal the combination of <prefix>/<version>/<state>
        @param: fileName - full path to a filename to check the state of.

        @author: Roy Nielsen
        '''
        fromFile = ""
        toFile = ""
        diff = None
        isSame = False
        if self.isSaneFilePath(fileName):
            fromFile = metaState + fileName
            if self.isSaneFilePath(metaState):
                toFile = fileName
        self.logger.log(lp.DEBUG, "metaState: " + str(fromFile) + " fileName: " + str(toFile))
        
        if fromFile and toFile and os.path.exists(fromFile) and os.path.exists(toFile):
            if re.match("^filecmp$", self.mode):
                #####
                # Check the two files, performing a filecomp.
                isSame = filecmp.cmp(fromFile, toFile)
            elif re.match("^unified$", self.mode) or re.match("^ndiff$", self.mode):
                #####
                # Setup to perform the diff
                # we're passing these as arguments to the diff function
                fromdate = time.ctime(os.stat(fromFile).st_mtime)
                todate = time.ctime(os.stat(toFile).st_mtime)
                fromlines = open(fromFile, 'U').readlines()
                tolines = open(toFile, 'U').readlines()
                if re.match("^unified$", self.mode):
                    lines = len(fromlines)
                    diff = difflib.unified_diff(fromlines, tolines, fromFile, toFile,
                                                fromdate, todate, n=lines)
                elif re.match("^ndiff$", self.mode): 
                    diff = difflib.ndiff(fromlines, tolines)
                if diff is not None and not diff:
                    #####
                    # String is NOT empty, so we have a match
                    isSame = False
                    self.logger.log(lp.DEBUG, "Found a diff: '" + str(diff) + "'")
                else:
                    #####
                    # String is empty, so we have a match
                    isSame = True 
                    self.logger.log(lp.DEBUG, "Found a diff: '" + str(diff) + "'")
        self.logger.log(lp.DEBUG, "isSame: " + str(isSame))
        self.logger.log(lp.DEBUG, "diff:   " + str(diff))
        return isSame, diff

    def areFilesInStates(self, states[], files=[]):
        '''
        Make sure all files in the files list identify as from the same list.
        '''
        success = False
        allMeta = []
        for fileName in files:
            allMeta.append(self.checkStateOfFile(fromState, toState, fileName))
        try:
            fileRef = allMeta[0]
        except KeyError, err:
            self.logger.log(lp.DEBUG, "Error attempting to acquire reference.")
            self.logger.log(lp.DEBUG, traceback.format_exc(err))
        else:
            try:
                if allMeta[1:] == allMeta[:-1]:
                    metaStateFound = allMeta[0]
                    success = True
            except KeyError, err:
                self.logger.log(lp.DEBUG, "Error attempting to acquire references.")
                self.logger.log(lp.DEBUG, traceback.format_exc(err))
        return success, metaStateFound

    def isFileInStates(self, states=[], fileName=''):
        '''
        Check Item State, will check for the latest known good state, by way
        of the fromState, and current version of the application using this
        library, then iterate backwards through known good versions defined by
        the directory path in the class header.  
        
        @param: fromState - first expected known good state to check.  
        @param: toState - expected state based on passed in state and 
                          application version.
        @param: filename - full path to a file on the filesystem.

        @author: Roy Nielsen
        '''
        success = False
        metaState = None
        self.version = self.getVersion()

        if isinstance(states, list):
            for state in states:
                if isinstance(state, basestring) and state and self.isSaneFilePath(state):

                toMetaState = self.prefix + "/" + str(self.getVersion()) + "/" + toState
                self.logger.log(lp.DEBUG, "toMetaStat: " + str(toMetaState))
                toFileState = toMetaState + fileName
                
                #####
                # Check to state first
                success, metaStateFound = self.isKnownStateMatch(toMetaState, fileName)
                if not success:
                    fromVersionsList = self.buildSearchList(fromState)
                    toVersionsList = self.buildSearchList(toState)
                    stateCheckList = fromVersionsList + toVersionsList
    
                    for check in stateCheckList:
                        #####
                        # Find the first state in the sorted list
                        isSame, diff = self.isKnownStateMatch(check, fileName)
                        if isSame:
                            metaState = check
                            success = True
                            break
        
        self.logger.log(lp.DEBUG, "Success: " + str(success))
        self.logger.log(lp.DEBUG, "metaState: " + str(metaState))
        return success, metaState

    def changeFileState(self, fromState='', fileName=''):
        '''
        Change the file state from the "fromState" to the fileName.  
        
        @param: fromState - known good reference state of a file.
        @param: filename - the name of the filename to change.

        @author: Roy Nielsen
        '''
        success = False
        
        if not filecmp.cmp(fromState, fileName):
            try:
                shutil.copy2(fromState, fileName)
                success = True
            except OSError, err:
                self.logger.log(lp.INFO, "Error copying file from reference state.")
                self.logger.log(lp.DEBUG, traceback.format_exc(err))

            #####
            # May need to set correct permissions here . . .

        return success
            
    def buildSearchList(self, states=[]):
        """
        Use predefined prefix, version along with the state and filename
        to build a list of potential meta-states, sorted by version number.

        @param: state - a state to use to create a list of possible meta states

        @author: Roy Nielsen
        """
        versions = []
        listing = os.listdir(self.prefix)
        
        if listing:
            self.logger.log(lp.DEBUG, "listing: " + str(listing))
            for item in listing:
                if os.path.isdir(self.prefix + "/" + item):
                    versions.append(item)
            sorted = self.qsort(versions)
            self.logger.log(lp.DEBUG, "versions: " + str(sorted))
            versions = []
            for item in sorted:
                versions.append(self.prefix + "/" + item + "/" + state)
        return versions

    def getVersion(self):
        '''
        Acquire the version of the application using this library.
        
        @author: Roy Nielsen
        '''
        if self.version is None:
            #####
            # Acquire the version of the application from the "environment"
            self.version = self.environ.getstonixversion()
        return self.version

    #--------------------------------------------------------------------------
    # Qsort algorithm for sorting a list of version number as defined by the
    # distutils.version.LooseVersion
    def partition(self, data=[], pivot=""):
        '''
        Partitioning data based on the passed in pivot value.  Partition defined
        from the generic computer science QSORT algorithm varient.

        @param: data - the data to sort.  Expected data must be a string that
                       looks like a version number as defined by:
                       distutils.version.LooseVersion
        @param: pivot - a list value as determined by the calling method/function.
        '''
        self.logger.log(lp.DEBUG, "data: " + str(data))
        self.logger.log(lp.DEBUG, "pivot: " + str(pivot))
        less, equal, greater = [], [], []
        if isinstance(pivot, basestring) and isinstance(data, list):
            for version in data:
                if LooseVersion(version) < LooseVersion(pivot): less.append(version)
                if LooseVersion(version) == LooseVersion(pivot): equal.append(version)
                if LooseVersion(version) > LooseVersion(pivot): greater.append(version)
        else:
            self.logger.log(lp.DEBUG, "DAMN IT JIM!!!")
        self.logger.log(lp.DEBUG, "less   : " + str(less))
        self.logger.log(lp.DEBUG, "equal  : " + str(equal))
        self.logger.log(lp.DEBUG, "greater: " + str(greater))
        return less, equal, greater
    
    def qsort(self, data=[]):
        '''
        Generic computer science QSORT algorithm.
        '''
        success = False
        less = ['0']
        equal = ['0']
        greater = ['0']
        if len(data) <= 1:
            return data
        else:
            pivot = data[0]
            less, equal, greater = self.partition(data, pivot)
            
            return self.qsort(less) + equal + self.qsort(greater)
        return success

    #--------------------------------------------------------------------------



