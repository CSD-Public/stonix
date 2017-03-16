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

    def getMode(self, mode=''):
        '''
        Getter for the mode of differential checking
        '''
        return self.mode

    def setPrefix(self, prefix=''):
        '''
        Setter for the prefix used in building the compare path.
        '''
        if isinstance(prefix, basestring):
            self.prefix = prefix

    def getPrefix(self, prefix=''):
        '''
        Getter for the prefix used in building the compare path.
        '''
        return self.prefix

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

    def getVersion(self):
        '''
        Getter for the version to check against)
        '''
        return self.version

    def isSaneFilePath(self, filepath):
        """
        Check for a good file path in the passed in string.
        
        @author: Roy Nielsen
        """
        sane = False
        if isinstance(filepath, basestring):
            if re.match("^[A-Za-z0-9/.][A-Za-z0-9/_.\-]*", filepath):
                sane = True
        self.logger.log(lp.DEBUG, "sane: " + str(sane))
        return sane

    def warnOfMissMatch(self, message=''):
        '''
        Build a warning string for reporting purposes.
        '''
        pass

    def isKnownStateMatch(self, targetStateFile='', fileName=''):
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
            fromFile = targetStateFile
            if self.isSaneFilePath(targetStateFile):
                toFile = fileName
        self.logger.log(lp.DEBUG, "targetStateFile: " + str(fromFile) + " fileName: " + str(toFile))
        
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

    def areFilesInState(self, metaState='', files=[]):
        '''
        Are all files in the list in a known metaState
        '''
        success = False
        filesState = []
        
        for item in files:
            success = False
            success = filecmp.cmp(metaState + item, item)
            filesState.append(success)

        if False in filesState:
            success = False
        else:
            success = True

        return success

    def areFilesInStates(self, states=[], files=[]):
        '''
        Make sure all files in the files list identify as from the same list.
        '''
        success = False
        filesState = []
        state_search = {}
        thisState = False
        stateListItem = ""

        for state in states:
            state_search = self.buildSearchList(states=[state])
            for stateListItem in state_search:
                for fileName in files:
                    thisState, _ = self.isKnownStateMatch(stateListItem + fileName, fileName)
                    filesState.append(thisState)
                self.logger.log(lp.DEBUG, "filesState: " + str(filesState))
                if False in filesState:
                    filesState = []
                    continue
                else:
                    filesState = []
                    success = True
                    break
            if success is True:
                break
            else:
                filesState = []
        self.logger.log(lp.DEBUG, "areFilesInStates: " + str(success) + " " + str(stateListItem))
        return success, stateListItem

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

        inStates = False

        stateCheckList = self.buildSearchList(states, fileName)

        self.logger.log(lp.DEBUG, "stateCheckList: " + str(stateCheckList))

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

    def changeFileState(self, fromMetaState='', fileName=''):
        '''
        Change the file state from the "fromState" to the fileName.

        @param: fromState - known good reference state of a file.
        @param: filename - the name of the filename to change.

        @author: Roy Nielsen
        '''
        success = False

        if not filecmp.cmp(fromMetaState, fileName):
            try:
                shutil.copy2(fromMetaState, fileName)
                success = True
            except OSError, err:
                self.logger.log(lp.INFO, "Error copying file from reference state.")
                self.logger.log(lp.DEBUG, traceback.format_exc(err))

            #####
            # May need to set correct permissions here . . .

        return success

    def changeFilesState(self, fromMetaState='', files=''):
        '''
        Change the file state from the "fromState" to the fileName.

        @param: fromState - known good reference state of a file.
        @param: filename - the name of the filename to change.

        @author: Roy Nielsen
        '''
        success = False

        for item in files:
            if not filecmp.cmp(fromMetaState + item, item):
                try:
                    shutil.copy2(fromMetaState + item, item)
                    success = True
                except OSError, err:
                    self.logger.log(lp.INFO, "Error copying file from reference state.")
                    self.logger.log(lp.DEBUG, traceback.format_exc(err))

                #####
                # May need to set correct permissions here . . .

        return success

    def buildSearchList(self, states=[], map=""):
        """
        Use predefined prefix, version along with the state and filename
        to build a list of potential meta-states, sorted by version number.

        @param: state - a state to use to create a list of possible meta states

        @author: Roy Nielsen
        """
        versions = []
        states2check = []
        listing = os.listdir(self.prefix)
        
        if listing and states and map:
            #####
            # create the search list of states for a specific file map
            self.logger.log(lp.DEBUG, "listing: " + str(listing))
            #####
            # Validate that only directory names are in the list
            for item in listing:
                if os.path.isdir(self.prefix + "/" + item):
                    versions.append(item)
            #####
            # Sort the version list
            sorted = self.qsort(versions)
            self.logger.log(lp.DEBUG, "sorted: " + str(sorted))

            #####
            # Create a new list only with valid files out of the versions
            # and states list, with the file map.
            for item in sorted:
                for state in states:
                    self.logger.log(lp.DEBUG, "item: " + item + " state: " + state)
                    fullPath = self.prefix + "/" + item + "/" + state + map
                    self.logger.log(lp.DEBUG, "fullPath: " + str(fullPath))
                    try:
                        if os.path.isfile(fullPath):
                            states2check.append(fullPath)
                    except OSError:
                        continue
        elif listing and states and not map:
            #####
            # Just need a metaState list, without the map...
            self.logger.log(lp.DEBUG, "listing: " + str(listing))
            #####
            # Validate that only directory names are in the list
            for item in listing:
                if os.path.isdir(self.prefix + "/" + item):
                    versions.append(item)
            #####
            # Sort the version list
            sorted = self.qsort(versions)
            self.logger.log(lp.DEBUG, "sorted: " + str(sorted))

            #####
            # Create a new list only with valid files out of the versions
            # and states list, WITHOUT the file map.
            for item in sorted:
                for state in states:
                    self.logger.log(lp.DEBUG, "item: " + item + " state: " + state)
                    fullPath = self.prefix + "/" + item + "/" + state
                    self.logger.log(lp.DEBUG, "fullPath: " + str(fullPath))
                    try:
                        if os.path.isdir(fullPath):
                            states2check.append(fullPath)
                    except OSError:
                        continue

        #####
        # reverse the array so the latest version is first - valid since
        # python 2.3.5
        states2check = states2check[::-1]
        return states2check

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
    # Quick sort algorithm for sorting a list of version number as defined by
    # the distutils.version.LooseVersion
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
        Generic computer science QSORT divide and conquer algorithm.
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
