import os
import re
import pwd
import sys
import copy
import time
import shutil
import difflib
import filecmp
import inspect
import datetime
import optparse
import traceback

from distutils.version import LooseVersion

from logdispatcher import LogPriority as lp

class FileStateManager(object):
    '''Handles state management of files based on directory path.
    
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
        self.mode = "filecmp"
        self.version = None
        self.prefix = None
        self.backupPrefix = None

    def setMode(self, mode=''):
        '''Setter for the mode of differential checking

        :param mode:  (Default value = '')

        '''
        modes = ["unified", "ndiff", "filecmp"]
        if isinstance(mode, basestring) and mode in modes:
            self.mode = mode

    def getMode(self, mode=''):
        '''Getter for the mode of differential checking

        :param mode:  (Default value = '')

        '''
        return self.mode

    def setPrefix(self, prefix=''):
        '''Setter for the prefix used in building the compare path.

        :param prefix:  (Default value = '')

        '''
        success = False
        if isinstance(prefix, basestring) and self.isSaneFilePath(prefix):
            self.prefix = prefix
            #####
            # Move to a backup location if it isn't a directory and is a file.
            if not os.path.isdir(prefix) and os.path.isfile(prefix):
                newName = prefix + "-" + str(datetime.datetime.now().strftime("%Y%m%d.%H%M.%s"))
                shutil.move(prefix, newName)
            if not os.path.isdir(prefix):
                os.makedirs(prefix)
                success = True
            else:
                success = True
        return success

    def setBackupPrefix(self, prefix='', inspectLevel=1):
        '''Setter for the prefix used in building the compare path.

        :param prefix:  (Default value = '')
        :param inspectLevel:  (Default value = 1)

        '''
        success = False

        if not self.backupPrefix or not prefix:
            programFullPath = sys.argv[0]
            programName = programFullPath.split("/")[-1]
            programNameWithoutExtension = ".".join(programName.split(".")[:-1])
            version = self.getVersion()
            (_, inspectFileName, _, _, _, _) = inspect.getouterframes(inspect.currentframe())[inspectLevel]
            inspectFileName = ".".join(inspectFileName.split("/")[-1].split(".")[:-1])
            datestamp = datetime.datetime.now()
            stamp = datestamp.strftime("%Y%m%d.%H%M%S.%f")

            euid = os.geteuid()

            if euid == 0:
                userPrefix = "/var/db/"
            else:
                userInfo = pwd.getpwuid(euid)
                userHome = userInfo[5]
                userPrefix = userHome

            self.backupPrefix = userPrefix + \
                                "/" + programNameWithoutExtension + \
                                "/" + version + \
                                "/" + stamp + \
                                "/" + inspectFileName

        elif isinstance(prefix, basestring) and self.isSaneFilePath(prefix):
            self.backupPrefix = prefix

        #####
        # Move to a backup location if it isn't a directory and is a file.
        if not os.path.isdir(self.backupPrefix) and os.path.isfile(self.backupPrefix):
            newName = self.backupPrefix + "-" + str(datetime.datetime.now().strftime("%Y%m%d.%H%M.%s"))
            shutil.move(self.backupPrefix, newName)
        if not os.path.isdir(self.backupPrefix):
            try:
                os.makedirs(self.backupPrefix)
            except OSError:
                success = False
            else:
                success = True
        else:
            success = True

        return success

    def getPrefix(self):
        '''Getter for the prefix used in building the compare path.'''
        return self.prefix

    def setVersion(self, version=""):
        '''Setter for the version to check against)

        :param version:  (Default value = "")

        '''
        success = False
        lv = LooseVersion()
        if isinstance(version, basestring) and lv.component_re.match(version):
            self.version = version
            success = True
        return success

    def getVersion(self):
        '''Getter for the version to check against)'''
        return self.version

    def isSaneFilePath(self, filepath):
        '''Check for a good file path in the passed in string.
        
        @author: Roy Nielsen

        :param filepath: 

        '''
        sane = False
        if isinstance(filepath, basestring):
            if re.match("^[A-Za-z0-9/.][A-Za-z0-9/_.\-]*", filepath):
                sane = True
        self.logger.log(lp.DEBUG, "sane: " + str(sane))
        return sane

    def warnOfMissMatch(self, message=''):
        '''Build a warning string for reporting purposes.

        :param message:  (Default value = '')

        '''
        pass

    def getLatestStatePath(self, state=''):
        '''Get the path to the latest version of a specified state.

        :param state:  (Default value = '')

        '''
        statePath = ''
        stateSearchList = self.buildSearchList([state])
        for state in stateSearchList:
            if os.path.exists(state):
                statePath = state
                break
        return state

    def getLatestFileSet(self, state=''):
        '''Get the latest file set from a specific state.

        :param state:  (Default value = '')

        '''
        fileList = []
        lastState = ''
        #####
        # Input validation
        if state and self.isSaneFilePath(state):
            ######
            # build a state list
            scratchStateList = self.buildSearchList([state])
            self.logger.log(lp.DEBUG, "available states: " + str(scratchStateList))
            #####
            # Find the latest existing state in the state list
            for state in scratchStateList:
                if os.path.exists(state):
                    lastState = state
                    break

            statePathLength = len(lastState.split("/"))
            pathStart = statePathLength

            #####
            # collect the files from that state
            for (dirPath, dirnames, filenames) in os.walk(lastState):
                for filename in filenames:
                    pathItem = dirPath + "/" + filename
                    self.logger.log(lp.DEBUG, pathItem)
                    pathItemList = pathItem.split("/")[pathStart:]
                    pathItem = "/" + "/".join(pathItemList)
                    fileList.append(pathItem)

            self.logger.log(lp.DEBUG, "fileList: " + str(fileList))
        return lastState, fileList



    def buildTextFilesOutput(self, files=[]):
        '''

        :param files:  (Default value = [])

        '''
        isValid = []
        text = ""
        if isinstance(files, list):
            for filename in files:
                if isinstance(filename, list):
                    isValid.append(True)
                else:
                    isValid.append(False)
            if False not in isValid:
                text += "File states do not match.\n========================"
                i = 0
                for itemList in files:
                    if i == 0:
                        text += "Expected state of files:\n ---------\n"
                    elif i == 1:
                        text += " ------------------\nCurrent state of files:\n ---------\n"
                    elif i == 2:
                        text += " ------------------\nFactory state of files:\n ---------\n"
                    for item in itemList:
                        text += item + "\n-------"
                        itemFp = open(item, 'r')
                        text = itemFp.read()
        return text

    def buildHtmlFilesOutput(self, files=[]):
        '''

        :param files:  (Default value = [])

        '''
        pass

    def acquireReferenceFilesSets(self, afterState='', beforeState=''):
        '''Get three files lists.  First, the expected state, second the current
        state, third the passed in 'before' state.

        :param afterState:  (Default value = '')
        :param beforeState:  (Default value = '')

        '''
        latestAfterState, self.afterStateFiles = self.getLatestFileSet(afterState)

        referenceFiles = copy.deepcopy(self.afterStateFiles)
        currentFiles = []
        for filename in referenceFiles:
            currentFile = re.sub(latestAfterState, '', filename)
            currentFiles.append(currentFile)

        latestBeforeState, self.afterStateFiles = self.getLatestFileSet(beforeState)

        return latestAfterState, currentFiles, latestBeforeState

    def isKnownStateMatch(self, targetStateFile='', fileName=''):
        '''Checks the state of filename (full path to a file) against
        <metaState>/<filename>, where metaState is the path to a mirror
        of the full path file name provided.  The metaState is described below.

        :param targetStateFile:  (Default value = '')
        :param fileName:  (Default value = '')

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
        '''Are all files in the list in a known metaState

        :param metaState:  (Default value = '')
        :param files:  (Default value = [])

        '''
        success = False
        filesState = []
        self.logger.log(lp.DEBUG, "metaState: " + str(metaState)) 
        self.logger.log(lp.DEBUG, "files: " + str(files))
        if files:
            for item in files:
                success = False
                if os.path.exists(item) and os.path.exists(metaState + item):
                    success = filecmp.cmp(metaState + item, item)
                    filesState.append(success)
                else:
                    filesState.append(False)
    
            if False in filesState:
                success = False
            else:
                success = True

        return success

    def areFilesInStates(self, states=[], files=[]):
        '''Make sure all files in the files list identify as from the same list.

        :param states:  (Default value = [])
        :param files:  (Default value = [])

        '''
        success = False
        filesState = []
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
        '''Check Item State, will check for the latest known good state, by way
        of the fromState, and current version of the application using this
        library, then iterate backwards through known good versions defined by
        the directory path in the class header.

        :param states:  (Default value = [])
        :param fileName:  (Default value = '')

        '''
        success = False
        metaState = None
        version = self.getVersion()

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

    def backupFile(self, fileName='', inspectIndex=2):
        '''

        :param fileName:  (Default value = '')
        :param inspectIndex:  (Default value = 2)

        '''
        self.logger.log(lp.DEBUG, "Entering backupFile...")
        success = False
        if fileName and os.path.exists(fileName):
            if not self.backupPrefix:
                self.setBackupPrefix()
            backupFile = self.backupPrefix + fileName
            backupDir = os.path.dirname(backupFile)
            self.logger.log(lp.DEBUG, "backupDir: " + str(backupDir))
            if os.path.isfile(backupDir) and not os.path.isdir(backupDir):
                newfile = backupDir + "-" + str(datetime.datetime.now().strftime("%Y%m%d.%H%M.%s"))
                shutil.move(backupDir, newfile)

            if not os.path.exists(backupDir):
                try:
                    os.makedirs(backupDir)
                except OSError:
                    self.logger.log(lp.DEBUG, "Unable to make: " + str(backupDir))
            try:
                shutil.copy2(fileName, backupFile)
            except OSError:
                self.logger.log(lp.DEBUG, "Unable to make a backup: " + str(backupFile))
            else:
                success = True
        self.logger.log(lp.DEBUG, "Exiting backupFile...")            
        return success
    
    def changeFileState(self, fromMetaState='', fileName=''):
        '''Change the file state from the "fromState" to the fileName.

        :param fromMetaState:  (Default value = '')
        :param fileName:  (Default value = '')

        '''
        success = False

        if not os.path.exists(fileName):
            try:
                shutil.copy2(fromMetaState, fileName)
            except shutil.Error, err:
                self.logger.log(lp.INFO, "Error copying file from reference state.")
                self.logger.log(lp.DEBUG, traceback.format_exc(err))
            else:
                success = True
        elif not filecmp.cmp(fromMetaState, fileName):
            self.backupFile(fileName)
            try:
                shutil.copy2(fromMetaState, fileName)
            except shutil.Error, err:
                self.logger.log(lp.INFO, "Error copying file from reference state.")
                self.logger.log(lp.DEBUG, traceback.format_exc(err))
            else:
                success = True

            #####
            # May need to set correct permissions here . . .

        return success

    def changeFilesState(self, fromMetaState='', files=[]):
        '''Change the file state from the "fromState" to the fileName.

        :param fromMetaState:  (Default value = '')
        :param files:  (Default value = [])

        '''
        success = False
        copyResults = []
        self.logger.log(lp.DEBUG, "fromMetaState: " + str(fromMetaState))
        self.logger.log(lp.DEBUG, "files: " + str(files))
        if not self.backupPrefix:
            self.setBackupPrefix()
        for item in files:
            self.backupFile(item)
            if not os.path.exists(item):
                try:
                    shutil.copy2(fromMetaState + item, item)
                except OSError, err:
                    self.logger.log(lp.INFO, "Error copying file from reference state.")
                    self.logger.log(lp.DEBUG, traceback.format_exc(err))
                    copyResults.append(False)
                else:
                    copyResults.append(True)

            elif not filecmp.cmp(fromMetaState + item, item):
                try:
                    shutil.copy2(fromMetaState + item, item)
                except OSError, err:
                    self.logger.log(lp.INFO, "Error copying file from reference state.")
                    self.logger.log(lp.DEBUG, traceback.format_exc(err))
                    copyResults.append(False)
                else:
                    copyResults.append(True)
            else:
                self.logger.log(lp.DEBUG, "File doesn't need to be copied...")

            #####
            # May need to set correct permissions here . . .

        if False in copyResults:
            success = False
        else:
            success = True

        return success

    def buildSearchList(self, states=[], map=''):
        '''Use predefined prefix, version along with the state and filename
        to build a list of potential meta-states, sorted by version number.

        :param states:  (Default value = [])
        :param map:  (Default value = '')

        '''
        versions = []
        fullPath = ''
        states2check = []
        listing = os.listdir(self.prefix)
        self.logger.log(lp.DEBUG, "listing: " + str(listing))
        self.logger.log(lp.DEBUG, "states: " + str(states))
        self.logger.log(lp.DEBUG, "map: " + str(map))
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
                self.logger.log(lp.DEBUG, "item: " + str(item))
                for state in states:
                    self.logger.log(lp.DEBUG, "item: " + item + " state: " + state)
                    fullPath = self.prefix + "/" + item + "/" + state
                    self.logger.log(lp.DEBUG, "fullPath: " + str(fullPath))
                    if os.path.isdir(fullPath):
                        states2check.append(fullPath)
                        self.logger.log(lp.DEBUG, "Adding: " + str(fullPath) + " to the list . . .")
                        self.logger.log(lp.DEBUG, "states2check: " + str(states2check))
                    else:
                        self.logger.log(lp.DEBUG, "Damn it Jim!!!")
        else:
            self.logger.log(lp.DEBUG, "Variables invalid...")
        #####
        # reverse the array so the latest version is first - valid since
        # python 2.3.5
        reverseStates = states2check[::-1]
        self.logger.log(lp.DEBUG, "reverse: " + str(reverseStates))
        states2check = reverseStates
        return states2check

    #--------------------------------------------------------------------------
    # Quick sort algorithm for sorting a list of version number as defined by
    # the distutils.version.LooseVersion
    def partition(self, data=[], pivot=""):
        '''Partitioning data based on the passed in pivot value.  Partition defined
        from the generic computer science QSORT algorithm varient.

        :param data:  (Default value = [])
        :param pivot:  (Default value = "")

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
        '''Generic computer science QSORT divide and conquer algorithm.

        :param data:  (Default value = [])

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
