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
Created on Dec 13, 2011


@author: dkennel
'''

import os
import re
from logdispatcher import LogPriority


class ConfFile(object):
    '''
    The Conffile class is designed to handle common tasks involved in opening,
    saving, auditing and correcting the contents of common Unix configuration
    files. This class can handle a few different variants of config files and
    the specific variant can be specified when the conffile object is
    instantiated.

    @author: D. Kennel
    '''

    def __init__(self, filename, tempfile, filetype, directives, environment,
                 logdispatcher):
        '''
        Constructor

        The filetype parameter is an enum. Current valid options are:
        openeq - for files whose lines are in the format; "key = value\n"
        closedeq - for files formatted; "key=value\n"
        space - for files formatted; "key value\n"

        @param filename: String, full path to the config file
        @param tempfile: String, full path to the temp version of the file
        @param filetype: String, style of config file
        @param directives: Dict, dictionary of required directives in
            key: value format. Keys and values must be strings.
        @param environment: An instance of the STONIX environment object
        @author: D. Kennel
        '''
        validtypes = ['openeq', 'closedeq', 'space']
        self.comment = re.compile('^#')
        self.filename = filename
        self.tempfile = tempfile
        self.filetype = filetype
        if self.filetype not in validtypes:
            raise
        self.directives = directives
        self.environment = environment
        self.logger = logdispatcher
        self.present = os.path.exists(filename)
        self.filedata = []
        if self.present:
            try:
                rhandle = open(self.filename, 'r')
                self.filedata = rhandle.readlines()
                rhandle.close()
            except(IOError, OSError):
                self.logger.log(LogPriority.INFO,
                                ['ConfFile',
                                 self.filename + ' could not be read!'])
                self.logger.log(LogPriority.INFO,
                                ['ConfFile',
                                 'Setting file present to false and using null file data'])
                self.present = False
                self.filedata = []

    def audit(self):
        '''
        Audit() This method will check the currently loaded file data for all
        of the directives in the passed directives dictionary.

        @return: Bool - True if all directives/values were found
        @author: D. Kennel
        '''
        compliant = True
        pattern = 'BOGUSdefaultPATTERN'
        patternlist = []
        for directive in self.directives:
            pattern = 'BOGUSdefaultPATTERN'
            if self.filetype == 'openeq':
                pattern = directive + ' = ' + self.directives[directive] + '\n'
            if self.filetype == 'closedeq':
                pattern = directive + '=' + self.directives[directive] + '\n'
            if self.filetype == 'space':
                pattern = directive + ' ' + self.directives[directive] + '\n'
            patternlist.append(pattern)
        for pattern in patternlist:
            if pattern not in self.filedata:
                compliant = False
                self.logger.log(LogPriority.INFO,
                                ['ConfFile', 'Directive not found: ' + pattern])
        return compliant

    def fix(self):
        '''
        Fix() This method will set all directives specified in the dictionary as
        the current values in the working configuration set. This action
        does not change the file on disk. The writefile method must be called
        to change the file on disk.

        @author: D. Kennel
        '''
        for directive in self.directives:
            newconf = []
            found = False
            # Set up a pattern match to find the config item
            pattern = '^' + directive + ' = '
            if self.filetype == 'openeq':
                pattern = '^' + directive + ' = '
            if self.filetype == 'closedeq':
                pattern = '^' + directive + '='
            if self.filetype == 'space':
                pattern = '^' + directive

            # Set up the line we want
            if self.filetype == 'openeq':
                newline = directive + ' = ' + self.directives[directive] + '\n'
            if self.filetype == 'closedeq':
                newline = directive + '=' + self.directives[directive] + '\n'
            if self.filetype == 'space':
                newline = directive + ' ' + self.directives[directive] + '\n'

            for line in self.filedata:
                if self.comment.match(line):
                    pass
                elif re.search(pattern, line):
                    found = True
                    if line != newline:
                        line = newline
                newconf.append(line)
            if not found:
                newconf.append(newline)
            self.filedata = newconf

    def reread(self):
        '''
        Reread
        '''
        if self.present:
            try:
                rhandle = open(self.filename, 'r')
                self.filedata = rhandle.readlines()
                rhandle.close()
            except(IOError, OSError):
                self.logger.log(LogPriority.INFO,
                                ['ConfFile',
                                 self.filename + ' could not be read!'])
                self.logger.log(LogPriority.INFO,
                                ['ConfFile',
                                 'Setting file present to false and using null file data'])
                self.present = False
                self.filedata = []

    def ispresent(self):
        '''
        IsPresent
        '''
        return self.present

    def getfiledata(self):
        '''
        GetFileData
        '''
        return self.filedata

    def setfiledata(self, filedata):
        '''
        SetFileData

        @param filedata: List with embedded newlines
        '''
        self.filedata = filedata

    def setDirectives(self, directives):
        '''
        SetDirectives(directives) This method in concert with getfiledata and
        setfiledata can be used for advanced usage scenarios. E.G. processing
        one file with two different set of directives.

        @param directives: Dict, dictionary of required directives in
            key: value format. Keys and values must be strings.
        @author: dkennel
        '''
        self.directives = directives

    def writefile(self):
        '''
        WriteFile
        '''
        whandle = open(self.tempfile, 'w')
        for line in self.filedata:
            whandle.write(line)
        whandle.close()
