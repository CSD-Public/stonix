#!/usr/bin/python -u
"""
Create a "module" version stamp, sed a file with it.

To maintain module versions.

@author: Roy Nielsen
"""
from __future__ import absolute_import

import os
import re
import sys
import argparse
from datetime import datetime

from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp

class SedFile4VersionStamp(object):
    def __init__(self, files=[], logger=False):
        if not logger:
            self.logger = CyLogger()
            self.logger.initializeLogs()
        else:
            self.logger = logger
        self.acquireStamp()
        self.module_version = '20160224.032043.009191'
        if files:
            for myfile in files:
                self.sedFileWithDateTimeStamp(myfile)

    def acquireStamp(self):
        """
        Get the UTC time and format a time stamp string for the version.

        @author: Roy Nielsen
        """
        format = ""
        datestamp = datetime.utcnow()
        
        self.stamp = datestamp.strftime("%Y%m%d.%H%M%S.%f")
        self.logger.log(lp.DEBUG, "Stamp: " + str(self.stamp))

    def sedFileWithDateTimeStamp(self, file2change=""):
        """
        Find "^(\s+module_version\s*=\s*)\S*" or
             "^(\s+self.module_version\s*=\s*)\S*"
        and replace with x.group(1) + "'" +  acquireStamp() + "'"

        @author: Roy Nielsen
        """
        self.logger.log(lp.INFO, "********** Entered sed method...**************")
        startString = ""
        found = False
        if file2change:
            fp = open(file2change, "r")
            lines = fp.readlines()
            fp.close()
            fp = open(file2change, "w")
            for line in lines:
                check1 = re.match("^(\s+module_version\s*=\s*)\S*", line)
                check2 = re.match("^(\s+self\.module_version\s*=\s*)\S*", line)
                if check1:
                    self.logger.log(lp.DEBUG, "Found first check..")
                    startString = check1.group(1)
                    fp.write(re.sub("^\s+module_version\s*=\s*\S*", \
                                    startString + "'" + \
                                    self.stamp + "'", line))
                elif check2:
                    self.logger.log(lp.DEBUG, "Found second check...")
                    startString = check2.group(1)
                    fp.write(re.sub("^\s+self\.module_version\s*=\s*\S*", \
                                    startString + "'" + \
                                    self.stamp + "'", line))
                else:
                    fp.write(line)
            fp.close()

if __name__ == "__main__":
    message_level = "normal"
    files = ""
    parser = argparse.ArgumentParser()

    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='verbose flag' )

    parser.add_argument('-f', '--files',
                        action='append',
                        dest="files",
                        required=True,
                        help='Files to update...')

    parser.add_argument('--debug', '-d',
                        action='store_true',
                        help='debug flag -- trumps verbose flag...' )

    args = parser.parse_args()

    if args.debug:
        message_level = "debug"
    elif args.debug:
        message_level = "verbose"

    files = args.files
    logger = CxLogger()
    logger.initializeLogs()
    logger.log(lp.INFO, "Files: " + str(files))

    SedFile4VersionStamp(files, logger=logger)

