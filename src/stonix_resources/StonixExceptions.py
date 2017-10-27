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
'''
Created on Oct 10, 2017

Module dedicated to custom exceptions written for STONIX
All custom exceptions for STONIX should go in this module

@author: Breen Malmberg
'''

import re

from environment import Environment
from logdispatcher import LogDispatcher
from logdispatcher import LogPriority


class repoError(Exception):
    '''
    Meant to be raised when a remote repository (in linux) is inaccessible, for any reason
    '''

    def __init__(self, ptype, ecode, errmsg=""):
        '''
        class init

        @param ptype: string; package manager name; valid values:
            apt
            dnf
            yum
            zypper
        @param ecode: int; exit code
        @param errmsg: string; (OPTIONAL); include any error string you want this class to parse 
                in order to more accurately determine the success or failure of the pkg mgr action
        @return: void
        @author: Breen Malmberg
        '''

        super(repoError, self).__init__(ptype, ecode, errmsg)
        self.environ = Environment()
        self.logger = LogDispatcher(self.environ)

        # default initialization of variables
        msg = "No further information available"
        successrange = []
        self.success = True
        self.errmsgdict = {"Error parsing config": False,
                           "Could not parse": False,
                           "No repomd file": False,
                           "repositories failed": False,
                           "doesn't have enough cached data to continue": False,
                           "Abort, retry, ignore": False,
                           "System management is locked": False,
                           "Error: No matching packages to list": True}

        try:

            if ptype == "zypper":
                msg = self.zypperCodes(ecode)
                successrange = [0, 100, 101, 102, 103, 106]
            elif ptype == "yum":
                msg = self.yumCodes(ecode)
                successrange = [0, 100]
            elif ptype == "apt":
                msg = self.aptCodes(ecode)
                successrange = [0]
            elif ptype == "dnf":
                msg = self.dnfCodes(ecode)
                successrange = [0, 100]
            else:
                self.logger.log(LogPriority.DEBUG, "Unable to identify package manager. Cannot guarantee package manager action success!")

        except (KeyboardInterrupt, SystemExit):
            raise

        try:

            # First we try to go based off of the content of the error message
            # Since that is more reliable than exit codes, when trying to determine
            # Actual success or failure of the package manager command
            if errmsg:
                # (maybe we couldn't identify the package manager and
                # as a result couldn't populate the errmsgdict)
                if self.errmsgdict:
                    for entry in self.errmsgdict:
                        if re.search(entry, errmsg, re.IGNORECASE):
                            self.success = self.errmsgdict[entry]
                            if self.success:
                                # If success then the message passed is merely informational in nature
                                self.logger.log(LogPriority.INFO, errmsg)
                            else:
                                # If not success, then the message passed indicates an actual problem
                                self.logger.log(LogPriority.WARNING, errmsg)
                            return

            # If there is no error message passed, then we do our best
            # To determine success or failure based off of what the exit 
            # Code indicates
            if ecode in successrange:
                self.logger.log(LogPriority.INFO, msg)
            else:
                self.success = False
                self.logger.log(LogPriority.WARNING, msg)

        except IndexError as indexE:
            self.logger.log(LogPriority.WARNING, str(indexE))

        return

    def zypperCodes(self, ecode):
        '''
        Return information about the zypper exit codes

        @param ecode: int; the numeric exit status code
        @return: msg
        @rtype: string
        @author: Breen Malmberg
        '''

        msg = "No further information available"

        codeDict = {0: "ZYPPER_EXIT_OK",
                    1: "ZYPPER_EXIT_ERR_BUG",
                    2: "ZYPPER_EXIT_ERR_SYNTAX",
                    3: "ZYPPER_EXIT_ERR_INAVLID_ARGS",
                    4: "ZYPPER_EXIT_ERR_ZYPP",
                    5: "ZYPPER_EXIT_ERR_PRIVILEGES",
                    6: "ZYPPER_EXIT_NO_REPOS",
                    7: "ZYPPER_EXIT_ZYPP_LOCKED",
                    8: "ZYPPER_EXIT_ERR_COMMIT",
                    100: "ZYPPER_EXIT_INF_UPDATE_NEEDED",
                    101: "ZYPPER_EXIT_INF_SEC_UPDATE_NEEDED",
                    102: "ZYPPER_EXIT_INF_REBOOT_NEEDED",
                    103: "ZYPPER_EXIT_INF_RESTART_NEEDED",
                    104: "ZYPPER_EXIT_INF_CAP_NOT_FOUND",
                    105: "ZYPPER_EXIT_ON_SIGNAL",
                    106: "ZYPPER_EXIT_INF_REPOS_SKIPPED"}
        # give more specific information on what the exit code actually means
        # (this is all taken from the official online zypper application documentation)
        extendedDict = {"ZYPPER_EXIT_OK": "Successfull run of zypper with no special information",
                        "ZYPPER_EXIT_ERR_BUG": "Unexpected situation occured, probably caused by a bug",
                        "ZYPPER_EXIT_ERR_SYNTAX": "Zypper was invoked with an invalid command or option, or bad syntax",
                        "ZYPPER_EXIT_ERR_INAVLID_ARGS": "One or more of the provided arguments were invalid",
                        "ZYPPER_EXIT_ERR_ZYPP": "A problem reported by ZYPP library. Example: another instance of ZYPP is running",
                        "ZYPPER_EXIT_ERR_PRIVILEGES": "User invoking zypper has insufficient privileges for the specified operation",
                        "ZYPPER_EXIT_INF_UPDATE_NEEDED": "Returned by the patch-check command if there are patches available for installation",
                        "ZYPPER_EXIT_INF_SEC_UPDATE_NEEDED": "Returned by the patch-check command if there are security patches available for installation",
                        "ZYPPER_EXIT_INF_REBOOT_NEEDED": "Returned after a successfull installation of a patch which requires reboot of the computer",
                        "ZYPPER_EXIT_INF_RESTART_NEEDED": "Returned after a successfull installation of a patch which requires restart of the package manager",
                        "ZYPPER_EXIT_INF_CAP_NOT_FOUND": "Returned by the install and the remove commands, in case any of the arguments does not match any of the available (or installed) package names",
                        "ZYPPER_EXIT_ON_SIGNAL": "Returned upon exiting after receiving a SIGINT or SIGTERM",
                        "ZYPPER_EXIT_INF_REPOS_SKIPPED": "Some repository had to be disabled temporarily because it failed to refresh. You should check your repository configuration",
                        "ZYPPER_EXIT_ZYPP_LOCKED": "The ZYPP library is locked, e.g. packagekit is running",
                        "ZYPPER_EXIT_NO_REPOS": "No repositories are defined",
                        "ZYPPER_EXIT_ERR_COMMIT": "An error occurred during installation or removal of packages. You may run zypper verify to repair any dependency problems"}

        try:
            msg = str(codeDict[ecode] + " : " + extendedDict[codeDict[ecode]])
        except KeyError as err:
            self.logger.log(LogPriority.DEBUG, str(err))

        return msg

    def yumCodes(self, ecode):
        '''
        Return information about the yum exit codes

        @param ecode: int; the numeric exit code
        @return: msg
        @rtype: string
        @author: Breen Malmberg
        '''

        msg = "No further information available"

        codeDict = {0: "Success",
                    1: "An error occurred",
                    100: "There are packages available for update"}

        try:
            msg = str(codeDict[ecode])
        except KeyError as err:
            self.logger.log(LogPriority.DEBUG, str(err))

        return msg

    def aptCodes(self, ecode):
        '''
        Return information about the apt-get/dpkg exit codes

        @param ecode: int; the numeric exit code
        @return: msg
        @rtype: string
        @author: Breen Malmberg
        '''

        msg = "No further information available"

        codeDict = {0: "Success",
                    1: "An error occurred",
                    2: "Unrecoverable fatal error",
                    100: "apt-get was unavailable due to process lock / busy"}

        try:
            msg = str(codeDict[ecode])
        except KeyError as err:
            self.logger.log(LogPriority.DEBUG, str(err))

        return msg

    def dnfCodes(self, ecode):
        '''
        Return information about the dnf exit codes

        @param ecode: int; the numeric exit code
        @return: msg
        @rtype: string
        @author: Breen Malmberg
        '''

        msg = "No further information available"

        codeDict = {0: "Operation was successful",
                    1: "An error occurred which was handled by dnf",
                    3: "An unknown unhandled error occurred during operation",
                    100: "There are packages available for update",
                    200: "There was a problem with acquiring or releasing of locks"}

        try:
            msg = str(codeDict[ecode])
        except KeyError as err:
            self.logger.log(LogPriority.DEBUG, str(err))

        return msg
