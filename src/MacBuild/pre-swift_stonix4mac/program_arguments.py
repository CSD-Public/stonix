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
"""
Created November 4, 2011

Contains class that gathers command line arguments for running in CLI mode

@operatingsystem: Generic
@author: Roy Nielsen

"""
import re
import sys
from optparse import OptionParser, SUPPRESS_HELP
from localize import STONIXVERSION

class ProgramArguments(object):
    """
    Class for holding the command line options

    @author: Roy Nielsen

    """
    def __init__(self):
        """
        Initialization routine for our program options
        Acquiring command line arguments with OptionParser
        """
        self.parser = OptionParser(usage="  %prog [options]\n\n Use \"%prog -h\" to get a list of options",
                              version="%prog " + STONIXVERSION)

        self.parser.add_option("-m", "--module", dest="mod", help="Module to run.",
                          default="", action="store")

        self.parser.add_option("-v", "--verbose", action="store_true",
                          dest="verbose", default=0, \
                          help="Print status messages")

        self.parser.add_option("-d", "--debug", action="store_true", dest="debug",
                          default=True, help="Print debug messages")

        self.parser.add_option("-X", "--rollback", action="store_true",
                          dest="rollback", default=False,
                          help="Roll back fixes if possible.")

        self.parser.add_option("-r", "--report", action="store_true", dest="report",
                          default=False, help="Report the status of rules.")

        self.parser.add_option("-f", "--fix", action="store_true", dest="fix",
                          default=False,
                          help="Set the status of rules according to the config file, or if unavailable - to default settings.")

        self.parser.add_option("-u", "--update", action="store_true", dest="update",
                          default=False,
                          help="Update this software package, if necessary.")

        self.parser.add_option("-i", "--install", action="store_true",
                          dest="install", default=False, help="Install")

        self.parser.add_option("-G", "--gui", action="store_true", dest="gui",
                          default=False, help="Start the GUI.")

        self.parser.add_option("-c", "--cli", action="store_true", dest="cli",
                          default=False,
                          help="Start the Command Line Interface.")

        self.parser.add_option("-p", "--printconfigsimple", action="store_true",
                          dest="pcs",
                          default=False,
                          help="Generate a new config file with current options in the simple format.")

        self.parser.add_option("-P", "--printconfigfull", action="store_true",
                          dest="pcf",
                          default=False,
                          help="Generate a new config file with the current options in the full format (shows all options).")

        #####
        # How verbose to be
        self.parser.add_option("--message-level", type='choice', \
                          action='store', dest="message_level", \
                          choices=['normal', 'quiet', 'verbose', 'debug'], \
                          default="normal", help=SUPPRESS_HELP, \
                          metavar="LEVEL")

        #####
        # The Self Update test will look to a development/test environment
        # to test Self Update rather than testing self update
        self.parser.add_option("-S", "--selfupdatetest", action="store_true",
                               dest="selfupdatetest",
                               default=False,
                               help="SUPPRESS_HELP")

        (self.opts, self.args) = self.parser.parse_args()

        if self.opts.fix and self.opts.report and self.opts.rollback:
            self.parser.error("Fix, Report and Rollback functions are mutually exclusive.")
        if self.opts.fix and self.opts.report:
            self.parser.error("Fix and Report options are mutually exclusive.")
        if self.opts.fix and self.opts.rollback:
            self.parser.error("Fix and Rollback options are mutually exclusive.")
        if self.opts.report and self.opts.rollback:
            self.parser.error("Report and Rollback options are mutually exclusive.")
        if self.opts.pcf and (self.opts.fix or self.opts.report or self.opts.rollback or self.opts.pcs or self.opts.update):
            self.parser.error('The -P --printconfigfull option may not be used with the fix, report, rollback, update or GUI options')
        if self.opts.pcs and (self.opts.fix or self.opts.report or self.opts.rollback or self.opts.pcf or self.opts.update):
            self.parser.error('The -p --printconfigsimple option may not be used with the fix, report, rollback, update or GUI options')

        if self.opts.debug:
            print "Selected options: "
            print self.opts
            print self.args

    def get_gui(self):
        """
        Return whether or not to start the GUI.

        @author: Roy Nielsen

        """
        return self.opts.gui

    def get_install(self):
        """
        Return the install option (True/False)

        @author: Roy Nielsen

        """
        return self.opts.install

    def get_update(self):
        """
        Return whether or not to update this software package.

        @author: Roy Nielsen

        """
        return self.opts.update

    def get_fix(self):
        """
        Return whether or not to run in fix mode.

        @author: Roy Nielsen

        """
        return self.opts.fix

    def get_report(self):
        """
        Return the filename passed in, or the default value

        @author: Roy Nielsen

        """
        return self.opts.report

    def get_rollback(self):
        """
        Return whether or not to run in rollback mode.

        @author: Roy Nielsen

        """
        return self.opts.rollback

    def get_verbose(self):
        """
        Return the filename passed in, or the default value

        @author: Roy Nielsen

        """
        return self.opts.verbose

    def get_debug(self):
        """
        Return the filename passed in, or the default value

        @author: Roy Nielsen

        """
        return self.opts.debug

    def get_module(self):
        """
        Return the filename passed in, or the default value

        @author: Roy Nielsen

        """
        return self.opts.mod

    def get_num_of_args(self):
        """
        Return the number of arguments passed in.

        @author: Roy Nielsen

        """
        return len(self.args)

    def get_cli(self):
        """
        Return whether or not to run in Command Line Mode

        @author: Roy Nielsen

        """
        return self.opts.cli

    def getPrintConfigFull(self):
        """
        Return the bool for whether or not the CLI has requested the
        generation of a full config file.

        @author: Roy Nielsen

        """
        return self.opts.pcf

    def getPrintConfigSimple(self):
        """
        Return the bool for whether or not the CLI has requested the
        generation of a simple config file.

        @author: Roy Nielsen

        """
        return self.opts.pcs

    def getProgramVersion(self):
        """
        Return the version of stonix.

        @author: Roy Nielsen
        """
        programVersion = self.parser.get_version()
        programVersion = programVersion.split(' ')
        programVersion = programVersion[1]
        return programVersion

    def get_msg_lvl(self):
        """
        Return the message level passed in, or the default value
        
        @author: Roy Nielsen
        """
        if self.opts.message_level and \
           not re.match("^normal$", self.opts.message_level):
            msg_lvl = self.opts.message_level

        elif self.opts.verbose:
            msg_lvl = "verbose"

        elif self.opts.debug:
            msg_lvl = "debug"
        else :
            msg_lvl = "normal"

        return msg_lvl

    def getArgs(self):
        '''
        Get the list of arguments - from the optparse webpage: 

        "the list of arguments to process (default: sys.argv[1:])"

        @author: Roy Nielsen
        '''
        return sys.argv[1:]
