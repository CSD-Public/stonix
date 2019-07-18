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


"""
Created November 4, 2011

Contains class that gathers command line arguments for running in CLI mode

@operatingsystem: Generic
@author: Roy Nielsen

"""
from optparse import OptionParser, SUPPRESS_HELP
from .localize import STONIXVERSION


class ProgramArguments(object):
    '''Class for holding the command line options
    
    @author: Roy Nielsen


    '''
    def __init__(self):
        """
        Initialization routine for our program options
        Acquiring command line arguments with OptionParser
        """
        self.parser = OptionParser(usage="  %prog [options]\n\n Use \"%prog -h\" to get a list of options",
                              version="%prog " + STONIXVERSION)

        self.parser.add_option("-m", "--module", dest="mod",
                               help="Module(s) to run. To run multiple " \
                               "modules, use a comma-separated list (e.g. "
                               "rule1,rule2,rule3)",
                               default="", action="store")

        self.parser.add_option("-v", "--verbose", action="store_true",
                          dest="verbose", default=0, \
                          help="Print status messages")

        self.parser.add_option("-d", "--debug", action="store_true", dest="debug",
                          default=False, help="Print debug messages")

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

        self.parser.add_option("-l", "--list", action="store_true",
                          dest="list",
                          default=False,
                          help="List all installed rules that stonix will run on this platform.")

        #####
        # The Self Update test will look to a development/test environment
        # to test Self Update rather than testing self update
        self.parser.add_option("-S", "--selfupdatetest", action="store_true",
                               dest="selfupdatetest",
                               default=False,
                               help=SUPPRESS_HELP)

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
        if self.opts.list and (self.opts.fix or self.opts.report or self.opts.rollback or self.opts.pcf or self.opts.update):
            self.parser.error('The -l --list option may not be used with the fix, report, rollback, update or GUI options')

        if self.opts.debug:
            print("Selected options: ")
            print(self.opts)
            print(self.args)

    def getBuildSelfUpdate(self):
        '''Getter for whether or not we use the test build for self updating
        
        @author: Roy Nielsen


        '''
        return self.opts.selfupdatetest

    def get_gui(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.gui

    def get_install(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.install

    def get_update(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.update

    def get_fix(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.fix

    def get_report(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.report

    def get_rollback(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.rollback

    def get_verbose(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.verbose

    def get_debug(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.debug

    def get_module(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.mod

    def get_num_of_args(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return len(self.args)

    def get_cli(self):
        '''


        :returns: @author: Roy Nielsen

        '''
        return self.opts.cli

    def getPrintConfigFull(self):
        '''


        :returns: generation of a full config file.
        
        @author: Roy Nielsen

        '''
        return self.opts.pcf

    def getPrintConfigSimple(self):
        '''


        :returns: generation of a simple config file.
        
        @author: Roy Nielsen

        '''
        return self.opts.pcs

    def getList(self):
        '''


        :returns: of installed rules.
        
        @author: D. Kennel

        '''
        return self.opts.list
