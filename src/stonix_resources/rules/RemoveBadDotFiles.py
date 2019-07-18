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
Created on Jul 13, 2012

@author: dkennel
@change: 02/13/2014 ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 ekkehard Implemented isapplicable
@change: 04/18/2014 dkennel Replace old-style CI invocation
@change: 2015/04/16 dkennel upate for new isApplicable
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''

import pwd
from ..rule import Rule
from ..stonixutilityfunctions import *


class RemoveBadDotFiles(Rule):
    '''The RemoveBadDotFiles class is responsible for checking for and removing
    any bad dot files that might reside in user home directories.
    @author: dkennel


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 47
        self.rulename = 'RemoveBadDotFiles'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = False
        datatype = 'bool'
        key = 'REMOVEBADDOTFILES'
        instructions = "To disable this rule set the value of " + \
        "REMOVEBADDOTFILES to False"
        default = True
        self.nonetrc = self.initCi(datatype, key, instructions, default)
        self.guidance = ['NSA 2.3.4.5', 'cce-4578-1']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}
        self.homelist = ['/', '/root']
        try:
            mypwd = pwd.getpwall()
            for user in mypwd:
                home = user[5]
                if home not in self.homelist:
                    self.homelist.append(home)
            if self.environ.geteuid() != 0:
                pwdsingle = pwd.getpwuid(self.environ.geteuid())
                self.homelist = pwdsingle[5]
        except(IndexError, OSError):
            pass

    def report(self):
        '''Search for and report whether or not any .netrc files exist. This
        report is a little tricky because if euid == 0 then we can't read nfs
        mounted dirs.


        :returns: bool
        @author: D.Kennel

        '''
        try:
            compliant = True
            self.detailedresults = ""
            myresults = "Bad dot files were detected: "
            badfiles = ['.netrc', '.shosts', '.rhosts']

            for home in self.homelist:
                badpaths = []
                for badfile in badfiles:
                    badpaths.append(os.path.join(home, badfile))
                try:
                    for badpath in badpaths:
                        if os.path.islink(badpath) and \
                        os.path.realpath(badpath) == '/dev/null':
                            continue
                        elif os.path.exists(badpath):
                            compliant = False
                            myresults = myresults + " " + badpath
                except OSError:
                    # we expect failures on NFS mounted homes when running
                    # as root
                    pass
            if compliant:
                self.detailedresults = 'No bad dot files were detected'
            else:
                self.detailedresults = myresults
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''Search and destroy any bad dot files. When running with euid == 0 we
        have no access to nfs mounted homes.
        @author: D. Kennel


        '''
        self.detailedresults = ""
        if not self.nonetrc.getcurrvalue():
            self.formatDetailedResults("fix", self.rulesuccess,
                                       self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return self.rulesuccess
        badfiles = ['.netrc', '.shosts', '.rhosts']
        try:
            for home in self.homelist:
                badpaths = []
                for badfile in badfiles:
                    badpaths.append(os.path.join(home, badfile))
                try:
                    for badpath in badpaths:
                        if os.path.islink(badpath) and \
                        os.path.realpath(badpath) == '/dev/null':
                            continue
                        elif os.path.exists(badpath):
                            os.remove(badpath)
                except OSError:
                    # we expect failures on NFS mounted homes when running
                    # as root
                    pass
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
