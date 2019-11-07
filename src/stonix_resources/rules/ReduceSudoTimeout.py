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
Created on Feb 13, 2013

The ReduceSudoTimeout class removes the default 5 minute window of stored sudo
authorization after a successful sudo authorization is made.

@author: Breen Malmberg
@change: 02/14/2014 ekkehard Implemented self.detailedresults flow
@change: 02/14/2014 ekkehard Implemented isapplicable
@change: 03/27/2014 ekkehard make os x mavericks compliant
@change: 04/18/2014 dkennel Replaced mid-style CI invocation.
@change: 05/07/2014 dwalker testing and refactoring rule
@change: 2015/04/16 dkennel updated for new isApplicable
@change: 2015/09/09 eball Improved feedback
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2015/11/09 ekkehard - make eligible of OS X El Capitan
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''



import re
import os
import traceback

from rule import Rule
from stonixutilityfunctions import iterate
from stonixutilityfunctions import resetsecon
from logdispatcher import LogPriority


class ReduceSudoTimeout(Rule):
    '''The ReduceSudoTimeout class removes the default 5 minute window of stored
    sudo authorization after a successful sudo authorization is made.
    @author Breen Malmberg


    '''

    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''

        Rule.__init__(self, config, environ, logdispatch, statechglogger)

        self.logger = logdispatch
        self.rulenumber = 151
        self.rulename = 'ReduceSudoTimeout'
        self.formatDetailedResults("initialize")
        self.sethelptext()
        self.guidance = ['N/A']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        datatype = "bool"
        key = "REDUCESUDOTIMEOUT"
        instructions = "If set to true, the REDUCESUDOTIMEOUT " + \
            "variable will set the sudo timeout to 0, requiring a password " + \
            "for each sudo call."
        if self.environ.getostype() == 'Mac OS X':
            self.mandatory = True
            default = True
        else:
            default = False
        self.ci = self.initCi(datatype, key, instructions, default)
        self.iditerator = 0

        todatatype = "string"
        tokey = "TIMEOUTMINUTES"
        toinstructions = "Enter the value (in minutes) you want each sudo authentication to last. Acceptable values are from 0 to 15."
        todefault = ""
        self.timeoutCI = self.initCi(todatatype, tokey, toinstructions, todefault)

    def report(self):
        '''determine whether the amount of time a stored sudo credential exists
        is limited to an appropriate value (0 minutes to 15 minutes)


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        self.timeouttime = self.timeoutCI.getcurrvalue()
        if not self.timeouttime:
            self.timeouttime = "0"
        if int(self.timeouttime) > 15:
            self.logger.log(LogPriority.DEBUG, "User entered an invalid time out value. Resetting it to 0...")
            self.timeouttime = "0"
        self.reportsudotimeout = "^Defaults\s+timestamp_timeout=" + self.timeouttime
        self.detailedresults = ""
        self.compliant = True
        self.sudofile = "/etc/sudoers"
        found = False

        try:

            if os.path.exists(self.sudofile):
                self.logger.log(LogPriority.DEBUG, "Scanning " + str(self.sudofile) + " for required configuration setting...")
                f = open(self.sudofile, 'r')
                contents = f.readlines()
                f.close()
                for line in contents:
                    if re.search(self.reportsudotimeout, line, re.IGNORECASE):
                        found = True
                        self.logger.log(LogPriority.DEBUG, "Found required configuration setting in " + str(self.sudofile))
                if not found:
                    self.detailedresults += "\nDid not find required configuration setting in " + str(self.sudofile)
                    self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''set the sudo timeout to a pre-defined appropriate value
        
        @author Breen Malmberg


        '''

        self.detailedresults = ""
        self.rulesuccess = True
        self.iditerator = 0
        changed = False
        tempfile = self.sudofile + ".stonixtmp"
        self.fixsudotimeout = "Defaults        timestamp_timeout=" + self.timeouttime + "\n"

        try:

            if self.ci.getcurrvalue():

                f = open(self.sudofile, 'r')
                contents = f.readlines()
                f.close()
                for line in contents:
                    if re.search("^Defaults\s+env_reset", line):
                        contents.insert((contents.index(line) + 1), self.fixsudotimeout)
                        changed = True
                if changed:
                    tf = open(tempfile, 'w')
                    tf.writelines(contents)
                    tf.close()
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "conf",
                             "filepath": self.sudofile}
                    self.statechglogger.recordchgevent(myid, event)
                    self.statechglogger.recordfilechange(self.sudofile, tempfile, myid)
                    os.rename(tempfile, self.sudofile)
                    os.chown(self.sudofile, 0, 0)
                    os.chmod(self.sudofile, 0o440)
                    resetsecon(self.sudofile)
                    self.logger.log(LogPriority.DEBUG, "Added the configuration setting to " + str(self.sudofile))

            else:
                self.detailedresults += "\nRule was not enabled. Nothing was done."
                self.logger.log(LogPriority.DEBUG, "Rule was not enabled. Nothing was done.")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess
