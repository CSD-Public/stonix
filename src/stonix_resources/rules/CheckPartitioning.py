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
Created on Oct 10, 2012
This class checks the system partitions to see if best partitioning practices
have been followed. The class is audit only.
@author: dkennel
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 2015/04/14 dkennel updated to use new isApplicable
@change: 2015/10/07 eball Help text cleanup
@change: 2017/08/28 ekkehard - Added self.sethelptext()
'''

from __future__ import absolute_import
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority


class CheckPartitioning(Rule):
    '''This class checks the system partitions to see if best partitioning
    practices have been followed. The class is audit only.This class inherits
    the base Rule class, which in turn inherits observable.


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
        self.rulenumber = 1
        self.rulename = 'CheckPartitioning'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = False
        self.guidance = ['CCE 14161-4', 'CCE 14777-7', 'CCE 14011-1',
                         'CCE 14171-3', 'CCE 14559-9']
        self.applicable = {'type': 'black',
                           'family': ['darwin']}
        self.hasrunalready = False
        self.auditonly = True

    def report(self):
        '''CheckPartitioning.report(): produce a report on whether or not the
        systems partitioning appears to follow best practices.


        :returns: self.compliant

        :rtype: bool
@author: David Kennel
@change: Breen Malmberg - 07/30/2018 - added potential missing format
        detailedresults; minor docstring edit

        '''

        self.detailedresults = ""
        self.compliant = True

        if self.hasrunalready:
            self.formatDetailedResults('report', self.compliant, self.detailedresults)
            return self.compliant

        tempcompliant = False
        varcompliant = False
        varlogcompliant = False
        varlogauditcomp = False
        vartmpcomp = False
        homecomp = False
        results = 'The following filesystems should be on their own partitions:'
        fstabfile = '/etc/fstab'
        fsnodeindex = 1

        if self.environ.getosfamily() == 'solaris':
            fstabfile = '/etc/vfstab'
            fsnodeindex = 2

        try:

            fstab = open(fstabfile, 'r')
            fstabdata = fstab.readlines()

            for line in fstabdata:
                line = line.split()
                self.logger.log(LogPriority.DEBUG, 'Processing: ' + str(line))
                if len(line) > 0 and not re.search('^#', line[0]):
                    try:
                        # dev = line[0]
                        fsnode = line[fsnodeindex]
                        # fstype = line[2]
                        # opts = line[4]
                        # dump1 = line[5]
                        # dump2 = line[6]
                    except (IndexError):
                        continue
                    if re.search('^/tmp', fsnode):
                        tempcompliant = True
                    if re.search('^/var$', fsnode):
                        varcompliant = True
                    if re.search('^/var/log$', fsnode):
                        varlogcompliant = True
                    if re.search('^/var/log/audit$', fsnode):
                        varlogauditcomp = True
                    if re.search('^/var/tmp$', fsnode):
                        vartmpcomp = True
                    if re.search('^/home$|^/export/home$', fsnode):
                        homecomp = True
            if not tempcompliant:
                self.compliant = False
                results = results + ' /tmp'
            if not varcompliant:
                self.compliant = False
                results = results + ' /var'
            if not varlogcompliant:
                self.compliant = False
                results = results + ' /var/log'
            if not varlogauditcomp:
                self.compliant = False
                results = results + ' /var/log/audit'
            if not vartmpcomp:
                self.compliant = False
                results = results + ' /var/tmp'
            if not homecomp:
                self.compliant = False
                results = results + ' /home or /export/home'

            self.detailedresults += results

            self.hasrunalready = True

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.compliant = False
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)

        return self.compliant
