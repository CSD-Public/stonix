#!/usr/bin/env python
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




# ============================================================================ #
#               Filename          $RCSfile: stonix/cli.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL 
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2010/08/24 14:00:00 $
# ============================================================================ #

'''
Created on Aug 24, 2010

@author: dkennel
'''

from view import View
from logdispatcher import LogPriority

class Cli (View):
    
    """
    
    :version:
    :author:
    """
    
    def __init__(self, environment):
        View.__init__(self)
        
        self.environ = environment
        self.currmessage = ''
        self.currrule = ''
        #self.currdetstatus = ''
        #self.currstatus = ''
        self.percentage = 0
        self.normal = [LogPriority.CRITICAL, LogPriority.ERROR,
                       LogPriority.WARNING]
        self.verbose = [LogPriority.CRITICAL, LogPriority.INFO,
                       LogPriority.ERROR, LogPriority.WARNING]
        
        
    def displaymessage(self, message):
        """
        WARNING! Fix Me.
        This method appears to be redundant (see printmessage)
        
        Send message to screen.
        @param string message: Message to be printed to std out
        """
        print message

    def displayhelp(self):
        """
        

        @return  :
        @author
        """
        pass
    
    
    def update(self, subject):
        """
        Called by observed objects when reporting changes
        @return: void
        @author: D. Kennel
        """
        try:
            #self.currrule = subject.getcurrentrule()
            percentage = subject.getcompletionpercentage()
            self.percentage = percentage
            if self.environ.getverbosemode() or self.environ.getdebugmode():
                self.printmessage('Percent complete: ' + str(self.percentage)
                                  + '%')
        except(AttributeError):
            pass

    def printmessage(self, messagetext):
        """
        Print a message to stdout.

        @param string messageText : Message text to be printed.
        @return  :
        @author D. Kennel
        """
        print messagetext

    def displayrulename(self, rulename):
        """
        

        @param string ruleName : Name of the rule.
        @return  :
        @author
        """
        pass

    def displayrulestatus(self, status, rulename):
        """
        

        @param enum status : Enum of rule status:
            processing
            complete
            failed
            warning
        @param string rulename : 
        @return  :
        @author
        """
        pass

    def displaydetailedrulestatus(self, ruledetailedstatus):
        """
        

        @param string ruledetailedstatus : Detailed status information about 
        the rule
        @return  :
        @author
        """
        pass

    def displayrulehelp(self, rulehelptext):
        """
        

        @param string rulehelptext : Help text for rule
        @return  :
        @author
        """
        pass


    def clearbuttons(self):
        """
        

        @return  :
        @author
        """
        pass


    def displayruleconfigopts(self, ruleconfigopts):
        """
        

        @param dict ruleconfigopts : 
        @return  :
        @author
        """
        pass

    def displayconfigopts(self, configopts):
        """
        

        @param dict configOpts : 
        @return  :
        @author
        """
        pass
    