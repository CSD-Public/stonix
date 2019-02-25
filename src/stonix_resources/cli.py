#!/usr/bin/env python

###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
    