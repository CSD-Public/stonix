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
#               Filename          $RCSfile: stonix/view.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL 
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2010/8/24 14:00:00 $
# ============================================================================ #

'''
This is the base module for all user interface events. It serves to abstract
which ui type we are using cli or gui.
Created on Aug 24, 2010

WARNING! FIX ME! Is this object still relevant? Can we remove this? 

@author: dkennel
'''

class View:

    """
    Abstract class. Not intended to be instantiated, only inherited.
    :version:
    :author:
    """
    def __init__(self):
        
        #self.controller = controller
        pass

    def update(self, subject):
        """
        Called when isDirty message is received.
        GUI and CLI versions are independent of each other.

        @return  :
        @author
        """
        pass