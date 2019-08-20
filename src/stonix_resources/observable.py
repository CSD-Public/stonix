#!/usr/bin/env python3
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




# ============================================================================#
#               Filename          $RCSfile: stonix/Observable.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2010/8/24 14:00:00 $
# ============================================================================#
""" Base class for objects implementing the observer pattern.
This class should be inherited only, no direct invocations.
"""


class Observable:

    '''Base class for objects that are observable
    :version:
    :author:


    '''
    def __init__(self):
        self.dirty = False
        self.listeners = []

    def register_listener(self, listener):
        '''

        :param object_: listener : Name of listening object
        :param listener: 
        :returns: void

        '''
        if not listener in self.listeners:
            self.listeners.append(listener)
            # debug element
            #print "Listener Registered " + str(listener)

    def detatch_listener(self, listener):
        '''

        :param listener: Name of listening object to be removed
                                 from notification list
        :returns: void

        '''
        if listener in self.listeners:
            del self.listeners[listener]

    def set_dirty(self):
        '''


        :returns: void

        '''
        self.dirty = True

    def set_clean(self):
        '''


        :returns: void

        '''
        self.dirty = False

    def notify_observers(self):
        '''Call update() on every attached listener


        :returns: author

        '''
        for listener in self.listeners:
            listener.update(self)
            # Debug
            #print "Update called on: " + str(listener)

    def notify_check(self):
        '''


        :returns: author

        '''
        if self.dirty:
            self.notify_observers()
            self.set_clean()
