#!/usr/bin/env python

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

    """
    Base class for objects that are observable
    :version:
    :author:
    """
    def __init__(self):
        self.dirty = False
        self.listeners = []

    def register_listener(self, listener):
        """


        @param object_ listener : Name of listening object
        @return  :
        @author
        """
        if not listener in self.listeners:
            self.listeners.append(listener)
            # debug element
            #print "Listener Registered " + str(listener)

    def detatch_listener(self, listener):
        """


        @param object_ listener: Name of listening object to be removed
                                 from notification list
        @return  :
        @author
        """
        if listener in self.listeners:
            del self.listeners[listener]

    def set_dirty(self):
        """


        @return:
        @author
        """
        self.dirty = True

    def set_clean(self):
        """


        @return:
        @author
        """
        self.dirty = False

    def notify_observers(self):
        """
        Call update() on every attached listener
        @return:
        @author
        """
        for listener in self.listeners:
            listener.update(self)
            # Debug
            #print "Update called on: " + str(listener)

    def notify_check(self):
        """

        @return:
        @author
        """
        if self.dirty:
            self.notify_observers()
            self.set_clean()
