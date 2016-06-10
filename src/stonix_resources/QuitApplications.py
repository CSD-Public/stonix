'''
###############################################################################
#                                                                             #
# Copyright 2016.  Los Alamos National Security, LLC. This material was       #
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

@author: ekkehard
@change: 2016/06/10 original implementation
'''
import QuitAppmacOS

class QuitApplications(object):
    '''
    QuitApplications is a factory object that implements quitting of 
    applications running that need to either quit with user interaction of force quit

    @author: ekkehard
    '''

    def __init__(self, environment, logdispatcher):
        '''
        QuitApplications needs to receive the STONIX environment and
        logdispatcher objects as parameters to init.

        @param environment: STONIX environment object
        @param logdispatcher: STONIX logdispather object
        '''
        self.environ = environment
        self.logdispatcher = logdispatcher
        if self.environ.getostype() == "Mac OS X":
            self.QuitAppObject = QuitAppmacOS.QuitAppmacOS(self.logdispatcher)
        else:
            self.QuitAppObject = None
