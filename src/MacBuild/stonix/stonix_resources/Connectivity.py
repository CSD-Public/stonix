"""
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
"""
import re
import socket
import httplib
import urllib
import urllib2

from stonixutilityfunctions import set_no_proxy
from logdispatcher import LogPriority

class Connectivity(object):
    """
    Check different methods of network connectivity
    
    @author: Roy Nielsen
    """
    def __init__(self, logger):
        """
        Constructor
        """
        self.logger = logger
        ##########################
        # Make it so this will only work on the yellow.
        set_no_proxy()

    ############################################################
        
    def is_site_socket_online(self, host):
        """ This function checks to see if a host name has a DNS entry by checking
            for socket info. If the website gets something in return, 
            we know it's available to DNS.
        """
        retval = False
        try:
            socket.setdefaulttimeout(5)
            socket.gethostbyname(host)
            retval = True
        except socket.gaierror, err:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        except socket.herror, exerr:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        except socket.timeout, err:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        except Exception, err:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        else:
            msg = "Socket connection available to: " + str(host)
            self.logger.log(LogPriority.ERROR, msg)
            
        return retval

    ############################################################

    def is_site_available(self, site="", path=""): #, path):
        """ This function retreives the status code of a website by requesting
            HEAD data from the host. This means that it only requests the headers.
            If the host cannot be reached or something else goes wrong, it returns
            False.
            
            This will only work if the self.set_no_proxy method is used before
            this method is called.
        """        
        retval = False

        try:
            page = site + path
            req = urllib2.Request(page, headers={'User-Agent' : "Magic Browser"}) 
            req.add_header('User-agent', 'Firefox/31.5.0')
            request = urllib2.urlopen(req, timeout=3)
            retval = True
        except urllib2.URLError, err:
            msg = "Error trying to get web page type: " + str(err)
            try:
                self.logger.log(LogPriority.ERROR, msg)
                if hasattr(err, 'code'):
                    msg = "code - " + str(err.code)
                    self.logger.log(LogPriority.ERROR, msg)
            except socket.gaierror, err:
                msg = "Can't connect to server, socket problem: " + str(err)
                self.logger.log(LogPriority.DEBUG, msg)
            except socket.herror, exerr:
                msg = "Can't connect to server, socket problem: " + str(err)
                self.logger.log(LogPriority.DEBUG, msg)
            except socket.timeout, err:
                msg = "Can't connect to server, socket problem: " + str(err)
                self.logger.log(LogPriority.DEBUG, msg)
            except Exception, err:
                msg = "General Exception: Can't connect to server: " + str(err)
                self.logger.log(LogPriority.DEBUG, msg)
        else:
            self.logger.log(LogPriority.DEBUG, "Got the right web page type.")
        
        return retval


