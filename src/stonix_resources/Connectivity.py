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

"""
"""

import re
import ssl
import socket
import http.client
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse

#--- non-native python libraries in this source tree
from .logdispatcher import LogPriority
from .localize import PROXY


class ConnectivityInvalidURL(Exception):
    '''Custom Exception'''
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class Connectivity(object):
    '''Check different methods of network connectivity
    
    @author: Roy Nielsen


    '''
    def __init__(self, logger, use_proxy=False):
        """
        Constructor
        """
        self.logger = logger
        self.use_proxy = use_proxy

        ##########################
        # Make it so this will only work on the yellow.
        if not use_proxy:
            self.set_no_proxy()

    ############################################################

    def is_site_socket_online(self, host):
        '''This function checks to see if a host name has a DNS entry by checking
            for socket info. If the website gets something in return,
            we know it's available to DNS.

        :param host: 

        '''
        retval = False
        try:
            socket.setdefaulttimeout(5)
            socket.gethostbyname(host)
            retval = True
        except socket.gaierror as err:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        except socket.herror as exerr:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        except socket.timeout as err:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        except Exception as err:
            msg = "Can't connect to server, socket problem: " + str(err)
            self.logger.log(LogPriority.ERROR, msg)
        else:
            msg = "Socket connection available to: " + str(host)
            self.logger.log(LogPriority.DEBUG, msg)

        return retval

    ############################################################

    def is_site_available(self, site="", path=""):
        '''This function retrieves the status code of a web site by requesting
        HEAD data from the host. This means that it only requests the headers.
        If the host cannot be reached or something else goes wrong, it returns
        False.
        
        This will only work if the self.set_no_proxy method is used before
        this method is called.

        :param site: string; fqdn (domain); ex: http://www.google.com/ (Default value = "")
        :param path: string; the rest of the URL; ex: docs/about (Default value = "")
        :returns: retval
        :rtype: bool
@author: ???
@change: 02/12/2018 - Breen Malmberg - added doc string decorators; proxy
        will now be set for the test if the use_proxy argument in __init__ is
        True.

        '''

        retval = True

        try:

            if self.use_proxy:
                self.set_proxy()

            page = site + path
            req = urllib.request.Request(page, headers={'User-Agent' : "Magic Browser"})
            req.add_header('User-agent', 'Firefox/31.5.0')
            request = urllib.request.urlopen(req, timeout=3)
            retcode = request.getcode()

            # get the first digit of the return code
            # if it is not in the 200 range, then an error has occurred
            # (all http successful response codes are in the 2xx range)
            idd = int(str(retcode)[:1])
            if idd != 2:
                self.logger.log(LogPriority.DEBUG, "Failed to reach specified page: " + str(page) + " with HTTP error code: " + str(retcode))

            if retval:
                self.logger.log(LogPriority.DEBUG, "Site is available.")

        except Exception:
            raise

        return retval

    def isPageAvailable(self, url="", timeout=8):
        '''Check if a specific webpage link is available, using httplib's
        request('GET', url).  If a 200 is received in return, the connection
        to the page was successful.

        :param eter: url - valid http:// or https:// url
        :param eter: timeout - how fast to timeout the connection.
        :param url:  (Default value = "")
        :param timeout:  (Default value = 8)

        '''
        url = url.strip()
        self.logger.log(LogPriority.DEBUG, "URL: '" + str(url) + "'")
        self.logger.log(LogPriority.DEBUG, "timeout: " + str(timeout))

        success = False
        if isinstance(url, str):
            #####
            # Check for a valid URL
            if self.isUrlValid(url):
                self.logger.log(LogPriority.DEBUG, "URL is valid...")
                #####
                # Identify the different parts of the URL
                host, port, page = self.decomposeURL(url)
                self.logger.log(LogPriority.DEBUG, "host: " + str(host))
                self.logger.log(LogPriority.DEBUG, "port: " + str(port))
                self.logger.log(LogPriority.DEBUG, "page: " + str(page))
                              
                if host and port:
                    #####
                    # Revert to unverified context
                    if hasattr(ssl, '_create_unverified_context'):
                        ssl._create_default_https_context = ssl._create_unverified_context
                    #####
                    # Create a different type of connection based on 
                    # http or https...
                    if re.match("^https://.+", url):
                        conn = http.client.HTTPSConnection(host=host, port=port, timeout=timeout, cert_file="", key_file="")
                    elif re.match("^http://.+", url):
                        conn = http.client.HTTPConnection(host, port, timeout)
                    #####
                    # Get the page, see if we get a return value of 200 
                    # (success)
                    try:                    
                        conn.request('GET', url)
                        response = conn.getresponse()
                    except socket.error:
                        self.logger.log(LogPriority.INFO, "No connection " + \
                                                           "to: " + str(url))
                    else:
                        self.logger.log(LogPriority.DEBUG, "Status: " + \
                                                           str(response.status))
                        if re.match("^200$", str(response.status)):
                            success = True

        return success

    def isUrlValid(self, url):
        '''Check for a valid URL -
        
        1 - cannot have multiple colons in the host portion of the url.
            one colon may separate the host and port, ie:
              proxy.example.com:8888
        2 - Only http and https are supported
        3 - the URL is a string

        :param url: 

        '''
        success = False
        self.logger.log(LogPriority.DEBUG, "URL: " + str(url))
        
        if isinstance(url, str) and url:
            self.logger.log(LogPriority.DEBUG, "URL: '" + str(url) + "'")
            self.logger.log(LogPriority.DEBUG, "URL is a string and not empty...")
            if re.match("^http://.+", url) or re.match("^https://.+", url):
                self.logger.log(LogPriority.DEBUG, "Found valid protocol...")
                urlsplit = url.split("/")
                #####
                # Get the hostname, may be in the form of <host>:<port> or
                # ie: http://example.com:8080 would yield example.com:8080
                hostAndPort = urlsplit[2]
                self.logger.log(LogPriority.DEBUG, "urlsplit: " + str(urlsplit))
                if re.match(".+:.+", hostAndPort):
                    #####
                    # If there is a colon in the host field, get both
                    # the hostname and the port
                    self.logger.log(LogPriority.DEBUG, "hostAndPort:" + \
                                                        str(hostAndPort))
                    #####
                    # Get the host - check if there is a port indication in the URL, 
                    # ie. poxyout.example.com:8888 if so, get both.
                    hostList = hostAndPort.split(":")
                    self.logger.log(LogPriority.DEBUG, "hostList: " + str(hostList))
                    ####
                    # Multiple colons is invalid, so raise an exception if two or 
                    # more are found.
                    if len(hostList) == 2 or not re.match(":", hostList):
                        success = True
                    else:
                        #####
                        # Problem parsing the URL passed in...
                        raise ConnectivityInvalidURL("Multiple colons in " + \
                                                     "hostname portion " + \
                                                     "of the URL...")
                elif not re.search(":", hostAndPort):
                    success = True
            else:
                self.logger.log(LogPriority.DEBUG, "Could NOT find valid " + \
                                                   "protocol...")                
        else:
            self.logger.log(LogPriority.DEBUG, "URL is not a string, or it " + \
                                               "is an empty string...")
        return success
    
    def decomposeURL(self, url=""):
        '''Acquire the host, port and page of the URL and return them to the
        caller.

        :param eter: url - a valid web URL, must be http:// or https://
        :param url:  (Default value = "")
        :returns: s: host - the host to which we want to connect.

        '''
        host = ""
        port = 0
        page = ""
        if isinstance(url, str) and url:
            if re.match("^http://.+", url) or re.match("^https://.+", url):
                urlsplit = url.split("/")
                hostAndPort = urlsplit[2]
                if re.match(".+:.+", hostAndPort):
                    #####
                    # Get the host - check if there is a port indication in the URL, 
                    # ie. poxyout.example.com:8888 if so, get both.
                    hostList = hostAndPort.split(":")
                    self.logger.log(LogPriority.DEBUG, "hostList - " + str(hostList))
                    ####
                    # Multiple colons is invalid, so raise an exception if two or 
                    # more are found.
                    if len(hostList) < 2:
                        self.host = hostList[0]
                        self.port = hostList[1]
                elif not re.search(":", hostAndPort):
                    #####
                    # No port defined, use default ports
                    if re.match("^https://.+", url):
                        port = 443
                    elif re.match("^http://.+", url):
                        port = 80
                    host = hostAndPort
                        
                else:
                    raise ConnectivityInvalidURL("Multiple colons in " + \
                                                 " hostname portion " + \
                                                 "of the URL...")
                #####
                # Put together the "page" - or string after the 
                # host:port section of the URL
                try:
                    tmpstring = urlsplit[3:]
                    page = "/" + "/".join(tmpstring)
                except IndexError as err:
                    self.logger.log(LogPriority.DEBUG, "No page...")
                
        self.logger.log(LogPriority.DEBUG, "URL: " + str(url))
        self.logger.log(LogPriority.DEBUG, "host: " + str(host))
        self.logger.log(LogPriority.DEBUG, "port: " + str(port))
        self.logger.log(LogPriority.DEBUG, "page: " + str(page))

        return str(host), str(port), str(page)

    ###########################################################################
    
    def set_no_proxy(self):
        '''This method described here: http://www.decalage.info/en/python/urllib2noproxy
        to create a "no_proxy" environment for python
        
        @author: Roy Nielsen


        '''

        proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)

    def set_proxy(self):
        '''This method configures the proxy for the outgoing connection based on the proxy
        set in localize.py (PROXY)
        
        @author: Breen Malmberg


        '''

        ptype = 'https'
        psite = ''
        pport = '8080'

        sproxy = PROXY.split(':')
        if len(sproxy) == 3:
            ptype = sproxy[0]
            psite = sproxy[1].strip('/')
            pport = sproxy[2]

        proxy_handler = urllib.request.ProxyHandler({ptype : psite + ':' + pport})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)

    ###########################################################################
    
    def buildValidatingOpener(self, ca_certs, proxy=False):
        '''Return a urllib2 'opener' that can verify a site based on a public CA
        pem file.

        :param ca_certs: 
        :param proxy:  (Default value = False)
        :returns: s: a valid urllib2 https handler, or False, having not been able
                  to load the ssl library
        
        example:
        
        
        @compiler: Roy Nielsen

        >>> opener = buildValidatingOpener(resourcesDir + "/.ea.pem")
        >>> params = urllib.urlencode({'PropNumIn' : self.prop_num})
        >>> headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        >>> url = 'https://' + str(host) + str(page)
        >>>
        >>> req = urllib2.Request(url, params, headers)
        >>>
        >>> data = opener.open(req).read()
        >>>
        >>> opener.close()
        '''
        url_opener = False
        try:
            import ssl
        except ImportError:
            self.logger.log(LogPriority.DEBUG, "SSL not found.  Not able to " +\
                                               "a validating https opener.")
        else:
            class VerifiedHTTPSConnection(http.client.HTTPSConnection):
                def connect(self):
                    # overrides the version in httplib so that we do
                    #    certificate verification
                    sock = socket.create_connection((self.host, self.port),
                                                    self.timeout)
                    if self._tunnel_host:
                        self.sock = sock
                        self._tunnel()

                    # wrap the socket using verification with the root
                    #    certs in trusted_root_certs
                    self.sock = ssl.wrap_socket(sock,
                                                self.key_file,
                                                self.cert_file,
                                                cert_reqs=ssl.CERT_REQUIRED,
                                                ca_certs=ca_certs,
                                                )

            # wraps https connections with ssl certificate verification
            class VerifiedHTTPSHandler(urllib.request.HTTPSHandler):
                def __init__(self, connection_class=VerifiedHTTPSConnection):
                    self.specialized_conn_class = connection_class
                    urllib.request.HTTPSHandler.__init__(self)

                def https_open(self, req):
                    return self.do_open(self.specialized_conn_class, req)

            https_handler = VerifiedHTTPSHandler()
            if proxy:
                url_opener = urllib.request.build_opener(https_handler, urllib.request.ProxyHandler({'https' : proxy}))
            else:
                url_opener = urllib.request.build_opener(https_handler, urllib.request.ProxyHandler({}))

        return url_opener
    
