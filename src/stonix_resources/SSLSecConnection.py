import sys
import http.client
import urllib.request, urllib.error, urllib.parse
import ssl
import socket

class SSLSecConnection(http.client.HTTPSConnection):
    '''

    '''

    def __init__(self, *args, **kwargs):
        '''

        :param args:
        :param kwargs:
        '''

        http.client.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        '''Interesting reference: http://nullege.com/codes/show/src%40p%40y%40pydle-HEAD%40pydle%40connection.py/144/ssl.VERIFY_CRL_CHECK_CHAIN/python
        This class is not currently checking certificate revocation...


        '''

        if hasattr(ssl, '_create_unverified_context'):
            # allow unverified SSL
            ssl._create_default_https_context = ssl._create_unverified_context

        self.sock = socket.create_connection((self.host, self.port), self.timeout)

        """
        if self._tunnel_host:
            self.sock = sock
            # peercert = sock.getpeercert()
            # ssl.match_hostname(peercert, self.host)
            self._tunnel()

        if sys.hexversion >= 0x02070900:
            context = ssl.SSLContext()
            ""
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ""
            #####
            #  verify_mode must be one of:
            #  CERT_NONE (In this mode (the default), no certificates will be 
            #             required from the other side of the socket connection.
            #             If a certificate is received from the other end, no
            #             attempt to validate it is made.)
            #  CERT_OPTIONAL (in this mode no certificates will be required from
            #                 the other side of the socket connection; but if 
            #                 they are provided, validation will be attempted 
            #                 and an SSLError will be raised on failure.)
            #  CERT_REQUIRED (In this mode, certificates are required from the 
            #                 other side of the socket connection; an SSLError 
            #                 will be raised if no certificate is provided, or
            #                 if its validation fails.)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            ""
            #context.load_default_certs()
            # Set some relevant options:
            # - No server should use SSLv2 any more, it's outdated and full of security holes.
            # - Disable compression in order to counter the CRIME attack. (https://en.wikipedia.org/wiki/CRIME_%28security_exploit%29)
            for opt in [ 'NO_SSLv2', 'NO_COMPRESSION']:
                if hasattr(ssl, 'OP_' + opt):
                    context.options |= getattr(ssl, 'OP_' + opt)
            """

        # self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)

class SSLSecHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(SSLSecConnection(), req)

if sys.hexversion >= 0x02070900:
    urllib.request.install_opener(urllib.request.build_opener(SSLSecHandler()))
