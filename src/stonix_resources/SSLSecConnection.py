import sys
import httplib
import urllib2

class SSLSecConnection(httplib.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        httplib.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        """ 
        Interesting reference: http://nullege.com/codes/show/src%40p%40y%40pydle-HEAD%40pydle%40connection.py/144/ssl.VERIFY_CRL_CHECK_CHAIN/python
        This class is not currently checking certificate revocation...
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            peercert = sock.getpeercert()
            ssl.match_hostname(peercert, self.host)
            self._tunnel()

        if sys.hexversion >= 0x02070900:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            # Set some relevant options:
            # - No server should use SSLv2 any more, it's outdated and full of security holes.
            # - Disable compression in order to counter the CRIME attack. (https://en.wikipedia.org/wiki/CRIME_%28security_exploit%29)
            for opt in [ 'NO_SSLv2', 'NO_COMPRESSION']:
                if hasattr(ssl, 'OP_' + opt):
                    context.options |= getattr(ssl, 'OP_' + opt)

        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)

class SSLSecHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(SSLSecConnection(), req)

if sys.hexversion >= 0x02070900:
    urllib2.install_opener(urllib2.build_opener(SSLSecHandler()))


