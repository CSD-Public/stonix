'''
Created on Oct 18, 2012
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

This module contains variables used to localize STONIX behavior for a given
site. It is intended to be edited by the personnel packaging STONIX for use and
is not intended to be modified by systems administrators or end users.

These variables will be referenced directly by STONIX with only nominal safety
checks. Mistakes made in this file may lead to errors in STONIX behavior or
run-time failures. Pay attention to comments documenting both the content and
format of entries.

@author: dkennel
@change: 2014/07/14 - ekkehard - added foo.bar.com = FOO.BAR.COM to
KERB5
@change: 2014/08/20 - Added version variable to here and updated all locations
that access the version variable to use this copy.
@change: 2015/03/01 - ekkehard - incremented STONIXVERSION = '0.8.15'
@change: 2015/04/07 - ekkehard - incremented STONIXVERSION = '0.8.16'
'''

# The Version number of the STONIX application. Modify this only if you need to
# define a local version number. Caution should be used to not conflict with
# the upstream versioning numbers. The version is handled as a string so
# arbitrary values are fine. A recommended local version might look like this:
# 1.2.2-local3 or just 1.2.2-3 or 1.2.2.3

STONIXVERSION = '0.8.20'

# The report server should be a string containing a valid FQDN or IP address
# for the host that STONIX should upload it's run report XML data to.
REPORTSERVER = 'foo.bar.com'

# If you are not using a central report server then set the value of
# sendreports to False. Please note no quotes.
# sendreports = False
SENDREPORTS = True

# The SoftwarePatching rule will check to see if local update sources are being
# used. If you have local update sources list them here. This check will be
# skipped if the list is empty. The list is in python list format:
# updateservers = ['myserver1.mydomain.tld', 'myserver2.mydomain.tld']
UPDATESERVERS = ['foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com',
                 'foo.bar.com']

# Stonix can set OS X systems to use a local Apple Software Update Server
# if you have an ASUS server on your network enter its FQDN here. A zero
# length entry will be ignored.
APPLESOFTUPDATESERVER = 'http://foo.bar.com:8088/'

# If you are using central logging servers for catching syslog data you can
# configure that hostname here as either a FQDN or IP address.
CENTRALLOGHOST = 'foo.bar.com'

# Warning Banners are site-specific
# You may edit the text of the warning banner here to reflect your particular
# site
WARNINGBANNER = "**WARNING**WARNING**WARNING**WARNING**WARNING**\n\n" + \
"This is a Department of Energy (DOE) computer system. DOE computer\n" + \
"systems are provided for the processing of official U.S. Government\n" + \
"information only. All data contained within DOE computer systems is\n" + \
"owned by the DOE, and may be audited, intercepted, recorded, read,\n" + \
"copied, or captured in any manner and disclosed in any manner, by\n" + \
"authorized personnel. THERE IS NO RIGHT OF PRIVACY IN THIS SYSTEM.\n" + \
"System personnel may disclose any potential evidence of crime found on\n" + \
"DOE computer systems to appropriate authorities. USE OF THIS SYSTEM BY\n" + \
"ANY USER, AUTHORIZED OR UNAUTHORIZED, CONSTITUTES CONSENT TO THIS\n" + \
"AUDITING, INTERCEPTION, RECORDING, READING, COPYING, CAPTURING, and\n" + \
"DISCLOSURE OF COMPUTER ACTIVITY.\n\n" + \
"**WARNING**WARNING**WARNING**WARNING**WARNING**"


# Warning Banners abbreviated for OS X login Screen
OSXSHORTWARNINGBANNER = "This is a U.S. Government Federal computer " + \
"system. Authorized use only. Users have no explicit/implicit expectation " + \
"of privacy. By using this system the user consents to monitoring and " + \
"disclosure. See http://foo.bar.com/copyright.shtml#disclaimers"

# Here you can specify the FQDN of your mail relay server
# Use the convention: hostname.domain
MAILRELAYSERVER = 'foo.bar.com'

# STONIX Error Message Source Address
# Set this to the email address that STONIX error messages should appear to
# come from.
STONIXERR = 'stonixerr@bar.com'

# STONIX Error Message Destination
# Set the email address that STONIX error messages should be delivered to.
STONIXDEVS = 'stonix-dev@bar.com'

# Set the URL and port of your proxy server if one is in use.
# If you do not use a proxy server set this to None.
# Note that STONIX will not work through authenticating proxies.
# PROXY = 'http://my.proxy.com:3128'
# PROXY = None
PROXY = 'http://foo.bar.com:8080'
PROXYCONFIGURATIONFILE = "http://foo.bar.com/wpad.dat"

# Specify a subnet to allow services access to in /etc/hosts.allow
ALLOWNET = '192.168.0.1/24'

# Specify a subnet to use with XinetdAccessControl (/etc/xinetd.conf)
XINETDALLOW = '192.168.0.1/24'

# Specify a subnet to allow printer browsing on
# This will be written in the cups config file for the system
PRINTBROWSESUBNET = ''

# Specify a list of internal Network Time Protocol (NTP) Servers
NTPSERVERSINTERNAL = ["foo.bar.com", "foo.bar.com"]

# Specify a list of external Network Time Protocol (NTP) Servers
NTPSERVERSEXTERNAL = ["0.us.pool.ntp.org", "1.us.pool.ntp.org",
                      "2.us.pool.ntp.org", "3.us.pool.ntp.org"]

# List Of Corporate Network Servers used to determine if we are on the
# corporate network they need to be reachable only internally on port 80
CORPORATENETWORKSERVERS = ["foo.bar.com"]

# Content of the kerb5.conf file
KERB5 = '''[libdefaults]
    default_realm = bar.com
    allow_weak_crypto = true
    forwardable = true
[realms]
    bar.com = {
    kdc = foo.bar.com
    kdc = foo.bar.com
    admin_server = foo.bar.com
    }
[pam]
    debug = false
    krb4_convert = false
[domain_realm]
    foo.bar.com = FOO.BAR.COM
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM'''

# Self Update server - a web server that houses packages for Mac, Solaris and
# Gentoo, for a self update feature, since these OSs do not have good package
# management like yum and apt-get.
SELFUPDATESERVER = "foo.bar.com"

HOSTSDENYDEFAULT = """##########################################################################
#
# FILENAME: hosts.deny
#  LASTMOD: Thu Jan  4 12:35:00 MST 2001
#
#  DESCRIP: CTN standard hosts.deny file for tcp wrappers with banners
#       OS: common
#
#   AUTHOR:
#
# WARNINGS: By default if it's not allowed it is denied
#
##########################################################################

all : all : banners /etc/banners : DENY
"""

HOSTSALLOWDEFAULT = """##########################################################################
## Filename:            hosts.allow
## Description:         Access control file for TCP Wrappers 7.6
## Author:
## Notes:               By default all services are denied. Uncomment the
##                      relevant lines to allow access.
## Release/ver:         stor3.1
## Modified date:       10/30/2007
## Changelog:           Added commented entries for nfs services
##########################################################################

# Allow access to localhost
all : 127.0.0.1 : ALLOW

# Kerberized services (uncomment to allow access)
#ftpd : {allownet} : ALLOW
#kshd : {allownet} : ALLOW
#klogind : {allownet} : ALLOW
#telnetd : {allownet} : ALLOW

# Need special access for sgi_fam
# Should be temporary
#fam: ALL : ALLOW

# Services that may be needed for NFS
#sunrpc: {allownet} : ALLOW
#nfs: {allownet} : ALLOW
#portmap: {allownet} : ALLOW
#lockd: {allownet} : ALLOW
#mountd: {allownet} : ALLOW
#rquotad: {allownet} : ALLOW
#statd: {allownet} : ALLOW

# SSH access
sshd: {allownet} : ALLOW
sshdfwd-X11: {allownet} : ALLOW

# Other services (uncomment to allow access)
#in.fingerd : {allownet} : banners /etc/banners : ALLOW
#in.ftpd : {allownet} : banners /etc/banners/in.ftpd : ALLOW
#in.rexecd : {allownet} : banners /etc/banners : ALLOW
#in.rlogind : {allownet} : banners /etc/banners/in.rlogind : ALLOW
#in.rshd : {allownet} : banners /etc/banners/in.rshd : ALLOW
#in.telnetd : {allownet} : banners /etc/banners/in.telnetd : ALLOW

# Deny all other access
all : all : DENY
"""

# This is used in the SecureMailClient Rule to set up DomainForMatching
APPLEMAILDOMAINFORMATCHING = "bar.com"

# This list contains quoted strings that are fully qualified paths to
# world writable directories that are common at your site (possibly due to
# widely deployed software).
SITELOCALWWWDIRS = []

# Default messages for self.detailedresults initialization, report, fix, undo
DRINITIAL = "Neither report, fix, or revert have been run yet."
DRREPORTCOMPIANT = "Rule is Compliant."
DRREPORTNOTCOMPIANT = "Rule is not Compliant."
DRREPORTNOTAVAILABLE = "This Rule does not support report."
DRFIXSUCCESSFUL = "Rule was fixed successfully."
DRFIXFAILED = "The fix for this Rule failed."
DRFIXNOTAVAILABLE = "This Rule does not support fix."
DRREPORTAVAILABLE = "This Rule does not support report."
DRUNDOSUCCESSFUL = "Revert was completed successfully."
DRUNDOFAILED = "The revert for this Rule failed."
DRUNDONOTAVAILABLE = "No recoverable events are available for this Rule."
GATEKEEPER = "4BF178C7-A564-46BA-8BD1-9C374043CC17"
WINLOG = "@@foo.bar.com"
LANLLOGROTATE = "700.lanl.logrotate"
