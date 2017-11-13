###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
'''
Created on Oct 18, 2012

This module contains variables used to localize STONIX behavior for a given
site. It is intended to be edited by the personnel packaging STONIX for use and
is not intended to be modified by systems administrators or end users.

These variables will be referenced directly by STONIX with only nominal safety
checks. Mistakes made in this file may lead to errors in STONIX behavior or
run-time failures. Pay attention to comments documenting both the content and
format of entries.

@author: dkennel
@change: 2014/07/14 - ekkehard - added eia-ecs-p-f5.lanl.gov = WIN.LANL.GOV to
KERB5
@change: 2014/08/20 - Added version variable to here and updated all locations
that access the version variable to use this copy.
@change: 2015/03/01 - ekkehard - incremented STONIXVERSION = '0.8.15'
@change: 2015/04/07 - ekkehard - incremented STONIXVERSION = '0.8.16'
@change: 2015/08/20 - eball - Added KRB5 for Linux Kerberos setup
@change: 2015/12/07 - eball Renamed KERB5 to MACKRB5 and KRB5 to LINUXKRB5
@change: 2015/12/14 - ekkehard update os x kerberos option & stonixversion
@change: 2016/01/13 - rsn Added MACREPOROOT
@change: 2016/02/03 - ekkehard - incremented STONIXVERSION = '0.9.5'
@change: 2016/05/05 - eball Add LOCALDOMAINS for AuditFirefoxUsage(84)
@change: 2017/03/07 - dkennel add FISMACAT for FISMA/FIPS 199 risk category
@change: 2017/07/07 - ekkehard - incremented STONIXVERSION = '0.9.10'
@change: 2017/10/10 - ekkehard - incremented STONIXVERSION = '0.9.13'
@change: 2017/11/13 - ekkehard - incremented STONIXVERSION = '0.9.13'
'''

# The Version number of the STONIX application. Modify this only if you need to
# define a local version number. Caution should be used to not conflict with
# the upstream versioning numbers. The version is handled as a string so
# arbitrary values are fine. A recommended local version might look like this:
# 1.2.2-local3 or just 1.2.2-3 or 1.2.2.3

# Variable Type: String
STONIXVERSION = '0.9.14'

# FISMACAT is the FISMA/FIPS 199 risk categorization of the system. This value
# is used to determine rule applicability and behavior with the higher the
# risk value is causing more rules to activate and active rules to be more
# stringent. This can be overridden by the System Administrator via the conf
# file but may never be lower than the value specified here. Valid values are
# 'low', 'med' and 'high'

FISMACAT = 'low'

# The report server should be a string containing a valid FQDN or IP address
# for the host that STONIX should upload it's run report XML data to.
REPORTSERVER = 'csd-web.lanl.gov'

# If you are not using a central report server then set the value of
# sendreports to False. Please note no quotes.
# sendreports = False
SENDREPORTS = True

# The SoftwarePatching rule will check to see if local update sources are being
# used. If you have local update sources list them here. This check will be
# skipped if the list is empty. The list is in python list format:
# updateservers = ['myserver1.mydomain.tld', 'myserver2.mydomain.tld']
UPDATESERVERS = ['rhnsd.lanl.gov',
                 'rhnsc.lanl.gov',
                 'rhus.lanl.gov',
                 'rhnsg.lanl.gov',
                 'rhusd.lanl.gov',
                 'rhusc.lanl.gov']

# Stonix can set OS X systems to use a local Apple Software Update Server
# if you have an ASUS server on your network enter its FQDN here. A zero
# length entry will be ignored.
APPLESOFTUPDATESERVER = 'http://asus.lanl.gov:8088/'

# Repository used by the package helper to retrieve software for installation.
# Currently only uses "https" as a valid protocol
MACREPOROOT = 'https://jds001.lanl.gov/CasperShare/'

# If you are using central logging servers for catching syslog data you can
# configure that hostname here as either a FQDN or IP address.
CENTRALLOGHOST = 'winlog.lanl.gov'

# Warning Banners are site-specific
# You may edit the text of the warning banner here to reflect your particular
# site
WARNINGBANNER = "**WARNING**WARNING**WARNING**WARNING**WARNING**\n\n" + \
"This is a Department of Energy (DOE) computer system. DOE computer " + \
"systems are provided for the processing of official U.S. Government " + \
"information only. All data contained within DOE computer systems is " + \
"owned by the DOE, and may be audited, intercepted, recorded, read, " + \
"copied, or captured in any manner and disclosed in any manner, by " + \
"authorized personnel. THERE IS NO RIGHT OF PRIVACY IN THIS SYSTEM. " + \
"System personnel may disclose any potential evidence of crime found on " + \
"DOE computer systems to appropriate authorities. USE OF THIS SYSTEM BY " + \
"ANY USER, AUTHORIZED OR UNAUTHORIZED, CONSTITUTES CONSENT TO THIS " + \
"AUDITING, INTERCEPTION, RECORDING, READING, COPYING, CAPTURING, and " + \
"DISCLOSURE OF COMPUTER ACTIVITY.\n\n" + \
"**WARNING**WARNING**WARNING**WARNING**WARNING**\n"

ALTWARNINGBANNER = "This is a Department of Energy (DOE) computer system. DOE computer\\n" + \
"systems are provided for the processing of official U.S. Government\\n" + \
"information only. All data contained within DOE computer systems is\\n" + \
"owned by the DOE, and may be audited, intercepted, recorded, read,\\n" + \
"copied, or captured in any manner and disclosed in any manner, by\\n" + \
"authorized personnel. THERE IS NO RIGHT OF PRIVACY IN THIS SYSTEM.\\n" + \
"System personnel may disclose any potential evidence of crime found on\\n" + \
"DOE computer systems to appropriate authorities. USE OF THIS SYSTEM BY\\n" + \
"ANY USER, AUTHORIZED OR UNAUTHORIZED, CONSTITUTES CONSENT TO THIS\\n" + \
"AUDITING, INTERCEPTION, RECORDING, READING, COPYING, CAPTURING, and\\n" + \
"DISCLOSURE OF COMPUTER ACTIVITY.\n\n"

# Warning Banners abbreviated for OS X login Screen
OSXSHORTWARNINGBANNER = "This is a U.S. Government Federal computer " + \
"system. Authorized use only. Users have no explicit/implicit expectation " + \
"of privacy. By using this system the user consents to monitoring and " + \
"disclosure. USE OF THIS SYSTEM BY ANY USER, AUTHORIZED OR UNAUTHORIZED, " + \
"CONSTITUTES CONSENT TO THIS AUDITING, INTERCEPTION, RECORDING, READING, " + \
"COPYING, CAPTURING, and DISCLOSURE OF COMPUTER ACTIVITY. " + \
"See http://int.lanl.gov/copyright.shtml#disclaimers"

# Here you can specify the FQDN of your mail relay server
# Use the convention: hostname.domain
MAILRELAYSERVER = 'mail.lanl.gov'

# STONIX Error Message Source Address
# Set this to the email address that STONIX error messages should appear to
# come from.
STONIXERR = 'dkennel@lanl.gov'

# STONIX Error Message Destination
# Set the email address that STONIX error messages should be delivered to.
STONIXDEVS = 'stonix-dev@lanl.gov'

# Set the URL and port of your proxy server if one is in use.
# If you do not use a proxy server set this to None.
# Note that STONIX will not work through authenticating proxies.
# PROXY = 'http://my.proxy.com:3128'
# PROXY = None
PROXY = 'http://proxyout.lanl.gov:8080'
PROXYCONFIGURATIONFILE = "http://wpad.lanl.gov/wpad.dat"
PROXYDOMAIN = "lanl.gov"
PROXYDOMAINBYPASS = "*.lanl.gov"

# Domain Name Server (DNS) defaults
DNS = "128.165.4.4 128.165.4.33"

# Specify a subnet to allow services access to in /etc/hosts.allow
# use format: xxx.xxx.0.0/16
ALLOWNETS = ['128.165.0.0/16']

# Specify a subnet to allow in xinetd.conf
XINETDALLOW = '128.165.0.0/16'

# Specify a subnet to allow printer browsing on
# This will be written in the cups config file for the system
PRINTBROWSESUBNET = '192.168.0.1/24'

# Specify a list of internal Network Time Protocol (NTP) Servers
NTPSERVERSINTERNAL = ["time.lanl.gov", "ntp.lanl.gov"]

# Specify a list of external Network Time Protocol (NTP) Servers
NTPSERVERSEXTERNAL = ["0.us.pool.ntp.org", "1.us.pool.ntp.org",
                      "2.us.pool.ntp.org", "3.us.pool.ntp.org"]

# List Of Corporate Network Servers used to determine if we are on the
# corporate network they need to be reachable only internally on port 80
CORPORATENETWORKSERVERS = ["csd-web.lanl.gov"]

# Content of the krb5.conf file
MACKRB5 = '''# Updated Test Configuration
# https://tf.lanl.gov/sf/wiki/do/viewPage/projects.piv/wiki/ProposedKrb5Configuration

# 20160928  [libdefaults]  Added dns_lookup_kdc=false and dns_lookup_realm=false
#           [domain_realm] Added Exchange and SharePoint file share realm mappings
# 20161014  Added note to service admins
#           [domain_realm] Added file share realm mappings
# 20161018  [appdefaults]  Added section
#           [pam] section removed; pam config added to [appdefaults] per krb5 syntax
# 20161020  [domain_realm] Added mappings of services discovered through Splunk logs
#           These include unique results in Server OUs with more than 14 hits last month
# 20170228  [domain_realm] Renamed xsamba03.lanl.gov to xsamba.lanl.gov

### NOTE to Service Admins: Suggested configuration is to ensure your service DNS A record
### is in the same domain/realm as the service SPN (i.e. service.lanl.gov has the SPN 
### HTTP/service.lanl.gov registered in the lanl.gov Kerberos realm or service.win.lanl.gov
### has the SPN HTTP/service.win.lanl.gov registered in the WIN.LANL.GOV Kerberos realm).
### Situations such as where service.lanl.gov has the SPN HTTP/service.lanl.gov registered
### in the WIN.LANL.GOV Kerberos realm may cause issues with clients finding the SPN

[libdefaults]
   default_realm = lanl.gov
   forwardable = true
   dns_lookup_kdc = false
   dns_lookup_realm = false
   ticket_lifetime = 24h
   renew_lifetime = 7d
   clockslew = 300

[realms]
   lanl.gov = {
      kdc = kerberos-slaves.lanl.gov
      kdc = kerberos.lanl.gov
      admin_server = kerberos.lanl.gov
   }
   WIN.LANL.GOV = {
      kdc = win.lanl.gov
   }

[capaths]
   WIN.LANL.GOV = {
      lanl.gov = .
   }

[domain_realm]
# LANL domains
   .win.lanl.gov = WIN.LANL.GOV
   .lanl.gov = lanl.gov
   win.lanl.gov = WIN.LANL.GOV

# File shares
   slide.lanl.gov = WIN.LANL.GOV
   slip.lanl.gov = WIN.LANL.GOV
   nisac.lanl.gov = WIN.LANL.GOV
   myhome.lanl.gov = WIN.LANL.GOV
   eden.lanl.gov = WIN.LANL.GOV
   lenz.lanl.gov = WIN.LANL.GOV
   bioassay4.lanl.gov = WIN.LANL.GOV
   cfo-acct.lanl.gov = WIN.LANL.GOV
   EIA-DW-P-WS2.lanl.gov = WIN.LANL.GOV
   EIA-EDMS-P-CS1.lanl.gov = WIN.LANL.GOV
   eia-emp-b-wa2.lanl.gov = WIN.LANL.GOV
   eia-esbmc-d-as1.lanl.gov = WIN.LANL.GOV
   eia-gis-p-as2.lanl.gov = WIN.LANL.GOV
   eia-gis-p-ws2.lanl.gov = WIN.LANL.GOV
   EIA-PFITS-B-SQ2.lanl.gov = WIN.LANL.GOV
   esde-dev-ph.lanl.gov = WIN.LANL.GOV
   esde-sql-ph.lanl.gov = WIN.LANL.GOV
   eswebserver.lanl.gov = WIN.LANL.GOV
   eswebserver2.lanl.gov = WIN.LANL.GOV
   hdcs.lanl.gov = WIN.LANL.GOV
   HODAKA.lanl.gov = WIN.LANL.GOV
   hsr-rpas.lanl.gov = WIN.LANL.GOV
   ITSM-ARS-P.lanl.gov = WIN.LANL.GOV
   ITSM-SQL-P.lanl.gov = WIN.LANL.GOV
   MAICO.lanl.gov = WIN.LANL.GOV
   rtg-atf.lanl.gov = WIN.LANL.GOV
   ta55storageb.lanl.gov = WIN.LANL.GOV
   virginia.lanl.gov = WIN.LANL.GOV
   xfiles02.lanl.gov = WIN.LANL.GOV
   xsamba.lanl.gov = WIN.LANL.GOV

# Web services
   exg13-p-mbx01-f5.lanl.gov = WIN.LANL.GOV
   sp2013-p-f5.lanl.gov = WIN.LANL.GOV
   sp2013-p-hns-f5.lanl.gov = WIN.LANL.GOV
   sp2013-p-ssf-f5.lanl.gov = WIN.LANL.GOV
   sp2013-p-ssf-f5-oce.lanl.gov = WIN.LANL.GOV
   sp2013-p-f5.lanl.gov = WIN.LANL.GOV
   sp2013-p-ws01-f5.lanl.gov = WIN.LANL.GOV
   sp2013-p-ws02-f5.lanl.gov = WIN.LANL.GOV
   sp2013-p-106-ws02.lanl.gov = WIN.LANL.GOV
   sp2013-p-106-hns.lanl.gov = WIN.LANL.GOV
   cmdp1.lanl.gov = WIN.LANL.GOV
   cmdp2.lanl.gov = WIN.LANL.GOV
   cmdp3.lanl.gov = WIN.LANL.GOV
   cmmp1.lanl.gov = WIN.LANL.GOV
   cmsup.lanl.gov = WIN.LANL.GOV
   conmanmp.lanl.gov = WIN.LANL.GOV
   eia-drs-p-ws1.lanl.gov = WIN.LANL.GOV
   EIA-DWSUB-P-AS2.lanl.gov = WIN.LANL.GOV
   EIA-EAS-P-AS2.lanl.gov = WIN.LANL.GOV
   EIA-EAS-P-WS1.lanl.gov = WIN.LANL.GOV
   eia-sp10-p-as1.lanl.gov = WIN.LANL.GOV
   grantami.lanl.gov = WIN.LANL.GOV
   jobboss.lanl.gov = WIN.LANL.GOV
   lims-as3.lanl.gov = WIN.LANL.GOV
   mymail.lanl.gov = WIN.LANL.GOV
   pmdprintsrv.lanl.gov = WIN.LANL.GOV
   pmdshpt-b.lanl.gov = WIN.LANL.GOV
   pmd-shpt-prod.lanl.gov = WIN.LANL.GOV
   pmd-sql-p.lanl.gov = WIN.LANL.GOV
   print02.lanl.gov = WIN.LANL.GOV
   proforce-web.lanl.gov = WIN.LANL.GOV

# Other

[appdefaults]
   pam = {
      debug = false
      krb4_convert = false
   }

'''

LINUXKRB5 = '''# Test Configuration
# 2016-09-28
# https://tf.lanl.gov/sf/wiki/do/viewPage/projects.piv/wiki/ProposedKrb5Configuration
# + logging
# + ticket_lifetime = 24h, renew_lifetime = 7d, clockslew = 300
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log
[libdefaults]
  default_realm = lanl.gov
  forwardable = true
  dns_lookup_kdc = false
  dns_lookup_realm = false
  ticket_lifetime = 24h
  renew_lifetime = 7d
  clockslew = 300
[realms]
  lanl.gov = {
    kdc = kerberos-slaves.lanl.gov
    kdc = kerberos.lanl.gov
    admin_server = kerberos.lanl.gov
  }
  WIN.LANL.GOV = {
    kdc = win.lanl.gov
  }
[pam]
  debug = false
  krb4_convert = false
[domain_realm]
  win.lanl.gov = WIN.LANL.GOV
 .win.lanl.gov = WIN.LANL.GOV
  lanl.gov = lanl.gov
 .lanl.gov = lanl.gov
 exg13-p-mbx01-f5.lanl.gov = WIN.LANL.GOV
 sp2013-p-f5.lanl.gov = WIN.LANL.GOV
 sp2013-p-ws01-f5.lanl.gov = WIN.LANL.GOV
 sp2013-p-ws02-f5.lanl.gov = WIN.LANL.GOV
 sp2013-p-106-ws02.lanl.gov = WIN.LANL.GOV
 sp2013-p-106-hns.lanl.gov = WIN.LANL.GOV
 myhome.lanl.gov = WIN.LANL.GOV
[capaths]
  WIN.LANL.GOV = {
    lanl.gov = .
  }

'''

# Self Update server - a web server that houses packages for Mac, Solaris and
# Gentoo, for a self update feature, since these OSs do not have good package
# management like yum and apt-get.
SELFUPDATESERVER = "csd-web.lanl.gov"

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
APPLEMAILDOMAINFORMATCHING = "lanl.gov"

# This list contains quoted strings that are fully qualified paths to
# world writable directories that are common at your site (possibly due to
# widely deployed software).
SITELOCALWWWDIRS = ['/var/lanl/puppet/run']

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
WINLOG = "@@winlog.lanl.gov"
LANLLOGROTATE = "700.lanl.logrotate"

# The following should be system accounts which should not be disabled by DisableInactiveAccounts
EXCLUDEACCOUNTS = ["jss-server-account", "puppet"]

# The following list is used by AuditFirefoxUsage(84). It lists domains that
# are approved for browsing by the root user.
LOCALDOMAINS = ["127.0.0.1", "localhost", "lanl.gov"]

# these options will be set in /etc/dhcp/dhclient.conf
# a value of 'request' will cause the client to request that
# option's configuration from the dhcp server. a value of
# 'supersede' will cause the client to use the locally-defined
# value in the DHCPSup dictionary, defined here in localize.py
# below are the request/supersede settings used at LANL. do not
# change, unless you have an exception or deviation
DHCPDict = {'subnet-mask': 'request',
            'time-offset': 'supersede',
            'routers': 'request',
            'domain-name': 'supersede',
            'domain-name-servers': 'supersede',
            'nis-domain': 'supersede',
            'nis-servers': 'supersede',
            'ntp-servers': 'supersede'}

# these options will be used whenever a value of
# 'supersede' is specified for one of the options in
# DCHPDict. Change these to reflect your organization's
# actual servers/domains/settings

# change the 'changeme' values if you choose to supersede
# them in the DHCPDict dictionary, above!
DHCPSup = {'subnet-mask': 'changeme',
           'time-offset': '-21600',
           'routers': 'changeme',
           'domain-name': '"lanl.gov"',
           'domain-name-servers': '128.165.4.4, 128.165.4.33',
           'nis-domain': '""',
           'nis-servers': '""',
           'ntp-servers': '"ntp.lanl.gov"'}


# LANL root certificate
ROOTCERT = """-----BEGIN CERTIFICATE-----
MIIDsTCCAxqgAwIBAgIEPZxq5jANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJV
UzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MR0wGwYDVQQLExREZXBhcnRtZW50
IG9mIEVuZXJneTEnMCUGA1UECxMeTG9zIEFsYW1vcyBOYXRpb25hbCBMYWJvcmF0
b3J5MB4XDTAyMTAwMzE1MzYwMFoXDTIyMTAwMzE2MDYwMFowbzELMAkGA1UEBhMC
VVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEdMBsGA1UECxMURGVwYXJ0bWVu
dCBvZiBFbmVyZ3kxJzAlBgNVBAsTHkxvcyBBbGFtb3MgTmF0aW9uYWwgTGFib3Jh
dG9yeTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtH18PJVcwScwCqq8vcPW
QRsdx5Olyh8ebMIi4y+2UnHxvOe5V/5C7ScGmwNk1Aiik6zu4r/k5HDMA/mukHhT
SKYzPqv76ta3BShLIvTUL+vIMb8l3ujxhjJZ2caD/0bgWm0o2Zn9tT83bUptV0u8
0WiA0nPUulgtfSjn7E8Brw0CAwEAAaOCAVgwggFUMBEGCWCGSAGG+EIBAQQEAwIA
BzCBlwYDVR0fBIGPMIGMMIGJoIGGoIGDpIGAMH4xCzAJBgNVBAYTAlVTMRgwFgYD
VQQKEw9VLlMuIEdvdmVybm1lbnQxHTAbBgNVBAsTFERlcGFydG1lbnQgb2YgRW5l
cmd5MScwJQYDVQQLEx5Mb3MgQWxhbW9zIE5hdGlvbmFsIExhYm9yYXRvcnkxDTAL
BgNVBAMTBENSTDEwKwYDVR0QBCQwIoAPMjAwMjEwMDMxNTM2MDBagQ8yMDIyMTAw
MzE2MDYwMFowCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaAFGpUvk0hTQtmaeQo/XTb
RQpSbe8KMB0GA1UdDgQWBBRqVL5NIU0LZmnkKP1020UKUm3vCjAMBgNVHRMEBTAD
AQH/MB0GCSqGSIb2fQdBAAQQMA4bCFY1LjA6NC4wAwIEkDANBgkqhkiG9w0BAQUF
AAOBgQBzHXovZ7uyqHEmT8H1ov83leUZrg7IYjtUBxhQ//YkmCLtrUoklzjC0qyT
i/zquys8IPF+WLFtQrThyN/t0n9mnFhGAg1vtkwQtCXfzqAizXXUx0ni8NOO/O3M
i44wV+MRwyGk0t7l1mz9pKEsbJ1ZkvjmyjNBHLDfv2s64qgDBw==
-----END CERTIFICATE-----"""


PWQUALITY_HIGH_REGEX =  "^password[ \t]+requisite[ \t]+pam_pwquality.so[ \t]+" + \
    "minlen=14[ \t]+minclass=4[ \t]+difok=7[ \t]+dcredit=0[ \t]ucredit=0[ \t]" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"
PWQUALITY_REGEX = regex = "^password[ \t]+requisite[ \t]+pam_pwquality.so[ \t]+" + \
    "minlen=8[ \t]+minclass=3[ \t]+difok=7[ \t]+dcredit=0[ \t]ucredit=0[ \t]" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"
CRACKLIB_HIGH_REGEX = "^password[ \t]+requisite[ \t]+pam_cracklib.so[ \t]+" + \
    "minlen=14[ \t]+minclass=4[ \t]+difok=7[ \t]+dcredit=0[ \t]ucredit=0[ \t]" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"
CRACKLIB_REGEX = "^password[ \t]+requisite[ \t]+pam_cracklib.so[ \t]+" + \
    "minlen=8[ \t]+minclass=3[ \t]+difok=7[ \t]+dcredit=0[ \t]ucredit=0[ \t]" + \
    "lcredit=0[ \t]+ocredit=0[ \t]+retry=3[ \t]+maxrepeat=3"
PAMFAIL_REGEX = "^auth[ \t]+required[ \t]+pam_faillock.so preauth silent audit " + \
                        "deny=5 unlock_time=900 fail_interval=900"
PAMTALLY_REGEX = "^auth[ \t]+required[ \t]+pam_tally2.so deny=5 " + \
                        "unlock_time=900 onerr=fail"

AUTH_APT = '''auth        required      pam_env.so
auth        required      pam_tally2.so deny=5 unlock_time=900 onerr=fail
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        required      pam_deny.so
'''

ACCOUNT_APT = '''account     required      pam_tally2.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

PASSWORD_APT = '''password    requisite     \
pam_pwquality.so minlen=8 minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow try_first_pass \
use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

SESSION_APT = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
-session    optional      pam_systemd.so
'''

SESSION_HOME_APT = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
-session    optional      pam_systemd.so
session     required      pam_mkhomedir.so skel=/etc/skel umask=0077
'''

AUTH_ZYPPER = '''auth    required        pam_env.so
auth    required        pam_tally2.so deny=5 unlock_time=900 onerr=fail
auth    optional        pam_gnome_keyring.so
auth    sufficient      pam_unix.so     try_first_pass
auth    required        pam_sss.so      use_first_pass
'''

ACCOUNT_ZYPPER = '''account requisite       pam_unix.so     try_first_pass
account sufficient      pam_localuser.so
account required        pam_sss.so      use_first_pass
'''

PASSWORD_ZYPPER = '''password        requisite       \
pam_pwquality.so minlen=8 minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 \
ocredit=0 retry=3 maxrepeat=3
password        sufficient      pam_unix.so sha512 shadow \
try_first_pass use_authtok remember=10
password        optional        pam_gnome_keyring.so    use_authtok
password        required        pam_sss.so      use_authtok
'''

SESSION_ZYPPER = '''session required        pam_limits.so
session required        pam_unix.so     try_first_pass
session optional        pam_sss.so
session optional        pam_umask.so
session optional        pam_systemd.so
session optional        pam_gnome_keyring.so    auto_start \
only_if=gdm,gdm-password,lxdm,lightdm
session optional        pam_env.so
'''

SESSION_HOME_ZYPPER = '''session required        pam_limits.so
session required        pam_unix.so     try_first_pass
session optional        pam_sss.so
session optional        pam_umask.so
session optional        pam_systemd.so
session optional        pam_gnome_keyring.so    auto_start \
only_if=gdm,gdm-password,lxdm,lightdm
session optional        pam_env.so
session     required      pam_mkhomedir.so skel=/etc/skel umask=0077
'''

AUTH_NSLCD = '''auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 \
unlock_time=900 fail_interval=900
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_krb5.so use_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=5 \
unlock_time=900 fail_interval=900
auth        required      pam_deny.so
'''

ACCOUNT_NSLCD = '''account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

PASSWORD_NSLCD = '''password    requisite     pam_pwquality.so minlen=8 \
minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow \
try_first_pass use_authtok remember=10
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

SESSION_NSLCD = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''

SESSION_HOME_NSLCD = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     optional      pam_mkhomedir.so umask=0077
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_krb5.so
'''

AUTH_YUM = '''auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent audit deny=5 \
unlock_time=900 fail_interval=900
auth        sufficient    pam_unix.so try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        sufficient    pam_sss.so use_first_pass
auth        sufficient    pam_krb5.so use_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=5 \
unlock_time=900 fail_interval=900
auth        required      pam_deny.so
'''

ACCOUNT_YUM = '''account     required      pam_faillock.so
account     required      pam_access.so
account     required      pam_unix.so broken_shadow
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     required      pam_permit.so
'''

PASSWORD_YUM = '''password    requisite     pam_pwquality.so minlen=8 \
minclass=3 difok=7 dcredit=0 ucredit=0 lcredit=0 ocredit=0 retry=3 maxrepeat=3
password    sufficient    pam_unix.so sha512 shadow try_first_pass \
use_authtok remember=10
password    sufficient    pam_sss.so use_authtok
password    sufficient    pam_krb5.so use_authtok
password    required      pam_deny.so
'''

SESSION_YUM = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session    optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
session     optional      pam_krb5.so
'''

SESSION_HOME_YUM = '''session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session    optional      pam_systemd.so
session     optional      pam_mkhomedir.so umask=0077
session     [success=1 default=ignore] pam_succeed_if.so service in crond \
quiet use_uid
session     required      pam_unix.so
session     optional      pam_sss.so
session     optional      pam_krb5.so
'''
