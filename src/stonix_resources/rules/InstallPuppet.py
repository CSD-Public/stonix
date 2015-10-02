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
'''
Created on Nov 1, 2012
This is the rule for installing puppet.

THIS IS A LOCAL RULE, NOT TO BE DISTRIBUTED

@operating system: generic
@author: Roy Nielsen
@change: 02/12/2014 ekkehard Implemented self.detailedresults flow
@change: 02/12/2014 ekkehard Implemented isapplicable
@change: 03/24/2014 rsn & ekkehard converted to command helper
@change: 04/08/2014 ekkehard command updates
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/15 dkennel updated for new isApplicable
'''
from __future__ import absolute_import
import os
import re
import shutil
import socket
import urllib2
import traceback
import time
import platform
from time import sleep

# The period was making python complain. Adding the correct paths to PyDev
# made this the working scenario.
from ..rule import Rule
from ..logdispatcher import LogPriority
from ..InstallingHelper import InstallingHelper
from ..configurationitem import ConfigurationItem
from ..ServiceHelper import ServiceHelper
from ..stonixutilityfunctions import set_no_proxy, \
                                     has_connection_to_server
from ..CommandHelper import CommandHelper
from ..filehelper import FileHelper

if platform.system() == "Darwin":
    from ..IHmac import IHmac


class InstallPuppet(Rule):
    """
    This class installs puppet on the system.
    """
    def __init__(self, config, environ, logdispatch, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logdispatch, statechglogger)
        self.logdispatch = logdispatch
        self.rulenumber = 248
        self.rulename = 'InstallPuppet'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.helptext = '''This rule to installs puppet.'''
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.10']}}
        self.environ = environ
        self.my_os = self.environ.getosfamily()

        datatype = 'bool'
        self.myci = ConfigurationItem(datatype)
        key = 'InstallPuppet'
        self.myci.setkey(key)
        instructions = '''To disable the installation of the puppet client set the INSTALLPUPPET option to no or False.'''
        self.myci.setinstructions(instructions)
        default = True
        self.myci.setdefvalue(default)
        self.confitems.append(self.myci)
        #self.CIInstallPuppet = self.initCi(datatype, key, instructions,
        #                                   default)
        self.puppetdirectory = ""
# Set up CommandHelper instance
        self.ch = CommandHelper(self.logdispatch)
# Set up service helper instance
        self.sh = ServiceHelper(self.environ, self.logdispatch)
        self.service = {"/Library/LaunchDaemons/gov.lanl.puppetd.plist":
                        "gov.lanl.puppetd"}
# Set up FileHelper instance
        self.fh = FileHelper(self.logdispatch)
        self.files = {"puppetd": {"path":
                                  "/Library/LaunchDaemons/gov.lanl.puppetd.plist",
                                  "remove": False,
                                  "content": None,
                                  "permissions": 0o0644,
                                  "owner": 0,
                                  "group": 0}}
# NVRAM Check Location
        self.nvramcheck = '/usr/sbin/nvram MAC_UID 2>/dev/null'
# Domain Name
        self.domainname = ".lanl.gov"
# Puppet LaunchD job name
        self.puppetlaunchdname = "gov.lanl.puppetd"
# Puppet LaunchD job location
        self.puppetlaunchdpath = "/Library/LaunchDaemons/" + \
        self.puppetlaunchdname + ".plist"
# Name of puppet server
        self.puppetserver = "puppet-prod" + self.domainname
# Name of the server to get the puppet package from
        self.puppetpkgserver = self.puppetserver
# Path to the puppet directory
        if self.environ.getosfamily() == 'darwin':
            self.puppetdirectory = "/usr/bin/"
        elif self.environ.getosfamily() == 'solaris':
            self.puppetdirectory = "/opt/csw/bin/"
# Puppet SSL Certificate Location
        self.puppetcertificatepath = "/usr/local/puppet/etc/ssl"
# Location of puppet program
        self.puppetfullpath = self.puppetdirectory + "/puppet"
# Puppet Facter location
        self.puppetfacterfullpath = self.puppetdirectory + '/facter'
# Location of puppet wrapper program
        self.puppetlocalwrapperpath = "/usr/local/puppet/sbin/lanlpup.py"
# url for darwin download zip

        if re.match("^darwin$", self.environ.getosfamily()):
            # Get the OS version which should be something like 10.7.5 or 10.9.5
            # get the 7.5 or 9.5 and compare it to 9.  If it is greater than 9
            # then puppet package including puppet 3.7.3 can be installed
            # -- Did think about doing a try/catch here - I don't think it would
            # be wise - if this fails, it is most likely won't install the right
            # version of puppet
            if float(".".join(self.environ.getosver().split(".")[1:])) >= 9.0 :
                # Specifically for puppet equal to or greater than 10.9.
                self.puppetdownloadzipdarwin = "http://" + self.puppetpkgserver + \
                                               "/puppet/puppet.zip"
                # url to puppet version string
                self.puppetversionurl = "http://" + self.puppetpkgserver + \
                                        "/puppet/puppet.version.txt"
            else:
                self.puppetdownloadzipdarwin = "http://" + self.puppetpkgserver + \
                                               "/puppet/puppet3.4/puppet.zip"
                # url to puppet version string
                self.puppetversionurl = "http://" + self.puppetpkgserver + \
                                        "/puppet/puppet3.4/puppet.version.txt"
        else:
                # url to puppet version string
                self.puppetversionurl = "http://" + self.puppetpkgserver + \
                                        "/puppet/puppet.version.txt"

# puppet certname
        self.certname = self.getCertName()
# Initialize the service helper
        self.sh = ServiceHelper(self.environ, self.logdispatch)

    def report(self):
        '''
        Report on the status of this rule

        @author: Roy Nielsen
        '''
        self.logdispatch.log(LogPriority.DEBUG,
                             "******** Starting Report ********************")
        try:
            self.compliant = False
            self.currstate = "notconfigured"
            self.detailedresults = ""
            self.logdispatch.log(LogPriority.DEBUG,
                                 "\n\n\tmy_os: \"" + str(self.my_os) + \
                                 "\"\n\n")
            if re.match("^darwin$", str(self.my_os)):

                serverCompliant, serverMessage = self.isServerCheckCorrect()
                localCompliant, localMessage = self.islocalMacConfigCorrect()

                if re.match("^\s*$", self.detailedresults):
                    self.detailedresults = "Server Message: " + \
                    str(serverMessage)
                else:
                    self.detailedresults = self.detailedresults + \
                                           ", Server Message: " + \
                                           str(serverMessage)

                self.detailedresults = self.detailedresults + \
                                       ", Client Message: " + \
                                       str(localMessage)

                if re.search("does not exist\.\s+Need to install Puppet", self.detailedresults):
                    self.compliant = False

                if serverCompliant and localCompliant:
                    self.compliant = True
                    self.currstate = "configured"
                self.logdispatch.log(LogPriority.DEBUG,
                                     "**************************************")
                self.logdispatch.log(LogPriority.DEBUG,
                                     "\n\n\tserverCompliant: " + \
                                      str(serverCompliant) + \
                                      "\tlocalCompliant: " + \
                                      str(localCompliant) + "\n\n")
            self.logdispatch.log(LogPriority.DEBUG,
                                 "******************************************")
            self.logdispatch.log(LogPriority.DEBUG,
                                 "\n\n\tCompliant: " + str(self.compliant) + \
                                 "\n\n")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception, err:
            self.detailedresults = self.detailedresults + \
            str(traceback.format_exc())
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                               "Exception - " + str(err) + " - " +
                               self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

###############################################################################

    def fix(self):
        '''
        Fix template

        @author: Roy Nielsen
        '''
        self.logdispatch.log(LogPriority.DEBUG,
                             "*********** Starting Fix ********************")
        try:
            installPuppet = self.myci.getcurrvalue()
            if not installPuppet:
                self.logdispatch.log(LogPriority.INFO, "Rule is user disabled")
            if self.environ.getosfamily() == 'darwin':

                self.logdispatch.log(LogPriority.DEBUG, "Attempting to fix mac")

# If there network, install, else no network, log
                hasconnection = has_connection_to_server(self.logdispatch,
                                                         self.puppetpkgserver)
                if hasconnection:
# Set up the installation
                    installing = IHmac(self.environ,
                                       self.puppetdownloadzipdarwin,
                                       self.logdispatch)
# Install the package
                    installing.install_package_from_server()

                    self.logdispatch.log(LogPriority.DEBUG,
                                         "Connection with server exists, " + \
                                         "can install puppet.")
# wait 20 seconds to make sure the install process has
# created the certs
                    time.sleep(20)

                else:
                    self.logdispatch.log(LogPriority.ERROR,
                                         "Do not have connection with " + \
                                         "server, cannot install puppet.")

# Verify plist ownership and permissions - FileHelper already set up in report
# method
                plistCorrected = self.fh.fixFiles()

                if not plistCorrected:
                    self.logdispatch.log(LogPriority.INFO,
                                         "Problem trying to fix plist..")
                else:
                    self.logdispatch.log(LogPriority.INFO,
                                         "Puppet LaunchDaemon plist fixed.")

# Verify launchd that runs puppet
# check for plist existence
                if os.path.exists(self.puppetlaunchdpath):
# Check if plist is loaded or not - load it if it is
# not loaded.  Using the Service Helper.
                    if not self.sh.auditservice(self.puppetlaunchdpath, \
                                                self.puppetlaunchdname):
                        self.sh.enableservice(self.puppetlaunchdpath,
                                              self.puppetlaunchdname)
                        self.logdispatch.log(LogPriority.ERROR,
                                             "Puppet launchdaemon is not " + \
                                             "loaded, loading")
                    else:
                        self.logdispatch.log(LogPriority.DEBUG,
                                             "Puppet launchdaemon loaded")

# Check the MAC_UID for sanity
                (sane, certname) = self.isCertnameSane()
                if certname:
                    if sane:
                        self.logdispatch.log(LogPriority.DEBUG,
                                             "Good certname: " + certname +
                                             " for MAC_UID, in nvram")
                    else:
                        self.logdispatch.log(LogPriority.ERROR,
                                             "Bad certname: " + certname +
                                             " for MAC_UID, in nvram")

# Check for bad cert
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Checking for bad cert")
                (needtocleancert, self.detailedresults) = self.isOldMacCert()
                if needtocleancert:
                    self.cleanCertLocal()
                    self.cleanCertSvr()

            self.sync()

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

###############################################################################

    def getCertName(self):
        """
        This function returns a (hopefully) unique name to use as the
        identifying certificate with the puppet server. On Mac systems we try
        to use the serial number of the system. Failing this an attempt is
        made to use the property number, the primary mac address or the
        hostname. On non-mac systems we will use the hostname.

        @return : string - certname for this host in the format of an FQDN
        """
        certname = ''
        if self.environ.getosfamily() == 'darwin':
            certname = self.buildCertnameFromNVRAM()
            if certname == '':
                certname = self.buildCertnameFromSerialNumber()
            if certname == '':
                certname = self.buildCertnameFromPropertyNumber()
            if certname == '':
                certname = self.buildCertnameFromUUID()
            if certname == '':
                certname = self.buildCertnameFromPrimaryMacAddress()
            if certname == '':
                certname = self.buildCertnameFromFullyQualifiedDomainName()
        else:
            certname = self.buildCertnameFromUUID()
            if certname == '':
                if self.environ.getosfamily() == 'solaris':
                    certname = self.buildCertnameFromHostID()
                elif self.environ.getosfamily() == 'linux':
                    certname = self.buildCertnameFromPropertyNumber()
            if certname == '':
                certname = self.buildCertnameFromFullyQualifiedDomainName()
        if self.environ.getosfamily() == 'darwin':
            if not re.match(certname, self.buildCertnameFromNVRAM()):
                self.writeCertnameToNVRAM(certname)
        return certname

###############################################################################

    def buildCertnameFromNVRAM(self):
        """
        This function is for Darwin platforms only. It attempts to retrieve the
        certname from NVRAM.
        @return: string - certname if found empty if not
        """
        certname = ''
        output = None
        error = None

        if self.environ.getosfamily() == 'darwin':

            if not self.ch.executeCommand(self.nvramcheck):
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Cannot find certname in nvram...")
            else:
                output = self.ch.getOutput()
                error = self.ch.getError()

            if output:
                try:
                    nvramid = output[0].split()
                    nvramid = nvramid[1]
                except(IndexError):
                    nvramid = ''

                certname = nvramid
        return certname

###############################################################################

    def buildCertnameFromSerialNumber(self):
        """
        This function is for Darwin platforms only. It attempts to retrieve
        the system serial number from NVRAM and assemble that into a usable
        cert name.

        @return: string - certname if found empty if not
        """
        certname = ''
        snum = ''
        snfact = re.compile('sp_serial_number')
        if self.environ.getosfamily() == 'darwin':

            if not self.ch.executeCommand(self.puppetfacterfullpath):
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Cannot determine the serial number...")
            else:
                output = self.ch.getOutput()
                error = self.ch.getError()

            if output:
                if isinstance(output, basestring):
                    facts = output.split("\n")

                    for fact in facts:
                        if snfact.match(fact):
                            fact = fact.split()
                            try:
                                snum = fact[2]
                            except(IndexError):
                                snum = ''

# Filter garbage results, no zero length strings, system or System
# indicates the logic board has been replaced. 0 indicates a virtual
# guest.
            if len(snum) != 0 and not re.search('system|System|^0$', snum):
                specialchars = '\\\|/|\s|\;|\~|\!|\@|\#|\$|\%|\^|\&|\*|\+|\=|\|'
                snum = re.sub(specialchars, '', snum)
            else:
                snum = ''
            if len(snum) != 0:
                certname = snum + self.domainname
            certname = certname.rstrip().lower()
        return certname

###############################################################################

    def buildCertnameFromPropertyNumber(self):
        """
        This function is for Darwin and Red Hat. It attempts to retrieve the
        property number from NVRAM  or disk and assemble a certname from that.

        @return: string - certname if found empty if not
        """
        certname = ''
        propnum = ''
        if self.environ.getosfamily() == 'darwin':
            pnfetch = '/usr/sbin/nvram asset_id 2>/dev/null'
            if not self.ch.executeCommand(pnfetch):
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Cannot determine the property number...")
            else:
                output = self.ch.getOutputString()
                error = self.ch.getError()

            if output:
                splitoutput = output.split()
                try:
                    propnum = splitoutput[1]
                except(IndexError):
                    propnum = ''
        if self.environ.getosfamily() == 'linux':
            propfile = '/etc/property-number'
            if os.path.exists(propfile):
                fhandle = open(propfile, 'r')
                propnum = fhandle.readline()
                propnum = propnum.strip()
                fhandle.close()
        if propnum != '':
            certname = propnum + self.domainname
            certname = certname.rstrip().lower()
        return certname

###############################################################################

    def buildCertnameFromPrimaryMacAddress(self):
        """
        This function is for Darwin platforms only. It attempts to retrieve the
        primary mac address from facter and assemble a certname from that.

        @return: string - certname if found empty if not.
        """
        certname = ''
        macaddr = ''
        macfact = re.compile('macaddress =>')
        if self.environ.getosfamily() == 'darwin':
            if not self.ch.executeCommand(self.puppetfacterfullpath):
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Cannot determine the property number...")
            else:
                output = self.ch.getOutput()
                error = self.ch.getError()

            if output:
                if isinstance(output, basestring):
                    facts = output.split("\n")

                for fact in facts:
                    if macfact.match(fact):
                        fact = fact.split()
                        try:
                            macaddr = fact[2]
                        except(IndexError):
                            macaddr = ''
            if len(macaddr) != 0:
                certname = macaddr + self.domainname
                certname = certname.rstrip().lower()
        return certname

###############################################################################

    def buildCertnameFromUUID(self):
        """
        This function tries to fetch the system UUID number. I should work on
        all non-sparc systems.

        @return: string - certname if found empty if not.
        """
        certname = ''
        uuid = self.environ.get_sys_uuid()
        if len(uuid) == 36:
            uuid = re.sub('-', '_', uuid)
            certname = uuid + self.domainname
            certname = certname.rstrip().lower()
        return certname

###############################################################################

    def buildCertnameFromHostID(self):
        """
        This function is Solaris specific and assembles a certname from the
        hostid which should be reasonably unique given the limited number of
        Solaris Sparc
        systems.

        @return: string - certname if found empty if not.
        """
        certname = ''
        if self.environ.getosfamily() == 'solaris':
            fetchhostid = '/usr/bin/hostid'
            try:
                self.ch.executeCommand(fetchhostid)
                hostid = self.ch.getOutputString()
            except:
                self.logdispatch.log(LogPriority.ERROR,
                                     "Exception trying to build the " + \
                                     "certname from the hostid")
                raise
            if len(hostid) != 0:
                certname = hostid.rstrip() + self.domainname
                certname = certname.rstrip().lower()
        return certname

###############################################################################

    def buildCertnameFromFullyQualifiedDomainName(self):
        """
        This function retrieves the FQDN for the host for use as a certname.
        Under LANL DNS policy the FQDN should be unique.

        @return: string - FQDN hostname for use as a certname, empty str if
        there's a problem.
        """
        hostname = socket.getfqdn()
        test = hostname.split('.')
        if len(test) < 3:
            # In rare circumstances we don't get a FQDN from socket.getfqdn
            # this is usually due to a configuration error on the host.
            # take the first non zero length element and use that or return an
            # empty string.
            if len(test[0]) > 0:
                hostname = test[0] + self.domainname
            elif len(test[1]) > 0:
                hostname = test[1] + self.domainname
            else:
                hostname = ''
            hostname = hostname.rstrip().lower()
        return hostname

###############################################################################

    def writeCertnameToNVRAM(self, certname):
        """
        This function writes the certname to NVRAM. This is applicable only to
        Darwin systems.

        @param string: certname in the format of an FQDN.
        @return: void
        """
        if certname != '':
            command = '/usr/sbin/nvram MAC_UID=' + certname
            try:
                self.ch.executeCommand(command)
            except:
                self.logdispatch.log(LogPriority.ERROR,
                                     "Error writing certname to nvram...")
                raise

###############################################################################

    def cleanCertLocal(self):
        """
        This function clears the local certificates.
        """
        if os.path.exists(self.puppetcertificatepath):
            shutil.rmtree(self.puppetcertificatepath)

###############################################################################

    def cleanCertSvr(self):
        """
        This function cleans the certs on the server.
        """
        set_no_proxy()
        respdata = ''
        query = 'http://' + self.puppetserver + \
        '/cgi-bin/cleanCert.rb?certname=' + self.certname
        try:
            wwwresponse = urllib2.urlopen(query)
            respdata = wwwresponse.readline()
            self.logdispatch.log(LogPriority.DEBUG, respdata)
        except Exception, err:
            self.logdispatch.log(LogPriority.ERROR,
                                 str(err) + " - " +
                                 respdata +
                                 ". Problem communicating " +
                                 "with the puppet server.")

###############################################################################

    def isOldMacCert(self):
        """
        This function checks for the 2.7.4 cert.

        @returns: True if the old cert is found
                  False if there is no match.

        @author: Roy Nielsen
        """
        self.logdispatch.log(LogPriority.DEBUG,
                             "Checking for bad cert")
        needtocleancert = False
        detailedresults = ""
        if os.path.exists(self.puppetcertificatepath + "/certs/ca.pem"):
            self.logdispatch.log(LogPriority.DEBUG,
                                 "certfile exists, checking the fingerprint")
            currentcertfingerprint = None
            command = "/usr/bin/openssl x509 -noout -in " + \
            self.puppetcertificatepath + "/certs/ca.pem -fingerprint -sha1"
            try:
                self.ch.executeCommand(command)
                currentcertfingerprint = self.ch.output
            except:
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Error trying to get the current " + \
                                     "cert fingerprint...")
                raise

            oldcertfingerprint = "SHA1 Fingerprint=CE:F9:F4:C8:90:17:7C:EC:A2:E7:C6:26:25:AD:FA:7C:60:93:14:C8"

            if currentcertfingerprint:
                self.logdispatch.log(LogPriority.DEBUG,
                                     "Found cert fingerprint: " + \
                                     str(currentcertfingerprint))
                needtocleancert = False
                for line in currentcertfingerprint:
                    # if certs match exactly
                    if re.match("^%s$" % oldcertfingerprint.rstrip(),
                                line.rstrip()):
                        detailedresults = "Bad certs match, need to scrub certs."
                        self.logdispatch.log(LogPriority.DEBUG,
                                             detailedresults)
                        needtocleancert = True
                        break
            else:
                detailedresults = "Could not acquire cert fingerprint"
                self.logdispatch.log(LogPriority.DEBUG,
                                    detailedresults)
        else:
            self.logdispatch.log(LogPriority.DEBUG,
                                 "Cert file does not exist for: " +
                                 str(self.certname))
        return (needtocleancert, detailedresults)

###############################################################################

    def isCertnameSane(self):
        """
        Check to make sure the certname isn't bad - typical necessary checks
        for the Mac platform.
        """
        # Check the MAC_UID for sanity

        command = ["/usr/sbin/nvram", "MAC_UID"]
        try:
            self.ch.executeCommand(command)
            mac_uid = self.ch.output
        except:
            self.logdispatch.log(LogPriority.DEBUG,
                                 "Exception trying to get the MAC_UID " + \
                                 "from nvram...")
            raise
        if mac_uid:
            for line in mac_uid:
                if re.search("MAC_UID\s+\S+", line):
                    mu_certname = re.match("MAC_UID\s+(\S+)", line)
                    certname = mu_certname.group(1)
                    break
            if re.match("^0\.\S+", certname) or \
               re.match("\.\S+", certname) or \
               re.search(":", certname):
                sane = False
                msgstring = "Bad certname: " + certname + " for MAC_UID, " + \
                "in nvram"
                self.logdispatch.log(LogPriority.DEBUG, msgstring)
            else:
                sane = True
                msgstring = "Good certname: " + certname + " for MAC_UID, " + \
                "in nvram"
                self.logdispatch.log(LogPriority.DEBUG, msgstring)
        else:
            certname = None

        return (sane, certname)

###############################################################################

    def checkVersion(self, version="0.0.0", versionurl=""):
        """
        Takes the passed in version, and compares it against the version 
        string on the server.

        The standard puppet versions come 3 numbers separated by 2 dots.

        @return: True - current puppet version is current with version string
                        on the server
                 False - current version is older than version string on the
                         server

        @author: Roy Nielsen
        """
        install = None
        warning = None

        if re.match("^0\.0\.0$", version) or \
           re.match("^\s*$", version) or \
           not re.match("^http", versionurl) or \
           re.match("^\s*$", versionurl):

            self.logdispatch.log(LogPriority.DEBUG,
                                 "Bad parameters for this method - ")
            self.logdispatch.log(LogPriority.DEBUG,
                                "version: " + str(version))
            self.logdispatch.log(LogPriority.DEBUG,
                                 "versionurl: " + str(versionurl))
            warning = "Bad parameters passed in to checkVersion"
        elif re.match("^\d+\.\d+\.\d+", version):

# Get version string from server
            getstring = InstallingHelper(self.environ, versionurl,
                                         self.logdispatch)

            urlVersion = getstring.get_string_from_url(self.puppetversionurl)

            if not re.match("^\d+\.\d+\.\d+\.\d+$", urlVersion):
                warning = "Cannot acquire server version."
                self.logdispatch.log(LogPriority.DEBUG,
                                     str(warning) + str(urlVersion))
            else:
                warning = "Found string from server: "
                self.logdispatch.log(LogPriority.DEBUG,
                                     str(warning) + str(urlVersion))

                # Compare the two
                mycompare = re.compile("^(\d+)\.(\d+)\.(\d+)\.(\d+)$")
                currver = mycompare.match(str(version))
                serverver = mycompare.match(str(urlVersion))

                if currver:
                    versionMajor = currver.group(1)
                    versionMinor = currver.group(2)
                    versionRelease = currver.group(3)
                    versionTiny = currver.group(4)
                    if serverver:
                        urlVersionMajor = serverver.group(1)
                        urlVersionMinor = serverver.group(2)
                        urlVersionRelease = serverver.group(3)
                        urlVersionTiny = serverver.group(4)

                        if urlVersionMajor > versionMajor:
                            #####
                            # Install Puppet.
                            install = True
                            warning = "Current version is older than " + \
                            "server version."
                            msgstring = "Major version: Current " + \
                            "version is older than what's on the server, " + \
                            "server version: " + str(urlVersion) + \
                            ", current version: " + str(version)
                            self.logdispatch.log(LogPriority.DEBUG, msgstring)
                        elif urlVersionMajor < versionMajor:
# Warn that the user is using a version of puppet higher
# than what is on the server
                            install = False
                            warning = "Server version is older than the " + \
                            "current version."
                            msgstring = "Group1: Current version " + \
                            "is newer than what's on the server, server " + \
                            "version: " + str(urlVersion) + \
                            ", current version: " + str(version)
                            self.logdispatch.log(LogPriority.DEBUG, msgstring)
                        else:
                            if urlVersionMinor > versionMinor:
# Install Puppet
                                install = True
                                warning = "Current version is older than " + \
                                "server version."
                                msgstring = "Minor version: " + \
                                "Current version is older than what's " + \
                                "on the server, server version: " + \
                                str(urlVersion) + ", current version: " + \
                                str(version)
                                self.logdispatch.log(LogPriority.DEBUG,
                                                    msgstring)
                            elif urlVersionMinor < versionMinor:
# Warn that the user is using a version of puppet higher
# than what is on the server
                                install = False
                                warning = "Server version is older than " + \
                                "the current version."
                                msgstring = "Minor version: " + \
                                "Current version is newer than what's " + \
                                "on the server, server version: " + \
                                str(urlVersion) + " , current version: " + \
                                str(version)
                                self.logdispatch.log(LogPriority.DEBUG,
                                                    msgstring)
                            else:
                                if urlVersionRelease > versionRelease:
# Install Puppet
                                    install = True
                                    warning = "Current version is older " + \
                                    "than server version."
                                    msgstring = "Revision version: " + \
                                    "Current version is older than " + \
                                    "what's on the server, server " + \
                                    "version: " + str(urlVersion) + \
                                    ", current version: " + str(version)
                                    self.logdispatch.log(LogPriority.DEBUG,
                                                         msgstring)
                                elif urlVersionRelease < versionRelease:
# Warn that the user is using a version of puppet higher
# than what is on the server
                                    install = False
                                    warning = "Server version is older " + \
                                    "than the current version."
                                    msgstring = "Revision version: " + \
                                    "Current version is newer than what's " + \
                                    "on the server, server version: " + \
                                    str(urlVersion) + ", current version: " + \
                                    str(version)
                                    self.logdispatch.log(LogPriority.DEBUG,
                                                         msgstring)
                                else:
                                    if urlVersionTiny > versionTiny:
# Install Puppet
                                        install = True
                                        warning = "Current version is " + \
                                        "older than server version."
                                        msgstring = "Tiny version: " + \
                                        "Current version is older than " + \
                                        "what's on the server, server " + \
                                        "version: " + str(urlVersion) + \
                                        ", current version: " + str(version)
                                        self.logdispatch.log(LogPriority.DEBUG,
                                                             msgstring)
                                    elif urlVersionTiny < versionTiny:
# Warn that the user is using a version of puppet higher
# than what is on the server
                                        install = False
                                        warning = "Server version is " + \
                                        "older than the current version."
                                        msgstring = "Tiny version: " + \
                                        "Current version is newer than " + \
                                        "what's on the server, server " + \
                                        "version: " + str(urlVersion) + \
                                        ", current version: " + str(version)
                                        self.logdispatch.log(LogPriority.DEBUG,
                                                             msgstring)
                                    else:
# Report that the version matches the server version.
                                        install = False
                                        warning = ""
                                        msgstring = "Current and server " + \
                                        "versions match. Server version: " + \
                                        str(urlVersion) + ", current " + \
                                        "version: " + str(version)
                                        self.logdispatch.log(LogPriority.DEBUG,
                                                             msgstring)
        return (install, warning)

###############################################################################

    def isServerCheckCorrect(self):
        """
        Cross platform checks:

        if /usr/bin/puppet exists 
        if version is a number
        if connected to the yellow
        if can connect to server for the MD5, version and puppet package
        Checks server version against local version

        Sets values for:

        self.puppetVersionBad
        self.notOnCorperateNetwork
        self.notConnectedToServer
        compliant, can equal True, False and "Unknown"

        author: Roy Nielsen
        """
        compliant = True
        message = ""
        #####
        # Check yellow connection
        if self.environ.oncorporatenetwork():
            self.notOnCorperateNetwork = False
            #####
            # Check connection to server that has puppet.zip
            if has_connection_to_server(self.logdispatch, self.puppetpkgserver):
                self.notConnectedToServer = False
                if not os.path.exists("/usr/bin/puppet"):
                    compliant = False
                    message = "/usr/bin/puppet does not exist. Need to install Puppet."
                else:
                    #####
                    # Check puppet receipt for version
                    if os.path.exists("/var/db/.puppet_pkgdmg_installed_puppet.dmg"):
                        try:
                            fileHandle = open("/var/db/.puppet_pkgdmg_installed_puppet.dmg", "r")
                            if fileHandle:
                                line = fileHandle.readline()
                            fileHandle.close()
                            puppetVersion = str(line.strip())
                        except Exception, err :
                            compliant = False
                            message = "Error trying to open puppet receipt: " + str(err)
                            self.logdispatch.log(LogPriority.DEBUG, message)
                        else:

                            self.logdispatch.log(LogPriority.DEBUG,
                                                 "Puppet receipt version: " + \
                                                 str(puppetVersion))
                            if not re.match("^\d+\.\d+\.\d+\.\d+$", str(puppetVersion)):
                                message = "Puppet is not returning a version number, Need to install Puppet."
                                compliant = False
                            else:
                                installPuppet, puppetVersionMessage = \
                                     self.checkVersion(puppetVersion,
                                                       self.puppetversionurl)
                                if installPuppet:
                                    compliant = False
                                    message = str(puppetVersionMessage)
                                else:
                                    message = "Good Puppet version"
                                    compliant = True
                    else:
                        message = "Puppet receipt missing"
                        compliant = False
            else:
                compliant = "Unknown"
                message = "Problem with connecting to the server with the puppet package on it."
        else:
            compliant = "Unknown"
            message = "Problem connecting to the yellow, cannot validate server version."

        return (compliant, message)

###############################################################################

    def islocalMacConfigCorrect(self):
        """
        Check the status of local files and processes

        @author: Roy Nielsen
        """
        compliant = True
        message = []
        addFileSuccess = True
        #####
        # Check cron/plist file settings - OS dependant
        if self.environ.getosfamily() == 'darwin':
            #####
            # Check plist with file helper
            for fileLabel, fileInfo in sorted(self.files.items()):
                addFileReturn = self.fh.addFile(fileLabel,
                                                fileInfo["path"],
                                                fileInfo["remove"],
                                                fileInfo["content"],
                                                fileInfo["permissions"],
                                                fileInfo["owner"],
                                                fileInfo["group"])
                if not addFileReturn:
                    addFileSuccess = False
            if not addFileSuccess:
                #####
                # Log adding to the fileHelper failed..

                self.logdispatch.log(LogPriority.DEBUG,
                                     "Did not succeed adding a adding to " + \
                                     "the file object for FileHelper")
            else:
                plistCorrect = self.fh.evaluateFiles()
                if not plistCorrect:
                    #####
                    # Report plist incorrect - get message
                    mymessage = self.fh.getFileMessage()
                    self.logdispatch.log(LogPriority.DEBUG, mymessage)
                    message.append(mymessage)
                    compliant = False
                else:
                    #####
                    # Report plist correct
                    mymessage = "Plist file correct ownership and permissions"
                    message.append(mymessage)
                    self.logdispatch.log(LogPriority.DEBUG,
                                    ["InstallPuppet.islocalMacConfigCorrect",
                                     mymessage])
#####
# Check the launchDaemon with service helper
            serviceresults = ""
            for currentservicename, currentservice in self.service.items():
                if self.sh.auditservice(currentservicename, currentservice):
                    if serviceresults == "":
                        serviceresults = "('" + str(currentservicename) + \
                        "','" + str(currentservice) + "')"
                    else:
                        serviceresults = serviceresults + ", ('" + \
                        str(currentservicename) + "','" + \
                        str(currentservice) + "')"
                    mymessage = "Service: isrunning('" + currentservice + \
                    "','" + currentservicename + "') = True!"
                    self.logdispatch.log(LogPriority.INFO, mymessage)
                else:
                    mymessage = "Service: isrunning('" + currentservice + \
                    "','" + currentservicename + "') = False!"
                    self.logdispatch.log(LogPriority.DEBUG, mymessage)
                    compliant = False
            message.append(mymessage)

#####
# Check for valid server cert
            isCertOld, mymessage = self.isOldMacCert()
            if isCertOld:
                mymessage = "Cert is old, needs fixing: " + \
                str(self.isOldMacCert)
                message.append(mymessage)
                self.logdispatch.log(LogPriority.DEBUG, mymessage)
                compliant = False
            else:
                mymessage = "Cert is ok"
                message.append(mymessage)
                self.logdispatch.log(LogPriority.DEBUG, mymessage)

#####
# Check for valid certname
        if not self.isCertnameSane():
            mymessage = "Problem with certname"
            message.append(mymessage)
            self.logdispatch.log(LogPriority.DEBUG, mymessage)
            compliant = False
        else:
            mymessage = "Certname clean"
            message.append(mymessage)
            self.logdispatch.log(LogPriority.DEBUG, mymessage)

        self.logdispatch.log(LogPriority.DEBUG, "|".join(message))
        return (compliant, mymessage)

    def sync(self):
        """
        Sync the disk buffers -- used at the end of fix to make sure the puppet
        install has been sync'd to disk.
        
        @author: Roy Nielsen
        """
        i = 0
        mysync = '/bin/sync'
        while (i<4):
            i = i + 1
            try:
                self.ch.executeCommand(mysync)
                hostid = self.ch.getOutputString()
            except:
                self.logdispatch.log(LogPriority.ERROR,
                                     "Exception trying sync puppet to disk... ")
                raise
            sleep(2)
