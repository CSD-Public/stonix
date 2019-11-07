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
Created on Oct 18, 2013

TCPWrappers is a library which provides simple access control and standardized
logging for supported applications which accept connections over a network.
Historically, TCP Wrapper was used to support inetd services. Now that inetd is
deprecated (see Section 3.2.1), TCP Wrapper supports only services which were
built to make use of the libwrap library.

@author: Breen Malmberg
@change: 02/13/2014 Ekkehard Implemented self.detailedresults flow
@change: 02/13/2014 Ekkehard Implemented isapplicable
@change: 04/18/2014 Ekkehard ci updates and ci fix method implementation
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/09/29 Eric Ball Fixed potential first-run failure
@change: 2015/10/08 Eric Ball Help text cleanup
@change: 2016/06/14 Eric Ball Rewrote most code
"""



import os
import re
import traceback
import socket

from rule import Rule
from logdispatcher import LogPriority
from stonixutilityfunctions import iterate

from localize import ALLOWNETS, HOSTSALLOWDEFAULT, HOSTSDENYDEFAULT


class TCPWrappers(Rule):
    '''TCPWrappers is a library which provides simple access control and
    standardized logging for supported applications which accept connections
    over a network. Historically, TCPWrappers was used to support inetd
    services. Now that inetd is deprecated (see Section 3.2.1), TCPWrappers
    supports only services which were built to make use of the libwrap library.
    
    @author: Breen Malmberg


    '''

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 13
        self.rulename = 'TCPWrappers'
        self.formatDetailedResults("initialize")
        self.compliant = False
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.guidance = ['CIS', 'NSA(2.5.4)', '4434-7']
        self.applicable = {'type': 'white',
                           'family': ['linux']}

        # init CIs
        self.ci = self.initCi("bool",
                              "TCPWRAPPERS",
                              "To prevent TCP Wrappers from being " +
                              "configured on this system, set the " +
                              "value of TCPWrappers to False.",
                              True)

        datatype = "list"
        key = "ALLOWNETS"
        instructions = "Please enter a space-delimited list subnet ranges you wish to allow to " + \
            "connect via SSH and X-11 forwarding. To allow none, leave blank. Format for each subnet range = x.x.x.x/CIDR or x.x.x.x/y.y.y.y" + \
            " where y.y.y.y would be the subnet mask. We assume you know what you are doing if you edit the default values here!"
        default = ALLOWNETS

        self.allownetCI = self.initCi(datatype, key, instructions, default)

        self.osname = self.environ.getosname()
        self.osmajorver = self.environ.getosmajorver()

    def configure_allow_text(self):
        '''Set up hosts.allow content for later output to file
        
        @author: Breen Malmberg


        '''

        self.logger.log(LogPriority.DEBUG, "configuring hosts.allow text")

        self.hosts_allow_contents = []
        subnets = self.allownetCI.getcurrvalue()

        self.logger.log(LogPriority.DEBUG, "host os name = " + str(self.osname))
        self.logger.log(LogPriority.DEBUG, "host os major version = " + str(self.osmajorver))
        self.logger.log(LogPriority.DEBUG, "subnets before conversion = " + str(subnets))

        if self.environ.getosname().lower() in ["rhel", "centos"]:
            if self.environ.getosmajorver() == "6":
                # convert all subnet formats to legacy format
                subnets = [self.convert_to_legacy(subnet) for subnet in subnets]
        self.logger.log(LogPriority.DEBUG, "subnets after conversion = " + str(subnets))

        # build the hosts.allow content by modifying the default content with
        # either the default ranges in localize.py or the user-specified ranges
        # from the CI
        splitstring = HOSTSALLOWDEFAULT.splitlines(True)
        for line in splitstring:
            if not re.search("{allownet}", line):
                self.hosts_allow_contents.append(line)
            else:
                for s in subnets:
                    if type(s) is bytes:
                        s = s.decode('utf-8')
                    self.hosts_allow_contents.append(re.sub("{allownet}", s, line))

    def convert_to_legacy(self, subnet):
        '''converts modern tcp wrappers subnet specification to legacy (rhel 6, centos 6) format
        modern format = <servicename> : x.x.x.x/CIDR : <ALLOW|DENY>
        legacy format = <servicename> : x.x.x.x/y.y.y.y : <ALLOW|DENY>
        x.x.x.x = ip subnet spec, y.y.y.y = subnet mask

        :param subnet: 
        :returns: subnet
        :rtype: string
@author: Breen Malmberg

        '''

        subnet = str(subnet)

        # check whether this is a valid ip subnet spec
        # (other things can be used in tcp wrappers like hostname, domain, etc.
        # and we don't want to try to do this manipulation on those types)
        try:
            socket.inet_aton(re.sub("/.*", "", subnet))
        except:
            # will not try to manipulate anything that is not a valid ip subnet spec
            self.logger.log(LogPriority.DEBUG, "subnet provided not a valid ip subnet format. will not attempt to convert to legacy format")
            return subnet

        self.logger.log(LogPriority.DEBUG, "Converting " + str(subnet) + " from x.x.x.x/CIDR to legacy x.x.x.x/y.y.y.y format...")

        # CIDR number : subnet mask equivalent
        # (currently only supports 3 most common cases)
        conversion_matrix = {"/24": "/255.255.255.0",
                             "/16": "/255.255.0.0",
                             "/8": "/255.0.0.0"}

        # replace the cidr number with the subnet mask equivalent
        for case in conversion_matrix:
            subnet = re.sub(case, conversion_matrix[case], subnet)

        self.logger.log(LogPriority.DEBUG, "subnet re-formatted to fit legacy format: " + str(subnet))
        return subnet

    def report(self):
        '''Check for correct configuration of hosts.allow and hosts.deny


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        # if the REQUIRED constants from localize.py are not populated
        # then set the applicability of the rule to False
        # checkConsts logs a message saying the rule
        constlist = [ALLOWNETS, HOSTSALLOWDEFAULT, HOSTSDENYDEFAULT]
        if not self.checkConsts(constlist):
            self.compliant = False
            self.detailedresults += "\nRule did not run due to one or more required constants in localize.py not being defined"
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            self.logdispatch.log(LogPriority.INFO, self.detailedresults)
            return self.compliant

        try:

            self.detailedresults = ""
            self.compliant = True

            self.configure_allow_text()

            if not self.reportAllow():
                self.compliant = False
                self.logger.log(LogPriority.DEBUG, "reportAllow returned False")

            if not self.reportDeny():
                self.compliant = False
                self.logger.log(LogPriority.DEBUG, "reportDeny returned False")

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.compliant = False
            self.detailedresults += "\n" + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportAllow(self):
        '''check contents of hosts.allow file


        :returns: compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        compliant = True
        allowfile = "/etc/hosts.allow"

        if not os.path.exists(allowfile):
            compliant = False
            self.detailedresults += "\nhosts.allow doesn't exist"
            return compliant

        f = open(allowfile, "r")
        contentlines = f.readlines()
        f.close()

        if contentlines != self.hosts_allow_contents:
            self.detailedresults += "\ncontents of hosts.allow are not correct"
            compliant = False

        if compliant:
            self.logger.log(LogPriority.DEBUG, "hosts.allow file contents are correct")

        return compliant

    def reportDeny(self):
        '''check contents of hosts.deny file


        :returns: compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        compliant = True
        denyfile = "/etc/hosts.deny"

        if not os.path.exists(denyfile):
            compliant = False
            self.detailedresults += "\nhosts.deny doesn't exist"
            return compliant

        f = open(denyfile, "r")
        contents = f.read()
        f.close()

        if contents != HOSTSDENYDEFAULT:
            self.detailedresults += "\ncontents of hosts.deny are not correct"
            compliant = False

        if compliant:
            self.logger.log(LogPriority.DEBUG, "hosts.deny file contents are correct")

        return compliant

    def fix(self):
        '''Apply changes to hosts.allow and hosts.deny to correctly configure them


        :returns: self.rulesuccess

        :rtype: bool
@author: Breen Malmberg

        '''

        # defaults
        self.iditerator = 0
        self.detailedresults = ""
        self.rulesuccess = True

        try:

            if not self.ci.getcurrvalue():
                return self.rulesuccess

            if not self.fixAllow():
                self.rulesuccess = False

            if not self.fixDeny():
                self.rulesuccess = False

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults += "\n"  + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixAllow(self):
        '''fix contents for hosts.allow file


        :returns: success

        :rtype: bool
@author: Breen Malmberg

        '''

        success = True
        allowfile = "/etc/hosts.allow"
        allowtmp = allowfile + ".stonixtmp"

        try:

            f = open(allowtmp, "w")
            f.writelines(self.hosts_allow_contents)
            f.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "conf",
                     "filepath": allowfile}

            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(allowfile, allowtmp, myid)

            os.rename(allowtmp, allowfile)
            os.chmod(allowfile, 0o644)
            os.chown(allowfile, 0, 0)

        except Exception:
            raise

        return success

    def fixDeny(self):
        '''fix contents for hosts.deny file


        :returns: success

        :rtype: bool
@author: Breen Malmberg

        '''

        success = True
        denyfile = "/etc/hosts.deny"
        denytmp = denyfile + ".stonixtmp"

        try:

            f = open(denytmp, "w")
            f.write(HOSTSDENYDEFAULT)
            f.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {"eventtype": "conf",
                     "filepath": denyfile}

            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(denyfile, denytmp, myid)

            os.rename(denytmp, denyfile)
            os.chmod(denyfile, 0o644)
            os.chown(denyfile, 0, 0)

        except Exception:
            raise

        return success
