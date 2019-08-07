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

'''
Created on Jul 22, 2013

The Avahi daemon implements the DNS Service Discovery and Multicast DNS
protocols, which provide service and host discovery on a network. It allows a
system to automatically identify resources on the network, such as printers or
web servers. This capability is also known as mDNSresponder and is a major part
of Zeroconf networking. By default, it is enabled. This rule makes a number of
configuration changes to the avahi service in order to secure it.
networking. By default, it is enabled. This rule makes a number of \
configuration changes to the avahi service

@author: Breen Malmberg
@change: dwalker - added hash tag separator lines for methods
@change: 2014/02/16 ekkehard Implemented self.detailedresults flow
@change: 2014/02/16 ekkehard Implemented isapplicable
@change: 2014/04/16 ekkehard ci and self.setkvdefaultscurrenthost updates
@change: 2015/03/17 ekkehard modernized OS X approach
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/11/09 ekkehard - make eligible for OS X El Capitan
@change: 2015/11/16 eball Add undo events, change fix reporting
@change: 2015/12/01 eball Simplified version checking, removed OS X 10.11 from
    applicable list, due to unresolved issue with writing to plist
@change: 2015/12/02 eball Added OS X 10.11 compatibility
@change: 2016/02/11 eball PEP8 cleanup
@change: 2016/02/11 eball Added NOZEROCONF=yes KVEditor for Red Hat systems
    to comply with CCE-RHEL7-CCE-TBD 2.5.2
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 12/05/2017 Breen Malmberg - changed moniker to full name for author entries
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''


import os
import re
import traceback
import configparser
from ..logdispatcher import LogPriority
from ..ServiceHelper import ServiceHelper
from ..rule import Rule
from ..stonixutilityfunctions import iterate, setPerms, resetsecon, createFile
from ..KVEditorStonix import KVEditorStonix
from ..pkghelper import Pkghelper
from ..CommandHelper import CommandHelper


class SecureMDNS(Rule):
    '''The Avahi daemon implements the DNS Service Discovery and Multicast DNS
    protocols, which provide service and host discovery on a network. It allows
    a system to automatically identify resources on the network, such as
    printers or web servers. This capability is also known as mDNSresponder
    and is a major part of Zeroconf networking. By default, it is enabled.
    This rule makes a number of configuration changes to the avahi service
    in order to secure it.
    @change: 04/16/2014 ekkehard ci and self.setkvdefaultscurrenthost updates


    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 135
        self.rulename = 'SecureMDNS'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.compliant = False
        self.rulesuccess = True
        self.guidance = ['NSA(3.7.2)', 'CCE 4136-8', 'CCE 4409-9',
                         'CCE 4426-3', 'CCE 4193-9', 'CCE 4444-6',
                         'CCE 4352-1', 'CCE 4433-9', 'CCE 4451-1',
                         'CCE 4341-4', 'CCE 4358-8', 'CCE-RHEL7-CCE-TBD 2.5.2']
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}

# set up command helper object
        self.ch = CommandHelper(self.logger)

# init helper classes
        self.sh = ServiceHelper(self.environ, self.logger)
        self.serviceTarget = ""

        if self.environ.getostype() == "Mac OS X":
            self.ismac = True
            self.hasSIP = False
            self.plb = "/usr/libexec/PlistBuddy"
            osxversion = str(self.environ.getosver())
            versplit = osxversion.split(".")
            if len(versplit) > 2:
                minorVersion = int(versplit[1])
                releaseVersion = int(versplit[2])
            elif len(versplit) == 2:
                minorVersion = int(versplit[1])
                releaseVersion = 0
            else:
                self.logger.log(LogPriority.ERROR,
                                "Unexpected version string length")
                raise Exception
            if minorVersion == 10 and releaseVersion < 4:
                self.service = "/System/Library/LaunchDaemons/com.apple." + \
                    "discoveryd.plist"
                self.servicename = "com.apple.networking.discoveryd"
                self.parameter = "--no-multicast"
                self.pbr = self.plb + " -c Print " + self.service + \
                    " | grep 'no-multicast'"
                self.pbf = self.plb + ' -c "Add :ProgramArguments: string ' + \
                    self.parameter + '" ' + self.service
            elif minorVersion > 10:
                self.hasSIP = True
                self.service = "/System/Library/LaunchDaemons/" + \
                    "com.apple.mDNSResponder.plist"
                self.servicename = "com.apple.mDNSResponder.reloaded"
                self.parameter = "NoMulticastAdvertisements"
                self.preferences = "/Library/Preferences/" + \
                    "com.apple.mDNSResponder.plist"
                self.pbr = self.plb + " -c Print " + self.preferences + \
                    " | grep 'NoMulticastAdvertisements'"
                self.pbf = "defaults write " + self.preferences + " " + \
                    self.parameter + " -bool YES"
            else:
                self.service = "/System/Library/LaunchDaemons/" + \
                    "com.apple.mDNSResponder.plist"
                if minorVersion >= 10:
                    self.servicename = "com.apple.mDNSResponder.reloaded"
                else:
                    self.servicename = "com.apple.mDNSResponder"
                self.parameter = "-NoMulticastAdvertisements"
                self.pbr = self.plb + " -c Print " + self.service + \
                    " | grep 'NoMulticastAdvertisements'"
                self.pbf = self.plb + ' -c "Add :ProgramArguments: string ' + \
                    self.parameter + '" ' + self.service
        else:
            self.ismac = False
            # init CIs
            datatype = 'bool'
            mdnskey = 'SECUREMDNS'
            avahikey = 'DISABLEAVAHI'
            mdnsinstructions = 'To configure the Avahi server daemon ' + \
                'securely set the value of SECUREMDNS to True and the ' + \
                'value of DISABLEAVAHI to False.'
            avahiinstructions = 'To completely disable the Avahi server ' + \
                'daemon rather than configure it, set the value of ' + \
                'DISABLEAVAHI to True and the value of SECUREMDNS to False.'
            mdnsdefault = False
            avahidefault = True
            self.SecureMDNS = self.initCi(datatype, mdnskey, mdnsinstructions,
                                          mdnsdefault)
            self.DisableAvahi = self.initCi(datatype, avahikey,
                                            avahiinstructions, avahidefault)

            self.configparser = configparser.SafeConfigParser()

            self.confavahidict = {'use-ipv6':
                                  {'section': 'server', 'val': 'no'},
                                  'check-response-ttl':
                                  {'section': 'server', 'val': 'yes'},
                                  'disallow-other-stacks':
                                  {'section': 'server', 'val': 'yes'},
                                  'disable-publishing':
                                  {'section': 'publish', 'val': 'yes'},
                                  'disable-user-service-publishing':
                                  {'section': 'publish', 'val': 'yes'},
                                  'publish-addresses':
                                  {'section': 'publish', 'val': 'no'},
                                  'publish-hinfo':
                                  {'section': 'publish', 'val': 'no'},
                                  'publish-workstation':
                                  {'section': 'publish', 'val': 'no'},
                                  'publish-domain':
                                  {'section': 'publish', 'val': 'no'}}
            self.confoptions = {'server': {'use-ipv6': 'no',
                                           'check-response-ttl': 'yes',
                                           'disallow-other-stacks': 'yes'},
                                'publish': {'disable-publishing': 'yes',
                                            'disable-user-service-publishing':
                                            'yes',
                                            'publish-addresses': 'no',
                                            'publish-hinfo': 'no',
                                            'publish-workstation': 'no',
                                            'publish-domain': 'no'}}
        self.iditerator = 0

    def report(self):
        '''The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailed results and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.


        :returns: bool
        @author: Breen Malmberg
        @change: dwalker - added conditional call to reportmac()
        @change: Breen Malmberg - 12/05/2017 - removed unnecessary argument
                "serviceTarget" in linux-only call to servicehelper; removed
                assignment of unused local variable serviceTarget to self.servicename
                since servicename is not assigned in the linux code logic path (which
                was resulting in variable referenced before assignment error)

        '''

        try:

            # defaults
            compliant = True
            self.detailedresults = ''
            self.rulesuccess = True

            # if system is a mac, run reportmac
            if self.ismac:
                compliant = self.reportmac()

            # if not mac os x, then run this portion
            else:
                self.editor = None
                # set up package helper object only if not mac os x
                self.pkghelper = Pkghelper(self.logger, self.environ)

                # if the disableavahi CI is set, we want to make sure it is
                # completely disabled
                if self.DisableAvahi.getcurrvalue():
                    self.package = "avahi-daemon"
                    # if avahi-daemon is still running, it is not disabled
                    if self.sh.auditService('avahi-daemon'):
                        compliant = False
                        self.detailedresults += 'DisableAvahi has been ' + \
                            'set to True, but avahi-daemon service is ' + \
                            'currently running.\n'
                    self.numdependencies = 0
                    if self.pkghelper.determineMgr() == 'yum' or \
                       self.pkghelper.determineMgr() == 'dnf':
                        self.package = "avahi"
                        # The following KVEditor for /etc/sysconfig/network is
                        # used to meet the zeroconf requirement in
                        # CCE-RHEL7-CCE-TBD 2.5.2
                        path = "/etc/sysconfig/network"
                        self.path = path
                        if os.path.exists(path):
                            tmppath = path + ".tmp"
                            data = {"NOZEROCONF": "yes"}
                            self.editor = KVEditorStonix(self.statechglogger,
                                                         self.logger, "conf",
                                                         path, tmppath, data,
                                                         "present", "closedeq")
                            if not self.editor.report():
                                self.compliant = False
                                self.detailedresults += path + " does not " + \
                                    "have the correct settings.\n"
                        else:
                            self.compliant = False
                            self.detailedresults += path + " does not exist.\n"

                        self.numdependencies = \
                            self.parseNumDependencies(self.package)
                        if self.numdependencies <= 3:
                            if self.pkghelper.check(self.package):
                                compliant = False
                                self.detailedresults += 'DisableAvahi is ' + \
                                    'set to True, but Avahi is currently ' + \
                                    'installed.\n'
                        else:
                            self.detailedresults += 'Avahi has too many ' + \
                                'dependent packages. Will not attempt to ' + \
                                'remove it.\n'

                    elif self.pkghelper.determineMgr() == "zypper":
                        self.package = "avahi"
                    elif self.pkghelper.check(self.package):
                        compliant = False
                        self.detailedresults += 'DisableAvahi is ' + \
                            'set to True, but Avahi is currently ' + \
                            'installed.\n'

                # otherwise if the securemdns CI is set, we want to make sure
                # it is securely configured
                if self.SecureMDNS.getcurrvalue():

                    # if the config file is found, proceed
                    if os.path.exists('/etc/avahi/avahi-daemon.conf'):

                        kvtype = "tagconf"
                        intent = "present"
                        filepath = '/etc/avahi/avahi-daemon.conf'
                        tmpfilepath = '/etc/avahi/avahi-daemon.conf.stonixtmp'
                        conftype = "closedeq"
                        self.avahiconfeditor = KVEditorStonix(
                            self.statechglogger, self.logger, kvtype,
                            filepath, tmpfilepath, self.confoptions,
                            intent, conftype)
                        self.avahiconfeditor.report()
                        if self.avahiconfeditor.fixables:
                            compliant = False
                            self.detailedresults += "\nThe following configuration options are missing or incorrect in " + str(filepath) + ":\n" + "\n".join(self.avahiconfeditor.fixables)

                    # if config file not found, check if avahi is installed
                    else:

                        # if not installed, we can't configure anything
                        if not self.pkghelper.check('avahi'):
                            self.detailedresults += 'Avahi Daemon not ' + \
                                'installed. Cannot configure it.\n'
                            compliant = True
                            self.logger.log(LogPriority.DEBUG,
                                            self.detailedresults)

                        # if it is installed, then the config file is missing
                        else:
                            compliant = False
                            self.detailedresults += 'Avahi is installed ' + \
                                'but could not find config file in ' + \
                                'expected location.\n'
                            self.logger.log(LogPriority.DEBUG,
                                            self.detailedresults)

            self.compliant = compliant

        except (IOError):
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def reportmac(self):
        '''check for configuration items needed for mac os x


        :returns: bool
        @author: Breen Malmberg
        @change: dwalker - implemented kveditor defaults

        '''
        try:
            self.detailedresults = ""
            # See if parameter is set
            self.ch.executeCommand(self.pbr)
            resultOutput = self.ch.getOutput()
            if len(resultOutput) >= 1:
                if (resultOutput[0] == ""):
                    commandsuccess = False
                    self.detailedresults += "Parameter: " + str(self.parameter) + \
                        " for service " + self.servicename + " is not set.\n"
                else:
                    commandsuccess = True
                    debug = "Parameter: " + str(self.parameter) + \
                        " for service " + self.servicename + \
                        " is set correctly."
                    self.logger.log(LogPriority.DEBUG, debug)
            else:
                commandsuccess = False
                self.detailedresults += "Parameter: " + str(self.parameter) + \
                    " for service " + self.servicename + " is not set.\n"
            # see if service is running
            if not re.match("^10.11", self.environ.getosver()):
                servicesuccess = self.sh.auditService(self.service,
                                                      serviceTarget=self.servicename)
            else:
                servicesuccess = self.sh.auditService(self.service,
                                                      serviceTarget=self.servicename)
            if servicesuccess:
                debug = "Service: " + str(self.service) + ", " + \
                    self.servicename + " audit successful."
                self.logger.log(LogPriority.DEBUG, debug)
            else:
                self.detailedresults += "Service: " + str(self.service) + \
                    ", " + self.servicename + " audit failed.\n"

            if servicesuccess and commandsuccess:
                return True
            else:
                return False
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            raise
        return self.compliant

    def fix(self):
        '''The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.
        
        @author: Breen Malmberg
        @change: dwalker - added statechglogger findrulechanges and deleteentry
        @changed: Breen Malmberg - 12/05/2017 - removed unnecessary servicetarget


        '''

        try:

            self.rulesuccess = True
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)
            self.detailedresults = ""

            # if this system is a mac, run fixmac()
            if self.ismac:
                self.rulesuccess = self.fixmac()

            # if not mac os x, run this portion
            else:
                # if DisableAvahi CI is enabled, disable the avahi service
                # and remove the package
                if self.DisableAvahi.getcurrvalue():
                    avahi = self.package
                    avahid = 'avahi-daemon'
                    if self.sh.auditService(avahid):
                        debug = "Disabling " + avahid + " service"
                        self.logger.log(LogPriority.DEBUG, debug)
                        self.sh.disableService(avahid)
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "servicehelper",
                                 "servicename": avahid,
                                 "startstate": "enabled",
                                 "endstate": "disabled"}
                        self.statechglogger.recordchgevent(myid, event)
                    if self.environ.getosfamily() == 'linux' and \
                       self.pkghelper.check(avahi):
                        if self.numdependencies <= 3:
                            self.pkghelper.remove(avahi)
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            event = {"eventtype": "pkghelper",
                                     "pkgname": avahi,
                                     "startstate": "installed",
                                     "endstate": "removed"}
                            self.statechglogger.recordchgevent(myid, event)
                        else:
                            debug += 'Avahi package has too many dependent ' \
                                + 'packages. Will not attempt to remove.\n'
                            self.logger.log(LogPriority.DEBUG, debug)

                    if self.pkghelper.determineMgr() == 'yum' or \
                       self.pkghelper.determineMgr() == 'dnf':
                        path = self.path
                        if not os.path.exists(path):
                            if createFile(path, self.logger):
                                self.iditerator += 1
                                myid = iterate(self.iditerator,
                                               self.rulenumber)
                                event = {"eventtype": "creation",
                                         "filepath": path}
                                self.statechglogger.recordchgevent(myid, event)
                            else:
                                self.rulesuccess = False
                                self.detailedresults += "Failed to create " + \
                                    "file: " + path + ".\n"
                        if self.editor is None:
                            tmppath = path + ".tmp"
                            data = {"NOZEROCONF": "yes"}
                            self.editor = KVEditorStonix(self.statechglogger,
                                                         self.logger, "conf",
                                                         path, tmppath, data,
                                                         "present", "closedeq")
                        if not self.editor.report():
                            if self.editor.fix():
                                self.iditerator += 1
                                myid = iterate(self.iditerator, self.rulenumber)
                                self.editor.setEventID(myid)
                                if not self.editor.commit():
                                    self.rulesuccess = False
                                    self.detailedresults += "Could not " + \
                                        "commit changes to " + path + ".\n"
                            else:
                                self.rulesuccess = False
                                self.detailedresults += "Could not fix " + \
                                    "file " + path + ".\n"

                # if SecureMDNS CI is enabled, configure avahi-daemon.conf
                if self.SecureMDNS.getcurrvalue():
                    # if config file is present, proceed
                    avahiconf = '/etc/avahi/avahi-daemon.conf'
                    if os.path.exists(avahiconf):
                        if self.avahiconfeditor.fixables:
                            self.iditerator += 1
                            myid = iterate(self.iditerator, self.rulenumber)
                            self.avahiconfeditor.setEventID(myid)
                            if not self.avahiconfeditor.fix():
                                self.rulesuccess = False
                                debug = "KVEditor fix for " + avahiconf + \
                                    "failed"
                                self.logger.log(LogPriority.DEBUG, debug)
                            elif not self.avahiconfeditor.commit():
                                self.rulesuccess = False
                                debug = "KVEditor commit for " + avahiconf + \
                                    "failed"
                                self.logger.log(LogPriority.DEBUG, debug)

                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        setPerms(avahiconf, [0, 0, 0o644], self.logger,
                                 self.statechglogger, myid)
                        resetsecon(avahiconf)

                    # if config file is not present and avahi not installed,
                    # then we can't configure it
                    else:
                        if not self.pkghelper.check(avahi):
                            debug = 'Avahi Daemon not installed. ' + \
                                'Cannot configure it.'
                            self.logger.log(LogPriority.DEBUG, debug)
                        else:
                            self.detailedresults += 'Avahi daemon ' + \
                                'installed, but could not locate the ' + \
                                'configuration file for it.\n'
                            self.rulesuccess = False

        except IOError:
            self.detailedresults += '\n' + traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def fixmac(self):
        '''apply fixes needed for mac os x
        
        @author: Breen Malmberg
        @change: dwalker - implemented kveditor instead of direct editing


        '''
        try:
            self.detailedresults = ""
            success = True
            # See if parameter is set
            self.ch.executeCommand(self.pbr)
            resultOutput = self.ch.getOutput()
            if len(resultOutput) >= 1:
                if (resultOutput[0] == ""):
                    fixit = True
                else:
                    fixit = False
            else:
                fixit = True
            # Add parameter
            if fixit:
                # Due to weaknesses in using PlistBuddy and defaults to delete
                # from plists, as well as shortcomings in STONIX's state change
                # logging, we will record this change as a file deletion.
                # If the rule's undo is run on OS X, it will restore the
                # previous version of this file.
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                if self.hasSIP:
                    self.statechglogger.recordfiledelete(self.preferences,
                                                         myid)
                else:
                    self.statechglogger.recordfiledelete(self.service, myid)
                self.ch.executeCommand(self.pbf)
                resultOutput = self.ch.getOutput()
                errorcode = self.ch.getReturnCode()
                if errorcode == 0:
                    debug = self.parameter + " was set successfully!"
                    self.logger.log(LogPriority.DEBUG, debug)
                else:
                    self.detailedresults += self.parameter + \
                        " was not set successfully!\n"
                    self.statechglogger.deleteentry(myid)
                    success = False
            else:
                debug = self.parameter + " was already set!"
                self.logger.log(LogPriority.DEBUG, debug)
            # Reload Service
            if success:
                success = self.sh.reloadService(self.service, serviceTarget=self.servicename)
                if success:
                    debug = "Service: " + str(self.service) + ", " + \
                        self.servicename + " was reloaded successfully."
                    self.logger.log(LogPriority.DEBUG, debug)
                else:
                    debug = "Service: " + str(self.service) + ", " + \
                        self.servicename + " reload failed!"
                    self.logger.log(LogPriority.DEBUG, debug)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            success = False
            raise
        return success

    def parseNumDependencies(self, pkgname):
        '''parse output of yum command to determine number of dependent packages
        to the given pkgname

        :param pkgname: 
        :returns: int
        @author: Breen Malmberg

        '''
        numdeps = 0
        flag = 0

        try:

            if self.pkghelper.determineMgr() == 'zypper':
                command = ['zypper', 'info', '--requires', pkgname]
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                for line in output:
                    if flag:
                        numdeps += 1
                    if re.search('Requires:', line):
                        flag = 1

            elif self.pkghelper.determineMgr() == 'yum':
                command = ['yum', '--assumeno', 'remove', pkgname]
                self.ch.wait = False
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                for line in output:
                    if re.search('Dependent packages\)', line):
                        sline = line.split('(+')
                        if len(sline) < 2:
                            return numdeps
                        cline = [int(s) for s in sline[1].split()
                                 if s.isdigit()]
                        numdeps = int(cline[0])

            elif self.pkghelper.determineMgr() == 'dnf':
                command = ['dnf', '--assumeno', 'remove', pkgname]
                self.ch.wait = False
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                for line in output:
                    if re.search('Dependent packages\)', line):
                        sline = line.split('(+')
                        if len(sline) < 2:
                            return numdeps
                        cline = [int(s) for s in sline[1].split()
                                 if s.isdigit()]
                        numdeps = int(cline[0])

            elif self.pkghelper.determineMgr() == 'apt-get':
                command = ['apt-cache', 'depends', pkgname]
                self.ch.executeCommand(command)
                output = self.ch.getOutput()
                for line in output:
                    if re.search('Depends:', line):
                        numdeps += 1
            else:
                self.detailedresults += 'Unable to detect package manager\n'
                return numdeps

        except (IOError, OSError):
            self.detailedresults += 'Specified package: ' + str(pkgname) + \
                ' not found.\n'
            return numdeps
        except Exception:
            raise
        return numdeps
