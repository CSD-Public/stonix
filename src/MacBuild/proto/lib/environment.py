#!/usr/bin/env python

###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was       #
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

# ============================================================================#
#               Filename          $RCSfile: stonix/environment.py,v $
#               Description       Security Configuration Script
#               OS                Linux, OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2010/8/24 14:00:00 $
# ============================================================================#
'''
Created on Aug 24, 2010

@author: Dave Kennel
@change: 2014/05/29 - ekkehard j. koch - pep8 and comment updates
@change: 2018/07/19 - Breen Malmberg - edited many doc strings for consistency and
        some typo's; added 3 methods getipaddress, gethostname, getmacaddress; re-factored
        code in guessnetwork to use the new methods; re-factored the method getallips;
        updated copyright date
'''

from __future__ import absolute_import

import os
import re
import sys
import socket
import subprocess
import types
import platform
import pwd
import time


class Environment:
    """
    The Environment class collects commonly used information about the
    execution platform and makes it available to the rules.
    :version: 1.0
    :author: Dave Kennel
    """

    def __init__(self):
        self.operatingsystem = ''
        self.osreportstring = ''
        self.osfamily = ''
        self.hostname = ''
        self.ipaddress = ''
        self.macaddress = ''
        self.osversion = ''
        self.numrules = 0
        self.euid = os.geteuid()
        currpwd = pwd.getpwuid(self.euid)
        try:
            self.homedir = currpwd[5]
        except (IndexError):
            self.homedir = '/dev/null'
        self.installmode = False
        self.verbosemode = False
        self.debugmode = False
        self.runtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.collectinfo()

    def setinstallmode(self, installmode):
        """
        Set the install mode bool value. Should be true if the prog should run
        in install mode.

        @param bool: installmode
        @return: void
        @author: Dave Kennel
        """

        try:
            if type(installmode) is types.BooleanType:
                self.installmode = installmode
        except (NameError):
            # installmode was undefined
            pass

    def getinstallmode(self):
        """
        Return the current value of the install mode bool. Should be true if
        the program is to run in install mode.

        @return: bool : installmode
        @author: Dave Kennel
        """

        return self.installmode

    def setverbosemode(self, verbosemode):
        """
        Set the verbose mode bool value. Should be true if the prog should run
        in verbose mode.

        @param bool: verbosemode
        @return: void
        @author: Dave Kennel
        """

        try:
            if type(verbosemode) is types.BooleanType:
                self.verbosemode = verbosemode
        except (NameError):
            # verbosemode was undefined
            pass

    def getverbosemode(self):
        """
        Return the current value of the verbose mode bool. Should be true if
        the program is to run in verbose mode.

        @return: bool : verbosemode
        @author: Dave Kennel
        """

        return self.verbosemode

    def setdebugmode(self, debugmode):
        """
        Set the verbose mode bool value. Should be true if the prog should run
        in verbose mode.

        @param bool: debugmode
        @return: void
        @author: Dave Kennel
        """

        try:
            if type(debugmode) is types.BooleanType:
                self.debugmode = debugmode
        except (NameError):
            # debugmode was undefined
            pass

    def getdebugmode(self):
        """
        Return the current value of the debug mode bool. Should be true if the
        program is to run in debug mode.

        @return: bool : debugmode
        @author: Dave Kennel
        """

        return self.debugmode

    def getostype(self):
        """
        Return the detailed operating system type.

        @return string :
        @author Dave Kennel
        """

        return self.operatingsystem

    def getosreportstring(self):
        """
        Return the detailed operating system type with full version info.

        @return string :
        @author Dave Kennel
        """

        return self.osreportstring

    def getosfamily(self):
        """Return the value of self.osfamily which should be linux, darwin,
        solaris or freebsd.
        @return string :
        @author: Dave Kennel
        """

        return self.osfamily

    def getosver(self):
        """
        Return the OS version as a string.

        @return string :
        @author Dave Kennel
        """

        return self.osversion

    def gethostname(self):
        """
        Return the hostname of the system.

        @return: string
        @author: Dave Kennel
        """

        return self.hostname

    def getipaddress(self):
        """
        Return the IP address associated with the host name.

        @return string :
        @author Dave Kennel
        """

        return self.ipaddress

    def getmacaddr(self):
        """
        Return the mac address in native format.

        @return string :
        @author Dave Kennel
        """

        return self.macaddress

    def geteuid(self):
        """
        Return the effective user ID

        @return int :
        @author Dave Kennel
        """

        return self.euid

    def geteuidhome(self):
        """
        Returns the home directory of the current effective user ID.

        @return: string
        @author: Dave Kennel
        """

        return self.homedir

    def collectinfo(self):
        """
        Method to populate data.

        @return: void
        @author Dave Kennel
        """

        # print 'Environment Running discoveros'
        self.discoveros()
        # print 'Environment running setosfamily'
        self.setosfamily()
        # print 'Environment running guessnetwork'
        self.guessnetwork()
        self.collectpaths()

    def discoveros(self):
        """
        Discover the operating system type and version
        @return : void
        @author: Dave Kennel
        """

        # Alternative (better) implementation for Linux
        if os.path.exists('/usr/bin/lsb_release'):
            proc = subprocess.Popen('/usr/bin/lsb_release -dr',
                                  shell=True, stdout=subprocess.PIPE,
                                  close_fds=True)
            description = proc.stdout.readline()
            release = proc.stdout.readline()
            description = description.split()
            # print description
            del description[0]
            description = " ".join(description)
            self.operatingsystem = description
            self.osreportstring = description
            release = release.split()
            release = release[1]
            self.osversion = release
        elif os.path.exists('/etc/redhat-release'):
            relfile = open('/etc/redhat-release')
            release = relfile.read()
            relfile.close()
            release = release.split()
            opsys = ''
            for element in release:
                if re.search('release', element):
                    break
                else:
                    opsys = opsys + " " + element
            self.operatingsystem = opsys
            self.osreportstring = opsys
            index = 0
            for element in release:
                if re.search('release', element):
                    index = index + 1
                    osver = release[index]
                else:
                    index = index + 1
            self.osversion = osver
        elif os.path.exists('/etc/gentoo-release'):
            relfile = open('/etc/gentoo-release')
            release = relfile.read()
            relfile.close()
            release = release.split()
            opsys = ''
            for element in release:
                if re.search('release', element):
                    break
                else:
                    opsys = opsys + " " + element
            self.operatingsystem = opsys
            self.osreportstring = opsys
            index = 0
            for element in release:
                if re.search('release', element):
                    index = index + 1
                    osver = release[index]
                else:
                    index = index + 1
            self.osversion = osver
        elif os.path.exists('/usr/bin/sw_vers'):
            proc1 = subprocess.Popen('/usr/bin/sw_vers -productName',
                                     shell=True, stdout=subprocess.PIPE,
                                     close_fds=True)
            description = proc1.stdout.readline()
            description = description.strip()
            proc2 = subprocess.Popen('/usr/bin/sw_vers -productVersion',
                                     shell=True, stdout=subprocess.PIPE,
                                     close_fds=True)
            release = proc2.stdout.readline()
            release = release.strip()
            self.operatingsystem = description
            self.osversion = release
            proc3 = subprocess.Popen('/usr/bin/sw_vers -buildVersion',
                                     shell=True, stdout=subprocess.PIPE,
                                     close_fds=True)
            build = proc3.stdout.readline()
            build = build.strip()
            opsys = description + ' ' + release + ' ' + build
            self.osreportstring = opsys

    def setosfamily(self):
        """
        Private method to detect and set the self.osfamily property. This is a
        fuzzy classification of the OS.
        """

        uname = sys.platform
        if uname == 'linux2':
            self.osfamily = 'linux'
        elif uname == 'darwin':
            self.osfamily = 'darwin'
        elif uname == 'sunos5':
            self.osfamily = 'solaris'
        elif uname == 'freebsd9':
            self.osfamily = 'freebsd'

    def getmacaddress(self):
        '''
        return the current system's mac address
        set the class variable self.macaddress

        @return: macaddr
        @rtype: string
        @author: Dave Kennel
        @author: Breen Malmberg
        '''

        netutil = self.getnetutil()
        netcmd = ""
        macaddr = "00:00:00:00:00:00"
        macre = "(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"
        match = None
        ipaddress = ""

        if not netutil:
            print "environment::getmacaddr():WARNING: Could not detect any net utility type/location"
            return macaddr
        elif "nmcli" in netutil:
            netcmd = netutil +  " -t device show"
        elif "ifconfig" in netutil:
            netcmd = netutil + " -a"
        elif "ip" in netutil:
            netcmd = netutil + " -o link"
        else:
            print "environment::getmacaddr():WARNING: Could not identify unknown net utility type"
            return macaddr

        try:

            ipaddress = self.getipaddress()
            macinfocmd = subprocess.Popen(netcmd, shell=True, stdout=subprocess.PIPE, close_fds=True)
            macinfo = macinfocmd.stdout.readlines()

            for line in macinfo:
                match = re.search(macre, line)
                if match is not None:
                    # print 'Matched MAC address'
                    macaddr = match.group()
                if re.search(ipaddress, line):
                    # print 'Found ipaddress'
                    break

        except Exception:
            raise

        self.macaddress = macaddr
        return macaddr

    def getnetutil(self):
        '''
        return the full path to the net utility tool used
        by the current system

        can detect the following net util's:
        * ip
        * ifconfig
        * nmcli

        @return: netutil
        @rtype: string
        @author: Breen Malmberg
        '''

        netutil = ""

        nmcli = "/usr/bin/nmcli"
        iptool = "/sbin/ip"
        ifconfigs = ["/sbin/ifconfig", "/usr/sbin/ifconfig"]

        if os.path.exists(nmcli):
            netutil = nmcli
        elif os.path.exists(iptool):
            netutil = iptool
        else:
            for loc in ifconfigs:
                if os.path.exists(loc):
                    netutil = loc

        return netutil

    def getipaddress(self):
        '''
        return the current system's ip address
        set the class variable self.ipaddress

        @return: ipaddr
        @rtype: string
        @author: Dave Kennel
        @author: Breen Malmberg
        '''

        ipaddr = ""

        try:

            hostname = self.gethostname()
            ipdata = socket.gethostbyname_ex(hostname)
            iplist = ipdata[2]

            try:
                iplist.remove('127.0.0.1')
            except (ValueError):
                # tried to remove loopback when it's not present, continue
                pass
            if len(iplist) >= 1:
                ipaddr = iplist[0]
            else:
                ipaddr = '127.0.0.1'

        except (socket.gaierror):
            # If we're here it's because socket.getfqdn did not in fact return
            # a valid hostname and gethostbyname errored.
            ipaddr = self.getdefaultip()

        self.ipaddress = ipaddr
        return ipaddr

    def gethostname(self):
        '''
        get the current system's host name
        (fully qualified domain name)
        set the class variable self.hostname

        @return: hostfqdn
        @rtype: string
        @author: Dave Kennel
        @author: Breen Malmberg
        '''

        hostfqdn = ""

        try:

            hostfqdn = socket.getfqdn()

        except Exception:
            raise

        self.hostname = hostfqdn
        return hostfqdn

    def guessnetwork(self):
        """
        This method checks the configured interfaces and tries to
        make an educated guess as to the correct network data. The
        following class variables will be updated by this method:
        * self.hostname
        * self.ipaddress
        * self.macaddress

        @author: Dave Kennel
        @author: Breen Malmberg
        """

        self.gethostname()
        self.getipaddress()
        self.getmacaddr()

    def getdefaultip(self):
        """
        This method will return the ip address of the interface
        associated with the current default route.

        @return: ipaddr
        @rtype: string
        @author: Dave Kennel
        """

        ipaddr = '127.0.0.1'
        gateway = ''

        if sys.platform == 'linux2':

            try:
                routecmd = subprocess.Popen('/sbin/route -n', shell=True, stdout=subprocess.PIPE, close_fds=True)
                routedata = routecmd.stdout.readlines()
            except (OSError):
                return ipaddr

            for line in routedata:
                if re.search('^default', line):
                    line = line.split()

                    try:
                        gateway = line[1]
                    except (IndexError):
                        return ipaddr
        else:

            try:

                if os.path.exists('/usr/sbin/route'):
                    cmd = '/usr/sbin/route -n get default'
                else:
                    cmd = '/sbin/route -n get default'
                routecmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)
                routedata = routecmd.stdout.readlines()
            except (OSError):
                return ipaddr

            for line in routedata:
                if re.search('gateway:', line):
                    line = line.split()
                    try:
                        gateway = line[1]
                    except (IndexError):
                        return ipaddr

        if gateway:
            iplist = self.getallips()
            for level in [1, 2, 3, 4]:
                matched = self.matchip(gateway, iplist, level)
                if len(matched) == 1:
                    ipaddr = matched[0]
                    break

        return ipaddr

    def matchip(self, target, iplist, level=1):
        """
        This method will when given an IP try to find matching ip
        from a list of IP addresses. Matching will work from left to right
        according to the level param. If no match is found
        the loopback address will be returned.

        @param string: ipaddress
        @param list: list of ipaddresses
        @param int: level
        @return: matchlist
        @rtype: list
        @author: Dave Kennel
        @change: Breen Malmberg - 07/19/2018 - slightly changed return logic
                so that return value type would be consistent; moved default variable
                inits to top of method; wrapped all code which could fail in try/except
        """

        network = "127.0.0.1"
        matchlist = []

        try:

            quad = target.split('.')

            if level == 1:
                network = quad[0]
            elif level == 2:
                network = quad[0] + '.' + quad[1]
            elif level == 3:
                network = quad[0] + '.' + quad[1] + '.' + quad[2]
            elif level == 4:
                matchlist.append(network)
                return matchlist

            for addr in iplist:
                if re.search(network, addr):
                    matchlist.append(addr)

            if not matchlist:
                matchlist.append("127.0.0.1")

        except Exception:
            raise

        return matchlist

    def getallips(self):
        """
        This method returns all ip addresses on all interfaces on the system.

        @return: iplist
        @rtype: list
        @author: Dave Kennel
        @change: Breen Malmberg - 07/29/2018 - re-factored rule to account for ifconfig
                not being installed, and the use case where ifconfig is located at
                /sbin/ifconfig and the output does not contain "addr:"
        """

        iplist = []
        ifconfig = ""
        nmcli = ""
        ifconfiglocs = ["/sbin/ifconfig", "/usr/sbin/ifconfig"]
        nmclilocs = ["/usr/bin/nmcli"]

        for loc in ifconfiglocs:
            if os.path.exists(loc):
                ifconfig = loc

        for loc in nmclilocs:
            if os.path.exists(loc):
                nmcli = loc

        if sys.platform == "linux2":

            if ifconfig:

                try:
                    ifcmd = subprocess.Popen(ifconfig, shell=True, stdout=subprocess.PIPE, close_fds=True)
                    ifdata = ifcmd.stdout.readlines()
                except (OSError):
                    return iplist

                for line in ifdata:
                    if re.search("inet addr:", line):
                        try:
                            line = line.split()
                            addr = line[1]
                            addr = addr.split(':')
                            addr = addr[1]
                            iplist.append(addr)
                        except (IndexError):
                            continue
                    elif re.search("inet ", line):
                        try:
                            line = line.split()
                            addr = line[1]
                            iplist.append(addr)
                        except (IndexError):
                            continue

            elif nmcli:

                try:
                    nmcmd = subprocess.Popen(nmcli, shell=True, stdout=subprocess.PIPE, close_fds=True)
                    nmdata = nmcmd.stdout.readlines()
                except (OSError):
                    return iplist

                for line in nmdata:
                    if re.search("IP4\.ADDRESS", line):
                        try:
                            sline = line.split(":")
                            group = sline[1]
                            if re.search("\/", group):
                                sgroup = group.split("/")
                                addr = sgroup[0]
                            else:
                                addr = group
                            iplist.append(addr)
                        except (IndexError):
                            continue

        return iplist

    def get_property_number(self):
        """
        Find and return the
        Property number of the local machine

        @return: propnum
        @rtype: int
        @author: scmcleni
        @author: Dave Kennel
        """

        propnum = 0

        try:

            if os.path.exists('/etc/property-number'):
                propertynumberfile = open('/etc/property-number', 'r')
                propnum = propertynumberfile.readline()
                propnum = propnum.strip()
                propertynumberfile.close()
            if platform.system() == 'Darwin':
                pnfetch = '/usr/sbin/nvram asset_id 2>/dev/null'
                cmd = subprocess.Popen(pnfetch, shell=True,
                                       stdout=subprocess.PIPE,
                                       close_fds=True)
                cmdout = cmd.stdout.readline()
                cmdout = cmdout.split()
                try:
                    propnum = cmdout[1]
                except (IndexError, KeyError):
                    propnum = 0
        except Exception:
            pass

        return propnum

    def get_system_serial_number(self):
        """
        Find and return the
        Serial number of the local machine

        @return: systemserial
        @rtype: string
        @author: Dave Kennel
        """

        systemserial = '0'

        if os.path.exists('/usr/sbin/system_profiler'):
            profilerfetch = '/usr/sbin/system_profiler SPHardwareDataType'
            cmd3 = subprocess.Popen(profilerfetch, shell=True,
                                    stdout=subprocess.PIPE,
                                    close_fds=True)
            cmd3output = cmd3.stdout.readlines()
            for line in cmd3output:
                if re.search('Serial Number (system):', line):
                    line = line.split(':')
                    try:
                        systemserial = line[1]
                    except (IndexError, KeyError):
                        pass
        systemserial = systemserial.strip()

        return systemserial

    def get_sys_uuid(self):
        """
        Find and return a unique identifier for the system. On most systems
        this will be the UUID of the system. On Solaris SPARC this will be
        a number that is _hopefully_ unique as that platform doesn't have
        UUID numbers.

        @return: uuid
        @rtype: string
        @author: Dave Kennel
        """

        uuid = '0'

        if os.path.exists('/usr/sbin/smbios'):
            smbiosfetch = '/usr/sbin/smbios -t SMB_TYPE_SYSTEM 2>/dev/null'
            cmd2 = subprocess.Popen(smbiosfetch, shell=True,
                                    stdout=subprocess.PIPE,
                                    close_fds=True)
            cmdoutput = cmd2.stdout.readlines()
            for line in cmdoutput:
                if re.search('UUID:', line):
                    line = line.split()
                    try:
                        uuid = line[1]
                    except (IndexError, KeyError):
                        pass
        elif os.path.exists('/usr/sbin/system_profiler'):
            profilerfetch = '/usr/sbin/system_profiler SPHardwareDataType'
            cmd3 = subprocess.Popen(profilerfetch, shell=True,
                                    stdout=subprocess.PIPE,
                                    close_fds=True)
            cmd3output = cmd3.stdout.readlines()
            for line in cmd3output:
                if re.search('UUID:', line):
                    line = line.split()
                    try:
                        uuid = line[2]
                    except (IndexError, KeyError):
                        pass
        elif platform.system() == 'SunOS':
            fetchhostid = '/usr/bin/hostid'
            cmd1 = subprocess.Popen(fetchhostid, shell=True,
                                    stdout=subprocess.PIPE,
                                    close_fds=True)
            uuid = cmd1.stdout.readline()
        uuid = uuid.strip()
        return uuid

    def ismobile(self):
        '''
        Returns a bool indicating whether or not the system in question is a
        laptop. The is mobile method is used by some rules that have alternate
        settings for laptops.

        @return: ismobile
        @rtype: bool
        @author: Dave Kennel
        '''

        ismobile = False

        # following commented out by Breen Malmberg on 07/19/2018 because it was not being used anywhere
        # dmitypes = ['LapTop', 'Portable', 'Notebook', 'Hand Held', 'Sub Notebook']

        if os.path.exists('/usr/sbin/system_profiler'):
            profilerfetch = '/usr/sbin/system_profiler SPHardwareDataType'
            cmd3 = subprocess.Popen(profilerfetch, shell=True,
                                    stdout=subprocess.PIPE,
                                    close_fds=True)
            cmd3output = cmd3.stdout.readlines()
            for line in cmd3output:
                if re.search('Book', line):
                    ismobile = True
                    break

        return ismobile

    def issnitchactive(self):
        """
        Returns a bool indicating whether or not the little snitch program is
        active. Little snitch is a firewall utility used on Mac systems and can
        interfere with STONIX operations.

        @return: issnitchactive
        @rtype: bool
        @author: ekkehard
        """

        issnitchactive = False

        if self.osfamily == 'darwin':
            cmd = 'ps axc -o comm | grep lsd'
            littlesnitch = 'lsd'
            proc = subprocess.Popen(cmd, shell=True,
                                    stdout=subprocess.PIPE, close_fds=True)
            netdata = proc.stdout.readlines()
            for line in netdata:
                print "processing: " + line
                match = re.search(littlesnitch, line)
                if match is not None:
                    print 'LittleSnitch Is Running'
                    issnitchactive = True
                    break

        return issnitchactive

    def collectpaths(self):
        """
        Determine how stonix is run and return appropriate paths for:

        icons
        rules
        conf
        logs

        @author: Roy Nielsen
        """

        script_path_zero = os.path.realpath(sys.argv[0])

        try:
            script_path_one = os.path.realpath(sys.argv[1])
        except Exception:
            script_path_one = ""

        self.test_mode = False
        #####
        # Check which argv variable has the script name -- required to allow
        # for using the eclipse debugger.
        if re.search("stonix.py$", script_path_zero) or re.search("stonix$", script_path_zero):
            #####
            # Run normally
            self.script_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        else:
            #####
            # Run with Eclipse debugger -- Eclipse debugger will never try to run
            # the "stonix" binary blob created by pyinstaller, so don't include
            # here.
            #print "DEBUG: Environment.collectpaths: unexpected argv[0]: " + str(sys.argv[0])
            if re.search("stonix.py$", script_path_one) or re.search("stonixtest.py$", script_path_one):
                script = script_path_one.split("/")[-1]
                script_path = "/".join(script_path_one.split("/")[:-1])

                if re.match("^stonixtest.py$", script) and \
                   os.path.exists(script_path_one) and \
                   os.path.exists(os.path.join(script_path, "stonixtest.py")) and \
                   os.path.exists(os.path.join(script_path, "stonix.py")):
                    self.test_mode = True
                    self.script_path = os.path.dirname(os.path.realpath(sys.argv[1]))
                else:
                    print "ERROR: Cannot run using this method"
            else:
                #print "DEBUG: Cannot find appropriate path, building paths for current directory"
                self.script_path = os.getcwd()

        #####
        # Set the rules & stonix_resources paths
        if re.search("stonix.app/Contents/MacOS$", self.script_path):
            #####
            # Find the stonix.conf file in the stonix.app/Contents/Resources
            # directory
            macospath = self.script_path
            self.resources_path = os.path.join(self.script_path,
                                               "stonix_resources")
            self.rules_path = os.path.join(self.resources_path,
                                           "rules")
        else:
            # ##
            # create the self.resources_path
            self.resources_path = os.path.join(self.script_path,
                                               "stonix_resources")
            # ##
            # create the self.rules_path
            self.rules_path = os.path.join(self.script_path,
                                           "stonix_resources",
                                           "rules")
        #####
        # Set the log file path
        if self.geteuid() == 0:
            self.log_path = '/var/log'
        else:
            userpath = self.geteuidhome()
            self.log_path = os.path.join(userpath, '.stonix')
            if userpath == '/dev/null':
                self.log_path = '/tmp'

        #####
        # Set the icon path
        self.icon_path = os.path.join(self.resources_path, 'gfx')

        #####
        # Set the configuration file path
        if re.search("stonix.app/Contents/MacOS/stonix$", os.path.realpath(sys.argv[0])):
            #####
            # Find the stonix.conf file in the stonix.app/Contents/Resources
            # directory
            macospath = self.script_path
            parents = macospath.split("/")
            parents.pop()
            parents.append("Resources")
            resources_dir = "/".join(parents)
            self.conf_path = os.path.join(resources_dir, "stonix.conf")
        elif os.path.exists(os.path.join(self.script_path, "etc", "stonix.conf")):
            self.conf_path = os.path.join(self.script_path, "etc", "stonix.conf")
        elif re.search('pydev', script_path_zero) and re.search('stonix_resources', script_path_one):
            print "INFO: Called by unit test"
            srcpath = script_path_one.split('/')[:-2]
            srcpath = '/'.join(srcpath)
            self.conf_path = os.path.join(srcpath, 'etc', 'stonix.conf')
            print self.conf_path
        else:
            self.conf_path = "/etc/stonix.conf"

    def get_test_mode(self):
        """
        Getter test mode flag

        @author: Roy Nielsen
        """

        return self.test_mode

    def get_script_path(self):
        """
        Getter for the script path

        @author: Roy Nielsen
        """

        return self.script_path

    def get_icon_path(self):
        """
        Getter for the icon path

        @author: Roy Nielsen
        """

        return self.icon_path

    def get_rules_path(self):
        """
        Getter for rules path

        @author: Roy Nielsen
        """

        return self.rules_path

    def get_config_path(self):
        """
        Getter for conf file path

        @author: Roy Nielsen
        """

        return self.conf_path

    def get_log_path(self):
        """
        Getter for log path

        @author: Roy Nielsen
        """

        return self.log_path

    def get_resources_path(self):
        """
        Getter for stonix resources directory

        @author: Roy Nielsen
        """

        return self.resources_path

    def getruntime(self):
        '''
        Return the runtime recorded.

        @author: Dave Kennel
        '''

        return self.runtime

    def setnumrules(self, num):
        '''
        Set the number of rules that apply to the system. This information is
        used by the log dispatcher in the run metadata.
        
        @param num: int - number of rules that apply to this host
        @author: Dave Kennel
        '''

        if type(num) is not int:
            raise TypeError('Number of rules must be an integer')
        elif num < 0:
            raise ValueError('Number of rules must be a positive integer')
        else:
            self.numrules = num

    def getnumrules(self):
        '''
        Return the number of rules that apply to this host.
        
        @author: Dave Kennel
        '''

        return self.numrules

    
