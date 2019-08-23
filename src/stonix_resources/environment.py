#!/usr/bin/env python3
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

@author: dkennel
@change: 2014/05/29 - ekkehard j. koch - pep8 and comment updates
@change: 2017/03/07 - dkennel - added fisma risk level support
@change: 2017/09/20 - bgonz12 - updated the implementation of getdefaultip and
            getallips.
'''
import os
import re
import sys
import socket
import subprocess
import platform
import pwd
import time
from .localize import CORPORATENETWORKSERVERS, STONIXVERSION, FISMACAT
if os.geteuid() == 0:
    try:
        import dmidecode
        DMI = True
    except(ImportError):
        DMI = False
else:
    DMI = False


class Environment:

    '''The Environment class collects commonly used information about the
    execution platform and makes it available to the rules.
    :version: 1.0
    :author: D. Kennel


    '''

    def __init__(self):
        self.operatingsystem = ''
        self.osreportstring = ''
        self.osfamily = ''
        self.osname = ''
        self.hostname = ''
        self.ipaddress = ''
        self.macaddress = ''
        self.osversion = ''
        self.major_ver = ''
        self.minor_ver = ''
        self.trivial_ver = ''
        self.systemtype = ''
        self.numrules = 0
        self.stonixversion = STONIXVERSION
        self.euid = os.geteuid()
        currpwd = pwd.getpwuid(self.euid)
        try:
            self.homedir = currpwd[5]
        except IndexError:
            self.homedir = '/dev/null'
        self.installmode = False
        self.verbosemode = False
        self.debugmode = False
        self.runtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.systemfismacat = 'low'
        self.systemfismacat = self.determinefismacat()
        self.collectinfo()

    def setsystemtype(self):
        '''determine whether the current system is based on:
        launchd
        systemd
        sysvinit (init)
        or upstart
        set the variable self.systemtype equal to the result
        
        @author: Breen Malmberg


        '''

        validtypes = ['launchd', 'systemd', 'init', 'upstart']
        cmdlocs = ["/usr/bin/ps", "/bin/ps"]
        cmdbase = ""
        cmd = ""

        # buld the command
        for cl in cmdlocs:
            if os.path.exists(cl):
                cmdbase = cl
        if cmdbase:
            cmd = cmdbase + " -p1"

        try:

            if cmd:
                # run the command
                cmdoutput = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, close_fds=True)
                outputlines = cmdoutput.stdout.readlines()
                for line in outputlines:
                    line = line.decode('ascii')
                    for vt in validtypes:
                        if re.search(vt, line, re.IGNORECASE):
                            self.systemtype = vt

            else:
                print("Unable to determine systemtype. Required utility 'ps' does not exist on this system")
        except OSError:
            print("Unable to determine systemtype. Required utility 'ps' does not exist on this system")

        if self.systemtype not in validtypes:
            print("This system is based on an unknown architecture")
        else:
            print(("Determined that this system is based on " + str(self.systemtype) + " architecture"))

    def getsystemtype(self):
        '''return the systemtype - either:
        launchd, systemd, init, or upstart
        (could potentially return a blank string)


        :returns: self.systemtype

        :rtype: string

@author: Breen Malmberg

        '''

        return self.systemtype

    def setinstallmode(self, installmode):
        '''Set the install mode bool value. Should be true if the prog should run
        in install mode.

        :param bool: installmode
        :param installmode: 
        :returns: void
        @author: D. Kennel

        '''
        try:
            if type(installmode) is bool:
                self.installmode = installmode
        except (NameError):
            # installmode was undefined
            pass

    def getinstallmode(self):
        '''Return the current value of the install mode bool. Should be true if
        the program is to run in install mode.


        :returns: bool : installmode
        @author: D. Kennel

        '''
        return self.installmode

    def setverbosemode(self, verbosemode):
        '''Set the verbose mode bool value. Should be true if the prog should run
        in verbose mode.

        :param bool: verbosemode
        :param verbosemode: 
        :returns: void
        @author: D. Kennel

        '''
        try:
            if type(verbosemode) is bool:
                self.verbosemode = verbosemode
        except (NameError):
            # verbosemode was undefined
            pass

    def getverbosemode(self):
        '''Return the current value of the verbose mode bool. Should be true if
        the program is to run in verbose mode.


        :returns: bool : verbosemode
        @author: D. Kennel

        '''
        return self.verbosemode

    def setdebugmode(self, debugmode):
        '''Set the verbose mode bool value. Should be true if the prog should run
        in verbose mode.

        :param bool: debugmode
        :param debugmode: 
        :returns: void
        @author: D. Kennel

        '''
        try:
            if type(debugmode) is bool:
                self.debugmode = debugmode
        except (NameError):
            # debugmode was undefined
            pass

    def getdebugmode(self):
        '''Return the current value of the debug mode bool. Should be true if the
        program is to run in debug mode.


        :returns: bool : debugmode
        @author: D. Kennel

        '''
        return self.debugmode

    def getostype(self):
        '''Return the detailed operating system type.


        :returns: string :
        @author D. Kennel

        '''
        return self.operatingsystem

    def getosreportstring(self):
        '''Return the detailed operating system type with full version info.


        :returns: string :
        @author D. Kennel

        '''
        return self.osreportstring

    def getosfamily(self):
        '''Return the value of self.osfamily which should be linux, darwin,
        solaris or freebsd.


        :returns: string :
        @author: D. Kennel

        '''
        return self.osfamily

    def getosver(self):
        '''Return the OS version as a string.


        :returns: string :
        @author D. Kennel

        '''
        return self.osversion

    def getosname(self):
        '''Return the OS name as a string.
        possible return values:
        Debian
        CentOS
        RHEL
        Fedora
        openSUSE
        Ubuntu
        Mac OS


        :returns: self.osname

        :rtype: string
@author: Breen Malmberg

        '''

        return self.osname

    def gethostname(self):
        '''Return the hostname of the system.


        :returns: string
        @author: dkennel

        '''
        return self.hostname

    def getipaddress(self):
        '''Return the IP address associated with the host name.


        :returns: string :
        @author D. Kennel

        '''
        return self.ipaddress

    def getmacaddr(self):
        '''Return the mac address in native format.


        :returns: string :
        @author D. Kennel

        '''
        return self.macaddress

    def geteuid(self):
        '''Return the effective user ID


        :returns: int :
        @author D. Kennel

        '''
        return self.euid

    def geteuidhome(self):
        '''Returns the home directory of the current effective user ID.


        :returns: string
        @author: D. Kennel

        '''
        return self.homedir

    def getstonixversion(self):
        '''Returns the version of the stonix program.


        :returns: string
        @author: D. Kennel

        '''
        return self.stonixversion

    def collectinfo(self):
        '''Private method to populate data.


        :returns: void
        @author D. Kennel

        '''

        self.discoveros()
        self.setosfamily()
        self.setosname()
        self.guessnetwork()
        self.collectpaths()
        self.determinefismacat()
        self.setsystemtype()
        self.sethostname()
        self.setipaddress()
        self.setmacaddress()

    def setosname(self):
        '''set the name of the OS (variable self.osname)
        
        @author: Breen Malmberg


        '''

        self.osname = "Unknown"
        namecommand = "/usr/bin/lsb_release -d"
        osnamedict = {"rhel": "RHEL",
                      "Red Hat Enterprise": "RHEL",
                      "CentOS": "CentOS",
                      "Fedora": "Fedora",
                      "Debian": "Debian",
                      "Ubuntu": "Ubuntu",
                      "openSUSE": "openSUSE"}

        namefile = ""
        namefiles = ["/etc/redhat-release", "/etc/os-release"]
        for path in namefiles:
            if os.path.exists(path):
                namefile = path

        contentlines = []

        try:

            if not namefile:
                if os.path.exists("/usr/bin/lsb_release"):
                    cmdoutput = subprocess.Popen(namecommand, shell=True, stdout=subprocess.PIPE, close_fds=True)
                    contentlines = cmdoutput.stdout.readlines()
            else:
                f = open(namefile, 'r')
                contentlines = f.readlines()
                f.close()
        except Exception:
            pass

        if contentlines:
            for line in contentlines:
                for key in osnamedict:
                    if re.search(key, line, re.IGNORECASE):
                        self.osname = osnamedict[key]
                        break

        if self.osname == "Unknown":
            if self.getosfamily() == "darwin":
                self.osname = "Mac OS"

    def discoveros(self):
        '''Discover the operating system type and version


        :returns: void
        @author: D. Kennel

        '''
        # Alternative (better) implementation for Linux
        if os.path.exists('/usr/bin/lsb_release'):
            proc = subprocess.Popen('/usr/bin/lsb_release -dr',
                                  shell=True, stdout=subprocess.PIPE,
                                  close_fds=True)
            description = proc.stdout.readline().decode('utf-8')
            release = proc.stdout.readline().decode('utf-8')
            #description = description.split()
            # print description
            #del description[0]
            #description = " ".join(str(description))
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

        # Breen Malmberg added support for os-release file
        # method of getting version information
        elif os.path.exists('/etc/os-release'):
            relfile = open('/etc/os-release', 'r')
            contentlines = relfile.readlines()
            relfile.close()
            for line in contentlines:
                if re.search('VERSION\=', line, re.IGNORECASE):
                    sline = line[+8:].split()
                    sline[0] = sline[0].replace('"', '')
                    self.osversion = sline[0]
                elif re.search('NAME\=', line, re.IGNORECASE):
                    sline = line[+5:].split()
                    sline[0] = sline[0].replace('"', '')
                    self.operatingsystem = sline[0]
            self.osreportstring = self.operatingsystem +  ' ' + self.osversion

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

    def getosmajorver(self):
        '''return the major revision number of the
        OS version as a string


        :returns: self.major_ver

        :rtype: string
@author: Breen Malmberg

        '''

        ver = self.getosver()
        #.decode('utf-8')
        try:
            self.major_ver = ver.split('.')[0]
        except IndexError:
            self.major_ver = 0

        return self.major_ver

    def getosminorver(self):
        '''return the minor revision number of the
        OS version as a string


        :returns: self.minor_ver

        :rtype: string
@author: Breen Malmberg

        '''

        ver = self.getosver()
        try:
            self.minor_ver = ver.split('.')[1]
        except IndexError:
            self.minor_ver = 0

        return self.minor_ver

    def getostrivialver(self):
        '''return the trivial revision number of the
        OS version as a string


        :returns: self.trivial_ver

        :rtype: string
@author: Breen Malmberg

        '''

        ver = self.getosver()
        try:
            self.trivial_ver = ver.split('.')[2]
        except IndexError:
            self.trivial_ver = 0

        return self.trivial_ver

    def setosfamily(self):
        '''Private method to detect and set the self.osfamily property. This is a
        fuzzy classification of the OS.


        '''
        uname = sys.platform
        if uname in ('linux2', 'linux'):
            self.osfamily = 'linux'
        elif uname == 'darwin':
            self.osfamily = 'darwin'
        elif uname == 'sunos5':
            self.osfamily = 'solaris'
        elif uname == 'freebsd9':
            self.osfamily = 'freebsd'

    def setmacaddress(self):
        '''return the current system's mac address
        set the class variable self.macaddress


        :returns: macaddr

        :rtype: string
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
            print("environment::getmacaddr():WARNING: Could not detect any net utility type/location")
            return macaddr
        elif "nmcli" in netutil:
            if self.getosmajorver() == "6":
                netcmd = netutil +  " -t dev list"
            else:
                netcmd = netutil + " device show"
        elif "ifconfig" in netutil:
            netcmd = netutil + " -a"
        elif "ip" in netutil:
            netcmd = netutil + " -o link"
        else:
            print("environment::getmacaddr():WARNING: Could not identify unknown net utility type")
            return macaddr

        try:

            ipaddress = self.getipaddress()
            macinfocmd = subprocess.Popen(netcmd, shell=True, stdout=subprocess.PIPE, close_fds=True)
            macinfo = macinfocmd.stdout.readlines()

            for line in macinfo:
                line = line.decode('ascii')
                match = re.search(macre, line)
                if match is not None:
                    macaddr = match.group()
                    if macaddr != "00:00:00:00:00:00":
                        break

        except Exception:
            raise

        self.macaddress = macaddr

    def getnetutil(self):
        '''return the full path to the net utility tool used
        by the current system
        
        can detect the following net util's:
        * ip
        * ifconfig
        * nmcli


        :returns: netutil

        :rtype: string
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

    def setipaddress(self):
        '''return the current system's ip address
        set the class variable self.ipaddress


        :returns: ipaddr

        :rtype: string
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

    def sethostname(self):
        '''get the current system's host name
        (fully qualified domain name)
        set the class variable self.hostname


        :returns: hostfqdn

        :rtype: string
@author: Dave Kennel
@author: Breen Malmberg

        '''

        hostfqdn = ""

        try:

            hostfqdn = socket.getfqdn()

        except Exception:
            raise

        self.hostname = hostfqdn

    def guessnetwork(self):
        '''This method checks the configured interfaces and tries to
        make an educated guess as to the correct network data. The
        following class variables will be updated by this method:
        * self.hostname
        * self.ipaddress
        * self.macaddress
        
        @author: Dave Kennel
        @author: Breen Malmberg


        '''

        self.gethostname()
        self.getipaddress()
        self.getmacaddr()

    def getdefaultip(self):
        '''This method will return the ip address of the interface
        associated with the current default route.


        :returns: ipaddr

        :rtype: string
@author: Dave Kennel

        '''

        ipaddr = '127.0.0.1'
        gateway = ''

        try:
            if os.path.exists("/usr/bin/nmcli"):
                nmclicmd = subprocess.Popen("/usr/bin/nmcli -t dev list", shell=True, stdout=subprocess.PIPE, close_fds=True)
                nmclidata = nmclicmd.stdout.readlines()
                for line in nmclidata:
                    if re.search("IP4-SETTINGS.ADDRESS:", line):
                        sline = line.split(":")
                        ipaddr = sline[1]
                        break
        except Exception:
            pass

        if ipaddr != "127.0.0.1":
            return ipaddr

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
        '''This method will when given an IP try to find matching ip
        from a list of IP addresses. Matching will work from left to right
        according to the level param. If no match is found
        the loopback address will be returned.

        :param string: ipaddress
        :param list: list of ipaddresses
        :param int: level
        :param target: 
        :param iplist: 
        :param level:  (Default value = 1)
        :returns: matchlist
        :rtype: list
@author: Dave Kennel
@change: Breen Malmberg - 07/19/2018 - slightly changed return logic
        so that return value type would be consistent; moved default variable
        inits to top of method; wrapped all code which could fail in try/except

        '''

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
        '''This method returns all ip addresses on all interfaces on the system.


        :returns: iplist

        :rtype: list
@author: Dave Kennel
@change: Breen Malmberg - 07/29/2018 - re-factored rule to account for ifconfig
        not being installed, and the use case where ifconfig is located at
        /sbin/ifconfig and the output does not contain "addr:"

        '''

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
        '''Find and return the
        Property number of the local machine
        @author: scmcleni
        @author: D. Kennel


        :returns: int

        '''
        propnum = 0
        try:
            if os.path.exists('/etc/property-number'):
                propertynumberfile = open('/etc/property-number', 'r')
                propnum = propertynumberfile.readline()
                propnum = propnum.strip()
                propertynumberfile.close()
            elif DMI and self.euid == 0:
                chassis = dmidecode.chassis()
                for key in chassis:
                    propnum = chassis[key]['data']['Asset Tag']
            if platform.system() == 'Darwin':
                pnfetch = '/usr/sbin/nvram asset_id 2>/dev/null'
                cmd = subprocess.Popen(pnfetch, shell=True,
                                       stdout=subprocess.PIPE,
                                       close_fds=True)
                cmdout = cmd.stdout.readline()
                cmdout = cmdout.split()
                try:
                    propnum = cmdout[1]
                except(IndexError, KeyError):
                    propnum = 0
        except:
            pass
            # Failed to obtain property number
        return propnum

    def get_system_serial_number(self):
        '''Find and return the
        Serial number of the local machine
        @author: dkennel


        :returns: string

        '''
        systemserial = '0'
        if DMI and self.euid == 0:
            try:
                system = dmidecode.system()
                for key in system:
                    try:
                        systemserial = system[key]['data']['Serial Number']
                    except(IndexError, KeyError):
                        continue
            except(IndexError, KeyError):
                # got unexpected data back from dmidecode
                pass
        elif os.path.exists('/usr/sbin/system_profiler'):
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
                    except(IndexError, KeyError):
                        pass
        systemserial = systemserial.strip()
        return systemserial

    def get_chassis_serial_number(self):
        '''Find and return the
        Chassis serial number
        @author: dkennel
        @requires: string


        '''
        chassisserial = '0'
        if DMI and self.euid == 0:
            try:
                chassis = dmidecode.chassis()
                for key in chassis:
                    chassisserial = chassis[key]['data']['Serial Number']
            except(IndexError, KeyError):
                # got unexpected data back from dmidecode
                pass
        chassisserial = chassisserial.strip()
        return chassisserial

    def get_system_manufacturer(self):
        '''Find and return the
        System manufacturer
        @author: D. Kennel


        :returns: string

        '''
        systemmfr = 'Unk'
        if DMI and self.euid == 0:
            try:
                system = dmidecode.system()
                for key in system:
                    try:
                        systemmfr = system[key]['data']['Manufacturer']
                    except(IndexError, KeyError):
                        continue
            except(IndexError, KeyError):
                # got unexpected data back from dmidecode
                pass
        systemmfr = systemmfr.strip()
        return systemmfr

    def get_chassis_manfacturer(self):
        '''Find and return the
        Chassis manufacterer
        @author: D. Kennel


        :returns: string

        '''
        chassismfr = 'Unk'
        if DMI and self.euid == 0:
            try:
                chassis = dmidecode.chassis()
                for key in chassis:
                    chassismfr = chassis[key]['data']['Manufacturer']
            except(IndexError, KeyError):
                # got unexpected data back from dmidecode
                pass
        chassismfr = chassismfr.strip()
        return chassismfr

    def get_sys_uuid(self):
        '''Find and return a unique identifier for the system. On most systems
        this will be the UUID of the system. On Solaris SPARC this will be
        a number that is _hopefully_ unique as that platform doesn't have
        UUID numbers.
        @author: D. Kennel


        :returns: string

        '''
        uuid = '0'
        if DMI and self.euid == 0:
            try:
                system = dmidecode.system()
                for key in system:
                    try:
                        uuid = system[key]['data']['UUID']
                    except(IndexError, KeyError):
                        continue
            except(IndexError, KeyError):
                # got unexpected data back from dmidecode
                pass
        elif os.path.exists('/usr/sbin/dmidecode') and self.euid == 0:
            uuidfetch = '/usr/sbin/dmidecode -s system-uuid'
            cmd1 = subprocess.Popen(uuidfetch, shell=True,
                                    stdout=subprocess.PIPE,
                                    close_fds=True)
            uuid = cmd1.stdout.readline()
        elif os.path.exists('/usr/sbin/smbios'):
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
                    except(IndexError, KeyError):
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
                    except(IndexError, KeyError):
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
        '''Returns a bool indicating whether or not the system in question is a
        laptop. The is mobile method is used by some rules that have alternate
        settings for laptops.
        @author: dkennel
        @regturn: bool - true if system is a laptop


        '''
        ismobile = False
        dmitypes = ['LapTop', 'Portable', 'Notebook', 'Hand Held',
                    'Sub Notebook']
        if DMI and self.euid == 0:
            try:
                chassis = dmidecode.chassis()
                for key in chassis:
                    chassistype = chassis[key]['data']['Type']
                if chassistype in dmitypes:
                    ismobile = True
            except(IndexError, KeyError):
                # got unexpected data back from dmidecode
                pass
        elif os.path.exists('/usr/sbin/system_profiler'):
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
        '''Returns a bool indicating whether or not the little snitch program is
        active. Little snitch is a firewall utility used on Mac systems and can
        interfere with STONIX operations.
        @author: ekkehard


        :returns: bool - true if little snitch is running

        '''
        issnitchactive = False
        if self.osfamily == 'darwin':
            cmd = '/bin/ps axc -o comm | grep lsd'
            littlesnitch = 'lsd'
            proc = subprocess.Popen(cmd, shell=True,
                                    stdout=subprocess.PIPE, close_fds=True)
            netdata = proc.stdout.readlines()
            for line in netdata:
                print("processing: " + line)
                match = re.search(littlesnitch, line)
                if match is not None:
                    print('LittleSnitch Is Running')
                    issnitchactive = True
                    break
        return issnitchactive

    def oncorporatenetwork(self):
        '''Determine if we are running on the corporate network


        :returns: amoncorporatenetwork

        :rtype: bool
@author: ekkehard j. koch
@change: Breen Malmberg - 2/28/2017 - added logic to ensure that this
        code only runs if the constant, CORPORATENETWORKSERVERS, is
        properly defined and not set to 'None', in localize.py;
        minor doc string edit; note: no logging facility available in
        environment, so can't log when CORPORATENETWORKSERVERS
        is undefined or None...

        '''

        amoncorporatenetwork = False

        # return False if the constant CORPORATENETWORKSERVERS is
        # either set to 'None' or not defined, in localize.py
        if CORPORATENETWORKSERVERS == None:
            print(str(os.path.basename(__file__)) + " :: " + str(self.oncorporatenetwork.__name__) + " :: " + str("The constant CORPORATENETWORKSERVERS has not been properly defined in localize.py"))
            return amoncorporatenetwork
        elif not CORPORATENETWORKSERVERS:
            print(str(os.path.basename(__file__)) + " :: " + str(self.oncorporatenetwork.__name__) + " :: " + str("The constant CORPORATENETWORKSERVERS has not been properly defined in localize.py"))
            return amoncorporatenetwork
        else:
            listOfServers = CORPORATENETWORKSERVERS
            for server in listOfServers:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((server, 80))
                    sock.close()
                    amoncorporatenetwork = True
                    return amoncorporatenetwork
                except (socket.gaierror, socket.timeout, socket.error):
                    amoncorporatenetwork = False
        return amoncorporatenetwork

    def collectpaths(self):
        '''Determine how stonix is run and return appropriate paths for:
        
        icons
        rules
        conf
        logs
        
        @author: Roy Nielsen


        '''
        try:
            script_path_zero = sys._MEIPASS
        except Exception:
            script_path_zero = os.path.realpath(sys.argv[0])

        try:
            script_path_one = os.path.realpath(sys.argv[1])
        except:
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
                    print("ERROR: Cannot run using this method")
            else:
                #print "DEBUG: Cannot find appropriate path, building paths for current directory"
                try:
                    self.script_path = sys._MEIPASS
                except Exception:
                    self.script_path = os.path.dirname(os.path.realpath(sys.argv[0]))

        #####
        # Set the rules & stonix_resources paths
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
        self.conf_path = "/etc/stonix.conf"

    def determinefismacat(self):
        '''This method pulls the fimsa categorization from the localize.py
        localization file. This allows a site to prepare special packages for
        use on higher risk systems rather than letting the system administrator
        self select the higher level.


        :returns: string - low, med, high
        @author: dkennel

        '''
        if FISMACAT not in ['high', 'med', 'low']:
            raise ValueError('FISMACAT invalid: valid values are low, med, high')
        else:
            return FISMACAT

    def get_test_mode(self):
        '''Getter test mode flag
        
        @author: Roy Nielsen


        '''
        return self.test_mode

    def get_script_path(self):
        '''Getter for the script path
        
        @author: Roy Nielsen


        '''
        return self.script_path

    def get_icon_path(self):
        '''Getter for the icon path
        
        @author: Roy Nielsen


        '''
        return self.icon_path

    def get_rules_path(self):
        '''Getter for rules path
        
        @author: Roy Nielsen


        '''
        return self.rules_path

    def get_config_path(self):
        '''Getter for conf file path
        
        @author: Roy Nielsen


        '''
        return self.conf_path

    def get_log_path(self):
        '''Getter for log path
        
        @author: Roy Nielsen


        '''
        return self.log_path

    def get_resources_path(self):
        '''Getter for stonix resources directory
        
        @author: Roy Nielsen


        '''
        return self.resources_path

    def getruntime(self):
        '''


        :returns: @author: dkennel

        '''
        return self.runtime

    def setnumrules(self, num):
        '''Set the number of rules that apply to the system. This information is
        used by the log dispatcher in the run metadata.

        :param num: int - number of rules that apply to this host
        @author: dkennel

        '''
        if type(num) is not int:
            raise TypeError('Number of rules must be an integer')
        elif num < 0:
            raise ValueError('Number of rules must be a positive integer')
        else:
            self.numrules = num

    def getnumrules(self):
        '''


        :returns: @author: dkennel

        '''
        return self.numrules

    def getsystemfismacat(self):
        '''Return the system FISMA risk categorization.


        :returns: string - low, med, high
        @author: dkennel

        '''
        return self.systemfismacat

    def setsystemfismacat(self, category):
        '''Set the systems FISMA risk categorization. The risk categorization
        cannot be set lower than the default risk level set in FISMACAT in
        localize.py

        :param category: string - low, med, high
        @author: dkennel

        '''

        if category not in ['high', 'med', 'low']:
            raise ValueError('SystemFismaCat invalid: valid values are low, med, high')
        elif self.systemfismacat == 'high':
            self.systemfismacat = 'high'
        elif self.systemfismacat == 'med' and category == 'high':
            self.systemfismacat = 'high'
        elif self.systemfismacat == 'low' and category == 'high':
            self.systemfismacat = category
