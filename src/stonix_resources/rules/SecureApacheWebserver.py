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
Created on Nov 20, 2012
This class is responsible for securing the Apache webserver configuration.
@author: dkennel
@change: 2015/04/17 updated for new isApplicable
@change: 2015/09/24 eball Fixed potential missing file error in fix()
@change: 2015/10/08 eball Help text cleanup
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
'''
from __future__ import absolute_import
import os
import re
import traceback
import stat
import subprocess
import shutil

from ..rule import Rule
from ..configurationitem import ConfigurationItem
from ..stonixutilityfunctions import resetsecon
from ..logdispatcher import LogPriority


class SecureApacheWebserver(Rule):
    '''
    This class is responsible for securing the configuration of the Apache
    webserver. It modifies the httpd.conf file and some files in conf.d. For
    future devs: N.B. the main apache config file location is a list thanks to
    Solaris 10 that insisted on shipping both Apache 1.3.4 and Apache 2.0 and
    making it possible to have both installed on the system at the same time.
    This affects all operations on the config file.

    @author: dkennel
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.rulenumber = 136
        self.rulename = 'SecureApacheWebserver'
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.11', 'r', '10.13.10']}}
        self.comment = re.compile('^#|^;')
        conflocations = ['/etc/httpd/conf/httpd.conf',
                         '/etc/apache2/apache2.conf',
                         '/etc/httpd/httpd.conf',
                         '/etc/apache2/httpd.conf',
                         '/etc/apache/httpd.conf',
                         '/usr/local/etc/apache/httpd.conf']
        self.conffiles = []
        for location in conflocations:
            if os.path.exists(location):
                self.conffiles.append(location)
        confdirs = ['/etc/httpd/conf.d', '/etc/apache2/extra', '/etc/apache',
                    '/etc/apache2', '/etc/apache2/other',
                    '/etc/apache2/users', '/etc/apache2/conf-enabled',
                    '/etc/apache2/sites-enabled']
        self.confdir = []
        for dirname in confdirs:
            if os.path.isdir(dirname):
                self.confdir.append(dirname)
        self.sslfiles = self.locatesslfiles()
        self.phpfile = '/etc/php.ini'
        phplocs = ['/etc/php.ini', '/usr/local/etc/php.ini']
        if not os.path.exists(self.phpfile):
            for phploc in phplocs:
                if os.path.exists(phploc):
                    self.phpfile = phploc
                    break
        self.binpaths = ['/usr/sbin/httpd', '/usr/local/sbin/httpd',
                         '/usr/sbin/apache2', '/usr/apache/bin/httpd',
                         '/usr/apache2/bin/httpd']
        self.controlpaths = ['/usr/sbin/apachectl',
                             '/usr/local/sbin/apachectl',
                             '/usr/sbin/apachctl', '/usr/apache/bin/apachectl',
                             '/usr/apache2/bin/apachectl']
        self.comment = re.compile('^#|^;')
        self.secureapache = self.__initializeSecureApache()
        self.domodules = self.__initializeSecureApacheMods()
        self.dossl = self.__initializeSecureApacheSsl()
        self.dophp = self.__initializeSecurePhp()
        self.guidance = ['NSA 3.16.3', 'CCE-4474-3', 'CCE-3756-4',
                         'CCE-4509-6', 'CCE-4386-9', 'CCE-4029-5',
                         'CCE-3581-6', 'CCE-4574-0']
        self.aglobals = ['TraceEnable off',
                         'ServerTokens Prod',
                         'ServerSignature Off']
        self.sslitems = ['SSLCipherSuite ALL:!EXP:!NULL:!ADH:!LOW:!SSLv2!MEDIUM']
        self.modules = ['rewrite_module modules/mod_rewrite.so',
                        'ldap_module modules/mod_ldap.so',
                        'authnz_ldap_module modules/mod_authnz_ldap.so',
                        'include_module modules/mod_include.so',
                        'dav_module modules/mod_dav.so',
                        'dav_fs_module modules/mod_dav_fs.so',
                        'dav_module modules/mod_dav.so',
                        'dav_lock_module modules/mod_dav_lock.so',
                        'status_module modules/mod_status.so',
                        'info_module modules/mod_info.so',
                        'speling_module modules/mod_speling.so',
                        'userdir_module modules/mod_userdir.so',
                        'proxy_balancer_module modules/mod_proxy_balancer.so',
                        'proxy_ftp_module modules/mod_proxy_ftp.so',
                        'proxy_http_module modules/mod_proxy_http.so',
                        'proxy_connect_module modules/mod_proxy_connect.so',
                        'cache_module modules/mod_cache.so',
                        'cache_disk_module modules/mod_cache_disk.so',
                        'cache_socache_module modules/mod_cache_socache.so',
                        'ext_filter_module modules/mod_ext_filter.so',
                        'expires_module modules/mod_expires.so',
                        'headers_module modules/mod_headers.so',
                        'vhost_alias_module modules/mod_vhost_alias.so']
        self.phpitems = ['display_errors = Off',
                         'expose_php = Off',
                         'log_errors = On',
                         'register_globals = Off',
                         'post_max_size = 1K',
                         'cgi.force_redirect = 0',
                         'file_uploads = Off',
                         'allow_url_fopen = Off',
                         'sql.safe_mode = On']
        self.phpcompliant = True
        self.sslcompliant = True
        self.modulescompliant = True
        self.httpcompliant = True

    def __initializeSecureApache(self):
        '''
        Private method to initialize the configurationitem object for the
        SECUREAPACHE bool.
        @return: configuration object instance
        @author: dkennel
        '''
        conf = 'SECUREAPACHE'
        confinst = '''If set to yes or true the SECUREAPACHE variable will set
the basic security settings for the Apache Webserver. This should be safe for
all systems.'''
        confdefault = True
        try:
            confcurr = self.config.getconfvalue(self.rulename, conf)
        except(KeyError):
            confcurr = confdefault
        conftype = 'bool'
        try:
            confuc = self.config.getusercomment(self.rulename, conf)
        except(KeyError):
            confuc = ''
        myci = ConfigurationItem(conftype, conf, confdefault, confuc,
                                        confinst, confcurr)
        self.logdispatch.log(LogPriority.DEBUG,
                             ['SecureApacheWebserver.__initializeSecureApache',
                              'SECUREAPACHE val = ' + str(confcurr)])
        self.confitems.append(myci)
        return myci

    def __initializeSecureApacheMods(self):
        '''
        Private method to initialize the configurationitem object for the
        SECUREAPACHEMODS bool.
        @return: configuration object instance
        @author: dkennel
        '''
        myci = ConfigurationItem('bool')
        key = 'SECUREAPACHEMODS'
        myci.setkey(key)
        confinst = '''If set to yes or true the SECUREAPACHEMODS variable will
minimize the installed Apache modules. Apache modules provide increased
functionality at the cost of increased attack surface and information leakage.
Users disabling this action should manually validate and minimize the installed
modules.'''
        myci.setinstructions(confinst)
        default = True
        myci.setdefvalue(default)
        try:
            confcurr = self.config.getconfvalue(self.rulename, key)
        except(KeyError):
            confcurr = default
        myci.updatecurrvalue(confcurr)
        try:
            confuc = self.config.getusercomment(self.rulename, key)
        except(KeyError):
            confuc = ''
        myci.setusercomment(confuc)
        self.confitems.append(myci)
        self.logdispatch.log(LogPriority.DEBUG,
                        ['SecureApacheWebserver.__initializeSecureApacheMods',
                         'SECUREAPACHEMODS val = ' + str(confcurr)])
        return myci

    def __initializeSecureApacheSsl(self):
        '''
        Private method to initialize the configurationitem object for the
        SECUREAPACHESSL bool.
        @return: configuration object instance
        @author: dkennel
        '''
        datatype = 'bool'
        key = 'SECUREAPACHESSL'
        instructions = '''If set to yes or true the SECUREAPACHESSL variable will prevent
the Apache server from using weak crypto for SSL sessions. This should be safe
unless the client population includes browsers restricted to US export level
crypto.'''
        default = True
        myci = self.initCi(datatype, key, instructions, default)
        return myci

    def __initializeSecurePhp(self):
        '''
        Private method to initialize the configurationitem object for the
        SECUREPHP bool.
        @return: configuration object instance
        @author: dkennel
        '''
        datatype = 'bool'
        key = 'SECUREPHP'
        instructions = '''If set to yes or true the SECUREPHP action will secure the
configuration in the php.ini file. This is generally safe for new PHP
development but some existing applications may use insecure side effects.'''
        default = True
        myci = self.initCi(datatype, key, instructions, default)
        return myci

    def locatesslfiles(self):
        '''Probe known apache config file locations to find the file(s)
        containing cipher specifications.
        @return: list of strings - list of fully qualified file paths
        @author: dkennel
        '''
        filelist = []
        sslfilelist = []
        try:
            for directory in self.confdir:
                self.logdispatch.log(LogPriority.DEBUG,
                                ['',
                                 'Listing directory ' + str(directory)])
                for filename in os.listdir(directory):
                    path = os.path.join(directory, filename)
                    self.logdispatch.log(LogPriority.DEBUG,
                                ['',
                                 'Adding path ' + str(path)])
                    filelist.append(path)
            for cpath in filelist:
                try:
                    rhandle = open(cpath, 'r')
                    filedata = rhandle.readlines()
                    rhandle.close()
                except(IOError):
                    continue
                for line in filedata:
                    if self.comment.match(line):
                        continue
                    if re.search('SSLCipherSuite', line):
                        sslfilelist.append(cpath)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = 'SecureApacheWebserver.locatesslfiles: '
            self.detailedresults = self.detailedresults + traceback.format_exc()
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                            ['SecureApacheWebserver.locatesslfiles',
                             self.detailedresults])
        return sslfilelist

    def __readconf(self, conffile):
        '''SecureApacheWebserver.__readconf() Private method to read the
        contents of the httpd.conf file. Returns the file content as a list.
        @author: dkennel
        @return: list - file content as returned by readlines
        '''
        config = []
        if os.path.exists(conffile):
            try:
                fhandle = open(conffile, 'r')
                config = fhandle.readlines()
                fhandle.close()
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.detailedresults = 'SecureApacheWebserver.__readconf: '
                self.detailedresults = self.detailedresults + traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR,
                            ['SecureApacheWebserver.__readconf',
                             self.detailedresults])
        return config

    def __chkvalues(self, keylist, conf, invert=False):
        '''SecureApacheWebserver.__chkvalues() Private method to check passed
        configuration data (apache conf format) for specified values. Values
        should be passed as a python list that can be used in a reg ex search.
        A dictionary will be returned. The list entries will be the keys in the
        dict and values will be True or False on whether the entry was present.
        @param keylist: list of strings
        @param conf: configuration data to search
        @param invert: Invert the search, ensure that the listed items _do_not_
        appear in the config file. 
        @return: dict
        @author: dkennel
        '''
        self.logdispatch.log(LogPriority.DEBUG,
                        ['SecureApacheWebserver.__chkvalues',
                         'Looking for keys: ' + str(keylist)])
        founddict = {}.fromkeys(keylist, False)
        for line in conf:
            if self.comment.match(line):
                continue
            for entry in keylist:
                if re.search(entry, line):
                    founddict[entry] = True
                    self.logdispatch.log(LogPriority.DEBUG,
                        ['SecureApacheWebserver.__chkvalues',
                         'Found key: ' + str(entry)])
        return founddict

    def __modcheck(self):
        '''SecureApacheWebserver.__modcheck() is a private method to check for
        modules that should be disabled. It is mirrored by the
        __fixapachemodules() method.
        @return: Tuple - two elements, bool indicating compliance, string
        with detailed results.
        @author: dkennel
        '''
        modulesd = '/etc/httpd/conf.modules.d'
        enabled = '/etc/apache2/mods-enabled'
        results = ''
        compliant = True
        filesToCheck = []

        if os.path.exists(modulesd) or os.path.exists(enabled):
            if os.path.exists(modulesd):
                modulesdirpath = modulesd
            elif os.path.exists(enabled):
                modulesdirpath = enabled

            for filename in os.listdir(modulesdirpath):
                filepath = os.path.join(modulesdirpath, filename)
                filesToCheck.append(filepath)
        for filename in self.conffiles:
            if os.path.exists(filename):
                filesToCheck.append(filename)
        self.logdispatch.log(LogPriority.DEBUG,
                             ['SecureApacheWebserver.__modcheck',
                              'Checking files: ' + str(filesToCheck)])
        for filetocheck in filesToCheck:
            if os.path.isfile(filetocheck):
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__modcheck',
                                      'Checking ' + str(filetocheck)])
                rhandle = open(filetocheck, 'r')
                modconf = rhandle.readlines()
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__modcheck',
                                      'Contents: ' + str(modconf)])
                rhandle.close()
                for line in modconf:
                    if self.comment.match(line):
                        continue
                    for entry in self.modules:
                        # Ubuntu is using a different path to modules
                        # so we split the list elements and re.search on the
                        # back half which contains the .so
                        entrysplit = entry.split(' ')
                        modpath = entrysplit[1]
#                         This code commented out because of its riduculous
#                         verbosity but retained in case needed.
#                         self.logdispatch.log(LogPriority.DEBUG,
#                                      ['SecureApacheWebserver.__modcheck',
#                                       'Comparing: ' + str(modpath) + ' ' + line])
                        if re.search(modpath, line):
                            self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__modcheck',
                                      'Found ' + str(modpath)])
                            self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__modcheck',
                                      'Line searched ' + str(line)])
                            compliant = False
                            results = results + ' File ' + filetocheck + \
                            ' contains module entry ' + entry + \
                            ' This should be disabled if possible.'
            else:
                continue

        return compliant, results

    def report(self):
        '''SecureApacheWebserver.report() Public method to report on the
        configuration status of the Apache webserver.
        @author: dkennel
        @return: bool - False if the method died during execution
        '''
        self.logdispatch.log(LogPriority.DEBUG, 'Entering report method')
        compliant = True
        self.detailedresults = 'Results '
        try:
            for filename in self.conffiles:
                if os.path.exists(filename):
                    rhandle = open(filename, 'r')
                else:
                    continue
                conf = rhandle.readlines()
                rhandle.close()
                self.logdispatch.log(LogPriority.DEBUG,
                            ['SecureApacheWebserver.report',
                             'Checking aglobals'])
                founddict1 = self.__chkvalues(self.aglobals, conf)
                for entry in self.aglobals:
                    if founddict1[entry] == False:
                        compliant = False
                        self.httpcompliant = False
                        self.detailedresults = self.detailedresults + \
                        'Required directive ' + entry + \
                        ' not found in Apache configuration. \n'
            self.logdispatch.log(LogPriority.DEBUG, 'Checking modules')
            modcompliant, results = self.__modcheck()
            if not modcompliant:
                self.modulescompliant = False
                compliant = False
                self.detailedresults = self.detailedresults + results

            self.logdispatch.log(LogPriority.DEBUG, 'Checking sslfiles')
            for filename in self.sslfiles:
                rhandle3 = open(filename, 'r')
                conf3 = rhandle3.readlines()
                rhandle3.close()
                founddict3 = self.__chkvalues(self.sslitems, conf3)
                for entry in self.sslitems:
                    if founddict3[entry] == False:
                        compliant = False
                        self.sslcompliant = False
                        self.detailedresults = self.detailedresults + \
                        filename + ' should contain ' + entry + ' \n'
            if os.path.exists(self.phpfile):
                self.logdispatch.log(LogPriority.DEBUG, 'Checking phpfile')
                rhandle4 = open(self.phpfile, 'r')
                conf = rhandle4.readlines()
                rhandle4.close()
                founddict4 = self.__chkvalues(self.phpitems, conf)
                for entry in self.phpitems:
                    if founddict4[entry] == False:
                        compliant = False
                        self.phpcompliant = False
                        self.detailedresults = self.detailedresults + \
                        self.phpfile + ' should contain ' + entry + ' \n'
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception, err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def __fixapacheglobals(self, conffile, eventid1, eventid2):
        '''SecureApacheWebserver.__fixapacheglobals() private method to
        configure the correct global config options for apache.
        @param conffile: string - path to the apache conf file
        @param eventid1: string - event id code for the change to the file
        @param eventid2: string - event id code for the permissions change
        '''
        self.logdispatch.log(LogPriority.DEBUG,
                        ['SecureApacheWebserver.__fixapacheglobals',
                         'Entering function'])
        if self.httpcompliant:
            return
        if os.path.exists(conffile):
            self.logdispatch.log(LogPriority.DEBUG,
                            ['SecureApacheWebserver.__fixapacheglobals',
                             'Located config file ' + conffile])
            localconf = self.__readconf(conffile)
            founddict = {}.fromkeys(self.aglobals, False)
            for directive in self.aglobals:
                self.logdispatch.log(LogPriority.DEBUG,
                                ['SecureApacheWebserver.__fixapacheglobals',
                                 'Processing directive: ' + directive])
                newconf = []
                fragment = directive.split()
                option = fragment[0]
                for line in localconf:
                    if self.comment.match(line):
                        pass
                    elif re.search(option, line) and not re.search(directive,
                                                                   line):
                        line = directive + '\n'
                        founddict[directive] = True
                        self.logdispatch.log(LogPriority.DEBUG,
                                        ['SecureApacheWebserver.__fixapacheglobals',
                                         'Corrected option: ' + option])
                    elif re.search(directive, line):
                        founddict[directive] = True
                        self.logdispatch.log(LogPriority.DEBUG,
                                        ['SecureApacheWebserver.__fixapacheglobals',
                                         'Found directive: ' + directive])
                    newconf.append(line)
                localconf = newconf
            for directive in self.aglobals:
                if founddict[directive] == False:
                    localconf.insert(30, directive + '\n')
                    self.logdispatch.log(LogPriority.DEBUG,
                                    ['SecureApacheWebserver.__fixapacheglobals',
                                     'Added directive: ' + directive])
            tempfile = conffile + '.stonixtmp'
            whandle = open(tempfile, 'w')
            for line in localconf:
                whandle.write(line)
            whandle.close()
            statdata = os.stat(conffile)
            owner = statdata.st_uid
            group = statdata.st_gid
            mode = stat.S_IMODE(statdata.st_mode)
            mytype1 = 'conf'
            mystart1 = self.currstate
            myend1 = self.targetstate
            myid1 = eventid1
            self.statechglogger.recordfilechange(conffile, tempfile, myid1)
            event1 = {'eventtype': mytype1,
                      'startstate': mystart1,
                      'endstate': myend1,
                      'myfile': conffile}
            self.statechglogger.recordchgevent(myid1, event1)
            os.rename(tempfile, conffile)
            if self.environ.getosfamily == 'solaris':
                if owner != 0 or group != 2 or mode != 420:
                    self.logdispatch.log(LogPriority.DEBUG,
                                    ['SecureApacheWebserver.__fixapacheglobals',
                                     'Applying Solaris permissions'])
                    myend2 = [0, 2, 420]
                    mytype2 = 'perm'
                    mystart2 = [owner, group, mode]
                    myid2 = eventid2
                    event2 = {'eventtype': mytype2,
                             'startstate': mystart2,
                             'endstate': myend2}
                    self.statechglogger.recordchgevent(myid2, event2)
                    os.chown(conffile, myend2[0], myend2[1])
                    os.chmod(conffile, myend2[2])
            elif owner != 0 or group != 0 or mode != 420:
                myend2 = [0, 0, 420]
                mytype2 = 'perm'
                mystart2 = [owner, group, mode]
                myid2 = eventid2
                event2 = {'eventtype': mytype2,
                          'startstate': mystart2,
                          'endstate': myend2,
                          'myfile': conffile}
                self.statechglogger.recordchgevent(myid2, event2)
                os.chown(conffile, myend2[0], myend2[1])
                os.chmod(conffile, myend2[2])
            resetsecon(conffile)

    def __fixapachemodules(self, conffile, eventid1, eventid2):
        '''SecureApacheWebserver.__fixapachemodules() private method to disable
        apache modules that are not needed. This method loops over locations
        for the apache binary but does not understand a list for conffile
        location.

        @param conffile: fully qualified path to the apache conf file
        @param eventid1: eventid number to generate a unique statechangelogger
        entry for the file change.
        @param eventid2: eventid number for permissions changes to the conf
        file. (May not be needed).
        '''
        self.logdispatch.log(LogPriority.DEBUG,
                        ['SecureApacheWebserver.__fixapachemodules',
                         'Entering function'])
        if self.modulescompliant:
            return
        movefile = False
        if re.search('mods-enabled', conffile):
            movefile = True
        disablefile = False
        tempfile = conffile + '.stonixtmp'
        tempfile2 = conffile + '.stonixtmp2'
        changecomplete = True
        owneronly = 448  # Integer representation of 0700

        # This is the code path for Apache laid out ubuntu 14.04 style
        # In this style the mods-enabled and mods-available directory contain
        # .load files which contain the module load directive and in some
        # cases .conf files which contain configuration for the module. To
        # succeed both files must be moved into the mods-available directory.
        if movefile:
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['SecureApacheWebserver.__fixapachemodules',
                                  'Processing conf file ' + conffile])
            rhandle = open(conffile, 'r+')
            filecontents = rhandle.read()
            rhandle.close()
            for module in self.modules:
                modulesplit = module.split(' ')
                modulepath = modulesplit[1]
                if re.search(modulepath, filecontents):
                    disablefile = True
            if disablefile:
                confpath = re.sub('\.load', '.conf', conffile)
                self.logdispatch.log(LogPriority.DEBUG,
                                 ['SecureApacheWebserver.__fixapachemodules',
                                  'Disabling: ' + conffile + ' ' + confpath])
                disabledir = '/etc/apache2/mods-available'
                if not os.path.isdir(disabledir):
                    os.makedirs(disabledir, owneronly)
                if os.path.exists(conffile):
                    if os.path.islink(conffile):
                        os.remove(conffile)
                    else:
                        shutil.move(conffile, disabledir)
                        type1 = 'move'
                        start1 = conffile
                        end1 = re.sub('mods-enabled', 'mods-available', conffile)
                        eid1 = eventid1
                        event1 = {'eventtype': type1,
                                  'startstate': start1,
                                  'endstate': end1,
                                  'myfile': conffile}
                        self.statechglogger.recordchgevent(eid1, event1)
                if os.path.exists(confpath):
                    if os.path.islink(confpath):
                        os.remove(confpath)
                    else:
                        shutil.move(confpath, disabledir)
                        type2 = 'move'
                        start2 = confpath
                        end2 = re.sub('mods-enabled', 'mods-available', confpath)
                        eid2 = eventid1
                        event2 = {'eventtype': type2,
                                  'startstate': start2,
                                  'endstate': end2,
                                  'myfile': confpath}
                        self.statechglogger.recordchgevent(eid2, event2)
        else:
            # Note to devs. This function calls the configtest function of the
            # apache server to check the config file for correctness. Because of
            # this we copy the config, then work on the live file. Then we do a
            # series of file swaps to put things in the right spots for the call
            # to the statechglogger.recordfilechange() function, before putting
            # things back where they're supposed to go. The gymnastics has to do
            # with the fact that the recordfilechange() and revertfilechange()
            # use the patch utility so file names are important.
            shutil.copyfile(conffile, tempfile)
            rhandle = open(conffile, 'r+')
            localconf = rhandle.read()
            rhandle.close()
            undoconf = localconf
            modconf = ''
            for module in self.modules:
                self.logdispatch.log(LogPriority.DEBUG,
                                ['SecureApacheWebserver.__fixapachemodules',
                                 'Processing module ' + module])
                line = 'LoadModule ' + module
                # this matches the newline and any space + the line
                pattern = '\n[\s]*' + line + '|^[\s]*' + line
                newline = '\n# ' + line
                modconf, numsubs = re.subn(pattern, newline, localconf)
                self.logdispatch.log(LogPriority.DEBUG,
                                ['SecureApacheWebserver.__fixapachemodules',
                                 'RE made ' + str(numsubs) + ' changes.'])
                localconf = modconf
            whandle = open(conffile, 'w')
            whandle.write(localconf)
            whandle.close()
            configtest = ''
            for path in self.binpaths:
                if os.path.exists(path):
                    configtest = path + ' -t  &> /dev/null'
                    retcode = subprocess.call(configtest, shell=True,
                                              close_fds=True)
                    if retcode != 0:
                        # Configuration failed selftest rollback the change!
                        changecomplete = False
                        localconf = undoconf
                        whandle = open(conffile, 'w')
                        whandle.write(undoconf)
                        whandle.close()
                        os.remove(tempfile)
                        self.logdispatch.log(LogPriority.INFO,
                                        ['SecureApacheWebserver.__fixapachemodules',
                                         'Conf failed test! Module changes undone.'])
            if changecomplete:
                # We actually wrote our changes into the main config file so we
                # need to flip flop the temp and primary config files
                statdata = os.stat(conffile)
                self.logdispatch.log(LogPriority.DEBUG,
                                    ['SecureApacheWebserver.__fixapachemodules',
                                     'Moving : ' + str(conffile) + ' to ' + str(tempfile2)])
                shutil.move(conffile, tempfile2)
                self.logdispatch.log(LogPriority.DEBUG,
                                    ['SecureApacheWebserver.__fixapachemodules',
                                     'Moving : ' + str(tempfile) + ' to ' + str(conffile)])
                shutil.move(tempfile, conffile)
                mytype = 'conf'
                mystart = 'notconfigured'
                myend = 'configured'
                myid = eventid1
                event = {'eventtype': mytype,
                         'startstate': mystart,
                         'endstate': myend,
                         'myfile': conffile}
                owner = statdata.st_uid
                group = statdata.st_gid
                mode = stat.S_IMODE(statdata.st_mode)
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(conffile, tempfile2, myid)
                self.logdispatch.log(LogPriority.DEBUG,
                                    ['SecureApacheWebserver.__fixapachemodules',
                                     'Renaming : ' + str(tempfile2) + ' to ' + str(conffile)])
                os.rename(tempfile2, conffile)
                if owner != 0 or group != 0 or mode != 420:
                    mytype2 = 'perm'
                    mystart2 = [owner, group, mode]
                    myend2 = [0, 0, 420]
                    myid2 = eventid2
                    event2 = {'eventtype': mytype2,
                              'startstate': mystart2,
                              'endstate': myend2,
                              'myfile': conffile}
                    self.statechglogger.recordchgevent(myid2, event2)
                os.chown(conffile, 0, 0)
                os.chmod(conffile, 420)
                resetsecon(conffile)

    def __fixsslconfig(self, sslfile, eventid1, eventid2):
        '''SecureApacheWebserver.__fixsslconfig() private method to configure
        the correct ssl config options for apache. This method takes args for
        the sslfile path, and the eventids to be passed to the
        state change logger for the edit and the permission change.
        @param string: sslfile full path to the file containing the ssl config.
        @param string: eventid1 for the file edit action.
        @param string: eventid2 for the permissions change to the file.
        '''
        if self.sslcompliant:
            return
        if os.path.exists(sslfile):
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['SecureApacheWebserver.__fixsslconfig',
                                  'Processing file ' + sslfile])
            rhandle = open(sslfile, 'r')
            localconf = rhandle.readlines()
            rhandle.close()
            ssltemp = sslfile + '.stonixtmp'
            founddict = {}.fromkeys(self.sslitems, False)
            for directive in self.sslitems:
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__fixsslconfig',
                                      'Processing directive ' + directive])
                newconf = []
                fragment = directive.split()
                option = fragment[0]
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__fixsslconfig',
                                      'Processing option ' + option])
                for line in localconf:
                    if self.comment.match(line):
                        pass
                    elif re.search(option, line) and not re.search(directive,
                                                                   line):
                        self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__fixsslconfig',
                                      'Substituting line ' + line])
                        line = directive + '\n'
                        founddict[directive] = True
                    elif re.search(directive, line):
                        founddict[directive] = True
                    newconf.append(line)
                localconf = newconf
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['SecureApacheWebserver.__fixsslconfig',
                                  'looking for missing directives.'])
            for directive in self.sslitems:
                if founddict[directive] == False:
                    self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__fixsslconfig',
                                      'Missing directive: ' + directive])
                    localconf.insert(20, directive + '\n')
            whandle = open(ssltemp, 'w')
            for line in localconf:
                whandle.write(line)
            whandle.close()
            statdata = os.stat(sslfile)
            mytype = 'conf'
            mystart = 'notconfigured'
            myend = 'configured'
            myid = eventid1
            event = {'eventtype': mytype,
                     'startstate': mystart,
                     'endstate': myend,
                     'myfile': sslfile}
            owner = statdata.st_uid
            group = statdata.st_gid
            mode = stat.S_IMODE(statdata.st_mode)
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(sslfile, ssltemp, myid)
            os.rename(ssltemp, sslfile)
            if owner != 0 or group != 0 or mode != 420:
                mytype2 = 'perm'
                mystart2 = [owner, group, mode]
                myend2 = [0, 0, 420]
                myid2 = eventid2
                event2 = {'eventtype': mytype2,
                          'startstate': mystart2,
                          'endstate': myend2,
                          'myfile': sslfile}
                self.statechglogger.recordchgevent(myid2, event2)
            os.chown(sslfile, 0, 0)
            os.chmod(sslfile, 420)
            resetsecon(sslfile)

    def __fixphpconfig(self):
        '''SecureApacheWebserver.__fixphpconfig() private method to configure
        secure PHP config options.'''
        if self.phpcompliant:
            return
        rhandle = open(self.phpfile, 'r')
        localconf = rhandle.readlines()
        rhandle.close()
        tempfile = self.phpfile + '.stonixtemp'
        founddict = {}.fromkeys(self.phpitems, False)
        for directive in self.phpitems:
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['SecureApacheWebserver.__fixphpconfig',
                                  'Processing directive ' + directive])
            newconf = []
            fragment = directive.split()
            option = fragment[0] + ' ='
            self.logdispatch.log(LogPriority.DEBUG,
                                 ['SecureApacheWebserver.__fixphpconfig',
                                  'Processing option ' + option])
            for line in localconf:
                if self.comment.match(line):
                    pass
                elif re.search(option, line) and not re.search(directive, line):
                    line = directive + '\n'
                    founddict[directive] = True
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['SecureApacheWebserver.__fixphpconfig',
                                          'Updated directive ' + line])
                elif re.search(option, line) and re.search(directive, line):
                    founddict[directive] = True
                    self.logdispatch.log(LogPriority.DEBUG,
                                         ['SecureApacheWebserver.__fixphpconfig',
                                          'Found directive ' + directive])
                newconf.append(line)
            localconf = newconf
        self.logdispatch.log(LogPriority.DEBUG,
                             ['SecureApacheWebserver.__fixphpconfig',
                              'state of founddict ' + str(founddict)])
        for directive in self.phpitems:
            if founddict[directive] == False:
                self.logdispatch.log(LogPriority.DEBUG,
                                     ['SecureApacheWebserver.__fixphpconfig',
                                      'adding directive ' + directive])
                localconf.insert(20, directive + '\n')
        whandle = open(tempfile, 'w')
        for line in localconf:
            whandle.write(line)
        whandle.close()
        statdata = os.stat(self.phpfile)
        mytype = 'conf'
        mystart = 'notconfigured'
        myend = 'configured'
        myid = '0136001'
        event = {'eventtype': mytype,
                 'startstate': mystart,
                 'endstate': myend}
        owner = statdata.st_uid
        group = statdata.st_gid
        mode = stat.S_IMODE(statdata.st_mode)
        self.statechglogger.recordchgevent(myid, event)
        self.statechglogger.recordfilechange(self.phpfile, tempfile, myid)
        os.rename(tempfile, self.phpfile)
        if owner != 0 or group != 0 or mode != 420:
            mytype2 = 'perm'
            mystart2 = [owner, group, mode]
            myend2 = [0, 0, 420]
            myid2 = '0136002'
            event2 = {'eventtype': mytype2,
                      'startstate': mystart2,
                      'endstate': myend2}
            self.statechglogger.recordchgevent(myid2, event2)
        os.chown(self.phpfile, 0, 0)
        os.chmod(self.phpfile, 420)
        resetsecon(self.phpfile)

    def fix(self):
        '''SecureApacheWebserver.fix() Public method to fix the apache
        configuration elements.
        '''
        try:
            self.detailedresults = ""
            prevchgs = self.statechglogger.findrulechanges(self.rulenumber)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = 'SecureApacheWebserver.fix: '
            self.detailedresults = self.detailedresults + \
            traceback.format_exc()
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        myidbase = 100
        if self.secureapache.getcurrvalue() and not self.httpcompliant:
            rangebase = str(self.rulenumber).zfill(4) + '1'
            self.logdispatch.log(LogPriority.DEBUG,
                                 'Deleting change events from ' + rangebase)
            try:
                for change in prevchgs:
                    if change[:5] == rangebase:
                        self.statechglogger.deleteentry(change)
                        self.logdispatch.log(LogPriority.DEBUG,
                                             'Deleting change event ' + change)
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.detailedresults = 'SecureApacheWebserver.fix: '
                self.detailedresults = self.detailedresults + \
                traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
            for apacheconf in self.conffiles:
                myidbase = myidbase + 1
                changeid = self.makeEventId(myidbase)
                myidbase = myidbase + 1
                permid = self.makeEventId(myidbase)
                try:
                    self.__fixapacheglobals(apacheconf, changeid, permid)
                except (KeyboardInterrupt, SystemExit):
                    # User initiated exit
                    raise
                except Exception:
                    self.detailedresults = 'SecureApacheWebserver.fix: '
                    self.detailedresults = self.detailedresults + \
                    traceback.format_exc()
                    self.rulesuccess = False
                    self.logdispatch.log(LogPriority.ERROR,
                                         self.detailedresults)

        myidbase = 200
        if self.domodules.getcurrvalue() and not self.modulescompliant:
            rangebase = str(self.rulenumber).zfill(4) + '2'
            self.logdispatch.log(LogPriority.DEBUG,
                                 'Deleting change events from ' + rangebase)
            try:
                for change in prevchgs:
                    if change[:5] == rangebase:
                        self.statechglogger.deleteentry(change)
                        self.logdispatch.log(LogPriority.DEBUG,
                                             'Deleting change event ' + \
                                             change)
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.detailedresults = 'SecureApacheWebserver.fix: '
                self.detailedresults = self.detailedresults + \
                traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
            modulesd = '/etc/httpd/conf.modules.d'
            enabled = '/etc/apache2/mods-enabled'
            filesToCheck = []

            if os.path.exists(modulesd) or os.path.exists(enabled):
                if os.path.exists(modulesd):
                    modulesdirpath = modulesd
                elif os.path.exists(enabled):
                    modulesdirpath = enabled
# TODO need control statement here to switch for moving files on ubuntu
                for filename in os.listdir(modulesdirpath):
                    filepath = os.path.join(modulesdirpath, filename)
                    filesToCheck.append(filepath)
            for filename in self.conffiles:
                if os.path.exists(filename):
                    filesToCheck.append(filename)
# TODO need control statement here to switch for moving files on ubuntu
            for apacheconf in filesToCheck:
                # Although paths were checked before, it is possible for a file
                # to be removed in its partner's self.__fixapachemodules call
                if not os.path.exists(apacheconf):
                    continue
                myidbase = myidbase + 1
                changeid = self.makeEventId(myidbase)
                myidbase = myidbase + 1
                permid = self.makeEventId(myidbase)
                try:
                    self.__fixapachemodules(apacheconf, changeid, permid)
                except (KeyboardInterrupt, SystemExit):
                    # User initiated exit
                    raise
                except Exception:
                    self.detailedresults = 'SecureApacheWebserver.fix: '
                    self.detailedresults = self.detailedresults + \
                    traceback.format_exc()
                    self.rulesuccess = False
                    self.logdispatch.log(LogPriority.ERROR,
                                         self.detailedresults)

        myidbase = 300
        if self.dossl.getcurrvalue() and not self.sslcompliant:
            rangebase = str(self.rulenumber).zfill(4) + '3'
            self.logdispatch.log(LogPriority.DEBUG,
                                 'Deleting change events from ' + rangebase)
            try:
                for change in prevchgs:
                    if change[:5] == rangebase:
                        self.statechglogger.deleteentry(change)
                        self.logdispatch.log(LogPriority.DEBUG,
                                             'Deleting change event ' + change)
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.detailedresults = 'SecureApacheWebserver.fix: '
                self.detailedresults = self.detailedresults + \
                traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
            for sslfile in self.sslfiles:
                myidbase = myidbase + 1
                changeid = self.makeEventId(myidbase)
                myidbase = myidbase + 1
                permid = self.makeEventId(myidbase)
                try:
                    self.__fixsslconfig(sslfile, changeid, permid)
                except (KeyboardInterrupt, SystemExit):
                    # User initiated exit
                    raise
                except Exception:
                    self.detailedresults = 'SecureApacheWebserver.fix: '
                    self.detailedresults = self.detailedresults + \
                    traceback.format_exc()
                    self.rulesuccess = False
                    self.logdispatch.log(LogPriority.ERROR,
                                         self.detailedresults)
        if self.dophp.getcurrvalue():
            try:
                self.__fixphpconfig()
            except (KeyboardInterrupt, SystemExit):
                # user initiated exit
                raise
            except Exception:
                self.detailedresults = 'SecureApacheWebserver.fix: '
                self.detailedresults = self.detailedresults + \
                traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)

    def undo(self):
        '''
        SecureApacheWebserver.undo()
        Undo method for reverting changes to the apache webserver.
        '''
        try:
            eventphp = self.statechglogger.getchgevent('0136001')
            if eventphp['startstate'] != eventphp['endstate']:
                self.statechglogger.revertfilechanges(self.phpfile,
                                                      '0136001')
        except(IndexError, KeyError):
            self.logdispatch.log(LogPriority.DEBUG,
                        ['SecureApacheWebserver.undo', "EventID 0136001 not found"])
        try:
            eventphpm = self.statechglogger.getchgevent('0136002')
            if eventphpm['startstate'] != eventphpm['endstate']:
                uid = eventphpm['startstate'][0]
                gid = eventphpm['startstate'][1]
                mode = eventphpm['startstate'][2]
                if os.path.exists(self.phpfile):
                    os.chown(self.phpfile, uid, gid)
                    os.chmod(self.phpfile, mode)
                    resetsecon(self.phpfile)
        except(IndexError, KeyError):
            self.logdispatch.log(LogPriority.DEBUG,
                        ['SecureApacheWebserver.undo', "EventID 0136002 not found"])
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = traceback.format_exc()
            self.rulesuccess = False
            self.logdispatch.log(LogPriority.ERROR,
                        ['SecureApacheWebserver.undo', self.detailedresults])
        myidbase = 100
        counter = 1
        miss = 0
        while counter < 300:
            try:
                myidbase = myidbase + 1
                counter = counter + 1
                eventid = self.makeEventId(myidbase)
                event = self.statechglogger.getchgevent(eventid)
                if event['eventtype'] == 'conf':
                    if event['startstate'] != event['endstate']:
                        conffile = event['myfile']
                        self.statechglogger.revertfilechanges(conffile,
                                                      eventid)
                if event['eventtype'] == 'move':
                    if event['startstate'] != event['endstate']:
                        shutil.move(event['endstate'], event['startstate'])
                if event['eventtype'] == 'perm':
                    if event['startstate'] != event['endstate']:
                        uid = event['startstate'][0]
                        gid = event['startstate'][1]
                        mode = event['startstate'][2]
                        conffile = event['myfile']
                        if os.path.exists(conffile):
                            os.chown(conffile, uid, gid)
                            os.chmod(conffile, mode)
                            resetsecon(conffile)
                if miss > 4 and myidbase < 200:
                    myidbase = 200
                if miss > 8 and myidbase < 300:
                    myidbase = 300
                if miss > 12 and myidbase > 300:
                    break

            except(IndexError, KeyError):
                self.logdispatch.log(LogPriority.DEBUG,
                                ['SecureApacheWebserver.undo',
                                 "EventID " + eventid + " not found"])
                miss = miss + 1
            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.detailedresults = traceback.format_exc()
                self.rulesuccess = False
                self.logdispatch.log(LogPriority.ERROR,
                                ['SecureApacheWebserver.undo', self.detailedresults])
        self.detailedresults = 'The Secure Apache Webserver rule has been undone.'
        self.currstate = 'notconfigured'

    def makeEventId(self, iditerator):
        '''Method to create event ID numbers for use with the state change
        logger. Modified from D.Walkers original for use by this rule.

        @author: dkennel
        @return: string'''
        if iditerator < 10:
            idbase = '013600'
            myid = idbase + str(iditerator)
        elif iditerator >= 10 and iditerator < 100:
            idbase = '01360'
            myid = idbase + str(iditerator)
        elif iditerator >= 100 and iditerator < 1000:
            idbase = '0136'
            myid = idbase + str(iditerator)
        else:
            raise ValueError('makeEventId: iditerator value too large.')
        return myid
