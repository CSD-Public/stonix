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
Created on Nov 5, 2012
The File Permissions rule audits and folders on the system to check for world
writable files, world writable folders, SUID/SGID programs and files without
known owners. It also ensures that the sticky-bit is set on world writable
directories.

@author: dkennel
@change: 2014/06/13 dkennel: Added skiplist to prevent scanning of large file
systems. Added code to remove world write from files in the root users path.
@change: 2014/10/31 ekkehard fixed isApplicable
@change: 2015/04/13 dkennel changed to use new isApplicable method in template
rule class
@change: 2015/08/28 eball - Updated suidlist
@change: 2015/10/07 eball Help text/PEP8 cleanup
@change: 2016/04/21 eball Added checks and fixes for group writable and non-
    root owned files in lib and bin paths.
@change: 2016/04/29 eball wwreport now checks ww dirs to make sure they are
    owned by a system account, per RHEL 7 STIG
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/08/28 rsn Fixing to use new help text methods
'''
from __future__ import absolute_import
import os
import traceback
import subprocess
import random
import shutil
import stat
import re
import pwd
import grp

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..localize import SITELOCALWWWDIRS
from ..stonixutilityfunctions import getlocalfs


class FilePermissions(Rule):
    '''
    This class audits world
    writable files, world writable folders, SUID/SGID programs and files
    without known owners. Where world writable folders are detected it will
    (in fix mode) attempt to set the sticky bit if it is not presently set and
    will remove the world write bit from files in the root users path.
    Otherwise this class is an audit only rule.

    @author: dkennel
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 25
        self.rulename = 'FilePermissions'
        self.mandatory = True
        self.formatDetailedResults("initialize")
        self.guidance = ['NSA 2.2.3.3', 'CCE-3795-2', 'CCE-4351-3',
                         'NSA 2.2.3.2', 'CCE-3399-3', 'NSA 2.2.3.4',
                         'CCE-4178-0', 'CCE-3324-1', 'CCE-4743-1',
                         'CCE-4281-2', 'NSA 2.2.3.5', 'CCE-4223-4',
                         'CCE-3573-3', 'CCE-26966-2 2.2.3.2.1',
                         'CCE-26966-2 2.2.3.2.2', 'CCE-26966-2 2.2.3.2.3',
                         'CCE-26966-2 2.2.3.2.4', "CCE-RHEL7-CCE-TBD 2.2.3.8",
                         "CCE-RHEL7-CCE-TBD 2.2.3.9"]
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}
        # The vars below are local to this rule and are not overrides of the
        # base class
        self.infodir = '/var/local/info'
        self.wwdir = os.path.join(self.infodir, 'worldwritable')
        self.suiddir = os.path.join(self.infodir, 'suidfiles')
        self.noownerdir = os.path.join(self.infodir, 'no-owners')
        for dbdir in [self.wwdir, self.suiddir, self.noownerdir]:
            if not os.path.exists(dbdir) and self.environ.geteuid() == 0:
                os.makedirs(dbdir, 448)
        self.wwdbfile = os.path.join(self.wwdir, 'wwfiles.db')
        self.wworigin = os.path.join(self.wwdir, 'wwfiles-at-install.db')
        self.wwlast = os.path.join(self.wwdir, 'wwfiles-previous.db')
        self.suiddbfile = os.path.join(self.suiddir, 'suidfiles.db')
        self.suidorigin = os.path.join(self.suiddir, 'suidfiles-at-install.db')
        self.suidlast = os.path.join(self.suiddir, 'suidfiles-previous.db')
        self.nodbfile = os.path.join(self.noownerdir, 'no-owners.db')
        self.noorigin = os.path.join(self.noownerdir,
                                     'no-owners-at-install.db')
        self.nolast = os.path.join(self.noownerdir, 'no-owners-previous.db')
        datatype = 'bool'
        key = 'setsticky'
        instructions = '''If set to yes or true the WorldWritables rule will \
attempt to set the sticky bit on any world writable directories the do not \
currently have the sticky bit set. SETSTICKY cannot be undone.'''
        default = True
        self.setsticky = self.initCi(datatype, key, instructions, default)
        datat = 'list'
        keyname = 'bypassfs'
        instr = '''Because this rule performs a full file system scan you may \
not want it to scan very large directly attached file systems (especially file \
systems on USB media). Any file systems listed in a space separated list after \
the BYPASSFS variable will not be scanned. N.B. This list does not handle \
file system names with spaces.'''
        defval = ['/run/media', '/media']
        self.bypassfs = self.initCi(datat, keyname, instr, defval)
        ww_datatype = 'bool'
        ww_key = 'fixww'
        ww_instructions = '''To prevent the FilePermissions rule from removing \
the world write permissions of files in the root user's path, set the value of \
FIXWW to False. You should not need to do this; World Writable files in the \
root user's path are very dangerous.'''
        ww_default = True
        self.fixww = self.initCi(ww_datatype, ww_key, ww_instructions,
                                 ww_default)
        datatype = 'bool'
        key = 'fixgw'
        instructions = '''To prevent the FilePermissions rule from removing \
the group write permissions of files in the lib and bin directories, set the \
value of FIXGW to False. The affected directories are: /bin, /usr/bin, \
/usr/local/bin, /sbin, /usr/sbin, /usr/local/sbin, /lib, /lib64, /usr/lib, \
/usr/lib64, /lib/modules.'''
        default = True
        self.fixgw = self.initCi(datatype, key, instructions, default)
        datatype = 'bool'
        key = 'fixrootownership'
        instructions = '''To prevent the FilePermissions rule from setting \
ownership on all files in the lib and bin directories to root, set the \
value of FIXROOTOWNERSHIP to False. The affected directories are: /bin, \
/usr/bin, /usr/local/bin, /sbin, /usr/sbin, /usr/local/sbin, /lib, /lib64, \
/usr/lib, /usr/lib64, /lib/modules.'''
        default = True
        self.fixroot = self.initCi(datatype, key, instructions, default)
        self.hasrunalready = False
        self.wwresults = ''
        self.gwresults = ''
        self.suidresults = ''
        self.unownedresults = ''
        self.firstrun = False
        self.findoverrun = False
        self.gwfiles = []
        self.nrofiles = []
        random.seed()
        self.sethelptext()

    def processconfig(self):
        """
        This is primarily a private method but may be called if the
        configuration has changed after the rules have been instantiated. This
        method will cause the rule to process its entries from the
        configuration file object and instantiate its dependent
        configuration item objects. Instantiated configuration items will be
        added to the self.confitems property.

        @return void :
        @author dkennel
        """
        pass

    def getfilesystems(self):
        '''
        This method, intended for private internal use only, gets all of the
        local filesystems and returns them as a list.

        @return: list of filesystems
        @author: dkennel
        '''
        try:
            fslist = getlocalfs(self.logger, self.environ)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

        except Exception:
            self.detailedresults = traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            ['WorldWritables.getfilesystems',
                             self.detailedresults])
        return fslist

    def multifind(self):
        '''
        Private method that runs the find command on the file system to create
        lists of world writable, suid/sgid, and unowned files. The invocation
        of the find shell command is a bit complex to do all of this in one
        shot.

        @author: dkennel
        '''

        try:
            dbsets = {'ww':
                      {'last': self.wwlast,
                       'db': self.wwdbfile,
                       'orig': self.wworigin,
                       'results': []},
                      'suid':
                      {'last': self.suidlast,
                       'db': self.suiddbfile,
                       'orig': self.suidorigin,
                       'results': []},
                      'unowned':
                      {'last': self.nolast,
                       'db': self.nodbfile,
                       'orig': self.noorigin,
                       'results': []}
                      }
            for dbset in dbsets:
                if os.path.exists(dbsets[dbset]['last']):
                    os.remove(dbsets[dbset]['last'])
                else:
                    self.firstrun = True
                    self.logger.log(LogPriority.DEBUG,
                                    ['FilePermissions.multifind',
                                     'No last run files detected, setting ' +
                                     'first run to true'])
                if os.path.exists(dbsets[dbset]['db']):
                    os.rename(dbsets[dbset]['db'], dbsets[dbset]['last'])

            fslist = self.getfilesystems()
            for filesystem in fslist:
                if filesystem in self.bypassfs.getcurrvalue():
                    self.logger.log(LogPriority.DEBUG,
                                    ['FilePermissions.multifind',
                                     'Skipping Filesystem: ' +
                                     str(filesystem)])
                    continue
                self.logger.log(LogPriority.DEBUG,
                                ['FilePermissions.multifind',
                                 'Walking Filesystem: ' + str(filesystem)])
                if self.findoverrun:
                        break
                for root, dirs, files in os.walk(filesystem):
                    # check the number of hits we have if we've got 30,000
                    # hits then this FS is so bad we don't want to continue
                    try:
                        if len(dbsets['ww']['results']) > 25000:
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'WW overflow!'])
                            self.findoverrun = True
                    except TypeError:
                        pass
                    try:
                        if len(dbsets['suid']['results']) > 25000:
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'SUID overflow!'])
                            self.findoverrun = True
                    except TypeError:
                        pass
                    try:
                        if len(dbsets['unowned']['results']) > 25000:
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'Unowned overflow!'])
                            self.findoverrun = True
                    except TypeError:
                        pass

                    if self.findoverrun:
                        break

                    # This wacky looking snippet filters out directories that
                    # are actually file system mount points
                    dirs[:] = [dirname for dirname in dirs if not
                               os.path.ismount(os.path.join(root, dirname))]
                    for dirname in dirs:
                        path = os.path.join(root, dirname)
                        try:
                            mode = os.stat(path)
                        except OSError:
                            continue
                        worldwrite = mode.st_mode & stat.S_IWOTH
                        # sticky = mode.st_mode & stat.S_ISVTX
                        if worldwrite:
                            dbsets['ww']['results'].append(path)
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'Found WW Dir: ' + str(path)])
                    for name in files:
                        try:
                            if len(dbsets['ww']['results']) > 25000:
                                self.logger.log(LogPriority.DEBUG,
                                                ['FilePermissions.multifind',
                                                 'WW overflow!'])
                                self.findoverrun = True
                        except TypeError:
                            pass
                        try:
                            if len(dbsets['suid']['results']) > 25000:
                                self.logger.log(LogPriority.DEBUG,
                                                ['FilePermissions.multifind',
                                                 'SUID overflow!'])
                                self.findoverrun = True
                        except TypeError:
                            pass
                        try:
                            if len(dbsets['unowned']['results']) > 25000:
                                self.logger.log(LogPriority.DEBUG,
                                                ['FilePermissions.multifind',
                                                 'Unowned overflow!'])
                                self.findoverrun = True
                        except TypeError:
                            pass

                        if self.findoverrun:
                            break

                        fpath = os.path.join(root, name)
                        if os.path.islink(fpath):
                            continue
                        try:
                            fmode = os.stat(fpath)
                        except OSError:
                            continue
                        worldwrite = fmode.st_mode & stat.S_IWOTH
                        if worldwrite:
                            dbsets['ww']['results'].append(fpath)
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'Found WW File: ' + str(fpath)])
                        suid = fmode.st_mode & stat.S_ISUID
                        sgid = fmode.st_mode & stat.S_ISGID
                        if suid or sgid:
                            dbsets['suid']['results'].append(fpath)
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'Found SUID File: ' + str(fpath)])
                        try:
                            pwd.getpwuid(fmode.st_uid)[0]
                        except KeyError:
                            dbsets['unowned']['results'].append(fpath)
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'Found unowned File: ' +
                                             str(fpath)])
                        try:
                            grp.getgrgid(fmode.st_gid)[0]
                        except KeyError:
                            dbsets['unowned']['results'].append(fpath)
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.multifind',
                                             'Found unowned File, bad group: '
                                             + str(fpath)])
            for myset in dbsets:
                data = '\n'.join(dbsets[myset]['results'])
                whandle = open(dbsets[myset]['db'], 'w')
                whandle.write(data)
                whandle.close()
                if not os.path.exists(dbsets[myset]['orig']):
                    shutil.copy(dbsets[myset]['db'], dbsets[myset]['orig'])

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

        except:
            self.detailedresults = traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            [self.rulename + '.multifind',
                             self.detailedresults])
            raise

    def wwreport(self):
        '''Public method to report on installed WorldWritable files.
        @author: dkennel
        '''
        # workflow is as follows
        # move previous run to wwlast
        # create new db.
        # if origin file doesn't exist create it.
        # compare current run to last and origin.
        # compare current run to package db or list of typical ww files
        compliant = False
        wwlist = ['/tmp', '/tmp/.ICE-unix', '/tmp/at-spi2', '/tmp/.Test-unix',
                  '/tmp/.font-unix', '/tmp/.X11-unix', '/tmp/.XIM-unix',
                  '/var/tmp', '/tmp/at-spi2', '/var/crash',
                  '/var/tmp/vi.recover', '/var/cache/fonts', '/var/spool/mail',
                  '/var/adm/spellhist', '/var/mail', '/var/preserve',
                  '/var/spool/pkg', '/var/spool/samba',
                  '/var/spool/uucppublic', '/var/webconsole/tmp',
                  '/var/krb5/rcache', '/var/dt/dtpower/schemes',
                  '/var/dt/dtpower/_current_scheme', '/var/dt/tmp',
                  '/var/lib/puppet/run', '/var/imq/instances',
                  '/usr/oasys/tmp/TERRLOG',
                  '/var/run/kdm', '/var/run/gdm', '/private/tmp',
                  '/private/var/tmp', '/Library/Caches']
        for pathelement in SITELOCALWWWDIRS:
            wwlist.append(pathelement)
        try:
            lastrun = open(self.wwdbfile, 'r').readlines()
        except(IOError):
            lastrun = []
        self.logger.log(LogPriority.DEBUG,
                        ['WorldWritables.report',
                         'lastrun: ' + str(lastrun)])
        prevrun = []
        if os.path.exists(self.wwlast):
            prevrun = open(self.wwlast, 'r').readlines()
        firstrun = []
        if os.path.exists(self.wworigin):
            firstrun = open(self.wworigin, 'r').readlines()
        newfilessincelast = []
        newfilessinceorigin = []
        notsticky = []
        notsysowned = []
        notknown = []
        # Important! lines coming from the files will have newlines unless
        # they are stripped.
        for wwfile in lastrun:
            wwpath = wwfile.strip()
            if wwfile not in prevrun:
                newfilessincelast.append(wwpath)
            if wwfile not in firstrun:
                newfilessinceorigin.append(wwpath)
            try:
                mode = os.stat(wwpath)[stat.ST_MODE]
                owner = os.stat(wwpath)[stat.ST_UID]
                if os.path.isdir(wwpath):
                    if not bool(mode & stat.S_ISVTX):
                        notsticky.append(wwpath)
                    if owner > 999:
                        notsysowned.append(wwpath)
                if wwpath not in wwlist:
                    notknown.append(wwpath)
            except OSError:
                continue
        if len(newfilessincelast) > 15:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'New since last: Too many files details ' +
                             'suppressed, review file at /var/local/info. ' +
                             'New: ' + str(len(newfilessincelast))])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'New since last: ' + str(newfilessincelast)])
        if len(newfilessinceorigin) > 15:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'New since first: Too many files details ' +
                             'suppressed, review file at /var/local/info. ' +
                             'New: ' + str(len(newfilessinceorigin))])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'New since first: '
                             + str(newfilessinceorigin)])
        if len(notsticky) > 15:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'Not Sticky: Too many files details suppressed, '
                             + 'review file at /var/local/info. New: ' +
                             str(len(notsticky))])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'Not Sticky: ' + str(notsticky)])
        if len(notsysowned) > 15:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'Not system account owned: Too many files ' +
                             'details suppressed, review file at ' +
                             '/var/local/info. New: ' + str(len(notsysowned))])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'Not system account owned: ' + str(notsysowned)])
        if len(notknown) > 15:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'Not Known: Too many files details suppressed, ' +
                             'review file at /var/local/info. New: ' +
                             str(len(notknown))])
        else:
            self.logger.log(LogPriority.DEBUG,
                            ['WorldWritables.report',
                             'Not Known: ' + str(notknown)])
        strnewsincefirst = ''
        if len(newfilessinceorigin) > 15:
            strnewsincefirst = str(len(newfilessinceorigin))
        else:
            for entry in newfilessinceorigin:
                strnewsincefirst = strnewsincefirst + entry + ' '
            strnewsincefirst = strnewsincefirst.strip()
        self.logger.log(LogPriority.INFO,
                        ['WorldWritables.report',
                         'New World Writable Files since install: '
                         + strnewsincefirst])
        strnotsticky = ''
        if len(notsticky) > 15:
            strnotsticky = str(len(notsticky))
        else:
            for entry in notsticky:
                strnotsticky = strnotsticky + entry + ' '
            strnotsticky = strnotsticky.strip()
        self.logger.log(LogPriority.INFO,
                        ['WorldWritables.report',
                         'World Writable directories without sticky bit: '
                         + strnotsticky])
        strnotsysowned = ''
        if len(notsysowned) > 15:
            strnotsysowned = str(len(notsysowned))
        else:
            for entry in notsysowned:
                strnotsysowned = strnotsysowned + entry + ' '
            strnotsysowned = strnotsysowned.strip()
        self.logger.log(LogPriority.INFO,
                        ['WorldWritables.report',
                         'World Writable directories not owned by a system ' +
                         'account: ' + strnotsysowned])
        strnotknown = ''
        if len(notknown) > 15:
            strnotknown = str(len(notknown))
        else:
            for entry in notknown:
                strnotknown = strnotknown + entry + ' '
            strnotknown = strnotknown.strip()
        self.logger.log(LogPriority.INFO,
                        ['WorldWritables.report',
                         'World Writable files not known to STONIX: '
                         + strnotknown])
        strnewsincelast = ''
        if len(newfilessincelast) > 15:
            strnewsincelast = str(len(newfilessincelast))
        else:
            for entry in newfilessincelast:
                strnewsincelast = strnewsincelast + entry + ' '
            strnewsincelast = strnewsincelast.strip()
        self.logger.log(LogPriority.INFO,
                        ['WorldWritables.report',
                         'New World Writable Files since last run: '
                         + strnewsincelast])
        if len(newfilessincelast) > 0:
            compliant = False
            self.wwresults = 'New World Writable Files since last run: ' + \
                strnewsincelast
            self.wwresults = self.wwresults + ' '
            self.wwresults = self.wwresults + '\nWorld Writable directories ' + \
                'without sticky bit: ' + strnotsticky
            self.wwresults = self.wwresults + ' '
            self.wwresults = self.wwresults + '\nWorld Writable directories ' + \
                'not owned by system account: ' + strnotsysowned
            self.wwresults = self.wwresults + ' '
            self.wwresults = self.wwresults + '\nWorld Writable files not ' + \
                'known to STONIX: ' + strnotknown
            self.wwresults = self.wwresults + ' '
            self.wwresults = self.wwresults + '\nNew World Writable Files ' + \
                'since install: ' + strnewsincefirst
            if self.findoverrun:
                self.wwresults = self.wwresults + '''
WARNING! Large numbers of files with incorrect permissions detected. Please \
conduct a manual check for world writable files and folders and correct \
permissions as needed.

To find world writable directories, run the following command as root:
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
To find world writable files:
find / -xdev -type f \( -perm -0002 -a ! -perm -1000 \) -print'''
        elif self.findoverrun:
            self.wwresults = '''
WARNING! Large numbers of files with incorrect permissions detected. Please \
conduct a manual check for world writable files and folders and correct \
permissions as needed.

To find world writable directories, run the following command as root:
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
To find world writable files:
find / -xdev -type f \( -perm -0002 -a ! -perm -1000 \) -print'''
        else:
            compliant = True
            self.wwresults = 'No new World Writable files since last run.'
        return compliant

    def gwreport(self):
        '''Public method to report on group-writable and non-root owned files
        in lib and bin directories.
        @author: eball
        '''
        compliant = False
        locationList = ["/lib", "/lib64", "/usr/lib", "/usr/lib64",
                        "/lib/modules", "/bin", "/usr/bin", "/usr/local/bin",
                        "/sbin", "/usr/sbin", "/usr/local/sbin"]
        gwfiles = []
        nrofiles = []

        for loc in locationList:
            if os.path.islink(loc):
                continue
            for root, dirs, files in os.walk(loc):
                for dirname in dirs:
                    path = os.path.join(root, dirname)
#                     if os.path.islink(path):
#                         continue
                    try:
                        mode = os.stat(path)
                    except OSError:
                        continue
                    groupwrite = mode.st_mode & stat.S_IWGRP
                    if groupwrite:
                        gwfiles.append(path)
                    if mode.st_uid != 0:
                        nrofiles.append(path)
                for name in files:
                    fpath = os.path.join(root, name)
                    if os.path.islink(fpath):
                        continue
                    try:
                        fmode = os.stat(fpath)
                    except OSError:
                        continue
                    groupwrite = fmode.st_mode & stat.S_IWGRP
                    if groupwrite:
                        gwfiles.append(fpath)
                    if fmode.st_uid != 0:
                        if self.environ.getosfamily == 'darwin':
                            macuucpfiles = ['/usr/lib/cron', '/usr/bin/cu',
                                            '/usr/bin/uucp', '/usr/bin/uuname',
                                            '/usr/bin/uustat', '/usr/bin/uux',
                                            '/usr/sbin/uucico',
                                            '/usr/sbin/uuxqt']
                            if fpath in macuucpfiles:
                                continue
                            else:
                                nrofiles.append(fpath)
                        else:
                            nrofiles.append(fpath)

        self.logger.log(LogPriority.DEBUG,
                        ['GroupWritable.report',
                         'Group Writable files found: '
                         + str(gwfiles)])
        self.logger.log(LogPriority.DEBUG,
                        ['GroupWritable.report',
                         'Non-root owned files found: '
                         + str(nrofiles)])

        self.gwfiles = gwfiles
        self.nrofiles = nrofiles

        if not gwfiles and not nrofiles:
            compliant = True
            self.gwresults = "No group writable files found in lib and " + \
                "bin paths.\n"
            self.gwresults += "No non-root owned files found in lib " + \
                "and bin paths.\n"
        else:
            gwFileLen = len(gwfiles)
            if gwFileLen > 0 and gwFileLen <= 15:
                self.gwresults = "Group writable files from lib and bin " + \
                    "paths: " + " ".join(gwfiles) + "\n"
            elif gwFileLen > 15:
                self.gwresults = "Group writable files from lib and bin " + \
                    "paths: " + str(gwFileLen) + "\n"
            else:
                self.gwresults = "No group writable files found in lib and " + \
                    "bin paths.\n"
            nroFileLen = len(nrofiles)
            if nroFileLen > 0 and nroFileLen <= 15:
                self.gwresults += "Non-root owned files from lib and bin " + \
                    "paths: " + " ".join(nrofiles) + "\n"
            elif nroFileLen > 15:
                self.gwresults += "Non-root owned files from lib and bin " + \
                    "paths: " + str(nroFileLen) + "\n"
            else:
                self.gwresults += "No non-root owned files found in lib " + \
                    "and bin paths.\n"

        return compliant

    def suidreport(self):
        '''Private method to report on installed SUID/SGID files.
        @author: dkennel
        '''
        # workflow is as follows
        # compare current run to last and origin.
        # compare current run to package db or list of typical suid files
        suidlist = ['/bin/mount',
                    '/bin/ping',
                    '/bin/ping6',
                    '/bin/su',
                    '/bin/umount',
                    '/sbin/mount.nfs',
                    '/sbin/mount.nfs4',
                    '/sbin/netreport',
                    '/sbin/pam timestamp check',
                    '/sbin/umount.nfs',
                    '/sbin/umount.nfs4',
                    '/sbin/unix chkpwd',
                    '/usr/bin/at',
                    '/usr/bin/chage',
                    '/usr/bin/chfn',
                    '/usr/bin/chsh',
                    '/usr/bin/crontab',
                    '/usr/bin/gpasswd',
                    '/usr/bin/locate',
                    '/usr/bin/lockfile',
                    '/usr/bin/newgrp',
                    '/usr/bin/passwd',
                    '/usr/bin/rcp',
                    '/usr/bin/rlogin',
                    '/usr/bin/rsh',
                    '/usr/bin/ssh-agent',
                    '/usr/bin/sudo',
                    '/usr/bin/sudoedit',
                    '/usr/bin/wall',
                    '/usr/bin/write',
                    '/usr/bin/Xorg',
                    '/usr/kerberos/bin/ksu',
                    '/usr/libexec/openssh/ssh-keysign',
                    '/usr/libexec/utempter/utempter',
                    '/usr/lib/squid/pam auth',
                    '/usr/lib/squid/ncsa auth',
                    '/usr/lib/vte/gnome-pty-helper',
                    '/usr/sbin/ccreds validate',
                    '/usr/sbin/lockdev',
                    '/usr/sbin/sendmail.sendmail',
                    '/usr/sbin/suexec',
                    '/usr/sbin/userhelper',
                    '/usr/sbin/userisdnctl',
                    '/usr/sbin/usernetctl',
                    '/usr/bin/sparcv9/newtask',
                    '/usr/bin/sparcv9/uptime',
                    '/usr/bin/sparcv9/w',
                    '/usr/bin/atq',
                    '/usr/bin/atrm',
                    '/usr/bin/eject',
                    '/usr/bin/fdformat',
                    '/usr/bin/login',
                    '/usr/bin/newgrp',
                    '/usr/bin/pfexec',
                    '/usr/bin/su',
                    '/usr/bin/tip',
                    '/usr/bin/ct',
                    '/usr/bin/cu',
                    '/usr/bin/uucp',
                    '/usr/bin/uuglist',
                    '/usr/bin/uuname',
                    '/usr/bin/uustat',
                    '/usr/bin/uux',
                    '/usr/bin/rdist',
                    '/usr/bin/chkey',
                    '/usr/bin/lpset',
                    '/usr/bin/pppd',
                    '/usr/bin/tsoljdslabel',
                    '/usr/bin/rmformat',
                    '/usr/bin/volrmmount',
                    '/usr/bin/mailq',
                    '/usr/bin/stclient',
                    '/usr/bin/cdrw',
                    '/usr/lib/fs/ufs/quota',
                    '/usr/lib/fs/ufs/ufsdump',
                    '/usr/lib/fs/ufs/ufsrestore',
                    '/usr/lib/pt_chmod',
                    '/usr/lib/utmp_update',
                    '/usr/lib/uucp/remote.unknown',
                    '/usr/lib/uucp/uucico',
                    '/usr/lib/uucp/uusched',
                    '/usr/lib/uucp/uuxqt',
                    '/usr/lib/webconsole/pamverifier',
                    '/usr/lib/print/lpd-port',
                    '/usr/lib/cacao/lib/tools/cacaocsc',
                    '/usr/lib/lp/bin/netpr',
                    '/usr/lib/fbconfig/SUNWnfb_config',
                    '/usr/lib/fbconfig/SUNWifb_config',
                    '/usr/lib/fbconfig/SUNWjfb_config',
                    '/usr/lib/fbconfig/SUNWpfb_config',
                    '/usr/lib/fbconfig/libSUNWast_conf.so.1',
                    '/usr/lib/ssh/ssh-keysign',
                    '/usr/lib/gnome-suspend',
                    '/usr/lib/acct/accton',
                    '/usr/openwin/bin/xlock',
                    '/usr/openwin/bin/sys-suspend',
                    '/usr/openwin/bin/xscreensaver',
                    '/usr/sbin/sparcv9/whodo',
                    '/usr/sbin/allocate',
                    '/usr/sbin/sacadm',
                    '/usr/sbin/traceroute',
                    '/usr/sbin/deallocate',
                    '/usr/sbin/list_devices',
                    '/usr/sbin/pmconfig',
                    '/usr/sbin/ping',
                    '/usr/sbin/smpatch',
                    '/usr/sbin/m64config',
                    '/usr/xpg4/bin/at',
                    '/usr/xpg4/bin/crontab',
                    '/usr/dt/bin/dtappgather',
                    '/usr/dt/bin/dtfile',
                    '/usr/dt/bin/dtprintinfo',
                    '/usr/dt/bin/dtsession',
                    '/usr/dt/bin/tsoldtlabel',
                    '/usr/dt/bin/tsolxagent',
                    '/usr/xpg6/bin/crontab',
                    '/etc/lp/alerts/printer',
                    '/opt/csw/bin/sudo.minimal',
                    '/opt/csw/bin/sudoedit.minimal',
                    '/bin/rcp',
                    '/sbin/mksnap_ffs',
                    '/sbin/ping',
                    '/sbin/ping6',
                    '/sbin/shutdown',
                    '/sbin/poweroff',
                    '/usr/bin/at',
                    '/usr/bin/atq',
                    '/usr/bin/atrm',
                    '/usr/bin/batch',
                    '/usr/bin/chpass',
                    '/usr/bin/chfn',
                    '/usr/bin/chsh',
                    '/usr/bin/ypchpass',
                    '/usr/bin/ypchfn',
                    '/usr/bin/ypchsh',
                    '/usr/bin/lock',
                    '/usr/bin/login',
                    '/usr/bin/opieinfo',
                    '/usr/bin/opiepasswd',
                    '/usr/bin/passwd',
                    '/usr/bin/yppasswd',
                    '/usr/bin/quota',
                    '/usr/bin/rlogin',
                    '/usr/bin/rsh',
                    '/usr/bin/su',
                    '/usr/bin/crontab',
                    '/usr/libexec/ulog-helper',
                    '/usr/local/bin/ksu',
                    '/usr/local/bin/sudo',
                    '/usr/local/bin/sudoedit',
                    '/usr/sbin/ppp',
                    '/usr/sbin/timedc',
                    '/usr/sbin/traceroute',
                    '/usr/sbin/traceroute6',
                    '/sbin/mount.ecryptfs_private',
                    '/bin/fusermount',
                    '/lib/dbus-1/dbus-daemon-launch-helper',
                    '/usr/bin/kgrantpty',
                    '/usr/bin/ksu',
                    '/usr/bin/staprun',
                    '/usr/bin/kpac_dhcp_helper',
                    '/usr/bin/pkexec',
                    '/usr/libexec/spice-gtk-i386/spice-client-glib-usb-acl-helper',
                    '/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache',
                    '/usr/libexec/polkit-1/polkit-agent-helper-1',
                    '/usr/libexec/pulse/proximity-helper',
                    '/usr/libexec/pt_chown',
                    '/usr/lib/nspluginwrapper/plugin-config',
                    '/bin/ps',
                    '/bin/rcp',
                    '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent',
                    '/System/Library/PrivateFrameworks/SystemAdministration.framework/Versions/A/Resources/readconfig',
                    '/usr/bin/at',
                    '/usr/bin/atq',
                    '/usr/bin/atrm',
                    '/usr/bin/batch',
                    '/usr/bin/crontab',
                    '/usr/bin/ipcs',
                    '/usr/bin/login',
                    '/usr/bin/newgrp',
                    '/usr/bin/quota',
                    '/usr/bin/rlogin',
                    '/usr/bin/rsh',
                    '/usr/bin/su',
                    '/usr/bin/sudo',
                    '/usr/bin/top',
                    '/usr/lib/sa/sadc',
                    '/usr/libexec/authopen',
                    '/usr/libexec/security_authtrampoline',
                    '/usr/sbin/traceroute',
                    '/usr/sbin/traceroute6',
                    '/usr/lib64/kde4/libexec/start_kdeinit',
                    '/usr/lib64/kde4/libexec/kdesud',
                    '/usr/lib64/kde4/libexec/kcheckpass',
                    '/usr/bin/fusermount',
                    '/usr/lib/gnome-pty-helper',
                    '/usr/lib/utempter/utempter',
                    '/usr/lib/polkit-1/polkit-agent-helper-1',
                    '/usr/lib/libgnomesu/gnomesu-pam-backend',
                    '/sbin/unix2_chkpwd',
                    '/usr/bin/umount',
                    '/usr/bin/ping',
                    '/usr/bin/ping6',
                    '/usr/bin/mount',
                    '/usr/lib64/vte-2.90/gnome-pty-helper',
                    '/usr/lib64/vte-2.91/gnome-pty-helper',
                    '/usr/libexec/Xorg.wrap',
                    '/usr/libexec/qemu-bridge-helper',
                    '/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper',
                    '/usr/libexec/dbus-1/dbus-daemon-launch-helper',
                    '/usr/bin/newuidmap',
                    '/usr/bin/newgidmap',
                    '/usr/sbin/netreport',
                    '/usr/sbin/postdrop',
                    '/usr/sbin/postqueue',
                    '/usr/lib64/dbus-1/dbus-daemon-launch-helper',
                    '/usr/libexec/sssd/krb5_child',
                    '/usr/libexec/sssd/ldap_child',
                    '/usr/libexec/sssd/selinux_child',
                    '/usr/libexec/kde4/kpac_dhcp_helper',
                    '/usr/libexec/kde4/kdesud',
                    '/usr/lib64/nspluginwrapper/plugin-config',
                    '/usr/lib64/vte/gnome-pty-helper']
        compliant = False
        try:
            lastrun = open(self.suiddbfile, 'r').readlines()
        except(IOError):
            # Probably first run and the db doesn't exist yet.
            lastrun = []
        prevrun = []
        if os.path.exists(self.suidlast):
            prevrun = open(self.suidlast, 'r').readlines()
        firstrun = []
        if os.path.exists(self.suidorigin):
            firstrun = open(self.suidorigin, 'r').readlines()
        newfilessincelast = []
        newfilessinceorigin = []
        notknown = []
        wrongmode = []
        # Important! lines coming from the files will have newlines unless
        # they are stripped.
        for suidfile in lastrun:
            suidpath = suidfile.strip()
            if suidfile not in prevrun:
                newfilessincelast.append(suidpath)
            if suidfile not in firstrun:
                newfilessinceorigin.append(suidpath)
            rpmchkval = self.rpmcheck(suidfile)
            if rpmchkval > 3:
                if suidpath not in suidlist:
                    notknown.append(suidpath)
            if rpmchkval == 0:
                wrongmode.append(suidpath)
        strnewfilessincelast = ''
        if len(newfilessincelast) > 15:
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'New SUID files since last run: Too many ' +
                             'files! Details suppressed, review file at ' +
                             '/var/local/info. New: ' +
                             str(len(newfilessincelast))])
        else:
            for entry in newfilessincelast:
                strnewfilessincelast = strnewfilessincelast + entry + ' '
            strnewfilessincelast = strnewfilessincelast.strip()
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'New since last: ' + str(strnewfilessincelast)])
        strnewfilessinceorigin = ''
        if len(newfilessinceorigin) > 15:
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'New since first run: Too many files! Details ' +
                             'suppressed, review file at /var/local/info. ' +
                             'New: ' + str(len(newfilessinceorigin))])
        else:
            for entry in newfilessinceorigin:
                strnewfilessinceorigin = strnewfilessinceorigin + entry + ' '
            strnewfilessinceorigin = strnewfilessinceorigin.strip()
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'New since first run: ' +
                             str(newfilessinceorigin)])
        strnotknown = ''
        if len(notknown) > 15:
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'SUID files not known by STONIX: Too many ' +
                             'files! Details suppressed, review file at ' +
                             '/var/local/info. New: ' + str(len(notknown))])
        else:
            for entry in notknown:
                strnotknown = strnotknown + entry + ' '
            strnotknown = strnotknown.strip()
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'SUID files not known by STONIX: ' +
                             str(notknown)])
        strwrongmode = ''
        if len(wrongmode) > 15:
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'SUID files where current mode does not match ' +
                             'the package dbase: Too many files! Details ' +
                             'suppressed, review file at /var/local/info. ' +
                             'New: ' + str(len(wrongmode))])
        else:
            for entry in wrongmode:
                strwrongmode = strwrongmode + entry + ' '
            strwrongmode = strwrongmode.strip()
            self.logger.log(LogPriority.INFO,
                            ['AuditSUID.report',
                             'SUID files where current mode does not match ' +
                             'the package dbase: ' + str(wrongmode)])
        if len(newfilessincelast) > 0 or len(wrongmode) > 0:
            compliant = False
            self.suidresults = 'New SUID Files since last run: ' + \
                strnewfilessincelast
            self.suidresults = self.suidresults + ' '
            self.suidresults = self.suidresults + '\nSUID files not known ' + \
                'by STONIX: ' + strnotknown
            self.suidresults = self.suidresults + ' '
            self.suidresults = self.suidresults + '\nSUID files where ' + \
                'current mode does not match the package dbase: ' + \
                strwrongmode
            if self.findoverrun:
                self.suidresults = self.suidresults + '''
WARNING! Large numbers of files with incorrect permissions detected. Please \
conduct a manual check for SUID / SGID files and correct \
permissions as needed.

To find SUID/SGID files, run the following command as root:
find / -xdev \( -perm -04000 -o -perm -02000 \) -print
'''
        elif self.findoverrun:
                self.suidresults = self.suidresults + '''
WARNING! Large numbers of files with incorrect permissions detected. Please \
conduct a manual check for SUID / SGID files and correct \
permissions as needed.

To find SUID/SGID files, run the following command as root:
find / -xdev \( -perm -04000 -o -perm -02000 \) -print
'''
        else:
            compliant = True
            self.suidresults = 'No new SUID/SGID files since last run.'

        return compliant

    def noownersreport(self):
        '''Private method to report on files without owners.
        @author: dkennel
        '''
        compliant = False
        try:
            lastrun = open(self.nodbfile, 'r').readlines()
        except(IOError):
            lastrun = []
        prevrun = []
        if os.path.exists(self.nolast):
            prevrun = open(self.nolast, 'r').readlines()
        firstrun = []
        if os.path.exists(self.noorigin):
            firstrun = open(self.noorigin, 'r').readlines()
        newfilessincelast = []
        newfilessinceorigin = []
        # Important! lines coming from the files will have newlines unless
        # they are stripped.
        for suidfile in lastrun:
            suidpath = suidfile.strip()
            if suidfile not in prevrun:
                newfilessincelast.append(suidpath)
            if suidfile not in firstrun:
                newfilessinceorigin.append(suidpath)
        strnewfilessincelast = ''
        if len(newfilessincelast) > 15:
            strnewfilessincelast = str(len(newfilessincelast))
            self.logger.log(LogPriority.INFO,
                            ['NoUnownedFiles.report',
                             'New files without owners since last run: Too ' +
                             'many files! Details suppressed, review file ' +
                             'at /var/local/info. New: ' +
                             strnewfilessincelast])
        else:
            for entry in newfilessincelast:
                strnewfilessincelast = strnewfilessincelast + entry + ' '
            strnewfilessincelast = strnewfilessincelast.strip()
            self.logger.log(LogPriority.INFO,
                            ['NoUnownedFiles.report',
                             'New since last: ' + str(strnewfilessincelast)])
        strnewfilessinceorigin = ''
        if len(newfilessinceorigin) > 15:
            strnewfilessinceorigin = str(len(newfilessinceorigin))
            self.logger.log(LogPriority.INFO,
                            ['NoUnownedFiles.report',
                             'New files without owners since first run: Too ' +
                             'many files! Details suppressed, review file ' +
                             'at /var/local/info. New: ' +
                             strnewfilessinceorigin])
        else:
            for entry in newfilessinceorigin:
                strnewfilessinceorigin = strnewfilessinceorigin + entry + ' '
            strnewfilessinceorigin = strnewfilessinceorigin.strip()
            self.logger.log(LogPriority.INFO,
                            ['NoUnownedFiles.report',
                             'New since last: ' + str(strnewfilessinceorigin)])

        if len(newfilessincelast) > 0:
            compliant = False
            self.unownedresults = 'New Files without owners since last run: ' \
                + strnewfilessincelast
            self.unownedresults = self.unownedresults + ' '
            self.unownedresults = self.unownedresults + 'Files without ' + \
                'owners since first run: ' + strnewfilessinceorigin
            if self.findoverrun:
                self.suidresults = self.suidresults + '''
WARNING! Large numbers of files with incorrect permissions detected. Please \
conduct a manual check for unowned files and correct \
permissions as needed.

To find unowned files, run the following command as root:
find / -xdev \( -nouser -o -nogroup \) -print
'''
        elif self.findoverrun:
                self.suidresults = self.suidresults + '''
WARNING! Large numbers of files with incorrect permissions detected. Please \
conduct a manual check for unowned files and correct \
permissions as needed.

To find unowned files, run the following command as root:
find / -xdev \( -nouser -o -nogroup \) -print
'''
        else:
            compliant = True
            self.unownedresults = 'No new files without valid owners ' + \
                'since last run.'

        return compliant

    def rpmcheck(self, path):
        '''
        The rpmcheck method is a private method intended to check the status of
        the program at the passed path in the rpm database. If the file was
        found in the RPM database but the mode has changed we return 0. If the
        file was found and the mode has not changed we return 1. If the file
        was not found we return 3. If the system does not use RPM then we
        return 4. If something weird happens we return 5.

        @return: int
        @author: dkennel
        '''
        path = path.strip()
        if not os.path.exists('/bin/rpm'):
            return 4
        cmd = '/bin/rpm -Vf ' + path
        try:
            proc = subprocess.Popen(cmd, shell=True, close_fds=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            output = proc.stdout.readlines()
            errout = proc.stderr.readlines()
            self.logger.log(LogPriority.DEBUG,
                            ['AuditSUID.rpmcheck',
                             'rpm -Vf Results: ' + str(output) + str(errout)])
            if len(output) == 0:
                for line in errout:
                    if re.search('No such file or directory', line):
                        return 3
                return 5
            for line in output:
                if re.search('M', line):
                    return 0
            return 1
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR,
                            ['AuditSUID.rpmcheck',
                             self.detailedresults])
            return 5

    def report(self):
        '''
        Public report method for the FilePermissions rule. This method will
        invoke the multifind and then call the report routines that examine
        the status of World Writable files, SUID/SGID files and files without
        known owners. This rule because of the length of time it takes to do
        the full filesystem scan sets a bool at self.hasrunalready after
        completing the report method. This prevents the scan from being invoked
        repeatedly by the controller logic.

        @author: dkennel
        '''

        self.detailedresults = ''
        try:
            if not self.hasrunalready or self.firstrun:
                self.logger.log(LogPriority.DEBUG,
                                ['FilePermissions.report',
                                 'Running find: has run ' +
                                 str(self.hasrunalready) +
                                 ' first run ' + str(self.firstrun)])
                self.multifind()
                wwstatus = self.wwreport()
                gwstatus = self.gwreport()
                suidstatus = self.suidreport()
                ownerstatus = self.noownersreport()
                self.detailedresults = self.wwresults + '\n' + self.gwresults \
                    + '\n' + self.suidresults + '\n' + self.unownedresults
                if wwstatus and gwstatus and suidstatus and ownerstatus:
                    self.compliant = True
                self.hasrunalready = True
                if os.path.exists(self.wwlast):
                    self.firstrun = False
                self.logger.log(LogPriority.DEBUG,
                                ['FilePermissions.report',
                                 'Find complete: has run ' +
                                 str(self.hasrunalready)
                                 + ' first run ' + str(self.firstrun) +
                                 ' compliant: ' + str(self.compliant) +
                                 ' wwstatus: ' + str(wwstatus) +
                                 ' gwstatus: ' + str(gwstatus) +
                                 ' suidstatus: ' + str(suidstatus) +
                                 ' ownerstatus: ' + str(ownerstatus)])
            else:
                self.logger.log(LogPriority.DEBUG,
                                ['FilePermissions.report',
                                 'Skipping find: has run ' +
                                 str(self.hasrunalready) + 'first run ' +
                                 str(self.firstrun)])
                note = '''This rule only runs once for performance reasons. It \
has been called a second time. The previous results are displayed. '''
                self.detailedresults = note + "\n" + self.wwresults + '\n' + \
                    self.gwresults + '\n' + self.suidresults + '\n' + \
                    self.unownedresults
            self.formatDetailedResults("report", self.compliant,
                                       self.detailedresults)

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

        except Exception:
            self.detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.ERROR,
                            [self.rulename + '.report',
                             self.detailedresults])
            self.rulesuccess = False

    def fix(self):
        """
        The fix method will apply the sticky bit to all world writable
        directories.
        self.rulesuccess will be updated if the rule does not succeed.

        @author dkennel
        """
        rootpath = os.environ["PATH"].split(':')
        pathre = '|'.join(rootpath)
        try:
            self.detailedresults = ""
            if os.path.exists(self.wwdbfile):
                fhandle = open(self.wwdbfile, 'r')
                wwfiles = fhandle.readlines()
                for wwfile in wwfiles:
                    wwfile = wwfile.strip()
                    if os.path.isdir(wwfile):
                        try:
                            os.chmod(wwfile, 01777)
                        except (OSError):
                            # catch OSError because we may be NFS or RO
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.fix',
                                             str(traceback.format_exc())])
                            continue
                    elif os.path.isfile(wwfile) and re.match(pathre, wwfile):
                        # File is in the root users path, remove world write
                        fstat = os.stat(wwfile)
                        # this call is doing a bitwise exclusive or operation
                        # on the original file mode to remove the write
                        # permission from the file
                        self.logger.log(LogPriority.INFO,
                                        ['FilePermissions.fix',
                                         'Removed world write from: ' +
                                         str(wwfile)])
                        newmode = fstat.st_mode ^ stat.S_IWOTH
                        self.logger.log(LogPriority.DEBUG,
                                        ['FilePermissions.fix',
                                         'Changing mode of ' +
                                         str(wwfile) + ' from ' +
                                         str(oct(fstat.st_mode)) + ' to ' +
                                         str(oct(newmode))])
                        try:
                            os.chmod(wwfile, newmode)
                        except (OSError):
                            # catch OSError because we may be NFS or RO
                            self.logger.log(LogPriority.DEBUG,
                                            ['FilePermissions.fix',
                                             str(traceback.format_exc())])
                            continue
            if self.fixgw.getcurrvalue():
                for gwfile in self.gwfiles:
                    fstat = os.stat(gwfile)
                    # this call is doing a bitwise exclusive or operation
                    # on the original file mode to remove the group write
                    # permission from the file
                    newmode = fstat.st_mode ^ stat.S_IWGRP
                    self.logger.log(LogPriority.DEBUG,
                                    ['FilePermissions.fix',
                                     'Changing mode of ' +
                                     str(gwfile) + ' from ' +
                                     str(oct(fstat.st_mode)) + ' to ' +
                                     str(oct(newmode))])
                    try:
                        os.chmod(gwfile, newmode)
                    except (OSError):
                        # catch OSError because we may be NFS or RO
                        self.logger.log(LogPriority.DEBUG,
                                        ['FilePermissions.fix',
                                         str(traceback.format_exc())])
                        continue
            if self.fixroot.getcurrvalue():
                for nrofile in self.nrofiles:
                    self.logger.log(LogPriority.DEBUG,
                                    ["FilePermissions.fix",
                                     "Changing owner of " + str(nrofile) +
                                     " to root"])
                    try:
                        os.chown(nrofile, 0, -1)
                    except OSError:
                        self.logger.log(LogPriority.DEBUG,
                                        ['FilePermissions.fix',
                                         str(traceback.format_exc())])
                        continue
            # Re-run gwreport(), so that group writable and non-root owned
            # lists are updated
            self.gwreport()
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
