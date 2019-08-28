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




# =========================================================================== #
#               Filename          $RCSfile: dylutils.py,v $
#               Description       Utility functions for STONIX
#               OS                RHEL, OS X, Solaris, Linux
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Linux Benchmark,
#                                 NSA RHEL Guideline
#                                 and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2011/10/30 16:00:00 $
# =========================================================================== #
# Changelog
#
#   2011/10/18 Copied in storutils as a jumpstart for utility functions.

'''
Created on Oct 18, 2011
Miscellaneous utility functions.

@author: Dave Kennel
@change: Breen Malmberg - 5/8/2017 - added method validateParam;
        fixed a bad indentation on/near line 1329, in method
        isServerVersionHigher; (Note: many methods missing try/except
        blocks!); Removed old, commented-out isApplicable method (commented
        out by Dave Kennel - per Dave Kennel "this block can probably be safely
        removed in 0.8.17"); removed unused method iterate2
@change: Breen Malmberg - 7/12/2017 - doc string pass on all methods; added try/except
        blocks to all methods which were missing it; removed unused imports; removed
        method cloneMeta() - will sub resetsecon where it was used
@todo: re-write checkUserGroupName so it only has 1 return type
        and update the rules which use it (currently only ConfigureLogging)
@todo: replace * import with needed types only
@todo: remove duplicate methods and change implementation in rules that used the removed ones
        to use the other one
@note: don't write methods without try/except blocks; log errors/issues; methods
        should only have 1, determinate, return type; don't write methods without
        doc strings or without naming the author; don't use lazy imports; record all
        changes with the @change tag (name and date of change and what was changed);
        don't write methods with return variables that have no default initialization
'''

import os
import grp
import inspect
import pwd
import re
import subprocess
import traceback
import socket
import stat
import urllib.request, urllib.error, urllib.parse

from grp import getgrgid
from pwd import getpwuid
from types import *
from distutils.version import LooseVersion
from subprocess import call, Popen, PIPE, STDOUT
from .logdispatcher import LogPriority


def resetsecon(filename):
    '''Reset the SELinux security context of a file. This should be done after
    sensitive files are modified to prevent breakage due to SELinux denials.

    :param filename: string; Full path to the file to be reset
    @author: D. Kennel
    :returns: void
    @change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except

    '''

    try:

        if os.path.exists('/sbin/restorecon'):
            call('/sbin/restorecon ' + filename + ' &> /dev/null', shell=True,
                 close_fds=True)

    except Exception:
        raise

def getlocalfs(logger, environ):
    '''This function is used to return a list of local filesystems. It is used
    in the FilePermissions rule among others.
    It must be passed references to the instantiated logdispatcher and
    environment objects.

    :param logger: logging object
    :param environ: environment object
    :returns: fslist; List of strings that are local filesystems (default = [])
    :rtype: list
@author: Dave Kennel
@change: Breen Malmberg - 7/12/2017 - minor doc string edit

    '''

    logger.log(LogPriority.DEBUG,
               ['GetLocalFs', 'Attempting to discover local filesystems'])

    fslist = []
    fstab = '/etc/fstab'
    fstypeindex = 2
    mpindex = 1

    # Macs are kinda broken vis-a-vis mounting so we do this to get the
    # local filesystem info from mount. Usually we're only worried about
    # /.

    if environ.getosfamily() == 'darwin':
        logger.log(LogPriority.DEBUG,
                        ['GetLocalFs', 'Performing OS X discovery'])
        try:

            cmd = '/sbin/mount'
            proc = subprocess.Popen(cmd, shell=True, close_fds=True,
                                    stdout=subprocess.PIPE)
            proc.wait()
            mountdata = proc.stdout.readlines()
            for line in mountdata:
                logger.log(LogPriority.DEBUG,
                           ['GetLocalFs', 'OS X processing: ' + line])
                if re.search('^/dev/disk', line):
                    piece = line.split()
                    try:
                        filesystem = piece[2]
                    except(KeyError):
                        logger.log(LogPriority.DEBUG,
                                   ['GetLocalFs',
                                    'OS X Key Error on: ' + line])
                        continue
                    if re.search('msdos', line):
                        # skip MSDOS filesystems because their permissions
                        # are nonsensical in a *nix context
                        logger.log(LogPriority.DEBUG,
                                   ['GetLocalFs',
                                    'OS X skipping msdos: ' + filesystem])
                        continue
                    if re.search('^/', filesystem):
                        logger.log(LogPriority.DEBUG,
                                   ['GetLocalFs',
                                    'OS X pattern match on: ' + filesystem])
                        fslist.append(filesystem)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

        except Exception:
            detailedresults = traceback.format_exc()
            logger.log(LogPriority.ERROR,
                       ['GetLocalFS', detailedresults])

    else:

        if environ.getosfamily() == 'solaris':
            logger.log(LogPriority.DEBUG,
                       ['GetLocalFs', 'Performing Solaris discovery'])
            fstab = '/etc/vfstab'
            fstypeindex = 3
            mpindex = 2

        try:

            fhandle = open(fstab, 'r')
            tabdata = fhandle.readlines()
            fhandle.close()
            fstypes = ['ext2', 'ext3', 'ext4', 'xfs', 'ufs', 'jfs',
                        'btrfs', 'reiserfs', 'ext3cow', ]
            logger.log(LogPriority.DEBUG,
                       ['GetLocalFs', 'Processing ' + str(fstab)])
            for line in tabdata:
                logger.log(LogPriority.DEBUG,
                            ['GetLocalFs', 'Processing ' + str(line)])
                if not re.search('^#', line):
                    try:
                        piece = line.split()
                        if piece[fstypeindex] in fstypes:
                            fslist.append(piece[mpindex])
                    except(KeyError, IndexError):
                        continue
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise

        except Exception:
            detailedresults = traceback.format_exc()
            logger.log(LogPriority.ERROR,
                       ['GetLocalFs', detailedresults])
    logger.log(LogPriority.DEBUG,
               ['GetLocalFs', 'Local filesystems: ' + str(fslist)])
    return fslist

# This will become a rule or part of a rule
def importkey(logger):
    '''On new installs we need to import the rpm gpg key to check package sigs.
    This function will import the key if has not been imported already. We
    don't need to do this if called in install mode because the assumption
    is that expressway has done it.

    :param logger: logging object
    @author: Roy Nielsen
    :returns: void
    @change: Breen Malmberg - 7/12/2017 - fixed doc string; added try/except;
            fixed method logic

    '''

    try:

        stdin, stdout, stderr = os.popen3('/bin/rpm -qi gpg-pubkey')
        isimported = stdout.read()
        stdout.close()
        stdin.close()
        stderr.close()
        importcommand = ""
    
        if not re.search('security@redhat.com', isimported):
            if os.path.exists('/usr/share/rhn/RPM-GPG-KEY'):
                importcommand = '/bin/rpm --import /usr/share/rhn/RPM-GPG-KEY'
            elif os.path.exists('/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release'):
                importcommand = '/bin/rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release'
            else:
                logger.log(LogPriority.DEBUG, ['importkey', "Could not locate RPM GPG key. Install GPG key manually"])

            if importcommand:
                retcode = call(importcommand, shell=True)
                if retcode < 0:
                    logger.log(LogPriority.DEBUG, "The rpm import gpg key command failed with exit code: " + str(retcode))

    except Exception:
        raise

def write_file(logger, file_name="", file_content=""):
    '''Write a config file (file_content) to destination (file_name)
    Initially intended for installing scripts and plists to be controlled by
    launchd

    :param logger: logging object
    :param file_name: string; file path to write to (Default value = "")
    :param file_content: string; contents to write to <file_name>
    @author: Roy Nielsen (Default value = "")
    :returns: void
    @change: Breen Malmberg - 7/12/2017 - fixed doc string; added try/except;
            simplified method logic; added logging

    '''

    try:

        # Need to make sure that file_name and file_content are not blank
        if not file_name:
            logger.log(LogPriority.DEBUG, "No file name provided. Nothing was written.")
        elif not file_content:
            logger.log(LogPriority.DEBUG, "No file content provided. Nothing was written.")
        else:

            fh = open(file_name, "w")
            fh.write(file_content)
            fh.close()

    except Exception:
        raise

def set_no_proxy():
    '''This method described here: http://www.decalage.info/en/python/urllib2noproxy
    to create a "no_proxy" environment for python
    
    @author: Roy Nielsen


    :returns: void
    @change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except

    '''

    try:

        proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)

    except Exception:
        raise

def delete_plist_key(plist="", key=""):
    '''**** Macintosh-specific Function ****
    Delete a key from a plist file

    :param plist: string; the fully qualified filename of the plist (Default value = "")
    :param key: string; the key to delete (Default value = "")
    :returns: in_compliance (0 for failed to delete 1 for done; default = 0)
    :rtype: int
@author: Roy Nielsen
@change: Breen Malmberg - 7/12/2017 - fixed doc string; added try/except

    '''

    in_compliance = 0

    try:

        # see if the value is there
        current_value = get_plist_value(plist, key)
    
        if re.match("-NULL-", current_value):
            # we are done; the key is not there
            in_compliance = 1
        else:
            # remove the key
    
            cmd = ["defaults", "delete", plist, key]
    
            Popen(cmd, stdout=PIPE).communicate()[0]
    
            # validate it is no longer there
            current_value = get_plist_value(plist, key)
    
            if re.match("-NULL-", current_value):
                in_compliance = 1

    except Exception:
        raise
    return in_compliance

def get_plist_value(plist="", key="", current_host=""):
    '''**** Macintosh-specific Function ****
    Get the value of a key in a plist file

    :param plist: string; the fully qualified filename of the plist (Default value = "")
    :param key: string; the key to delete (Default value = "")
    :param current_host: string; whether or not to use the -currentHost option
           0 = don't use option
           1 = use -currentHost option (Default value = "")
    :returns: current_value ('-NULL-' if the key is not found, otherwise it returns the value of the key; default = '-NULL-')
    :rtype: string
@author: Roy Nielsen
@change: Breen Malmberg - 7/12/2017 - doc string edit; added try/except;
        added return var default init; simplified method logic

    '''

    current_value = "-NULL-"

    try:

        # determine if the currentHost option should be used
        # use this option when reading in the user's ByHost dir
        if current_host:
            current_host = " -currentHost"

        if not current_host:
            cmd = ["defaults", "read", plist, key]
        else:
            cmd = ["defaults", current_host, "read", plist, key]

        # get the current value
        current_value = Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()[0]
    
        if re.search("does\s+not\s+exist$", current_value):
            current_value = "-NULL-"

    except Exception:
        raise
    return current_value

def has_connection_to_server(logger, server=None, port=80, timeout=1):
    '''Check to see if there is a connection to a server.

    :param logger: logger object
    :param server: string; name of the server you want to check connection with
            default = None
    :param port: int; port number you want to check connection with
            default=80
    :param timeout: int; the number of seconds to wait for a timeout, can be a float.
            default = 1 second
    :returns: resolvable (True if there is a connection, False if there is not; default = True)
    :rtype: bool
@author: Dave Kennel, Roy Nielsen
@change: Breen Malmberg - 7/12/2017 - minor doc string edit;

    '''

    resolvable = True

    if server:

        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((server, port))
            sock.close()

        except (socket.gaierror, socket.timeout, socket.error) as err:
            resolvable = False
            logger.log(LogPriority.ERROR, "has_connection_to_server: socket error: " + str(err))
            logger.log(LogPriority.ERROR, "has_connection_to_server: server: "
                       + str(server) + " port: " + str(port) + " timeout = "
                       + str(timeout) + " Connection failed")
    else:
        logger.log(LogPriority.DEBUG, "No server name provided. Cannot determine server connection status.")
        resolvable = False

    return resolvable

def isWritable(logger, filepath, owner="o"):
    '''return true or false, depending on whether filepath is writable by owner.
    if owner is not specified, will test for world-writable.
    owner should be specified as one of the following string values:
     other
     o
     group
     g
     user
     u

    :param s: filepath: string; path of file to check
    :param s: owner: string; type of writability to check
    :param s: logger: logging object
    :param logger: 
    :param filepath: 
    :param owner:  (Default value = "o")
    :returns: isw
    :rtype: bool
@author Breen Malmberg

    '''

    # set default return value isw to False
    isw = False

    # set up owner arg translation matrix
    ownerdict = {'other': stat.S_IWOTH,
                 'o': stat.S_IWOTH,
                 'user': stat.S_IWUSR,
                 'u': stat.S_IWUSR,
                 'group': stat.S_IWGRP,
                 'g': stat.S_IWGRP}

    # check if given filepath exists
    if not os.path.exists(filepath):
        return False

    try:

        if owner in ['other', 'o', 'user', 'u', 'group', 'g']:
            permissions = os.stat(filepath)
            isw = bool(permissions.st_mode & ownerdict[owner])
        else:
            return False

    except (KeyError):
        errmessage = traceback.format_exc()
        logger.log(LogPriority.INFO, ['stonixutilityfunctions - isWritable ',
                                     errmessage])

    return isw

def getOctalPerms(filepath):
    '''Get and return the octal format of the file permissions for filepath

    :param filepath: path of file to check
    @change: Breen Malmberg - 7/12/2017 - minor doc string edit; added
            try/except; added default return var init
    @change: Brandon R. Gonzales - 5/29/2018 - Now works with directory
            file paths
    :returns: octperms
    :rtype: int
@author: Breen Malmberg

    '''

    octperms = 0

    try:

        rawresult = os.stat(filepath).st_mode

        if stat.S_ISREG(rawresult) or stat.S_ISDIR(rawresult):
            octperms = oct(stat.S_IMODE(rawresult))
            if len(octperms) > 2:
                    octperms = octperms[2:]

    except Exception:
        raise
    return int(octperms)

def getOwnership(filepath):
    '''Get and return the numeric user and group owner of the filepath

    :param filepath: string; path of file to get ownership info from
    @author Breen Malmberg
    @change: Breen Malmberg - 7/12/2017 - minor doc string edit; added
            default return var init
    :returns: ownership (list; uid in position 0, gid in position 1; default = [])
    :rtype: list

    '''

    ownership = []

    try:

        owner = os.stat(filepath).st_uid
        group = os.stat(filepath).st_gid

        ownership = [owner, group]

    except Exception:
        raise
    return ownership

def isThisYosemite(environ):
    '''returns True if the current system's OS is Mountain Lion
    
    @author: ekkehard j. koch

    :param environ: environment object
    :returns: isYosemite (True if applicable False if not)
    :rtype: bool
@change: ekkehard j. koch - 10/17/2013 - Original Implementation
@change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except;
        simplified method logic; added default return var init

    '''

    isYosemite = False

    try:

        osfamily = environ.getosfamily()
        operatingsystem = environ.getostype()
        osversion = environ.getosver()
        if osfamily == "darwin" and operatingsystem == 'Mac OS X':
            if osversion.startswith("10.10"):
                isYosemite = True

    except Exception:
        raise
    return isYosemite

def isThisMavericks(environ):
    '''returns True if the current system's OS is Mavericks
    
    @author: ekkehard j. koch

    :param environ: environment object
    :returns: isMavericks (True if applicable False if not)
    :rtype: bool
@change: ekkehard j. koch - 10/17/2013 - Original Implementation
@change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except;
        added default return var init; simplified method logic

    '''

    isMavericks = False

    try:

        osfamily = environ.getosfamily()
        operatingsystem = environ.getostype()
        osversion = environ.getosver()
        if osfamily == "darwin" and operatingsystem == 'Mac OS X':
            if osversion.startswith("10.9"):
                isMavericks = True

    except Exception:
        raise
    return isMavericks

def isThisMountainLion(environ):
    '''returns True if the current system's OS is Mountain Lion
    
    @author: ekkehard j. koch

    :param environ: environment object
    :returns: isMountainLion (True if applicable False if not)
    :rtype: bool
@change: ekkehard j. koch - 10/17/2013 - Original Implementation
@change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except;
        added default return var init; simplified method logic

    '''

    isMountainLion = False

    try:

        osfamily = environ.getosfamily()
        operatingsystem = environ.getostype()
        osversion = environ.getosver()
        if osfamily == "darwin" and operatingsystem == 'Mac OS X':
            if osversion.startswith("10.8"):
                isMountainLion = True

    except Exception:
        raise
    return isMountainLion

def readFile(filepath, logger):
    '''Read a file's contents and return in a list format
    @author: Derek Walker

    :param filepath: string; path to file to read
    :param logger: logging object
    :returns: contents
    :rtype: list
@change: bgonz12 - 2017/06/02 - fixed the implementation to use std lib's
         readlines function, removing syntax error; moved the implementation
         into the try block
@change: Breen Malmberg - 7/12/2017 - minor doc string edit
@change: bgonz12 - 2018/1/18 - added handling for 'filepath' not existing

    '''
    
    contents = []

    if not os.path.exists(filepath):
        detailedresults = "Unable to open specified file: " + filepath + \
            ". File does not exist."
        logger.log(LogPriority.DEBUG, detailedresults)
    else:
        try:
            f = open(filepath, 'r')
            contents = f.readlines()
            f.close()
        except IOError:
            debug = "Unable to open the specified file: " + \
                filepath + ". " + traceback.format_exc()
            logger.log(LogPriority.DEBUG, debug)
            raise
    return contents

def readFileString(filepath, logger):
    '''Read a file's contents and return in a string format
    @author: Derek Walker

    :param filepath: string
    :param logger: logger object
    :returns: contents - string of file's contents

    '''
    contents = ""
    if not os.path.exists(filepath):
        detailedresults = "Unable to open specified file: " + filepath + \
            ". File does not exist."
        logger.log(LogPriority.DEBUG, detailedresults)
    else:
        try:
            f = open(filepath, 'r')
            contents = f.read()
            f.close()
        except IOError:
            debug = "Unable to open the specified file: " + \
                filepath + ". " + traceback.format_exc()
            logger.log(LogPriority.DEBUG, debug)
            raise
    return contents

def writeFile(tmpfile, contents, logger):
    """Write <contents> to <tmpfile>.
    Return True if successful, False if not.
    
    @author: Derek Walker

    :param tmpfile: string
    :param contents: string
    :param logger: logging object
    :returns: success
    :rtype: bool
@change: Breen Malmberg - 5/8/2017 - refactor to handle both
        list and string type contents parameter; no change needed
        to implementation in rules
@change: Breen Malmberg - 7/12/2017 - minor doc string edit

    """

    success = True

    try:

        # python 3 safety check on string/bytes argument input
        if type(tmpfile) is bytes:
            tmpfile = tmpfile.decode('utf-8')
        if type(contents) is bytes:
            contents = contents.decode('utf-8')
        if type(contents) is list:
            for i in contents:
                if type(i) is bytes:
                    contents = [i.decode('utf-8') for i in contents]

        # check if parent directory exists first
        parentdir = os.path.abspath(os.path.join(tmpfile, os.pardir))
        if not os.path.isdir(parentdir):
            success = False
            logger.log(LogPriority.DEBUG, "Parent directory for given path does not exist. Cannot write file.")
        else:
            w = open(tmpfile, 'w')

            if type(contents) is str:
                w.write(contents)
            elif type(contents) is list:
                w.writelines(contents)
            else:
                success = False
                logger.log(LogPriority.DEBUG, "Given contents was niether a string, nor a list! Could not write to file " + str(tmpfile))
            w.close()

    except Exception:
        raise
    return success

def getUserGroupName(filename):
    '''This method gets the uid and gid string name of a file
    and stores in a list where position 0 is the owner and
    position 1 is the group
    
    @author: Derek Walker

    :param filename: string; filename to get uid and gid name
    :returns: retval (uid in position 0 of list. gid in position 1 of list)
    :rtype: list
@change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except

    '''

    retval = []

    try:

        statdata = os.stat(filename)
        uid = statdata.st_uid
        gid = statdata.st_gid
        user = getpwuid(uid)[0]
        group = getgrgid(gid)[0]
        retval.append(user)
        retval.append(group)

    except Exception:
        raise
    return retval

def checkUserGroupName(ownergrp, owner, group, actualmode, desiredmode, logger):
    '''This method is usually used in conjuction with getUserGroupName.
    Returned list from getUserGroupName is passed through this method along
    with desired owner and group string name and checked to see if they match
    
    @author: Derek Walker

    :param ownergrp: list containing user/owner string name (0) and group string
        name (1)
    :param owner: Desired owner string name to check against
    :param group: Desired group string name to check against
    :param actualmode: Actual mode number to be compared with <desiredmode>
    :param desiredmode: Desired mode number to be compared with <actualmode>
    :param logger: logging object
    :returns: retval
    :rtype: list | bool
@change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except
@note: methods should not have more than 1 return type!!

    '''

    retval = []

    try:

        if not ownergrp[0]:
            debug = "There is no owner provided for checkUserGroupName method\n"
            logger.log(LogPriority.DEBUG, debug)
            return False
        if not ownergrp[1]:
            debug = "There is no group provided for checkUserGroupName method\n"
            logger.log(LogPriority.DEBUG, debug)
            return False

        if grp.getgrnam(group)[2] != "":
            gid = grp.getgrnam(group)[2]
        if pwd.getpwnam(owner)[2] != "":
            uid = pwd.getpwnam(owner)[2]
        if str(uid) and str(gid):
            if actualmode != desiredmode or ownergrp[0] != owner or ownergrp[1] != group:
                retval.append(uid)
                retval.append(gid)
                return retval
            else:
                return True
        else:
            debug = "There is no uid or gid associated with owner and group parameters\n"
            logger.log(LogPriority.DEBUG, debug)
            return False

    except Exception:
        raise
    return retval

def checkPerms(path, perm, logger):
    '''Check the given file's permissions.

    :param path: string; file path whose perm's to check
    :param perm: list; list of ownership and permissions information
    :param logger: LogDispatch object
    @author: Derek Walker
    @change: Breen Malmberg - 1/10/2017 - doc string edit; return val init;
            minor refactor; parameter validation; logging
    :returns: retval
    :rtype: bool

    '''

    retval = True

    try:

        if not isinstance(path, str):
            logger.log(LogPriority.DEBUG, "Specified parameter: path must be of type: string. Got: " + str(type(path)) + "\n")
        if not isinstance(perm, list):
            logger.log(LogPriority.DEBUG, "Specified parameter: perm must be of type: list. Got: " + str(type(perm)) + "\n")
        if not isinstance(logger, object):
            logger.log(LogPriority.DEBUG, "Specified parameter: logger must be of type: object. Got: " + str(type(logger)) + "\n")

        for v in locals():
            if not v:
                logger.log(LogPriority.DEBUG, "Specified parameter: " + str(v) + " was blank or None!\n")

        statdata = os.stat(path)
        owner = statdata.st_uid
        group = statdata.st_gid
        mode = stat.S_IMODE(statdata.st_mode)

        if owner != perm[0]:
            logger.log(LogPriority.DEBUG, "File: " + str(path) + " has incorrect owner.\n")
            retval = False
        if group != perm[1]:
            logger.log(LogPriority.DEBUG, "File: " + str(path) + " has incorrect group.\n")
            retval = False
        if mode != perm[2]:
            logger.log(LogPriority.DEBUG, "File: " + str(path) + " has incorrect permissions.\n")
            logger.log(LogPriority.DEBUG, "File perm's = " + str(mode) + "; Desired perm's = " + str(perm[2]) + "\n")
            retval = False

    except OSError:
        logger.log(LogPriority.DEBUG, "Unable to check permissions on: " + path + "\n")
        retval = False
    except Exception:
        raise

    return retval

def setPerms(path, perm, logger, stchlogger="", myid=""):
    '''Set the given <path>'s permissions to <perm>.

    :param path: string; full path to the file whose perms to set
    :param perm: list; integer list of permissions and ownership information
    :param logger: object; logger object
    :param stchlogger: object; statechangelogger object (Default value = "")
    :param myid: string; indicates a unique id to assign to the action of changing perms
    @author: Derek Walker
    @change: Breen Malmberg - 1/10/2017 - doc string edit; minor refactor; logging;
            return var init; parameter validation (Default value = "")
    :returns: retval
    :rtype: bool

    '''

    retval = True

    try:

        if not isinstance(path, str):
            logger.log(LogPriority.DEBUG, "Specified parameter: path must be of type: string. Got: " + str(type(path)) + "\n")
        if not isinstance(perm, list):
            logger.log(LogPriority.DEBUG, "Specified parameter: perm must be of type: list. Got: " + str(type(perm)) + "\n")
        if not isinstance(logger, object):
            logger.log(LogPriority.DEBUG, "Specified parameter: logger must be of type: object. Got: " + str(type(logger)) + "\n")

        for v in locals():
            if not v:
                logger.log(LogPriority.DEBUG, "Specified parameter: " + str(v) + " was blank or None!\n")

        statdata = os.stat(path)
        owner = statdata.st_uid
        group = statdata.st_gid
        mode = stat.S_IMODE(statdata.st_mode)

        if stchlogger:
            event = {'eventtype': 'perm',
                     'startstate': [owner, group, mode],
                     'endstate': perm,
                     'filepath': path}
            stchlogger.recordchgevent(myid, event)

        os.chown(path, perm[0], perm[1])
        os.chmod(path, perm[2])

    except OSError:
        logger.log(LogPriority.DEBUG, "Failed to set permissions on: " + str(path) + "\n")
        retval = False
    except Exception:
        raise

    return retval

def iterate(iditerator, rulenumber):
    '''Create and return a unique id number, in string format, for recording events
    in Stonix.
    
    @author: Derek Walker

    :param iditerator: int
    :param rulenumber: int
    :returns: myid (default = '0000')
    :rtype: string
@change: Breen Malmberg - 7/12/2017 - minor doc string edit; added return
        var init; added try/except

    '''

    myid = "0000"

    try:

        if len(str(rulenumber)) == 1:
            padding = "000"
        elif len(str(rulenumber)) == 2:
            padding = "00"
        elif len(str(rulenumber)) == 3:
            padding = "0"
        if iditerator < 10:
            idbase = padding + str(rulenumber) + "00"
            myid = idbase + str(iditerator)
        elif iditerator >= 10 and iditerator < 100:
            idbase = padding + str(rulenumber) + "0"
            myid = idbase + str(iditerator)
        elif iditerator >= 100 and iditerator < 1000:
            idbase = padding + str(rulenumber)
            myid = idbase + str(iditerator)

    except Exception:
        raise
    return myid

def createFile(path, logger):
    '''Create a blank file with file name = <path>, if <path>
    does not already exist.

    :param path: string representing full path to write
    :param logger: logging object
    :returns: retval
    :rtype: bool

@author: Derek Walker
@change: Breen Malmberg - 7/12/2017 - completed doc string; added return var;
        added return var init; added check to see if path already exists;
        changed the way new files get created to the canonical python way;
        changed the logging if an exception happens to just log the exception
        message itself instead of creating an artificial message; added debug
        logging about the processes of the method; changed the makedirs default
        permissions so directories will no longer be created with 777, but 755
        instead

    '''

    retval = True

    try:

        if not path:
            logger.log(LogPriority.DEBUG, "Given path is blank. Nothing to create.")
            retval = False
            return retval

        if os.path.exists(path):
            logger.log(LogPriority.DEBUG, "Path already exists. Will not overwrite it.")
            retval = False
            return retval

        parentdir, _ = os.path.split(path)

        if not parentdir:
            logger.log(LogPriority.DEBUG, "Got blank path for parent directory!")
            retval = False
            return retval
        elif not os.path.isdir(parentdir):
            logger.log(LogPriority.DEBUG, "Parent directory of file does not exist. Creating parent directory(ies)...")
            os.makedirs(parentdir, 0o755)

        try:
            open(path, 'a').close()
        except Exception as err:
            logger.log(LogPriority.DEBUG, str(err))
            retval = False

    except IOError as errmsg:
        logger.log(LogPriority.DEBUG, errmsg)
        retval = False
    except:
        raise
    return retval

def findUserLoggedIn(logger):
    '''Find the name of the logged-in user.

    :param logger: logging object
    @author: Roy Nielsen
    @change: Breen Malmberg - 7/12/2017 - completed doc string; added try/except
            and var init
    :returns: myuser
    :rtype: string

    '''

    myuser = ""
    reterr = ""
    cmds = ["/usr/bin/stat -f '%Su' /dev/console", "/usr/bin/stat -c %U /dev/console"]

    try:

        for cmd in cmds:
            myuser = ""
            reterr = ""
            (myuser, reterr) = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=False).communicate()
            if reterr:
                continue

        if myuser:
            if myuser != "?":
                logger.log(LogPriority.DEBUG, "User name is: " + myuser.strip())
            else:
                myuser = ""
                logger.log(LogPriority.DEBUG, "User name NOT FOUND")
        else:
            logger.log(LogPriority.DEBUG, "User name NOT FOUND")

    except Exception:
        raise
    myuser = myuser.strip()
    myuser = myuser.strip("'")
    return myuser

def isServerVersionHigher(client_version="0.0.0", server_version="0.0.0", logger=None):
    '''Compares two strings with potentially either 3 or 4 digits, to see which
    version is higher.
    
    WARNING: This relies on the programmer putting the SERVER VERSION in the
             last parameter.
    
    Returns - True: if version two is higher
              False: if version two is lower
                     Also returns false if the pattern \d+\.\d+\.\d+ is not met
    
    @author: Roy Nielsen

    :param client_version: string representing version of client (Default value = "0.0.0")
    :param server_version: string representing version of server (Default value = "0.0.0")
    :param logger: logging object (optional; default = None)
    @change: Breen Malmberg - 7/12/2017 - completed doc string; added try/except
    :returns: needToUpdate
    :rtype: bool

    '''

    needToUpdate = False

    try:

        client_version = str(client_version).strip()
        server_version = str(server_version).strip()

        if logger:
            def logprint(x):
                logger.log(LogPriority.DEBUG, "isServerVersion: " + x)
        else:
            def logprint(x):
                print(str(x))

        if re.match("^$", client_version) or re.match("^$", server_version):
            needToUpdate = False
        if re.match("^\s+$", client_version) or \
           re.match("^\s+$", server_version):
            needToUpdate = False
        elif not re.search("\d+\.\d+\.\d+", client_version):
            needToUpdate = False
        elif not re.search("\d+\.\d+\.\d+", server_version):
            needToUpdate = False
        else:
            logprint("\n\n\tOk so far . . .\n\n")
            logprint("cv: \"" + str(client_version) + "\"")
            logprint("sv: \"" + str(server_version) + "\"")
            needToUpdate = False
            c_vers = str(client_version).split(".")
            s_vers = str(server_version).split(".")
            if (len(c_vers) == len(s_vers)):
                """
                Lengths are equal, can compare each number without problem.
                """
                logprint("\n\n\tLengths equal:: clientver: " + str(client_version) + " serverver: " + str(server_version) + "\n\n")
                for i in range(len(c_vers)):
                    logprint("\t\ti: " + str(i) + " c_vers: " + str(c_vers[i]) + " s_vers: " + str(s_vers[i]))
                    if int(c_vers[i]) < int(s_vers[i]):
                        needToUpdate = True
                        break
                    if int(c_vers[i]) > int(s_vers[i]):
                        needToUpdate = False
                        break
                logprint("\n\n")
    
            elif (len(c_vers) > len(s_vers)):
                i = 0
                """
                Version of client is longer than server, if the first items all
                match, the version on the client is higher than on the server.
                """
                logprint("\n\n\tclient longer:: clientver: " + str(client_version) + " serverver: " + str(server_version) + "\n\n")
                for i in range(len(s_vers)):
                    logprint("\t\ti: " + str(i) + " c_vers: " + str(c_vers[i]) + " s_vers: " + str(s_vers[i]))
                    if i == len(s_vers):
                        break
                    if int(c_vers[i]) < int(s_vers[i]):
                        needToUpdate = True
                        break
                    if int(c_vers[i]) > int(s_vers[i]):
                        needToUpdate = False
                        break
                logprint("\n\n")
            elif (len(c_vers) < len(s_vers)):
                i = 0
                """
                Version of the server is longer than the version of the client.
                If the first items all match, and the server version is greater
                than 0, then the client needs to be upgraded.
                """
                logprint("\n\n\tserver longer:: clientver: " + str(client_version) + " serverver: " + str(server_version) + "\n\n")
                j = 0
                for i in range(len(c_vers)):
                    logprint("\t\ti: " + str(i) + " c_vers: " + str(c_vers[i]) + " s_vers: " + str(s_vers[i]))
                    if int(c_vers[i]) < int(s_vers[i]):
                        needToUpdate = True
                        break
                    if int(c_vers[i]) > int(s_vers[i]):
                        needToUpdate = False
                        break
                    j = i
                logprint("\n\n")
                if int(s_vers[j+1]) > 0 and needToUpdate == False:
                    needToUpdate = True
            logprint("\n\n\tneedToUpdate: " + str(needToUpdate) + "\n\n")

    except Exception:
        raise
    return needToUpdate

def versioncomp(firstver, secondver):
    '''versioncomp() is an alternate version comparison to the original
    isServerVersionHigher() function. This function takes two version strings
    as arguments. The second string is compared to the first and the results
    are based on that order. The return is a string that is one of the
    following values:
    equal - the two values are the same
    newer - the second version is a newer or higher version than the first
    older - the second version is older or lower than the first
    This function only works for purely numeric versions. e.g. 2.3.4 but not
    2.3.4B.

    :param string: firstver: the first version string
    :param string: secondver: the second version string
    :param firstver: 
    :param secondver: 
    :returns: versionis
    :rtype: string (equal | newer | older; default = equal)
@author: Dave Kennel
@change: Breen Malmberg - 7/12/2017 - minor doc string edit; added try/except;
        added return var; added return var init

    '''

    versionis = 'equal'

    try:

        if LooseVersion(secondver) == LooseVersion(firstver):
            versionis = 'equal'
        elif LooseVersion(secondver) > LooseVersion(firstver):
            versionis = 'newer'
        elif LooseVersion(secondver) < LooseVersion(firstver):
            versionis = 'older'

    except Exception:
        raise
    return versionis

def fixInflation(filepath, logger, perms, owner):
    '''this method is designed to remove newline character (\n) inflation in files
    it should not modify, nor remove any lines of actual content in the file
    return True if successful; else return False

    :param filepath: string full path to file
    :param logger: object reference logging object
    :param perms: int 4-digit octal permissions (ex: 0644 = rw, r, r)
    :param owner: list a list of 2 integers (ex: [0, 0] = root:root)
    :returns: retval
    :rtype: bool
@author: Breen Malmberg

    '''

    retval = True

    try:

        # validate all parameters; log and return if not valid
        if not logger:
            print("\nDEBUG:stonixutilityfunctions.fixInflation(): No logging parameter was passed. Cannot log.\n")
            print("DEBUG:stonixutilityfunctions.fixInflation(): Exiting method fixInflation()... Nothing was done.\n")
            retval = False
            return retval

        if not perms:
            logger.log(LogPriority.DEBUG, "Specified perms parameter was blank. Cannot proceed.")
            retval = False
            return retval

        if not isinstance(perms, int):
            paramtype = type(perms)
            logger.log(LogPriority.DEBUG, "Specified perms parameter was of type: " + str(paramtype))
            logger.log(LogPriority.DEBUG, "perms parameter must be an int! Cannot proceed.")
            retval = False
            return retval

        if not owner:
            logger.log(LogPriority.DEBUG, "Specified owner parameter was blank. Cannot proceed.")
            retval = False
            return retval

        if not isinstance(owner, list):
            paramtype = type(owner)
            logger.log(LogPriority.DEBUG, "Specified owner parameter was of type: " + str(paramtype))
            logger.log(LogPriority.DEBUG, "owner parameter must be a list! Cannot proceed.")
            retval = False
            return retval

        if not len(owner) == 2:
            numelements = len(owner)
            logger.log(LogPriority.DEBUG, "Specified owner parameter had " + str(numelements) + " elements.")
            logger.log(LogPriority.DEBUG, "owner parameter must be a list of exactly 2 elements. Cannot proceed.")
            retval = False
            return retval

        if not filepath:
            logger.log(LogPriority.DEBUG, "Specified filepath parameter was blank. Nothing to fix!")
            retval = False
            return retval

        if not isinstance(filepath, str):
            paramtype = type(filepath)
            logger.log(LogPriority.DEBUG, "Specified filepath parameter was of type: " + str(paramtype))
            logger.log(LogPriority.DEBUG, "filepath parameter must be a string! Cannot proceed.")
            retval = False
            return retval

        if not os.path.exists(filepath):
            logger.log(LogPriority.DEBUG, "Specified filepath does not exist. Nothing to fix!")
            retval = False
            return retval

        # read the file's contents into a list (contentlines)
        logger.log(LogPriority.DEBUG, "Reading file contents from: " + str(filepath))
        f = open(filepath, 'r')
        contentlines = f.readlines()
        f.close()

        # init variables to defaults
        i = 0
        newcontentlines = []
        blanklinesremoved = 0

        # only allow a maximum of 1 full blank line between lines with actual content
        # remove all extra blank lines; keep all lines with content in them (all non-blank)
        logger.log(LogPriority.DEBUG, "Removing extra blank lines from (de-flating) file contents...")
        for line in contentlines:
            if re.search('^\s*\n$', line):
                i += 1
                if i >= 2:
                    blanklinesremoved += 1
                else:
                    newcontentlines.append(line)
            else:
                newcontentlines.append(line)
                i = 0

        # write the de-flated contents out to the file
        # preserve the original/intended/specified ownership and permissions
        # preserve security context if applicable
        logger.log(LogPriority.DEBUG, "Writing de-flated contents to file: " + str(filepath))
        f = open(filepath, 'w')
        f.writelines(newcontentlines)
        f.close()
        logger.log(LogPriority.DEBUG, "Removed " + str(blanklinesremoved) + " blank lines from file: " + str(filepath) + ". File should now be de-flated.")
        os.chown(filepath, owner[0], owner[1])
        os.chmod(filepath, perms)
        resetsecon(filepath)

    except Exception as err:
        logger.log(LogPriority.ERROR, "stonixutilityfunctions.fixInflation(): " + str(err))
        retval = False
    return retval

def validateParam(logger, param, ptype, pname):
    '''check whether a param is of the given type
    return True if type matches
    return False if type does not match

    :param logger: logging object
    :param param: any; variable to check
    :param ptype: object base type
    :param pname: string; name of variable being passed (for logging purposes)
    :returns: valid
    :rtype: bool
@author: Breen Malmberg
@change: Breen Malmberg - 7/12/2017 - minor doc string edit

    '''

    valid = True
    log = True

    try:

        if not logger:
            print("No logging object was passed to method validateParam. Printing to console instead...")
            log = False

        if not pname:
            valid = False
            if log:
                logger.log(LogPriority.DEBUG, "Parameter pname was blank or None!")
            else:
                print("Parameter pname was blank or None!")
            return valid
        if not param:
            log = False
        if not ptype:
            log = False

        if not isinstance(param, ptype):
            valid = False
            if log:
                logger.log(LogPriority.DEBUG, "Parameter: " + str(pname) + " needs to be of type " + str(ptype) + ". Got: " + str(type(param)))
            else:
                print("One or more passed parameters was not specified or was an invalid type!")

    except Exception as errmsg:
        if log:
            logger.log(LogPriority.ERROR, str(errmsg))
        else:
            print(str(errmsg))
    return valid

def reportStack(level=1):
    filename = inspect.stack()[level][1]
    functionName = str(inspect.stack()[level][3])
    lineNumber = str(inspect.stack()[level][2])
    '''  
    print("----------------")
    print(filename)
    print(functionName) 
    print(lineNumber)   
    '''
    return filename + " : " + functionName + " : " + lineNumber + " : "

def psRunning(ps):
    '''check whether a process identified by the given pid is
    currently running or not

    :param pid: int; process id to check
    :param ps: 
    :returns: isrunning
    :rtype: bool

@author: Breen Malmberg

    '''

    isrunning = False
    cmd = ""

    if os.path.exists("/usr/bin/lslocks"):
        cmd = "/usr/bin/lslocks"
    elif os.path.exists("/usr/sbin/lsof"):
        cmd = "/usr/sbin/lsof"
    else:
        print(("Could not determine status of process: " + str(ps)))
        return isrunning

    output, errmsg = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=False).communicate()
    if ps in output.split():
        isrunning = True

    return isrunning
