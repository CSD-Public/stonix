#!/usr/bin/env python

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
@author: dkennel
@change: Breen Malmberg - 5/8/2017 - added method validateParam;
        fixed a bad indentation on/near line 1329, in method
        isServerVersionHigher; (Note: many methods missing try/except
        blocks!); Removed old, commented-out isApplicable method (commented
        out by Dave Kennel - per Dave Kennel "this block can probably be safely
        removed in 0.8.17"); removed unused method iterate2
@todo: many methods missing try/except blocks!
@todo: fix doc strings and standardize them
'''

import os
from grp import getgrgid
from pwd import getpwuid
import grp
import pwd
import re
import subprocess
import traceback
import socket
import random
import stat
from types import *
from distutils.version import LooseVersion
from environment import Environment
from subprocess import call, Popen, PIPE, STDOUT
import urllib2
from logdispatcher import LogPriority

# =========================================================================== #

def resetsecon(filename):
    '''resetsecon(filename)
    Resets the SELinux security context of a file. This should be done after
    sensitive files are modified to prevent breakage due to SELinux denials.

    @param filename: Full path to the file to be reset
    @author: D. Kennel
    '''

    if os.path.exists('/sbin/restorecon'):
        call('/sbin/restorecon ' + filename + ' &> /dev/null', shell=True,
             close_fds=True)

# =========================================================================== #

def getlocalfs(logger, environ):
    '''This function is used to return a list of local filesystems. It is used
    in the FilePermissions rule among others.
    It must be passed references to the instantiated logdispatcher and
    environment objects.

    @param Object: LogDispatcher instance
    @param Object: Environment instance
    @return: List of strings that are local filesystems
    @author: dkennel
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

# =========================================================================== #
# This will become a rule or part of a rule

def importkey(logger):
    """
    importkey()

    On new installs we need to import the rpm gpg key to check package sigs.
    This function will import the key if has not been imported already. We
    don't need to do this if called in install mode because the assumption
    is that expressway has done it.
    """

    stdin, stdout, stderr = os.popen3('/bin/rpm -qi gpg-pubkey')
    isimported = stdout.read()
    stdout.close()
    stdin.close()
    stderr.close()
    if not re.search('security@redhat.com', isimported):
        if os.path.exists('/usr/share/rhn/RPM-GPG-KEY'):
            importcommand = '/bin/rpm --import /usr/share/rhn/RPM-GPG-KEY'
        elif os.path.exists('/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release'):
            importcommand = '/bin/rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release'
        else:
            logger.log(LogPriority.INFO,
                       ['importkey',
                        "Could not locate RPM GPG key. Install GPG key manually"])
            return False

        try:
            retcode = call(importcommand, shell=True)
            if retcode < 0:
                # something bad happened
                pass

        except OSError, err:
            logger.log(LogPriority.ERROR, ['StonixUtilityFunctions.importkey',
                                           err])

def write_file(logger, file_name="", file_content=""):
    '''
    Write a config file (file_content) to destination (file_name)

    Initially intended for installing scripts and plists to be controlled by
    launchd

    @author: Roy Nielsen
    '''

    # Need to make sure there is content in file_name and file_content
    if not re.match("^$", file_name) and not re.match("^$", file_content):

        try:
            fh = open(file_name, "w")
            try:
                fh.write(file_content)
            finally:
                fh.close()
        except IOError, err:
            logger.log(LogPriority.ERROR, "Error opening file: " + file_name +
                       " error: " + err)

# =========================================================================== #

def set_no_proxy():
    """
    This method described here: http://www.decalage.info/en/python/urllib2noproxy
    to create a "no_proxy" environment for python

    @author: Roy Nielsen

    """
    proxy_handler = urllib2.ProxyHandler({})
    opener = urllib2.build_opener(proxy_handler)
    urllib2.install_opener(opener)

# =========================================================================== #

def delete_plist_key(plist="", key=""):
    '''
    **** Macintosh Specific Function ****

    Delete a key from a plist file

    @param: plist - the fully qualified filename of the plist
    @param: key   - the key to delete
    @returns: in_compliance - 0 for failed to delete
                              1 for done
    @author: Roy Nielsen
    '''
    in_compliance = 0
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
        else:
            in_compliance = 0

    return in_compliance

# =========================================================================== #

def get_plist_value(plist="", key="", current_host=""):
    '''
    **** Macintosh Specific Function ****

    Get the value of a key in the plist file

    @param: plist - the fully qualified filename of the plist
    @param: key   - the key to delete
    @param: current_host = whether or not to use the -currentHost option
                           0 = don't use option
                           1 = use -currentHost option
    @returns: "-NULL-" if the key is not found,
                       otherwise, it returns the value of the key
    @author: Roy Nielsen
    '''
    # determine if the currentHost option should be used
    # use this option when reading in the user's ByHost dir
    if current_host:
        current_host = " -currentHost"
    else:
        current_host = ""

    if re.match("^$", current_host):
        cmd = ["defaults", "read", plist, key]
    else:
        cmd = ["defaults", current_host, "read", plist, key]

    # get the current value
    current_value = Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()[0]

    if re.search("does not exist$", current_value):
        current_value = "-NULL-"

    return current_value

# =========================================================================== #

def has_connection_to_server(logger, server=None, port=80, timeout=1):
    '''
    Check to see if there is a connection to a server.
    @param logger: logger object
    @param server: name of the server you want to check connection with
                   default = None
    @param port: port number you want to check connection with
                 default=80
    @param timeout: the number of seconds to wait for a timeout, can be a float.
                    default = 1 second
    @return: True if there is a connection, False if there is not.

    @author: Dave Kennel/Roy Nielsen
    '''
    resolvable = False
    if server:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((server, port))
            sock.close()
            resolvable = True
        except (socket.gaierror, socket.timeout, socket.error), err:
            resolvable = False
            logger.log(LogPriority.ERROR, "has_connection_to_server: socket \
                       error: " + str(err))
            logger.log(LogPriority.ERROR, "has_connection_to_server: server: "
                       + str(server) + " port: " + str(port) + " timeout = "
                       + str(timeout) + " Connection failed")
    else:
        logger.log(LogPriority.ERROR, "has_connection_to_server: Need a \
        non-empty server name")
    return resolvable

# =========================================================================== #

def cloneMeta(logger, originFile, destinationFile):
    '''
    Copies all permissions, ownership and security context (secon) data
    from originFile to destinationFile. This function does not work on Mac OS X
    systems.

    @param originFile: string; full file path to copy metadata from
    @param destinationFile: string; full file path to copy metadata to
    @param logger: logDispatch object; for logging
    @return: void
    @author Breen Malmberg
    '''

    # note that the stat tool is not always installed by default on all systems
    # - namely: solaris and derivations thereof

    env = Environment()

    if env.getosfamily() == 'darwin':
        return

    try:

        # clone permissions; doesn't work on mac os x
        if env.getosfamily() == 'freebsd':
            (stdout, stderr) = Popen(["stat -f %Op " + originFile], shell=True,
                                     stdout=PIPE).communicate()
        else:
            (stdout, stderr) = Popen(["stat -c %a " + originFile], shell=True,
                                     stdout=PIPE).communicate()

        if stdout and isinstance(stdout, str):

            if not re.match("^[0-9]*$", stdout):
                logger.log(LogPriority.DEBUG,
                           'Improperly formatted permissions string returned')

            formattedperms = stdout.strip()

            # the freebsd version of the stat command can only return a string
            # which contains the file type code prepended to the octal
            # permissions string we must therefor strip the preceeding file
            # type code in order to perform a chmod with it
            if len(formattedperms) > 3:
                while len(formattedperms) > 3:
                    formattedperms = formattedperms[1:]

            os.system('chmod ' + formattedperms + ' ' + destinationFile)

            # clone ownership
            (stdout, stderr) = Popen(["stat -c %U:%G " + originFile],
                                     shell=True, stdout=PIPE).communicate()

            formattedownership = stdout.strip()

            os.system('chown ' + formattedownership + ' ' + destinationFile)

            # clone secon; doesn't work on mac os x
            if env.getosfamily() != 'darwin':

                os.system('chcon --reference=' + originFile + ' ' +
                          destinationFile)

        else:

            logger.log(LogPriority.DEBUG, 'stat command failed to get ' +
                       'output. Is the stat command available on this ' +
                       'system type?')
            return

    except (OSError):
        raise
    except Exception:
        raise

# =========================================================================== #

def isWritable(logger, filepath, owner="o"):
    '''
    return true or false, depending on whether filepath is writable by owner.
    if owner is not specified, will test for world-writable.
    owner should be specified as one of the following string values:
     other
     o
     group
     g
     user
     u

    @params filepath: string; path to file to check
    @params owner: string; type of writability to check
    @params logger: logDispatch object; for logging
    @return isw
    @rtype: bool
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

# =========================================================================== #

def getOctalPerms(filepath):
    '''
    Get and return the octal format of the file permissions for filepath

    @return int
    @author Breen Malmberg
    '''

    rawresult = os.stat(filepath).st_mode

    if stat.S_ISREG(rawresult):
        octperms = oct(stat.S_IMODE(rawresult))
        while len(octperms) > 3:
                octperms = octperms[1:]
    else:
        octperms = 0

    return int(octperms)

# =========================================================================== #

def getOwnership(filepath):
    '''
    Get and return the numeric user and group owner of the filepath

    @return list of type(int)
    @author Breen Malmberg
    '''

    try:

        owner = os.stat(filepath).st_uid
        group = os.stat(filepath).st_gid

        ownership = [owner, group]

        return ownership

    except Exception:
        raise

# =========================================================================== #

def isThisYosemite(environ):
    '''
    returns true if this is OS is Mountain Lion
    @author: ekkehard j. koch
    @param self:essential if you override this definition
    @return: boolean - true if applicable false if not
    @change: 10/17/2013 Original Implementation
    '''
    osfamily = environ.getosfamily()
    operatingsystem = environ.getostype()
    osversion = environ.getosver()
    if osfamily == "darwin" and operatingsystem == 'Mac OS X':
        if osversion.startswith("10.10"):
            isYosemite = True
        else:
            isYosemite = False
    else:
        isYosemite = False
    return isYosemite

# =========================================================================== #

def isThisMavericks(environ):
    '''
    returns true if this is OS is Mavericks
    @author: ekkehard j. koch
    @param self:essential if you override this definition
    @return: boolean - true if applicable false if not
    @change: 10/17/2013 Original Implementation
    '''
    osfamily = environ.getosfamily()
    operatingsystem = environ.getostype()
    osversion = environ.getosver()
    if osfamily == "darwin" and operatingsystem == 'Mac OS X':
        if osversion.startswith("10.9"):
            isMavericks = True
        else:
            isMavericks = False
    else:
        isMavericks = False
    return isMavericks

# =========================================================================== #

def isThisMountainLion(environ):
    '''
    returns true if this is OS is Mountain Lion
    @author: ekkehard j. koch
    @param self:essential if you override this definition
    @return: boolean - true if applicable false if not
    @change: 10/17/2013 Original Implementation
    '''
    osfamily = environ.getosfamily()
    operatingsystem = environ.getostype()
    osversion = environ.getosver()
    if osfamily == "darwin" and operatingsystem == 'Mac OS X':
        if osversion.startswith("10.8"):
            isMountainLion = True
        else:
            isMountainLion = False
    else:
        isMountainLion = False
    return isMountainLion

def readFile(filepath, logger):
    '''
    Read the contents of a file.

    @author: dwalker
    @param filepath: string; path to file to read
    @param logger: logger object; for logging
    @return: contents
    @rtype: list
    @change: bgonz12 - 2017/06/02 - fixed the implementation to use std lib's
             readlines fuction, removing syntax error; moved the implementation
             into the try block
    '''

    contents = []
    try:
        f = open(filepath, 'r')
        contents = f.readlines()
        f.close()
    except IOError:
        detailedresults = "unable to open the specified file"
        detailedresults += traceback.format_exc()
        logger.log(LogPriority.DEBUG, detailedresults)
        return []
    return contents
###############################################################################

def writeFile(tmpfile, contents, logger):
    '''
    Write the string of the contents to a file.

    @author: dwalker
    @param tmpfile: string
    @param contents: string
    @param logger: logger object
    @return: success
    @rtype: bool
    @change: Breen Malmberg - 5/8/2017 - refactor to handle both
            list and string type contents parameter; no change needed
            to implementation in rules
    '''

    success = True

    try:

        w = open(tmpfile, 'w')
        if isinstance(contents, basestring):
            w.write(contents)
        elif isinstance(contents, list):
            w.writelines(contents)
        else:
            success = False
            logger.log(LogPriority.DEBUG, "Given contents was niether a string, nor a list! Could not write to file " + str(tmpfile))
        w.close()
    except Exception:
        raise
    return success

###############################################################################

def getUserGroupName(filename):
    '''
    This method gets the uid and gid string name of a file
    and stores in a list where position 0 is the owner and 
    position 1 is the group

    @author: dwalker
    @param filename: string; filename to get uid and gid name
    @return: list of uid (0) and gid (1)
    '''

    retval = []
    statdata = os.stat(filename)
    uid = statdata.st_uid
    gid = statdata.st_gid
    user = getpwuid(uid)[0]
    group = getgrgid(gid)[0]
    retval.append(user)
    retval.append(group)
    return retval
###############################################################################

def checkUserGroupName(ownergrp, owner, group, actualmode, desiredmode, logger):
    '''
    This method is usually used in conjuction with getUserGroupName.
    Returned list from getUserGroupName is passed through this method along
    with desired owner and group string name and checked to see if they match

    @author: dwalker
    @param ownergrp: list containing user/owner string name (0) and group string
        name (1)
    @param owner: Desired owner string name to check against
    @param group: Desired group string name to check against
    @param mode: Desired mode number to check against
    @param logger: Logger object
    @return: list | bool
    '''

    retval = []
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
    
#####################################################################################

def checkPerms(path, perm, logger):
    '''
    Check the given file's permissions.

    @return: retval
    @rtype: bool
    @param path: string; file path whose perm's to check
    @param perm: list; list of ownership and permissions information
    @param logger: LogDispatch object
    @author: dwalker
    @change: Breen Malmberg - 1/10/2017 - doc string edit; return val init;
            minor refactor; parameter validation; logging
    '''

    retval = True

    try:

        if not isinstance(path, basestring):
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

###############################################################################

def setPerms(path, perm, logger, stchlogger="", myid=""):
    '''
    Set the given file's permissions.

    @return: retval
    @rtype: bool
    @param path: string; full path to the file whose perms to set
    @param perm: list; integer list of permissions and ownership information
    @param logger: object; logger object
    @param stchlogger: object; statechangelogger object
    @param myid: string; indicates a unique id to assign to the action of changing perms
    @author: dwalker
    @change: Breen Malmberg - 1/10/2017 - doc string edit; minor refactor; logging;
            return var init; parameter validation
    '''

    retval = True

    try:

        if not isinstance(path, basestring):
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

###############################################################################

def iterate(iditerator, rulenumber):
    '''
    A method to create a unique id number for recording events.

    @author: dwalker
    @param iditerator: int
    @param rulenumber: int 
    @return: string
    '''

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
    return myid

###############################################################################

def createFile(path, logger):
    '''
    Method that creates a file if not present.

    @author: dwalker
    @param path: string
    @return: bool
    '''

    debug = ""
    try:
        pathdir, _ = os.path.split(path)
        if not os.path.exists(pathdir):
            os.makedirs(pathdir)
        w = open(path, "w")
        w.close()
    except IOError:
        debug += "Unable to create the file: " + path
        debug += traceback.format_exc() + "\n"
        logger.log(LogPriority.DEBUG, debug)
        return False
    return True

###############################################################################

def findUserLoggedIn(logger):
    """
    Find the name of the user logged in.

    @author: Roy Nielsen
    """
    matchpat = re.compile("^(\w+)\s+")

    (retval, reterr) = Popen(["/usr/bin/stat", "-f", "'%Su'", "/dev/console"],
                                           stdout=PIPE, stderr=PIPE,
                                           shell=False)

    theuser = matchpat.match(retval)
    myuser = theuser.group(1)
    logger.log(LogPriority.DEBUG, "User is: " + myuser, "verbose")
    return myuser

###############################################################################

def isServerVersionHigher(client_version="0.0.0", server_version="0.0.0", logger=None):
    """
    Compares two strings with potentially either 3 or 4 digits, to see which
    version is higher.
    
    WARNING: This relies on the programmer putting the SERVER VERSION in the 
             last parameter.
    
    Returns - True: if version two is higher
              False: if version two is lower
                     Also returns false if the pattern \d+\.\d+\.\d+ is not met
    """
    client_version = str(client_version).strip()
    server_version = str(server_version).strip()

    if logger :
        def logprint(x):
            logger.log(LogPriority.DEBUG, "isServerVersion: " + x)
    else :
        def logprint(x):
            print str(x)

    needToUpdate = False
    if re.match("^$", client_version) or \
       re.match("^$", server_version):
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

    return needToUpdate


def versioncomp(firstver, secondver):
    '''
    versioncomp() is an alternate version comparison to the original
    isServerVersionHigher() function. This function takes two version strings
    as arguments. The second string is compared to the first and the results
    are based on that order. The return is a string that is one of the
    following values:
    equal - the two values are the same
    newer - the second version is a newer or higher version than the first
    older - the second version is older or lower than the first
    This function only works for purely numeric versions. e.g. 2.3.4 but not
    2.3.4B.
    @param string firstver: the first version string
    @param string secondver: the second version string
    @return: string equal | newer | older
    @author: dkennel
    '''
    if LooseVersion(secondver) == LooseVersion(firstver):
        return 'equal'
    elif LooseVersion(secondver) > LooseVersion(firstver):
        return 'newer'
    elif LooseVersion(secondver) < LooseVersion(firstver):
        return 'older'


def fixInflation(filepath, logger, perms, owner):
    '''
    this method is designed to remove newline character (\n) inflation in files
    it should not modify, nor remove any lines of actual content in the file
    return True if successful; else return False

    @param filepath: string full path to file
    @param logger: object reference logging object
    @param perms: int 4-digit octal permissions (ex: 0644 = rw, r, r)
    @param owner: list a list of 2 integers (ex: [0, 0] = root:root)
    @return: retval
    @rtype: bool
    @author: Breen Malmberg
    '''

    retval = True

    try:

        # validate all parameters; log and return if not valid
        if not logger:
            print "\nDEBUG:stonixutilityfunctions.fixInflation(): No logging parameter was passed. Cannot log.\n"
            print "DEBUG:stonixutilityfunctions.fixInflation(): Exiting method fixInflation()... Nothing was done.\n"
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

        if not isinstance(filepath, basestring):
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
    '''
    check whether a param is of the given type
    return True if type matches
    return False if type does not match

    @param logger: obj; logger object
    @param param: (variable type); variable to check
    @param ptype: obj; var type obj definition
    @param pname: string; name of variable being passed (for logging purposes)
    @return: valid
    @rtype: bool
    @author: Breen Malmberg
    '''

    valid = True
    log = True

    try:

        if not logger:
            print "No logging object was passed to method validateParam. Printing to console instead..."
            log = False

        if not pname:
            valid = False
            if log:
                logger.log(LogPriority.DEBUG, "Parameter pname was blank or None!")
            else:
                print "Parameter pname was blank or None!"
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
                print "One or more passed parameters was not specified or was an invalid type!"

    except Exception, errmsg:
        if log:
            logger.log(LogPriority.ERROR, str(errmsg))
        else:
            print str(errmsg)
    return valid
