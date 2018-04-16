#!/usr/bin/env python
'''
Created on Oct 18, 2011
Miscellaneous utility functions.
@author: dkennel
'''

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


import os
from grp import getgrgid
from pwd import getpwuid
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
# from twisted.python.procutils import which

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
    """importkey()

    On new installs we need to import the rpm gpg key to check package sigs.
    This function will import the key if has not been imported already. We
    don't need to do this if called in install mode because the assumption
    is that expressway has done it."""

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

    @param originFile: full file path to copy metadata from
    @param destinationFile: full file path to copy metadata to

    @author bemalmbe
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


def iterate2(idbase, iterator):
    '''
    take inputs iterator and idbase and dynamically create and output a
    properly formatted id string for use with 'event' dictionaries used in
    the undo() methods of each class/rule in Dylan

    @params idbase integer
    @params iterator integer

    @return int myid

    @author bemalmbe
    '''

    # #USE CASE 1 (<)
    # idbase = 01230
    # iterator = 1
    # if 5 < (7 - 1) = 5 < 6; true
    # i = (7 - (5 + 1) = 7 - 6 = 1
    # idbase = idbase + ('0' * 1) = 012300 = 6 characters
    # myid = idbase + iterator = 7 characters = 0123001

    # #USE CASE 2 (>=)
    # idbase = 01230000
    # iterator = 1
    # if 8 > (7 - 1); if 8 > 6; if idbase is greater than formatlen - len(iterator)
    # i = 8 - 7 = 1 + 1 = 2
    # idbase = idbase - 2 character = 6 characters = 012300
    # myid = idbase + iterator = 7 characters = 0123001

    iterator = str(iterator).strip()
    idbase = str(idbase).strip()
    formatlen = 7

    if len(idbase) < (formatlen - len(iterator)):
        i = (formatlen - (len(idbase) + len(iterator)))
        idbase = idbase + ('0' * i)

    elif len(idbase) >= (formatlen - len(iterator)):
        i = (len(idbase) - formatlen) + len(iterator)
        idbase = idbase.replace(' ', '')[:-i]

    myid = idbase + iterator
    myid = int(myid)

    return str(myid)

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

    @params filepath string
    @params owner string
    @params logger object
    @return bool
    @author bemalmbe
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
    @author bemalmbe
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
    @author bemalmbe
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

# =========================================================================== #
# Commented out by D. Kennel. Replaced by isApplicable method in template class
# this block can probably be safely removed in 0.8.17.

# def isApplicable(environ, whitelist=[], blacklist=[]):
#     '''
# <<<<<<< HEAD
#     checks if current os is either white or blacklisted
# =======
#     see if osfamily, operatingsystem, osversion are in the whitelist and not
#     in the blacklist
# >>>>>>> origin/develop
#     @author: ekkehard j. koch
#     @param enivron - the environment object
#     @param whitelist: list of string or dictionary
#     {0: osfamily,1: operatingsystem, 2: osversion}
#     @param blacklist: list of string or dictionary
#     {0: osfamily,1: operatingsystem, 2: osversion}
#     @return: boolean - true if applicable false if not
#     @change: 12/18/2013 - ekkehard - Original Implementation
#     @change: 07/23/2014 - ekkehard - added operating list processing to
#     white and black lists
#     @change: 2014/12/16 - dkennel - Fixed bug that was exposed by fix in
#     environment.getosver()
#     '''
# # Did we get a list for the whitelist?
#     vartype = type(whitelist)
#     if not vartype == ListType:
#         raise TypeError("whitelist = " +
#                         str(whitelist) +
#                         " is not a " + str(ListType) +
#                         " but a " + str(vartype) + ".")
# # Did we get a list for the blacklist?
#     vartype = type(blacklist)
#     if not vartype == ListType:
#         raise TypeError("blacklist = " +
#                         str(blacklist) +
#                         " is not a " + str(ListType) +
#                         " but a " + str(vartype) + ".")
# # What are we running on
#     osfamily = environ.getosfamily()
#     operatingsystem = environ.getostype()
#     osversion = environ.getosver()
# # Intitialize inWhiteList and inBlackList
#     inWhitlist = False
#     inBlacklist = False
# # Evaluate what we got and what we need to do
#     if whitelist == [] and blacklist == []:
#         processWhiteList = False
#         processBlackList = False
#     elif not whitelist == [] and not blacklist == []:
#         processWhiteList = True
#         processBlackList = True
#     elif not whitelist == []:
#         processWhiteList = True
#         processBlackList = False
#     elif not blacklist == []:
#         processWhiteList = False
#         processBlackList = True
#     else:
#         processWhiteList = False
#         processBlackList = False
# # Process the white list
#     if processWhiteList:
#         for item in whitelist:
#             wlosfamily = ""
#             wloperatingsytem = ""
#             wlosversion = None
#             wldictinary = None
#             itemtype = type(item)
#             if itemtype == StringType:
#                 wlosfamily = item
#                 if wlosfamily == osfamily:
#                     inWhitlist = True
#                     break
#             elif itemtype == DictType:
#                 wldictinary = item
# # Check out white list osfamily entry in dictionary needs to be string
#                 try:
#                     wlosfamily = wldictinary["0"]
#                 except(KeyError):
#                     wlosfamily = ""
#                 vartype = type(wlosfamily)
#                 if not vartype == StringType:
#                     raise TypeError("whitelist osfamily = " + \
#                                     str(wlosfamily) + \
#                                     " is not a " + str(StringType) + \
#                                     " but a " + str(vartype) + ".")
#                 elif not wlosfamily == "":
#                     if osfamily == wlosfamily:
#                         wlosfamilyIsApplicable = True
#                     else:
#                         wlosfamilyIsApplicable = False
#                 else:
#                     wlosfamilyIsApplicable = True
# # Check out white list operatingsystem entry in dictionary needs to be string
#                 try:
#                     wloperatingsytem = wldictinary["1"]
#                 except(KeyError):
#                     wloperatingsytem = ""
#                 vartype = type(wloperatingsytem)
#                 if vartype == ListType:
#                     for listitem in wloperatingsytem:
#                         vartype = type(listitem)
#                         if not vartype == StringType:
#                             raise TypeError("whitelist osversion " + \
#                                             str(operatingsystem) + \
#                                             " list item = " + str(listitem) + \
#                                             " is not a " + str(StringType) + \
#                                             " but a " + str(vartype) + ".")
#                     if not wloperatingsytem == []:
#                         wloperatingsytemIsApplicable = False
#                         for ver in wloperatingsytem:
#                             myver = str(ver)
#                             if re.match("^%s" % myver, str(operatingsystem)):
#                                 wloperatingsytemIsApplicable = True
#                     else:
#                         wloperatingsytemIsApplicable = True
#                 elif not vartype == StringType:
#                     raise TypeError("whitelist operatingsystem = " + \
#                                     str(wloperatingsytem) + \
#                                     " is not a " + str(StringType) + \
#                                     " but a " + str(vartype) + ".")
#                 elif not wloperatingsytem == "":
#                     if wloperatingsytem == operatingsystem:
#                         wloperatingsytemIsApplicable = True
#                     else:
#                         wloperatingsytemIsApplicable = False
#                 else:
#                     wloperatingsytemIsApplicable = True
# # Check out white list operatingsystem entry in dictionary needs to be string
#                 try:
#                     wlosversion = wldictinary["2"]
#                 except(KeyError):
#                     wlosversion = ""
#                 vartype = type(wlosversion)
#                 if vartype == StringType:
#                     if not wlosversion == "":
#                         mywlosversion = str(wlosversion)
#                         if re.match("^%s" % mywlosversion, str(osversion)):
#                             wlosversionIsApplicable = True
#                         else:
#                             wlosversionIsApplicable = False
#                     else:
#                         wlosversionIsApplicable = True
#                 elif vartype == ListType:
#                     for listitem in wlosversion:
#                         vartype = type(listitem)
#                         if not vartype == StringType:
#                             raise TypeError("whitelist osversion " + \
#                                             str(wlosversion) + \
#                                             " list item = " + str(listitem) + \
#                                             " is not a " + str(StringType) + \
#                                             " but a " + str(vartype) + ".")
#                     if not wlosversion == []:
#                         wlosversionIsApplicable = False
#                         for ver in wlosversion:
#                             myver = str(ver)
#                             myverlist = myver.split(".")
#                             osversionlist = str(osversion).split(".")
#                             counter = 0
#                             myvernumber = int(myverlist[counter])
#                             osversionnumber = int(osversionlist[counter])
#                             numbersequal = True
#                             for myveritem in myverlist:
#                                 myvernumber = int(myveritem)
#                                 if counter <= len(osversionlist):
#                                     try:
#                                         osversionnumber = int(osversionlist[counter])
#                                     except (IndexError):
#                                         numbersequal = False
#                                         continue
#                                 else:
#                                     numbersequal = False
#                                     continue
#                                 if not myvernumber == osversionnumber:
#                                     numbersequal = False
#                                 counter = counter + 1
#                             if numbersequal:
#                                 wlosversionIsApplicable = True
#                     else:
#                         wlosversionIsApplicable = True
#                 else:
#                     raise TypeError("whitelist osversion = " + \
#                                     str(wlosversion) + \
#                                     " is not a " + str(StringType) + \
#                                     " or a " + str(ListType) + \
#                                     " but a " + str(vartype) + ".")
# # if osfamily and operintingsystem and osversion are applicable it is in
# # whitelist
#                 if wlosfamilyIsApplicable and wloperatingsytemIsApplicable and wlosversionIsApplicable:
#                     inWhitlist = True
#                     break
#             else:
#                 raise TypeError("whitelist item = " + \
#                                     str(item) + \
#                                     " is not a " + str(StringType) + \
#                                     " or a " + str(DictType) + \
#                                     " but a " + str(itemtype) + ".")
# # Process the Black list
#     if processBlackList:
#         inBlacklist = False
#         for item in blacklist:
#             blosfamily = ""
#             bloperatingsytem = ""
#             blosversion = None
#             bldictinary = None
#             itemtype = type(item)
#             if itemtype == StringType:
#                 if item == osfamily:
#                     inBlacklist = True
#                     break
#             elif itemtype == DictType:
#                 bldictinary = item
# # Check out white list osfamily entry in dictionary needs to be string
#                 try:
#                     blosfamily = bldictinary["0"]
#                 except(KeyError):
#                     blosfamily = ""
#                 vartype = type(blosfamily)
#                 if not vartype == StringType:
#                     raise TypeError("blacklist osfamily = " + \
#                                     str(blosfamily) + \
#                                     " is not a " + str(StringType) + \
#                                     " but a " + str(vartype) + ".")
#                 elif not blosfamily == "":
#                     if osfamily == blosfamily:
#                         blosfamilyIsApplicable = True
#                     else:
#                         blosfamilyIsApplicable = False
#                 else:
#                     blosfamilyIsApplicable = True
# # Check out white list operatingsystem entry in dictionary needs to be string
#                 bloperatingsytem = bldictinary["1"]
#                 vartype = type(bloperatingsytem)
#                 if vartype == ListType:
#                     for listitem in bloperatingsytem:
#                         vartype = type(listitem)
#                         if not vartype == StringType:
#                             raise TypeError("whitelist osversion " + \
#                                             str(operatingsystem) + \
#                                             " list item = " + str(listitem) + \
#                                             " is not a " + str(StringType) + \
#                                             " but a " + str(vartype) + ".")
#                     if not bloperatingsytem == []:
#                         bloperatingsytemIsApplicable = False
#                         for ver in bloperatingsytem:
#                             myver = str(ver)
#                             if re.match("^%s" % myver, str(operatingsystem)):
#                                 bloperatingsytemIsApplicable = True
#                     else:
#                         bloperatingsytemIsApplicable = True
#                 elif not vartype == StringType:
#                     raise TypeError("blacklist operatingsystem = " + \
#                                     str(bloperatingsytem) + \
#                                     " is not a " + str(StringType) + \
#                                     " but a " + str(vartype) + ".")
#                 elif not bloperatingsytem == "":
#                     if bloperatingsytem == operatingsystem:
#                         bloperatingsytemIsApplicable = True
#                     else:
#                         bloperatingsytemIsApplicable = False
#                 else:
#                     bloperatingsytemIsApplicable = True
# # Check out white list operatingsystem entry in dictionary needs to be string
#                 blosversion = bldictinary["2"]
#                 vartype = type(blosversion)
#                 if vartype == StringType:
#                     if not blosversion == "":
#                         myblosversion = str(blosversion)
#                         if re.match("^%s" % myblosversion, str(osversion)):
#                             blosversionIsApplicable = True
#                         else:
#                             blosversionIsApplicable = False
#                     else:
#                         blosversionIsApplicable = True
#                 elif vartype == ListType:
#                     for listitem in blosversion:
#                         vartype = type(listitem)
#                         if not vartype == StringType:
#                             raise TypeError("blacklist osversion " +
#                                             str(blosversion) +
#                                             " list item = " + str(listitem) +
#                                             " is not a " + str(StringType) +
#                                             " but a " + str(vartype) + ".")
#                     if not blosversion == []:
#                         blosversionIsApplicable = False
#                         for ver in blosversion:
#                             myver = str(ver)
#                             myverlist = myver.split(".")
#                             osversionlist = str(osversion).split(".")
#                             counter = 0
#                             myvernumber = int(myverlist[counter])
#                             osversionnumber = int(osversionlist[counter])
#                             numbersequal = True
#                             for myveritem in myverlist:
#                                 myvernumber = int(myveritem)
#                                 if counter <= len(osversionlist):
#                                     try:
#                                         osversionnumber = int(osversionlist[counter])
#                                     except (IndexError):
#                                         numbersequal = False
#                                         continue
#                                 else:
#                                     numbersequal = False
#                                     continue
#                                 if not myvernumber == osversionnumber:
#                                     numbersequal = False
#                                 counter = counter + 1
#                             if numbersequal:
#                                 blosversionIsApplicable = True
#                     else:
#                         blosversionIsApplicable = True
#                 else:
#                     raise TypeError("blacklist osversion = " + \
#                                     str(blosversion) + \
#                                     " is not a " + str(StringType) + \
#                                     " or a " + str(ListType) + \
#                                     " but a " + str(vartype) + ".")
# # if osfamily and operintingsystem and osversion are applicable it is in
# # whitelist
#                 if blosfamilyIsApplicable and bloperatingsytemIsApplicable and blosversionIsApplicable:
#                     inBlacklist = True
#                     break
#             else:
#                 raise TypeError("blacklist item = " + \
#                                     str(item) + \
#                                     " is not a " + str(StringType) + \
#                                     " or a " + str(DictType) + \
#                                     " but a " + str(itemtype) + ".")
# 
# # See if isApplicable is valid due to the whitlist
#     if processWhiteList and inWhitlist:
#         isApplicableWhiteList = True
#     elif processWhiteList and not inWhitlist:
#         isApplicableWhiteList = False
#     elif not processWhiteList:
#         isApplicableWhiteList = True
# 
# # See if isApplicable is valid due to the blacklist
#     if processBlackList and inBlacklist:
#         isApplicableBlackList = False
#     elif processBlackList and not inBlacklist:
#         isApplicableBlackList = True
#     elif not processBlackList:
#         isApplicableBlackList = True
# 
# # Let's see what we should return
#     if isApplicableWhiteList and isApplicableBlackList:
#         isApplicableValue = True
#     else:
#         isApplicableValue = False
# 
#     return isApplicableValue

###############################################################################


def readFile(filepath, logger):
    '''Read the contents of a file.
    @author: dwalker
    @param filepath: string
    @param logger: logger object
    @return: list  '''
    contents = []
    try:
        f = open(filepath, 'r')
    except IOError:
        detailedresults = "unable to open the specified file"
        detailedresults += traceback.format_exc()
        logger.log(LogPriority.DEBUG, detailedresults)
        return []
    for line in f:
        contents.append(line)
    f.close()
    return contents
###############################################################################


def writeFile(tmpfile, contents, logger):
    '''Write the string of the contents to a file.
    @author: dwalker
    @param tmpfile: string
    @param contents: string
    @param logger: logger object
    @return: bool'''
    debug = ""
    try:
        w = open(tmpfile, "w")
    except IOError:
        debug += "unable to open the specified file\n"
        debug += traceback.format_exc()
        logger.log(LogPriority.DEBUG, debug)
        return False
    try:
        w.write(contents)
    except IOError:
        debug += "unable to write to the specified file\n"
        debug += +traceback.format_exc() + "\n"
        logger.log(LogPriority.DEBUG, debug)
        return False
    w.close()
    return True
###############################################################################

def getUserGroupName(filename):
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

def checkPerms(path, perm, logger):
    '''Check the current file's permissions.
    @author: dwalker
    @param path: string
    @param perm: list
    @param param: logger object
    @return: bool  '''
    debug = ""
    try:
        statdata = os.stat(path)
        owner = statdata.st_uid
        group = statdata.st_gid
        mode = stat.S_IMODE(statdata.st_mode)
        if owner != perm[0] or group != perm[1] or mode != perm[2]:
            debug += "The following file has incorrect permissions:" + path + "\n"
            logger.log(LogPriority.DEBUG, debug)
            return False
        else:
            return True
    except OSError:
        debug = "unable to check permissions on: " + path + "\n"
        logger.log(LogPriority.DEBUG, debug)
        return False
###############################################################################


def setPerms(path, perm, logger, stchlogger="", myid=""):
    '''Set the current file's permissions.
    @author: dwalker
    @param path: string
    @param perm: list
    @param logger: logger object
    @param stchlogger: state change logger object
    @param myid: string
    @return: bool  '''
    debug = ""
    try:
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
        return True
    except OSError:
        debug += "couldn't set the permissions on: " + path + "\n"
        logger.log(LogPriority.DEBUG, debug)
        return False
###############################################################################


def iterate(iditerator, rulenumber):
    '''A method to create a unique id number for recording events.
    @author: dwalker
    @param iditerator: int
    @param rulenumber: int 
    @return: string '''
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
    '''Method that creates a file if not present.
    @author: dwalker
    @param path: string
    @return: bool '''
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
    return retval
