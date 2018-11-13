#! /bin/env python

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
Created on Mar 25, 2014

Scripted setup of the tarball required to build the RPM. This should be run in
an exported tree of the source code.

@author: dkennel
'''
import os
import subprocess
import re
import optparse
import sys
import shutil


def readversion(srcpath):
    '''
    Pull the version string out of the source code. Return version as a
    string.
    '''

    papath = os.path.join(srcpath, 'stonix_resources/localize.py')
    rh = open(papath, 'r')
    fd = rh.readlines()
    rh.close()
    ver = None

    for line in fd:
        if re.search('^STONIXVERSION =', line):
            ver = line.split('=')[1]
            break
    # for some reason, the strip method
    # ver.strip('"') will not strip double quotes
    # from the string, so we will manually remove them...
    ver = ver.strip()
    ver = ver[1:][:-1]
    return ver

def checkspec(srcpath, ver):
    '''
    Check the spec file to make sure it has the right version number. Exit
    if it does not.
    '''

    print("Checking if program versions in localize and stonix.spec file match...")

    specpath = os.path.join(srcpath, 'stonix.spec')
    rh = open(specpath, 'r')
    fd = rh.readlines()
    rh.close()
    specver = None

    for line in fd:
        if re.search('^Version:', line):
            specver = line.split()[1].strip()
            break

    print("Version number in localize: " + str(ver))
    print("Version number in stonix.spec file: " + str(specver))
    if str(specver) != str(ver):
        print("Program versions specified in localize and stonix.spec files do not match")
        print("Please correct this and re-run the script")
        sys.exit(1)
    else:
        print("Versions match. Proceeding...")

def maketarball(srcpath, ver):
    '''
    Pull together the required files into a tarball.
    '''

    pathelements = srcpath.split('/')
    upone = '/'.join(pathelements[:-1])
    versionedsrc = os.path.join(upone, 'stonix-' + ver)
    shutil.copytree(srcpath, versionedsrc, symlinks=True, ignore=shutil.ignore_patterns('*.pyc', '*.ui', '.svn', 'zzz*.py'))
    tarballpath = 'stonix-' + ver + '.tgz'
    tarcmd = '/bin/tar -czvf ' + tarballpath + ' ' + versionedsrc
    tarproc = subprocess.call(tarcmd, shell=True)

def main():
    '''
    main
    '''

    myusage = 'usage: %prog [options] path to STONIX src'
    parser = optparse.OptionParser(usage=myusage)
    (options, args) = parser.parse_args()
    srcpath = None

    if len(args) == 0 or len(args) > 1:
        print 'Wrong number of arguments passed'
        sys.exit(1)
    else:
        srcpath = args[0]
    ver = readversion(srcpath)
    checkspec(srcpath, ver)
    maketarball(srcpath, ver)

if __name__ == '__main__':
    main()
