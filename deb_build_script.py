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

#!/bin/env python
"""
Created on Feb 28, 2014

build script for stonix package on debian systems

@author Breen Malmberg
@change: Breen Malmberg - 3/14/2017 - updated controltext and
        changelog text
"""

import os
import re
import shutil
import traceback

from src.stonix_resources.localize import STONIXVERSION

revision = '1'
red = False
color = ''

# get user input for variables
revision = input("Which package revision is this?\n")
red = input("Is this a red package?\n")

if red.lower() in ["y", "yes", "t", "true"]:
    color = '-red'

curruserid = os.geteuid()

# make sure user is running script with elevated privileges
if curruserid != 0:
    print("This script must be run as root or with sudo")
    quit()

print("\ncorrect uid detected\n")

stonixversion = STONIXVERSION

# specify package details for dpkg build process
controltext = '''Package: stonix''' + color + '''
Version: ''' + str(stonixversion) + '''
Architecture: all
Maintainer: STONIX Dev's <stonix-dev@lanl.gov>
Depends: python3
Section: python
Priority: extra
Description: ''' + str(stonixversion) + ''' release of STONIX hardening tool for Ubuntu
'''

print('\ncontroltext set\n')

changelogtext = str(stonixversion) + ''' BETA release notes:
http://trac.lanl.gov/cgi-bin/external/trac.cgi/wiki/STONIXreleaseNotes
'''

print('\nchangelogtext set\n')

# configuration file(s) which will be deployed by the package
conffilestext = '''/etc/stonix.conf
'''

print('\nconffilestext set\n')

copyrighttext = ''''''

print('\ncopyrighttext set\n')

# dynamically set path variables for build directory structure for STONIX
sourcedir = os.path.dirname(os.path.realpath(__file__)) + "/src/"
builddir = '/stonix-' + str(stonixversion) + color + '-' + revision + '.noarch'
pkgname = 'stonix-' + str(stonixversion) + color + '-' + revision + '.noarch.deb'
debiandir = builddir + '/DEBIAN/'
bindir = os.path.join(builddir, 'usr/bin/')
etcdir = os.path.join(builddir, 'etc/')

print('\ndirectory variables set\n')

# specify dpkg build directory structure for STONIX
filesneeded = {debiandir + 'control': controltext,
               debiandir + 'changelog': changelogtext,
               debiandir + 'copyright': copyrighttext,
               debiandir + 'conffiles' : conffilestext}

print('\nfilesneeded set\n')

try:

    # verify / create dpkg build directory structure for STONIX
    if not os.path.exists(bindir):
        os.makedirs(bindir, 0o755)
        os.chown(os.path.join(builddir, '/usr'), 0, 0)
        os.chown(bindir, 0, 0)
    if not os.path.exists(debiandir):
        os.makedirs(debiandir, 0o755)
        os.chown(debiandir, 0, 0)
    if not os.path.exists(etcdir):
        os.makedirs(etcdir, 0o755)
        os.chown(etcdir, 0, 0)

    # verify source directory for stonix files exists
    if not os.path.exists(sourcedir):
        print("Directory " + sourcedir + " not found")
        quit()

    # verify / create all files needed by dpkg to build the package
    for item in filesneeded:
        if not os.path.exists(item):
            f = open(item, 'w')
            f.write(filesneeded[item])
            f.close()
            os.chmod(item, 0o644)
        else:
            f = open(item, 'r')
            contents = f.read()
            f.close()
            if not re.search(filesneeded[item], contents):
                f = open(item, 'w')
                f.write(filesneeded[item])
                f.close()
                os.chmod(item, 0o644)

    # create stonix.conf in the build directory
    f = open(etcdir + 'stonix.conf', 'w')
    f.write('')
    f.close()
    os.chmod(etcdir + 'stonix.conf', 0o644)
    os.chown(etcdir + 'stonix.conf', 0, 0)

    # copy files to the build directory
    if not os.path.exists(bindir + 'stonix_resources'):
        shutil.copytree(sourcedir + 'stonix_resources',
                        bindir + 'stonix_resources')
    if not os.path.exists(builddir + 'usr/share/man/man8/stonix.8'):
        shutil.copytree(sourcedir + 'usr/share', builddir + '/usr/share')
        os.chmod(builddir + '/usr/share', 0o644)

    # ensure all directories and files have correct permissions
    for dirName, _, fileList in os.walk(bindir):
        fullDirName = os.path.join(os.path.abspath(bindir), dirName)
        os.chmod(fullDirName, 0o755)
        os.chown(fullDirName, 0, 0)
        for fname in fileList:
            fullFName = os.path.join(os.path.abspath(bindir), dirName, fname)
            if os.path.isfile(fullFName):
                os.chmod(fullFName, 0o644)
                os.chown(fullFName, 0, 0)
    if not os.path.exists(bindir + 'stonix.py'):
        shutil.copy2(sourcedir + 'stonix.py', bindir + 'stonix.py')
    os.chmod(bindir + 'stonix.py', 0o755)

    # create binary symlink to STONIX controller
    os.system('ln -s /usr/bin/stonix.py ' + bindir + 'stonix')

    # build package with dpkg utility
    os.system('dpkg-deb -b ' + builddir)

except OSError as err:
    print(traceback.format_exc())
    quit()
print("\n\n ==== Finished building package. Located at: " + builddir + ".deb ====\n\n")
