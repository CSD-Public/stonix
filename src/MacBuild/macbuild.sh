#!/bin/sh

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

# ============================================================================ #
#               Filename          $RCSfile: macbuild.sh,v $
#
#               Description       Build script to use Xcode's command line 
#                                 tools, Qt, PyQt, Pyinstaller, and luggage
#                                 to create a mac stonix4mac.app and stonix.app.
#                                 stonix4mac.app facilitates running stonix.app 
#                                 (in stonix4mac.app's Resources directory) 
#                                 as the user running stonix4mac.app, or, running
#                                 stonix.app with elevated privilege.
#                                 
#               OS                Mac OS X
#               Author            Roy Nielsen
#               Last updated by   $Author: $
#               Notes             
#               Release           $Revision: 1.0 $
#               Modified Date     $Date:  $
# ============================================================================ #

#####
# REQUIRED when tarring up stuff on the Mac filesystem - 
# IF this is not done, tar will pick up resource forks from HFS+
# filesystems, and when un-archiving, create separate files
# of the resource forks and make a MESS of the filesystem.
export COPYFILE_DISABLE=true

APPVERSION="0.9.4.28"

SVN="/usr/bin/svn"
ECHO="/bin/echo"
PERL="/usr/bin/perl"
MV="/bin/mv"
RM="/bin/rm"
CP="/bin/cp"
LN="/bin/ln"
TAR="/usr/bin/tar"
PWD="/bin/pwd"
ECHOPWD=`${PWD}`
${ECHO} ${ECHOPWD}
MKDIR="/bin/mkdir"
RSYNC="/usr/bin/rsync"
SU="/usr/bin/su"
SUDO="/usr/bin/sudo"
DEFAULTS="/usr/bin/defaults"
CHMOD="/bin/chmod"
CHOWN="/usr/sbin/chown"
HDIUTIL="/usr/bin/hdiutil"
SYNC="/bin/sync"
SLEEP="/bin/sleep"
ZIP="/usr/bin/zip"
MD5="/sbin/md5"
MKTEMP="/usr/bin/mktemp"
SED="/usr/bin/sed"

ONE="/Users/Shared/PyQt/PyQt-mac-gpl-4.10.3/pyuic/pyuic4"
TWO="/Users/Shared/Frameworks/PyQt-mac-gpl-4.9.6/pyuic/pyuic4"
THREE="/Users/Shared/Frameworks/PyQt/PyQt-mac-gpl-4.10.4/pyuic/pyuic4"
FOUR="/Users/Shared/Frameworks/PyQt/PyQt-mac-gpl-4.11.3/pyuic/pyuic4"
if [ -e ${ONE} ]
then
    PYUIC="/Users/Shared/PyQt/PyQt-mac-gpl-4.10.3/pyuic/pyuic4"
elif [ -e ${TWO} ]
then
    PYUIC="/Users/Shared/Frameworks/PyQt-mac-gpl-4.9.6/pyuic/pyuic4"
elif [ -e ${THREE} ]
then
    PYUIC=${THREE}
elif [ -e ${FOUR} ]
then
    PYUIC=${FOUR}
fi

_ONE_="/usr/local/bin/pyi-makespec"
_TWO_="/Users/Shared/Frameworks/pyinstaller/PyInstaller-2.1/utils/makespec.py"
if [ -e ${_ONE_} ]
then
    PYINSTALLER_MAKESPEC=${_ONE_}
    PYINSTALLER_BUILD="/usr/local/bin/pyi-build"
elif [ -e ${_TWO_} ]
then
    PYINSTALLER_MAKESPEC=${_TWO_}
    PYINSTALLER_BUILD="/Users/Shared/Frameworks/pyinstaller/PyInstaller-2.1/utils/build.py"
fi

#####
# Create version number - either with svn # or without
pushd ..
#if [ $1 != "" ] 
#then
#    BUILDVERSION=`${SVN} update 2>>/dev/null | grep "At revision" | awk '{ print $3 }' | awk -F"." '{print $1}'`
#    APPVERSION="${APPVERSION}.${BUILDVERSION}"
#else
    BUILDVERSION="1"
#fi

${ECHO} " "
${ECHO} " "
${ECHO} "   ******************************************************************"
${ECHO} "   ******************************************************************"
${ECHO} "   ***** App Version: ${APPVERSION}"
${ECHO} "   ******************************************************************"
${ECHO} "   ******************************************************************"
${ECHO} " "
${ECHO} " "    
popd

STONIX="stonix"
STONIXICON="stonix_icon"
STONIXVERSION=${APPVERSION}

STONIX4MAC="stonix4mac"
STONIX4MACICON="stonix_icon"
STONIX4MACVERSION=${APPVERSION}

function checkBuildUser ()
{

    ############################################################################
    ############################################################################
    ##### 
    ##### Check build user has UID of 0
    ##### 
    ############################################################################
    ############################################################################

	${ECHO} "Starting checkBuildUser..."

    #####
    # Get logged in user
    CURRENT_USER=`/usr/bin/stat -f "%Su" /dev/console`
	
    #####
    # get the uid of $CURRENT_USER
    RUNNING_ID=`/usr/bin/id -u`
    ${ECHO} "id: "${RUNNING_ID}

    if [[ "${RUNNING_ID}" != "0" ]]; then
        ${ECHO} " "
        ${ECHO} "****************************************"
        ${ECHO} "***** Currnet logged in user: "${CURRENT_USER}
        ${ECHO} "***** Please run with SUDO "
        ${ECHO} "****************************************"
        ${ECHO} " "
        exit -1
    else
        ${ECHO} "***** Currnet logged in user: "${CURRENT_USER}
    fi

    ${ECHO} "checkBuildUser Finished..."
}

function compileStonix4MacAppUiFiles ()
{

    ############################################################################
    ############################################################################
    ##### 
    ##### compile the .ui files to .py files for stonix4mac.app
    ##### 
    ############################################################################
    ############################################################################

    pushd $1

    ${ECHO} "Starting compileStonix4MacAppUiFiles..."
    ${ECHO} ${PWD}

    ###################################################
    # to compile the .ui files to .py files:
    ${ECHO} "Compiling Qt ui files to python files, for stonix4mac.app..."
    ${PYUIC} admin_credentials.ui > admin_credentials_ui.py
    ${PYUIC} general_warning.ui > general_warning_ui.py
    ${PYUIC} stonix_wrapper.ui > stonix_wrapper_ui.py

    popd

    ${ECHO} "compileStonix4MacAppUiFiles Finished..."
}

function setProgramArgumentsVersion ()
# D. Kennel 2014/08/20 - This now sets the version into localize.py
{
    ${ECHO} "Starting sed for versions in program_arguments.py..."

    SEDSTRING="s/^STONIXVERSION =.*$/STONIXVERSION = \'${APPVERSION}\'/"
    ${SED} -i .bak "${SEDSTRING}" ../stonix_resources/localize.py

    ${ECHO} "Finished sed for versions in program_arguments.py..."
		
}

function switchTmpDisk ()
{
    ${ECHO} "Starting sed for temporary disk..."

    if [ ! -e "$TMPHOME/the_luggage" ]; then
        ${MKDIR} "$TMPHOME/the_luggage"
    else
        if [ ! -d "$TMPHOME/the_luggage" ]; then
            TMPFILE=`${MKTEMP} -d $TMPHOME/the_luggage.XXXXXXXXXXXX`
            ${MV} $TMPHOME/the_luggage ${TMPFILE}
            ${MKDIR} $TMPHOME/the_luggage
        fi
    fi

    ls -lah $TMPHOME	
    printSeperator


    ${ECHO} "Putting the ramdisk into the Makefile"
    SEDLINE="s:LUGGAGE_TMP\S+:LUGGAGE_TMP=${TMPHOME}/the_luggage:"
    ${PERL} -pe ${SEDLINE} Makefile > Makefile.new
    ${RM} Makefile
    ${MV} Makefile.new Makefile

    ${ECHO} ". . . . . . . . . . . . ."
    printSeperator
    ${ECHO} "Finished sed for versions in program_arguments.py..."
}

function compileStonixAppUiFiles ()
{
    ############################################################################
    ############################################################################
    ##### 
    ##### compile the .ui files to .py files for stonix.app
    ##### 
    ##### STONIX UI files have been hand modified, so don't compile them!
    ##### 
    ##### 
    ############################################################################
    ############################################################################

    pushd $1

    ${ECHO} "Starting compileStonixAppUiFiles..."
    
    ###################################################
    # to compile the .ui files to .py files:
    #	${ECHO} "Compiling Qt ui files to python files, for stonix4mac.app..."
    #	${PYUIC} 
    #	${PYUIC} 

    popd

    ${ECHO} "compileStonixAppUiFiles Finished..."
}

function prepStonixBuild ()
{
    ############################################################################
    ############################################################################
    ##### 
    ##### Copy stonix source to app build directory
    ##### 
    ############################################################################
    ############################################################################

    ${ECHO} "Starting prepStonixBuild..."

    #####
    # Make sure the "stonix" directory exists, so we can put
    # together and create the stonix.app
    if [ ! -e "stonix" ]; then
        ${MKDIR} "stonix"
    else
        TMPFILE=`${MKTEMP} -d ../stonix.XXXXXXXXXXXX`
        ${MV} stonix ${TMPFILE}
        ${MKDIR} stonix
    fi
	
    ${CP} ../stonix.py stonix
    ${RSYNC} -ap --exclude=".svn" --exclude="*.tar.gz" --exclude="*.dmg" ../stonix_resources ./stonix

    ${ECHO} "prepStonixBuild Finished..."

}

function compileApp ()
{
    ############################################################################
    ############################################################################
    ##### 
    ##### Compiling stonix4mac.app
    ##### 
    ############################################################################
    ############################################################################

    APPNAME=$1
    APPVERSION=$2
    APPICON=$3

    ${ECHO} "Started compileApp with ${APPNAME}, ${APPVERSION}, ${APPICON}"

    pushd ${APPNAME}
			
    rm -rf build
    rm -rf dist

    ###################################################
    # to compile a pyinstaller spec file for app creation:
    ${ECHO} "Creating a pyinstaller spec file for the project..."
    ${PYINSTALLER_MAKESPEC} -w ${APPNAME}.py --noupx --strip --paths="stonix_resources/rules:stonix_resources" -i ../${APPICON}.icns
	
    ###################################################
    #to build:
    ${ECHO} "Building the app..."
    ${PYINSTALLER_BUILD} -y --clean --workpath=/tmp ${APPNAME}.spec

    SEDSTRING="s/\d+\.\d+\.\d+/${APPVERSION}/"
    ${PERL} -pe "${SEDSTRING}" ./dist/${APPNAME}.app/Contents/Info.plist > dist/${APPNAME}.app/Contents/Info.plist.new
    ${RM} ./dist/${APPNAME}.app/Contents/Info.plist
    ${MV} ./dist/${APPNAME}.app/Contents/Info.plist.new ./dist/${APPNAME}.app/Contents/Info.plist
 
    #####
    # Change version string of the app
    #${ECHO} "Changing .app version string..."
    ${DEFAULTS} rename ${ECHOPWD}/${APPNAME}/dist/${APPNAME}.app/Contents/Info CFBundleShortVersionString ${APPVERSION}

    #####
    # Change icon name in the app
    #${ECHO} "Changing .app icon..."
    ${DEFAULTS} rename ${ECHOPWD}/${APPNAME}/dist/${APPNAME}.app/Contents/Info CFBundleIconFile ${APPICON}.icns

    #####
    # Copy icons to the resources directory
    ${CP} ../${APPICON}.icns ./dist/${APPNAME}.app/Contents/Resources
	
    #####
    # Change mode of Info.plist to 664
    ${CHMOD} 755 ./dist/${APPNAME}.app/Contents/Info.plist

    popd

    ${ECHO} "compileApp with $APPNAME, $APPVERSION Finished..."

}

function buildStonix4MacAppResources ()
{
    ############################################################################
    ############################################################################
    ##### 
    ##### Copy and/or create all necessary files to the Resources directory 
    ##### of stonix4mac.app
    ##### 
    ############################################################################
    ############################################################################

    APPNAME=$1
    mypwd=${PWD}
    #{ECHO} "pwd: "$mypwd

    ${ECHO} "Started buildStonix4MacAppResources with \"${APPNAME}\" in "${mypwd}"..."

    ###################################################
    # Copy source to app dir
    ${RSYNC} -ap --exclude=".svn"  --exclude="*.tar.gz" --exclude="*.dmg" "../stonix_resources" "./stonix/dist/stonix.app/Contents/MacOS"
    #${RSYNC} -ap --exclude=".svn" "../stonix_resources" "./stonix/dist/stonix.app/Contents/Resources"
    mypwd=${PWD}
    ${ECHO} "pwd: "${mypwd}

    #####
    # Copy stonix.app to the stonix4mac Resources directory
    ${RSYNC} -ap --exclude=".svn"  --exclude="*.tar.gz" --exclude="*.dmg" ./stonix/dist/stonix.app ./${APPNAME}/dist/${APPNAME}.app/Contents/Resources
    # Copy stonix.conf to the stonix.app's Resources directory
    ${CP} ../etc/stonix.conf ./${APPNAME}/dist/${APPNAME}.app/Contents/Resources/stonix.app/Contents/Resources
    ${RSYNC} -ap ./stonix/dist/stonix.app/Contents/MacOS/stonix_resources/localize.py ./${APPNAME}/dist/${APPNAME}.app/Contents/MacOS
    mypwd=${PWD}
    ${ECHO} "pwd: "${mypwd}
    ${ECHO} "buildStonix4MacAppResources Finished..."

}

function copyResourcesToStonixApp ()
{

    #####
    # For future needs...
    ${ECHO} "this is just a placeholder for now..."

    mypwd=${PWD}
    ${ECHO} "pwd: "${mypwd}
}

function tarAndBuildStonix4MacAppPkg ()
{

    ################################################################################
    ################################################################################
    ##### 
    ##### Archive, build installer package and wrap into a dmg:
    ##### stonix4mac.app
    #####
    ################################################################################
    ################################################################################

    APPNAME=$1
    APPVERSION=$2
	
    ${ECHO} "Started tarAndBuildStonix4MacApp..."
    mypwd=${PWD}
    ${ECHO} "pwd: "${mypwd}
		
    #####
    # Make sure the "tarfiles" directory exists, so we can archive
    # tarfiles of the name $APPNAME-$APPVERSION.app.tar.gz there
    if [ ! -e "tarfiles" ]; then
       ${MKDIR} "tarfiles"
    else
        if [ ! -d "tarfiles" ]; then
            TMPFILE=`${MKTEMP} -d ../tarfiles.XXXXXXXXXXXX`
            ${MV} tarfiles ${TMPFILE}
            ${MKDIR} tarfiles
        fi
    fi
	
    #####
    # tar up the app and put it in the tarfiles directory
    ${ECHO} "Tarring up the app & putting the tarfile in the ../tarfiles directory"
    pushd ./${APPNAME}/dist
    mypwd=${PWD}
    ${ECHO} "pwd: "${mypwd}
    # ${TAR} czf ../../tarfiles/${APPNAME}-${APPVERSION}.app.tar.gz ${APPNAME}.app
    popd
    mypwd=${PWD}
    ${ECHO} "pwd: "${mypwd}
		
    ###################################################
    # to create the package
    pushd ${APPNAME}
    ${ECHO} "Putting new version into Makefile..."
    SEDLINE="s/PACKAGE_VERSION=\d+\.\d+\.\d+/PACKAGE_VERSION=${APPVERSION}/"
    ${PERL} -pe ${SEDLINE} Makefile > Makefile.new
    ${RM} Makefile
    ${MV} Makefile.new Makefile

    mytmphomedir=${TMPHOME}

    IFS=/ read -a mydirs <<< "${mytmphomedir}"

    fulldir=""

    for d in "${mydirs[@]}"
    do
       fulldir=${fulldir}\\\/"$d"
    done

    echo ${fulldir}


    # ${ECHO} "Putting the ramdisk into the Makefile"
    # SEDLINE="s:LUGGAGE_TMP\S+:LUGGAGE_TMP=${fulldir}:"
    # ${PERL} -pe ${SEDLINE} Makefile > Makefile.new
    # ${RM} Makefile
    # ${MV} Makefile.new Makefile

    if [ ! -e "../dmgs" ]; then
        ${MKDIR} "../dmgs"
    else
        if [ ! -d "../dmgs" ]; then
            TMPFILE=`${MKTEMP} -d ../dmgs.XXXXXXXXXXXX`
            ${MV} ../dmgs ${TMPFILE}
            ${MKDIR} ../dmgs
        fi
    fi
	
    if [ ! -e "${TMPHOME}/the_luggage" ]; then
        ${MKDIR} "${TMPHOME}/the_luggage"
    else
        if [ ! -d "${TMPHOME}/the_luggage" ]; then
            TMPFILE=`${MKTEMP} -d ${TMPHOME}/the_luggage.XXXXXXXXXXXX`
            ${MV} ${TMPHOME}/the_luggage ${TMPFILE}
            ${MKDIR} ${TMPHOME}/the_luggage
        fi
    fi

    ${ECHO} "Creating a .dmg file with a .pkg file inside for installation purposes..."
    ${SUDO} make dmg PACKAGE_VERSION=${APPVERSION} USE_PKGBUILD=1 LUGGAGE_TMP=${TMPHOME}/the_luggage
    ${ECHO} "Moving the dmg to the dmgs directory."
    ${MV} ${APPNAME}-${APPVERSION}.dmg ../dmgs

    popd

    ${ECHO} "tarAndBuildStonix4MacApp... Finished"
	
}

function makeSelfUpdatePackage ()
{
    pushd dmgs

    #####
    # Mount the dmg
    ${HDIUTIL} attach ${STONIX4MAC}-${STONIX4MACVERSION}.dmg

    #####
    # Copy the pkg to the local directory for processing
    ${CP} -a /Volumes/${STONIX4MAC}-${STONIX4MACVERSION}/${STONIX4MAC}-${STONIX4MACVERSION}.pkg ${STONIX4MAC}.pkg
    ${CP} -a /Volumes/${STONIX4MAC}-${STONIX4MACVERSION}/${STONIX4MAC}-${STONIX4MACVERSION}.pkg .

    #####
    # Make sure the copy is finished and hd sync'd
    ${SLEEP} 1
    ${SYNC}
    ${SLEEP} 1
    ${SYNC}
    ${SLEEP} 1
    ${SYNC}
    ${SLEEP} 1
    ${SYNC}
    ${SLEEP} 1            
    
    #####
    # Eject the dmg
    ${HDIUTIL} eject /Volumes/${STONIX4MAC}-${STONIX4MACVERSION}

    #####
    # Zip up the pkg - this will be what is served for self-update
    ${ZIP} -r ${STONIX4MAC}.zip ${STONIX4MAC}.pkg

    #####
    # Create the MD5 file - used to ensure package downloads without problem
    # (NOT FOR SECURITY'S SAKE)
    ${MD5} -q ${STONIX4MAC}.zip > ${STONIX4MAC}.md5.txt

    #####
    # Create the version file to put up on the server
    ${ECHO} ${STONIX4MACVERSION} > ${STONIX4MAC}.version.txt
    
    popd
}

###############################################################################
###############################################################################
###############################################################################
#####
##### Print a seperator . . .
#####
###############################################################################
###############################################################################
###############################################################################
function printSeperator () 
{
    ${ECHO} "    . . ."
    ${ECHO} "    . . ."
    ${ECHO} "    . . ."
}


###############################################################################
###############################################################################
###############################################################################
#####
##### Logical script start
#####
###############################################################################
###############################################################################
###############################################################################

#####
# Check that user building stonix has uid 0
checkBuildUser

#####
# Create temp home directory for building with pyinstaller
DIRECTORY=`env | grep HOME | perl -pe 's/HOME=//'`

TMPHOME=`${MKTEMP} -d -q /tmp/${CURRENT_USER}.XXXXXXXXXXXX`
export HOME=${TMPHOME}
${CHMOD} 755 ${TMPHOME}

printSeperator
pwd
printSeperator

# Create a ramdisk and mount it to the ${TMPHOME}  Not yet ready for prime time
DEVICE=`./setup_ramdisk.py -m ${TMPHOME} -s 2600`
${ECHO} "Device for tmp ramdisk is: "${DEVICE}

printSeperator
pwd
printSeperator

#####
# Copy src dir to /tmp/<username> so shutil doesn't freak about long filenames...
# ONLY seems to be a problem on Mavericks..
pushd ../..
${RSYNC} -ap --exclude=".svn"  --exclude="*.tar.gz" --exclude="*.dmg" src ${TMPHOME}


printSeperator

#####
# capture current directory, so we can copy back to it..
START_BUILD_DIR=${PWD}
${ECHO} "Start Build Dir: "${START_BUILD_DIR}

#####
# Keep track of the directory we're starting from...
pushd ${TMPHOME}/src/MacBuild
${ECHO} "TMPHOME: "${PWD}


printSeperator

#####
# Compile .ui files to .py files
# compileStonixAppUiFiles STONIX
compileStonix4MacAppUiFiles ${STONIX4MAC}


printSeperator

# Change the versions in the program_arguments.py in both stonix and stonix4mac
setProgramArgumentsVersion

# Copy stonix source to scratch build directory
prepStonixBuild


printSeperator

#####
# Compile the two apps...
compileApp ${STONIX} ${STONIXVERSION} ${STONIXICON}
compileApp ${STONIX4MAC} ${STONIX4MACVERSION} ${STONIX4MACICON}


printSeperator

#####
# Restore the HOME environment variable
export HOME=\"${DIRECTORY}\"

#####
# Copy and create all neccessary resources to app Resources dir
buildStonix4MacAppResources ${STONIX4MAC}
# copyResourcesToStonixApp


printSeperator
${ECHO} "PWD: "`pwd`
printSeperator

#####
# change the luggage build directory
switchTmpDisk

#####
# tar up build & create dmg with luggage
tarAndBuildStonix4MacAppPkg ${STONIX4MAC} ${STONIX4MACVERSION}

printSeperator
${ECHO} "PWD: "`pwd`
printSeperator


printSeperator

makeSelfUpdatePackage

printSeperator
${ECHO} "PWD: "`pwd`
printSeperator


cd ${TMPHOME}

#####
# chown so it's readable by everyone, writable by the group
${SUDO} ${CHOWN} -R ${CURRENT_USER} src
${SUDO} ${CHMOD} -R g+w src


printSeperator

#####
# Copy back to psudo-build directory
tempfoo=`basename $0`
TMPFILE=`${MKTEMP} -q /tmp/${tempfoo}.XXXXXX`
ECHO "TMPFILE: "${TMPFILE}
${ECHO} "#!/bin/bash" > ${TMPFILE}

printSeperator
${ECHO} "PWD: "`pwd`
printSeperator

printSeperator

LAST_RSYNC_COMMAND=${RSYNC}" -ap "${TMPHOME}"/src "${START_BUILD_DIR}

printSeperator

${ECHO} ${RSYNC}" -ap "${TMPHOME}"/src "${START_BUILD_DIR} >> ${TMPFILE}
${ECHO} "/bin/echo \"Done with rsync...\"" >> ${TMPFILE}
${CHMOD} 775 ${TMPFILE} 
${SU} - ${CURRENT_USER} -c ${TMPFILE}

printSeperator
${ECHO} "PWD: "`pwd`
printSeperator

printSeperator


#####
# Return to the start dir...
popd
popd

#####
# Eject the ramdisk.. Not yet ready for prime time
./detach_ramdisk.py -D ${DEVICE}


printSeperator

${ECHO} " "
${ECHO} " "
${ECHO} "    Done building stonix4mac.app..."
${ECHO} " "
${ECHO} " "

