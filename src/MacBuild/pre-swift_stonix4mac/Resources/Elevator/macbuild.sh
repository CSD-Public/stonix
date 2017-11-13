#!/bin/sh

#####
# Set this variable to exclude file resource forks from
# tar archives.
export COPYFILE_DISABLE=true

APPNAME="elevator"
APPVERSION="0.9.5"

PERL="/usr/bin/perl"
MV="/bin/mv"
RM="/bin/rm"
ECHO="/bin/echo"
CP="/bin/cp"
TAR="/usr/bin/tar"
PWD="/bin/pwd"
MKDIR="/bin/mkdir"
MKTEMP="/usr/bin/mktemp"
SUDO="/usr/bin/sudo"
MAKE="/usr/bin/make"
CS="/usr/bin/codesign"

#PYUIC="/usr/local/bin/pyuic5"

PYINSTALLER_MAKESPEC="/usr/local/bin/pyi-makespec"
PYINSTALLER_BUILD="/usr/local/bin/pyinstaller"

#PYINSTALLER_MAKESPEC="/opt/tools/pyinstaller-snapshot/PyInstaller/building/makespec.py"
#PYINSTALLER_BUILD="/opt/tools/pyinstaller-snapshot/PyInstaller/building/build_main.py"

###################################################
# Set these variables to make sure pyinstaller can
# find the tool libraries to build PyQt5 applications
export PYTHONPATH=/opt/tools/lib/Python/2.7/site-packages:/opt/tools/lib/Python/2.7/site-packages/PyQt5:/opt/tools/lib/Qt5.6.1/lib:/opt/tools/lib/Python/2.7/site-packages/sip:$PYTHONPATH
export DYLD_LIBRARY_PATH=/opt/tools/lib/Qt5.6.1/lib:/opt/tools/lib/Python/2.7/site-packages:/opt/tools/lib/Python/2.7/site-packages/PyQt5:/opt/tools/lib/Python/2.7/site-packages/sip:/lib:/usr/lib:/usr/local/lib:$DYLD_LIBRARY_PATH
export DYLD_FRAMEWORK_PATH=/opt/tools/lib/Qt5.6.1/lib:/opt/tools/lib/Python/2.7/site-packages:/opt/tools/lib/Python/2.7/site-packages/PyQt5:/opt/tools/lib/Python/2.7/site-packages/sip:/lib:/usr/lib:/usr/local/lib:$DYLD_FRAMEWORK_PATH
export LD_FRAMEWORK_PATH=/opt/tools/lib/Qt5.6.1/lib:/opt/tools/lib/Python/2.7/site-packages:/opt/tools/lib/Python/2.7/site-packages/PyQt5:/opt/tools/lib/Python/2.7/site-packages/sip:/lib:/usr/lib:/usr/local/lib:$LD_FRAMEWORK_PATH
export LD_LIBRARY_PATH=/opt/tools/lib/Qt5.6.1/lib:/opt/tools/lib/Python/2.7/site-packages:/opt/tools/lib/Python/2.7/site-packages/PyQt5:/opt/tools/lib/Python/2.7/site-packages/sip:/usr/lib:/lib:/usr/local/lib:$LD_LIBRARY_PATH

PYUIC="/opt/tools/bin/pyuic5"

#####
# Change version string in Lanl_Fv2.py
${ECHO} "Changing version string in Lanl_Fv2..."
SEDSTRING="s/\d+\.\d+\.\d+/$APPVERSION/"
${PERL} -pe ${SEDSTRING} ./${APPNAME}.py > ./${APPNAME}.py.new
$RM ./${APPNAME}.py
$MV ./${APPNAME}.py.new ./${APPNAME}.py

###################################################
# to compile the UI:
${ECHO} "Compiling Qt ui files to a python files..."
${PYUIC} elevator.ui > elevator_ui.py
${PYUIC} general_warning.ui > general_warning_ui.py

###################################################
# to compile a pyinstaller spec file for app creation:
${ECHO} "Creating a pyinstaller spec file for the project..."
#/Users/Shared/Frameworks/pyinstaller/pyinstaller-dev/utils/Makespec.py -w $APPNAME.py
#${PYINSTALLER_MAKESPEC} -w ${APPNAME}.py --noupx 
#${PYINSTALLER_MAKESPEC}  -D -d --noupx -i oxLock.icns -w -p /opt/tools/lib/Python/2.7/site-packages/PyQt5:/opt/tools/Qt5.6.1/lib:/opt/tools/lib/Python/2.7/site-packages:/opt/tools/lib/Python/2.7/site-packages/sip/PyQt5:/opt/tools/bin:/usr/lib --hidden-import=general_warning --hidden-import=run_commands --osx-bundle-identifier gov.lanl.PNpass ./${APPNAME}.py &> pyinstaller_makespec.log
${PYINSTALLER_MAKESPEC}  -D -d --noupx -i check.icns -w -p /opt/tools/lib/Python/2.7/site-packages/PyQt5:/opt/tools/Qt5.6.1/lib:/opt/tools/lib/Python/2.7/site-packages:/opt/tools/lib/Python/2.7/site-packages/sip/PyQt5:/opt/tools/bin:/usr/lib --osx-bundle-identifier gov.lanl.elevator ./${APPNAME}.py &> pyinstaller_makespec.log
###################################################
#to build:

# SET THE APP VERSION IN THE SPEC FILE

${ECHO} "Building the app..."
#/Users/Shared/Frameworks/pyinstaller/pyinstaller-dev/utils/Build.py -y $APPNAME.spec 
#${PYINSTALLER_BUILD} -y --clean --workpath=/tmp ${APPNAME}.spec --onefile
${PYINSTALLER_BUILD} -y --clean ${APPNAME}.spec --log-level=DEBUG &> pyinstaller_build.log 

#/Users/Shared/Frameworks/pyinstaller-beta/pyinstaller/utils/Build.py -y $APPNAME.spec 
echo "Copying necessary files to the Resources directory..."
# $CP -a ~/QtSDK/Desktop/Qt/4.8.1/gcc/lib/QtGui.framework/Resources/qt_menu.nib dist/$APPNAME.app/Contents/Resources/

######
# edit the .app's Info.plist & change the default value for CFBundleIconFile to your icon file (must be an icns file)
${ECHO} "Replacing string in Info.plist for the new icon..."
${PERL} -pe 's/icon-windowed/oxLock/' ./dist/${APPNAME}.app/Contents/Info.plist > dist/${APPNAME}.app/Contents/Info.plist.new
${RM} ./dist/${APPNAME}.app/Contents/Info.plist
${MV} ./dist/${APPNAME}.app/Contents/Info.plist.new ./dist/${APPNAME}.app/Contents/Info.plist

${ECHO} "Changing .app version string..."
SEDSTRING="s/\d+\.\d+\.\d+/${APPVERSION}/"
${PERL} -pe ${SEDSTRING} ./dist/${APPNAME}.app/Contents/Info.plist > dist/${APPNAME}.app/Contents/Info.plist.new
${RM} ./dist/${APPNAME}.app/Contents/Info.plist
${MV} ./dist/${APPNAME}.app/Contents/Info.plist.new ./dist/${APPNAME}.app/Contents/Info.plist

#####
# Copy icons to the resources directory
${CP} oxLock.icns ./dist/${APPNAME}.app/Contents/Resources

#####
# Sign the app before packaging:
SIGNING_OUTPUT=`sudo ${CS} -vvvv --deep -f -s 'Mac Developer: Roy Nielsen (9UJTCVZ7C3)' -r='designated => anchor trusted' ./dist/PNpass.app`

#####
# Make sure the "tarfiles" directory exists, so we can archive
# tarfiles of the name $APPNAME-$APPVERSION.app.tar.gz there
if [ ! -e "../tarfiles" ]; then
    mkdir "../tarfiles"
else
    if [ ! -d "../tarfiles" ]; then
        TMPFILE=`${MKTEMP} -d ../tarfiles.XXXXXXXXXXXX`
        mv ../tarfiles ${TMPFILE}
        mkdir ../tarfiles
    fi
fi

#####
# tar up the app and put it in the tarfiles directory
#${ECHO} "Tarring up the app & putting the tarfile in the ../build directory"
#cd dist; ${PWD}; ${TAR} czvf ../../tarfiles/${APPNAME}-${APPVERSION}.app.tar.gz ${APPNAME}.app; cd ..

#######
# Section NOT applicable to this app....
###################################################
# to create the package
#${ECHO} "Putting new version into Makefile..."
#SEDLINE="s/PACKAGE_VERSION=\d+\.\d+\.\d+/PACKAGE_VERSION=${APPVERSION}/"
#${PERL} -pe ${SEDLINE} Makefile > Makefile.new
#${RM} Makefile
#${MV} Makefile.new Makefile
#
#if [ ! -e "../dmgs" ]; then
#    mkdir "../dmgs"
#else
#    if [ ! -d "../dmgs" ]; then
#        TMPFILE=`${MKTEMP} -d ../dmgs.XXXXXXXXXXXX`
#        mv ../dmgs ${TMPFILE}
#        mkdir ../dmgs
#    fi
#fi
#
#${ECHO} "Creating a .dmg file with a .pkg file inside for installation purposes..."
#${SUDO} ${MAKE} dmg
#${ECHO} "Moving the dmg to the ../dmgs directory."
#${MV} ${APPNAME}-${APPVERSION}.dmg ../dmgs
#

