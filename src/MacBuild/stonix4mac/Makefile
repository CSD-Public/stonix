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

# This makefile creates a package or a dmg from any application
# that sits next to it
# make pkg
# make dmg

USE_PKGBUILD=1

include /usr/local/share/luggage/luggage.make

pack-stonix: l_Applications
	@sudo ${CP} -R ./dist/${TITLE}.app ${WORK_D}/Applications
	@sudo chown -R root:admin ${WORK_D}/Applications/${TITLE}.app
	@sudo chmod -R +rwx ${WORK_D}/Applications/${TITLE}.app
	@-sudo /usr/bin/xattr -dr com.apple.quarantine ${WORK_D}/Applications/${TITLE}.app


pack-stonix-manpage: l_usr_man_man8
	@sudo ${INSTALL} -m 644  ${MANPG} ${MAN8PATH}/stonix.8

pack-stonix4mac-install :
	@sudo ${INSTALL} -m 755 ${PI} ${SCRIPT_D}/postinstall
	@sudo ${INSTALL} -m 755 ${PRE} ${SCRIPT_D}/preinstall

MYPWD=$(shell pwd)
TITLE := stonix4mac
REVERSE_DOMAIN=gov.lanl.ds
PACKAGE_VERSION=0.9.5.0-1600.9.5.0-1590.9.5.0-1580.9.5.0-1570.9.5.0-1560.9.5.0-1550.9.5.0-1540.9.5.0-1530.9.5.0-1520.9.5.0-1510.9.5.0-1500.9.5.0-1490.9.5.0-1480.9.5.0-1480.9.5.0-1470.9.5.0-1460.9.5.0-1450.9.5.0-1440.9.5.0-1430.9.5.0-1420.9.5.0-1410.9.5.0-1400.9.5.0-1390.9.5.0-1380.9.5.0-1370.9.5.0-1360.9.5.0-1350.9.5.0-1340.9.5.0-1330.9.5.0-1320.9.5.0-1310.9.5.0-1300.9.5.0-1290.9.5.0-1280.9.5.0-1270.9.5.0-1260.9.5.0-1240.9.5.0-1230.9.5.0-1220.9.5.0-1210.9.5.0-1200.9.5.0-1200.9.5.0-1190.9.5.0-1180.9.5.0-1170.9.5.0-1160.9.5.0-1150.9.5.0-1140.9.5.0-1130.9.5.0-1120.9.5.0-1110.9.5.0-1110.9.5.0-1110.9.5.0-1110.9.5.0-1110.9.5.0-1110.9.5.0-1110.9.5.0-1100.9.5.0-1090.9.5.0-1080.9.5.0-1070.9.5.0-1060.9.5.0-1050.9.5.0-1050.9.5.0-1040.9.5.0-1030.9.5.0-1030.9.5.0-1030.9.5.0-1030.9.5.0-1030.9.5.0-1030.9.5.0-1030.9.5.0-1030.9.5.0-1020.9.5.0-1020.9.5.0-1020.9.5.0-1010.9.5.0-1010.9.5.0-100
PI=postinstall
PRE=preinstall
MANPG=../../usr/share/man/man8/stonix.8
MAN8PATH=/usr/share/man/man8
PAYLOAD=pack-stonix \
	pack-stonix-manpage \
	pack-stonix4mac-install


