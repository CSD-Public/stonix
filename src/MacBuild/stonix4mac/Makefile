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


# This makefile creates a package or a dmg from any application
# that sits next to it
# make pkg
# make dmg

USE_PKGBUILD=1

include /usr/local/share/luggage/luggage.make

pack-stonix: l_Applications
	@sudo ${CP} -R ./build/Release/${TITLE}.app ${WORK_D}/Applications
	@sudo chown -R root:admin ${WORK_D}/Applications/${TITLE}.app
	@sudo chmod -R 775 ${WORK_D}/Applications/${TITLE}.app
	@-sudo /usr/bin/xattr -dr com.apple.quarantine ${WORK_D}/Applications/${TITLE}.app

pack-stonix-manpage: l_usr_man_man8
	@sudo ${INSTALL} -m 644  ${MANPG} ${WORK_D}/${MAN8PATH}/stonix.8
	@chmod 644 ${WORK_D}/${MAN8PATH}/stonix.8
	@sync
	@sleep 4
	@sync
	@sync

pack-stonix4mac-install :
	@sudo ${INSTALL} -m 755 ${PI} ${SCRIPT_D}/postinstall
	@sudo ${INSTALL} -m 755 ${PRE} ${SCRIPT_D}/preinstall

MYPWD=$(shell pwd)
TITLE := stonix4mac
PACKAGE_VERSION=0.9.5.0
REVERSE_DOMAIN=gov.lanl.${TITLE}.${PACKAGE_VERSION}
PI=postinstall
PRE=preinstall
MANPG=../../usr/share/man/man8/stonix.8
MAN8PATH=/usr/share/man/man8
PAYLOAD=pack-stonix \
	pack-stonix-manpage \
	pack-stonix4mac-install


