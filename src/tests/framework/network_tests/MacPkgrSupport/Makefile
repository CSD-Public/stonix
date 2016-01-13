# This makefile creates a package or a dmg from any application
# that sits next to it
# see:
#   http://luggage.apesseekingknowledge.net/usage
#   https://github.com/unixorn/luggage/blob/master/examples/firefox/Makefile
#   http://glarizza.posterous.com/an-intro-to-using-the-luggage-for-packaging
#   /usr/local/share/luggage/luggage.make
# make pkg
# make dmg

include /usr/local/share/luggage/luggage.make

TITLE=testStonixMacPkgr
MYVERS=0.0.3
PACKAGE_VERSION=${MYVERS}
REVERSE_DOMAIN=gov.lanl.${TITLE}.${MYVERS}
PERL="/usr/local/bin/perl"
TOUCH="/usr/bin/touch"
MKD="/bin/mkdir"

pack-macpkgr-files: 
	./fix_postinstall.py ${TITLE}-${MYVERS}
	@sudo ${MKD} -p ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/two/three/3.5
	@sudo ${MKD} -p ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/two/four/five
	@sudo ${MKD} -p ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/six/seven
	@sudo ${CP} testfile ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/two/testfile1
	@sudo ${CP} testfile ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/two/four/five/testfile2
	@sudo ${CP} testfile ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/testfile3
	@sudo ${CP} testfile ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/testfile4
	@sudo ${CP} testfile ${WORK_D}/tmp/${TITLE}-${MYVERS}/one/six/seven/

pack-macpkgr-postinstall: pack-macpkgr-files
	@sudo ${INSTALL} -m 755 ./postinstall ${SCRIPT_D}

PAYLOAD=\
	pack-macpkgr-files \
	pack-macpkgr-postinstall 

