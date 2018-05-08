#!/usr/bin/python

import getpass
import os

#user = raw_input("Username: ")
#passwd = getpass.getpass("askpass -- Password: ")

tmplink = open('/tmp/test', 'r')
passlink = tmplink.readline()
tmplink.close()

myfile = open(passlink.strip(), 'r')
tmpvar = myfile.readline()
myfile.close()

try:
    os.unlink('/tmp/test')
    os.unlink(passlink.strip())
except OSError, err:
    print str(err)
    raise err

print tmpvar.strip()

