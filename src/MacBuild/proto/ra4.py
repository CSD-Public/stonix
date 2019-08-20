#!/usr/bin/env python3 -u

import os
import sys
import getpass
from subprocess import Popen, PIPE

username = input("Username: ")
passwd = getpass.getpass("Password: ")
print(username)
print(passwd)

cmdOne = ["/usr/bin/su", username.strip(), '-c', '/usr/bin/id']
oneout = open('oneout', 'wb')
oneerr = open('oneerr', 'wb')

onePipe = Popen(cmdOne, stdout=oneout, stderr=oneerr, stdin=PIPE, shell=True, bufsize=0)

#onePipe.stdout.readline()
#onePipe.stdout.readline()
line = oneout.read()
onePipe.stdin.write(passwd)

print(line)

#onePipe.stdout.readline()

#onePipe.stdout.flush()
#onePipe.stdin.write(passwd + "\n")

#onePipe.wait()

    
