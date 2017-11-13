#!/usr/bin/python
import os
import getpass
from subprocess import Popen, PIPE, check_call

username = raw_input("Username: ")
passwd = getpass.getpass("passwd: ")

#cmdOne = '/usr/bin/su - ' + username + ' -c "/usr/bin/top -l 1"'
#print cmdOne
cmdTwo = ['/usr/bin/su', '-', username, '-c', '/usr/bin/top -l 1']
print cmdTwo

read, write = os.pipe()

check_call(cmdTwo, stdin=read)

os.write(write, passwd)

#p1 = Popen(cmdTwo, stdin=PIPE, shell=True).communicate(input=passwd + "\n")
#p1 = Popen(cmdTwo, stdin=PIPE)

#p1.stdin.write(passwd + '\n')

#print p1.stdout.readlines()
#print p1.stderr.readlines()


