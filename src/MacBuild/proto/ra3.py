#!/usr/bin/python

import os
import fcntl
import getpass
from subprocess import Popen, PIPE  
def setNonBlocking(fd):
    """
    Set the file description of the given file descriptor to non-blocking.
    """
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)

username = raw_input("Username: ")
passwd = getpass.getpass("Password: ")

cmd = ["/usr/bin/su", "-", username, "-c", '"/bin/top -l 1"']
print str(cmd)
p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize=0, shell=True)

setNonBlocking(p.stdout)
setNonBlocking(p.stderr)

#p.stdin.write("\n")
#p.stdout.readline()
p.stdin.write(passwd)

while True:
    try:
        out1 = p.stdout.read()
    except IOError:
        continue
    else:
        break
#out1 = p.stdout.read()
#p.stdin.write("5\n")
#while True:
#    try:
#        out2 = p.stdout.read()
#    except IOError:
#        continue
#    else:
#        break

p.wait()

print p.stdout.readlines()
print p.stderr.readlines()

