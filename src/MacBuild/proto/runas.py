#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import getpass
from subprocess import Popen, PIPE, STDOUT

username = eval(input("Username: "))
passwd = getpass.getpass('gPass: ')

print(passwd)

'''
myenv = os.environ.copy()
            
myenv['SUDO_ASKPASS'] = '/tmp/askpass.py'
'''
lines = []            

command = ["/usr/bin/su", '-', username, str("-c"), '/bin/launchctl asuser rsn_local /Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix']

#proc = Popen(command, stdout=PIPE, stderr=PIPE).communicate('\n' + passwd + '\n')


#####
# Run the command
p = Popen(command,
          stdout=PIPE,
          stderr=PIPE,
          stdin=PIPE,
          shell=True,
          bufsize=0)
          #env=myenv)

#p.stdin.write('\n')
#p.stdin.flush()
out = p.stdout.readline()
#print out
#while p.poll() is not None:

while out:
  line = out
  line = line.rstrip("\n")
  lines.append(line)
  #print line
  if re.match("Password", line):
      p.stdin.write(passwd.strip())
      p.stdin.flush()
      time.sleep(.5)
      out = p.stdout.readline()
  else:
      out = p.stdout.readline()

p.wait()
