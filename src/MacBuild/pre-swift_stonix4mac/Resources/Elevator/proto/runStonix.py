#!/usr/bin/python

import os
from subprocess import Popen, PIPE, STDOUT
import getpass
import tempfile

passwd = getpass.getpass('gPasswd: ')

myenv = os.environ.copy()

myenv['SUDO_ASKPASS'] = '/tmp/askpass.py'

lines = []

tmpfile_fp, tmpfile_name = tempfile.mkstemp()
tmp_fp = os.fdopen(tmpfile_fp, 'w')
second = open('/tmp/test', 'w')

second.write(tmpfile_name)
tmp_fp.write(passwd)

second.close()
tmp_fp.close()

p = Popen(['/usr/bin/sudo', '-A', '-s', '/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix -d'],
          stdout=PIPE,
          stderr=STDOUT,
          stdin=PIPE,
          shell=False,
          bufsize=0,
          env=myenv)

#p.stdin.write('\n')
#p.stdin.flush()
out = p.stdout.readline()
#while p.poll() is not None:

while out:
  line = out 
  line = line.rstrip("\n")
  lines.append(line)
  print line
  if "Password" in line:

      pr = 1 
      p.stdin.write(passwd + '\n')
      p.stdin.flush()
      out = p.stdout.readline()
      continue
  else:
      out = p.stdout.readline()
      continue

p.wait()

for line in lines:
    print line

