#!/usr/bin/python

from subprocess import Popen, PIPE
from tempfile import SpooledTemporaryFile as tmp

f = tmp()

f.write('\nP@SSW0rd\n')

f.seek(0)

pipe = Popen('/usr/bin/su dcsadmin -c "/usr/bin/id"', stdout=PIPE, stdin=f, bufsize=1, shell=True)
pipe.stdout.read()
pipe.stdout.read()
pipe.stdout.read()
output = pipe.stdout.readlines()
f.close()

print(output)

