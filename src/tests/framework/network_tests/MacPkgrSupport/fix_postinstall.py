#!/usr/bin/env python3 -u
import re
import sys

f=open("postinstall", "r")
myfile = []
for line in f.readlines():
    if re.match("STAMP", line):
        myfile.append("STAMP=%s"%str(sys.argv[1]) + "\n")
    else:
        myfile.append(line)

f.close()

f=open("postinstall", "w")
for line in myfile:
    f.write(line)
f.close()


