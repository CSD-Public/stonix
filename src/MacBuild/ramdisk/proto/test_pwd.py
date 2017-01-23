#!/usr/local/bin/python

import re
import pwd


all = pwd.getpwall()


for user in all:
    if not re.match("^_", user.pw_name):
        print user.pw_name


