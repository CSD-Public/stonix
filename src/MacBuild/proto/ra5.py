#!/usr/bin/env python3

import os
import getpass

username = eval(input("Username: "))
passwd = getpass.getpass("Password: ")

cmd = 'su ' + username + ' -c "/bin/top -l 1"'
print(cmd)

p = os.popen(cmd, 'w')

test = p.write(passwd+ "\n")

print(test)



