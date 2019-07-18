#!/usr/bin/python

import os
import getpass
from subprocess import Popen, PIPE, call

def run_as(username):
    pipe = Popen(["/usr/bin/su", 'dcsadmin'], stdin=PIPE, stdout=PIPE, shell=True)

    #.communicate('Lindse4%tirling\n')
    #pipe.stdout.read()
    pipe.stdin.write('P@ssw0rd\n')
    #out, err = pipe.communicate("whoami")

    #print out

if __name__ == "__main__":
    username = input("Username: ")

    run_as(username)

