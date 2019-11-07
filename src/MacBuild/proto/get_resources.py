#!/usr/bin/env python3

import os

origdir = os.getcwd()

os.chdir("../..")
hiddenimports = []
for root, dirs, files in os.walk("stonix_resources"):
    for file in files:
        if file.endswith(".py"):
             #print(os.path.join(root, file)) 
             hiddenimports.append(os.path.join(root, file))

os.chdir(origdir)

for hiddenimport in hiddenimports:
    print(hiddenimport)

