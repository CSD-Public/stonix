###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################

#! /usr/bin/env python

'''
Created on Jan 13, 2014

This script is used by ScheduleStonix.py
This script will run stonix.py, in user context mode, once daily

@author: bemalmbe
'''

import os,time,getpass,pwd,re

#defaults
username = getpass.getuser()
userhome = ''
scriptsuccess = True

#get current user's home directory
for p in pwd.getpwall():
    if p[0] in username:
        if re.search('^/home/',p[5]) or re.search('^/Users/',p[5]):
            userhome = p[5]

todaysdate = time.strftime("%d%m%Y")
stonixscriptpath = '/usr/sbin/stonix.py'
stonixtempfolder = userhome + '/.stonix/'
alreadyran = False

#if the script has not already run today

if os.path.exists(stonixtempfolder + 'userstonix.log'):
       
    f = open(stonixtempfolder + 'userstonix.log','r')
    contentlines = f.readlines()
    f.close()
    
    for line in contentlines:
        line = line.split()
        #script log file entries should follow the format: usernameDDMMYYYY
        if re.search('^' + username,line[0]) and re.search(todaysdate,line[1]):
            alreadyran = True
    
    #if the script has not yet run today, then run it        
    if not alreadyran:
        
        try:
        
            #run stonix -f in user context
            os.system(stonixscriptpath + ' -cf')
            
        except IOError:
            exitcode = IOError.errno
            print(IOError.message)
            scriptsuccess = False
        except OSError:
            exitcode = OSError.errno
            print(OSError.message)
            scriptsuccess = False
        
        if scriptsuccess:
                    
            i = 0
            
            for line in contentlines:
                if re.search('^' + username,line) and not re.search(todaysdate,line):
                    line = username + ' ' + todaysdate
                    contentlines[i] = line
                    i += 1
            
            #create/update log entry
            f = open(stonixtempfolder + 'userstonix.log','w')
            f.writelines(contentlines)
            f.close()
        
        else:
            
            print("user-stonix.py script failed to run properly")
            exit(exitcode)