#! /usr/bin/env python

'''
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################
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
            print IOError.message
            scriptsuccess = False
        except OSError:
            exitcode = OSError.errno
            print OSError.message
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
            
            print "user-stonix.py script failed to run properly"
            exit(exitcode)