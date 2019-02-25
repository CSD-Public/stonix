#!/usr/bin/python
###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
import os
import re
import sys
import optparse
import traceback
from loggers import CyLogger
from loggers import LogPriority as lp

def getRulesList(pathToRules=''):
    '''
    Get a directory listing of the path passed in - the stonix/rules path.
    
    @author: Roy Nielsen
    '''
    rulesList = []
    allFilesList = os.listdir(pathToRules)
    for rule in allFilesList:
        if re.search("\.py$", rule) and not re.match("__init__\.py", rule):
            ruleClass = re.sub("\.py$", "", rule)
            rulesList.append(ruleClass)
    return rulesList

def getHeader(initFp=None):
    '''
    Return the header used in stonix files
    
    @author: Roy Nielsen
    '''
    header = ''
    header = '''###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
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
# from __future__ import absolute_import
'''
    return header

def writeInit(pathToRules, logger):
    '''
    'Controller' to write the rules __init__.py file
    
    @author: Roy Nielsen
    '''
    success = False
    try:
        header = getHeader()
        initPath = os.path.join(pathToRules, "__init__.py")
        logger.log(lp.DEBUG, "initPath: " + str(initPath))
        fp = open(initPath, 'w')
        fp.write(header)
        for rule in getRulesList(pathToRules):
            fp.write("import " + rule + "\n")
        fp.write("\n")
    except Exception, err:
        trace = traceback.format_exc() 
        logger.log(lp.DEBUG, "Traceback: " + trace)
        raise err
    else:
        success = True
        logger.log(lp.DEBUG, "Done writing init.")
    finally:
        try:
            fp.close()
        except:
            pass

    logger.log(lp.DEBUG, "\t\t.")
    logger.log(lp.DEBUG, "\t\t.")
    logger.log(lp.DEBUG, "\t\t.")
    logger.log(lp.DEBUG, "\t\t.")
    print "Attempted init creation....."
    logger.log(lp.DEBUG, "\t\t.")
    logger.log(lp.DEBUG, "\t\t.")
    logger.log(lp.DEBUG, "\t\t.")
    logger.log(lp.DEBUG, "\t\t.")

    return success

if __name__ == "__main__":
    '''
    "main" for creating a static rules/__init__.py importing all of the rules.

    @author: Roy Nielsen
    '''
    rulesPath = ''
    #####
    # Parse command line options
    parser = optparse.OptionParser()
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      default=False, help="debug mode, on or off.  Default off.")
    parser.add_option("-r", "--rules-path", action="store_true", dest="rulesPath",
                      default=False, help="Path to rules, for making rules init.")
    options, __ = parser.parse_args()
    #####
    # Instanciate and initialize a logger
    logger = CyLogger(debug_mode=options.debug)
    logger.initializeLogs()
    
    #####
    # Get the path to the rules directory
    if not rulesPath:
        pathToRules = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
    else:
        pathToRules = options.pkgPath
    
    logger.log(lp.DEBUG, "rulesPath: " + str(rulesPath))

    #####
    # Run the controller for this script
    writeInit(pathToRules, logger)
    sys.exit(0)
