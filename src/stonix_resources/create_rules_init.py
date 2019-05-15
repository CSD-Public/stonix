#!/usr/bin/python
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

import os
import re
import sys
import optparse
import traceback
from loggers import CyLogger
from loggers import LogPriority as lp

def getRulesList(pathToRules=''):
    '''Get a directory listing of the path passed in - the stonix/rules path.
    
    @author: Roy Nielsen

    :param pathToRules:  (Default value = '')

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

    :param initFp:  (Default value = None)
    :returns: @author: Roy Nielsen

    '''
    header = ''
    header = '''# from __future__ import absolute_import
'''
    return header

def writeInit(pathToRules, logger):
    ''''Controller' to write the rules __init__.py file
    
    @author: Roy Nielsen

    :param pathToRules: 
    :param logger: 

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
