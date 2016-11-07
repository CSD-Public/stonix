#!/usr/bin/python

import os
import tempfile

from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp

def getStonixAdminPlist(logger, cmd=[]):
    '''
    Create a launchjob plist for running stonix, create a temporary directory
    for it and launch it from there.
    
    @param: List of the full stonix command to run.
    
    @returns: full path to the plist written.
    
    @author: Roy Nielsen
    '''
    #####
    # Construct the header and footer of the plist
    stonixPlistHeader = '''<?xml version="1.0" encoding="UTF-8"?>''' + \
                        '''\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">''' + \
                        '''\n<plist version="1.0">''' + \
                        '''\n<dict>\n\t<key>Label</key>''' + \
                        '''\n\t<string>gov.lanl.stonix.report</string>''' + \
                        '''\n\t<key>ProgramArguments</key>''' + \
                        '''\n\t<array>'''

    stonixPlistFooter = '''\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>''' + \
                        '''\n</dict>\n</plist>'''

    #####
    # Build the plist
    stonixPlist = stonixPlistHeader
    for arg in cmd:
        stonixPlist += """\n\t\t<string>""" + arg + """</string>"""
    stonixPlist += stonixPlistFooter

    #####
    # Get a tempfilename
    fileDescriptor, stonixPlistFilename = tempfile.mkstemp(suffix=".plist", prefix='gov.lanl.stonix.')
    #####
    # Write the contents of the plist to the file
    os.write(fileDescriptor, stonixPlist)
    os.close(fileDescriptor)
    
    logger.log(lp.DEBUG, "stonixPlistFilename: " + str(stonixPlistFilename))

    #####
    # Return the full path filename of the plist
    return stonixPlistFilename


logger = CyLogger(debug_mode=True)

logger.initializeLogs()

plistPath = getStonixAdminPlist(logger, ['/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix', '-dv', '-G'])

logger.log(lp.INFO, "path is: " + str(plistPath))


