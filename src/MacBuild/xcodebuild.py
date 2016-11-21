#!/usr/bin/python

import os
import sys
from optparse import OptionParser, SUPPRESS_HELP

from buildlib import MacBuildLib

sys.path.append('./ramdisk')

from ramdisk.lib.loggers import CyLogger
from ramdisk.lib.loggers import LogPriority as lp

class Xcodebuild(MacBuildLib):
    def __init__(self, logger, pypaths=None):
        super(Xcodebuild, self).__init__(logger, pypaths=None)

    def buildApp(self, appName, buildDir, username, password, keychain=""):
        self.setUpForSigning(username, password, keychain)
        self.buildWrapper(username, appName, buildDir)

    def sign(self, appName, username, password, signature, verbose, keychain):
        self.setUpForSigning(username, password, keychain)
        self.codeSign(username, password, signature, verbose, appName)
        

if __name__ == '__main__':

    parser = OptionParser(usage="\n\n%prog [options]\n\n", version="0.7.2")

    parser.add_option("-a", "--app-name", dest="appName",
                      default='',
                      help="Name of the application to be processed")
    parser.add_option("-u", "--user-name", dest="userName",
                      default="",
                      help="Name oName of the mountpoint you want to mount to")
    parser.add_option("-p", dest="password",
                      default="",
                      help=SUPPRESS_HELP)
    parser.add_option("-k", "--keychain", dest="keychain",
                      default="",
                      help="Full path to the keychain to use.  Default is empty.")
    parser.add_option("-c", "--codesign", action="store_true",
                      dest="codesign", default=False,
                      help="Run a codesign rather than a xcodebuild.")
    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      default=0, help="Print debug messages")
    parser.add_option("--deep", action="store_true", dest="debug",
                      default=True, help="Perform a 'deep' signing if codesigning.")
    parser.add_option("--project_directory", dest="project_directory",
                      default='', help="full path to the <project>.xcodeproj")
    parser.add_option("-s", "--signature", dest="signature",
                      default="",
                      help="Signature to sign with..")
    parser.add_option("-v", "--verbose", dest="verbose",
                      default="",
                      help="Determine verbosity if performing a codesign.")
    
    (opts, args) = parser.parse_args()
    
    log_level = ""
    if opts.debug:
        loglevel = 20
    elif opts.verbose:
        loglevel = 30
    else:
        loglevel = 40

    logger = CyLogger(level=loglevel)
    
    logger.initializeLogs()

    os.environ['DEVELOPER_DIR'] = '/Applications/Xcode.app/Contents/Developer'

    #####
    # On the other end, each character was translated by 'ord' to a number,
    # and each number was separated by a colon.  Change the password from
    # letters that have been converted to a number via the 'ord' function
    # back to the origional character
    passArray = opts.password.split(':')
    keychainPass = ""
    for orded in passArray:
        keychainPass = keychainPass + chr(int(orded)) 

    xb = Xcodebuild(logger)
    if opts.codesign:
        xb.sign(opts.appName, opts.userName, keychainPass, opts.signature, opts.verbose, opts.keychain)
    else:
        xb.buildApp(opts.appName, opts.project_directory, opts.userName, keychainPass)

    sys.exit(0)
    
