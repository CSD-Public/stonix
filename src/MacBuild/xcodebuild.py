#!/usr/bin/python

import os
import sys
import traceback
from optparse import OptionParser, SUPPRESS_HELP

from buildlib import MacBuildLib

sys.path.append('./ramdisk')

from ramdisk.lib.loggers import CyLogger
from ramdisk.lib.loggers import LogPriority as lp

class Xcodebuild(MacBuildLib):
    def __init__(self, logger, pypaths=None):
        super(Xcodebuild, self).__init__(logger, pypaths=None)

    def buildApp(self, appName, buildDir, username, password, keychain=""):
        if not password:
            if self.buildWrapper(username, appName, buildDir):
                self.logger.log(lp.DEBUG, "Built package without signing...")
            else:
                self.logger.log(lp.DEBUG, "Error attempting to build package without signing...")
                raise Exception(traceback.format_exc())
        elif self.setUpForSigning(username, password, keychain):
            if self.buildWrapper(username, appName, buildDir, keychain):
                self.logger.log(lp.DEBUG, "Signing completed...")
            else:
                self.logger.log(lp.DEBUG, "buildWrapper failed...")
                raise Exception(traceback.format_exc())
        else:
            self.logger.log(lp.DEBUG, "setUpForSigning failed...")
            raise Exception(traceback.format_exc())

        xb.sign(opts.parentOfItemToBeProcessed, opts.itemName, opts.userName, keychainPass, opts.signature, opts.verbose, opts.keychain)

    def sign(self, psd, itemName, username, password, signature, verbose, keychain):
        self.setUpForSigning(username, password, keychain)
        self.codeSign(psd, username, password, signature, verbose, deep=True, itemName=itemName, keychain=keychain)

if __name__ == '__main__':

    parser = OptionParser(usage="\n\n%prog [options]\n\n", version="0.7.2")

    parser.add_option("-i", "--item-name", dest="itemName",
                      default='',
                      help="Name of the item to be processed")
    parser.add_option("-u", "--user-name", dest="userName",
                      default="",
                      help="Name oName of the mountpoint you want to mount to")
    parser.add_option("-p", dest="password",
                      default="",
                      help=SUPPRESS_HELP)
    parser.add_option("--psd", dest="parentOfItemToBeProcessed",
                      default="",
                      help="Parent directory of the item to be signed.")
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

    logger.log(lp.DEBUG, "Logger initialized")

    os.environ['DEVELOPER_DIR'] = '/Applications/Xcode.app/Contents/Developer'

    if opts.password:
        #####
        # On the other end, each character was translated by 'ord' to a number,
        # and each number was separated by a colon.  Change the password from
        # letters that have been converted to a number via the 'ord' function
        # back to the origional character
        passArray = opts.password.split(':')
        keychainPass = ""
        for orded in passArray:
            keychainPass = keychainPass + chr(int(orded)) 
        kechainPass = keychainPass.strip()
    else:
        keychainPass = False
    
    if keychainPass:
        logger.log(lp.DEBUG, "Pass grokked...")
    else:
        logger.log(lp.DEBUG, "Pass NOT grokked...")
        
    xb = Xcodebuild(logger)
    if opts.codesign:
        xb.sign(opts.parentOfItemToBeProcessed, opts.itemName, opts.userName, keychainPass, opts.signature, opts.verbose, opts.keychain)
    else:
        xb.buildApp(opts.itemName, opts.parentOfItemToBeProcessed, opts.userName, keychainPass, opts.keychain)

    sys.exit(0)
    
