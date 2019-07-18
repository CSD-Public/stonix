#!/usr/bin/python
import sys
sys.path.append('..')
import getpass
import ramdisk
from ramdisk.lib.loggers import CyLogger
from ramdisk.lib.loggers import LogPriority as lp
from ramdisk.lib.manage_keychain.manage_keychain import ManageKeychain

passwd = getpass.getpass("Password: ")
keychain = input("Keychain: ")

logger = CyLogger(debug_mode=True)
print(str(logger))
logger.initializeLogs()
mk = ManageKeychain(logger)
success = False
if (mk.lockKeychain(allKeychains=True)):
    success, _ = mk.unlockKeychain(passwd, keychain)

print("Success: " + str(success))



