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

'''

@author: ekkehard j. koch
@change: 2014/01/06 Original implementation
@change: 2015/10/26 eball Fixed logic errors, cleaned up code
@change: 2016/01/05 eball Added a test for removal of a non-existent file
@change: 2016-02-10 roy adding sys.path.append for both test framework and 
                        individual test runs.
'''
import unittest
import os
from shutil import rmtree
import sys

sys.path.append("../../../..")
from src.stonix_resources.filehelper import FileHelper as FileHelper
import src.stonix_resources.environment as environment
import src.tests.lib.logdispatcher_lite as logdispatcher
import src.stonix_resources.StateChgLogger as StateChgLogger
from src.tests.lib.logdispatcher_lite import LogPriority


class zzzTestFrameworkfilehelper(unittest.TestCase):

    def setUp(self):
        self.environ = environment.Environment()
        self.environ.setverbosemode(True)
        self.logdispatch = logdispatcher.LogDispatcher(self.environ)
        self.state = StateChgLogger.StateChgLogger(self.logdispatch,
                                                   self.environ)
        self.homedirectory = os.path.expanduser('~')
        self.fh = FileHelper(self.logdispatch, self.state)

    def tearDown(self):
        rmtree(self.homedirectory + "/temp")

    def test_create_file_and_remove(self):
        # Attempt to remove a file that does not exist
        self.logdispatch.log(LogPriority.DEBUG,
                             "Adding non-existent file for deletion")
        addfilesuccess = self.fh.addFile("tf0", self.homedirectory +
                                         "/temp/tf0.txt", True, None, 0o444,
                                         os.getuid(), os.getegid())
        if addfilesuccess:
            self.logdispatch.log(LogPriority.DEBUG,
                                 "Fixing non-existent file")
            self.assertTrue(self.fh.fixFiles(),
                            "Fix failed for removing a non-existent file")
        # Create Files
        self.fh.removeAllFiles()
        self.files = {"tf3": {"path": self.homedirectory +
                              "/temp/temp/temp/tf3.txt",
                              "remove": False,
                              "content": None,
                              "permissions": 0o777,
                              "owner": os.getuid(),
                              "group": os.getegid()},
                      "tf2": {"path": self.homedirectory +
                              "/temp/temp/tf2.txt",
                              "remove": False,
                              "content": "This is a test",
                              "permissions": "0777",
                              "owner": "root",
                              "group": 20},
                      "tf1": {"path": self.homedirectory + "/temp/tf1.txt",
                              "remove": False,
                              "content": None,
                              "permissions": None,
                              "owner": None,
                              "group": None}
                      }
        for filelabel, fileinfo in sorted(self.files.items()):
            addfilereturn = self.fh.addFile(filelabel,
                                            fileinfo["path"],
                                            fileinfo["remove"],
                                            fileinfo["content"],
                                            fileinfo["permissions"],
                                            fileinfo["owner"],
                                            fileinfo["group"]
                                            )
            if not addfilereturn:
                addfilesuccess = False
        self.assertTrue(addfilesuccess,
                        "Initial adding of Files to FileHelper failed!")
        filescreated = self.fh.fixFiles()
        self.assertTrue(filescreated, "1st creation of Files Failed!")
        # Remove Files without removing directories
        updatefilesuccess = True
        self.files["tf1"]["remove"] = True
        self.files["tf2"]["remove"] = True
        self.files["tf3"]["remove"] = True
        for filelabel, fileinfo in sorted(self.files.items()):
            updatefilereturn = self.fh.updateFile(filelabel,
                                                  fileinfo["path"],
                                                  fileinfo["remove"],
                                                  fileinfo["content"],
                                                  fileinfo["permissions"],
                                                  fileinfo["owner"],
                                                  fileinfo["group"]
                                                  )
            if not updatefilereturn:
                updatefilesuccess = False
        self.assertTrue(updatefilesuccess,
                        "1st updating of Files to FileHelper failed!")
        filesremoval = self.fh.fixFiles()
        self.assertTrue(filesremoval, "1st removal of Files Failed!")
        self.fh.setDefaultRemoveEmptyParentDirectories(True)
        # Remove Files without removing directories
        updatefilesuccess = True
        self.files["tf1"]["remove"] = False
        self.files["tf2"]["remove"] = False
        self.files["tf3"]["remove"] = False
        for filelabel, fileinfo in sorted(self.files.items()):
            updatefilereturn = self.fh.updateFile(filelabel,
                                                  fileinfo["path"],
                                                  fileinfo["remove"],
                                                  fileinfo["content"],
                                                  fileinfo["permissions"],
                                                  fileinfo["owner"],
                                                  fileinfo["group"]
                                                  )
            if not updatefilereturn:
                updatefilesuccess = False
        filescreated = self.fh.fixFiles()
        self.assertTrue(filescreated, "2nd creation of Files Failed!")
        filesremoval = self.fh.fixFiles()
        # Remove Files with removing directories
        updatefilesuccess = True
        self.files["tf1"]["remove"] = True
        self.files["tf2"]["remove"] = True
        self.files["tf3"]["remove"] = True
        for filelabel, fileinfo in sorted(self.files.items()):
            updatefilereturn = self.fh.updateFile(filelabel,
                                                  fileinfo["path"],
                                                  fileinfo["remove"],
                                                  fileinfo["content"],
                                                  fileinfo["permissions"],
                                                  fileinfo["owner"],
                                                  fileinfo["group"]
                                                  )
            if not updatefilereturn:
                updatefilesuccess = False
        self.assertTrue(updatefilesuccess,
                        "2nd updating of Files to FileHelper failed!")
        filesremoval = self.fh.fixFiles()
        self.assertTrue(filesremoval, "2nd removal of Files Failed!")

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
    