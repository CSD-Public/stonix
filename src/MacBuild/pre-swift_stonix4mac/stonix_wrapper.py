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

# ============================================================================ #
#               Filename          $RCSfile: run_commands.py,v $
#               Description       Class controlling gui that asks what user
#                                 you want to run Stonix as -- user running the
#                                 app, or an admin user.
#               OS                Mac OS X
#               Author            Roy Nielsen
#               Last updated by   $Author: $
#               Notes             
#               Release           $Revision: 1.0 $
#               Modified Date     $Date:  $
# ============================================================================ #

from stonix_wrapper_ui import Ui_StonixWrapper

####
# System Libraries
import os
import sys
import time
from subprocess import Popen, PIPE, call

# PyQt libraries
#from PyQt4.QtGui import QDialog, QMessageBox
#from PyQt4.QtCore import SIGNAL
#from PyQt4.QtCore import *
#from PyQt4.QtGui import *

from PyQt5 import QtWidgets, QtCore, QtGui

from admin_credentials_ui import Ui_AdministratorCredentials
from admin_creds import AdministratorCredentials
from general_warning import GeneralWarning
from stonix_wrapper_ui import Ui_StonixWrapper

from darwin_funcs import getResourcesDir, getMacOSDir
from run_commands import system_call_retval, \
                         runWithPty, \
                         runWithWaitTillFinished, \
                         RunThread
from lib.run_commands import RunWith
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp
from log_message import log_message

class StonixWrapper(QtWidgets.QDialog) :
    """
    Class controlling the stonix wrapper dialog
    """
    def __init__(self, args, message_level="normal", parent=None) :
        """
        Initialization method
        
        @author: Roy Nielsen
        """
        super(StonixWrapper, self).__init__(parent)
        self.ui = Ui_StonixWrapper()
        self.ui.setupUi(self)
        self.args = args
        
        #self.message_level = message_level
        self.message_level = message_level
        self.myuid = os.getuid()

        #####
        # Set up signals and slots
        self.ui.userButton.clicked.connect(self.processCurrentLoggedInUser)
        self.ui.adminButton.clicked.connect(self.processAdminUser)
        self.ui.quitButton.clicked.connect(self.rejectApp)
        #self.connect(self.ui.userButton, SIGNAL("clicked()"), self.processCurrentUser)
        #self.connect(self.ui.adminButton, SIGNAL("clicked()"), self.processAdminUser)
        #self.connect(self.ui.quitButton, SIGNAL("clicked()"), self.rejectApp)

        self.logger = CyLogger(debug_mode=True)
        self.rw = RunWith(self.logger)

        self.admin_creds = AdministratorCredentials(self.args, self.message_level)

    def rejectApp(self) :
        """
        Reject slot, print a message before sending the reject signal...
        
        Author: Roy Nielsen
        """
        QtWidgets.QMessageBox.warning(self, "Warning", "You hit Quit, exiting program.", QtWidgets.QMessageBox.Ok)
        QtCore.QCoreApplication.instance().quit()

    def processCurrentLoggedInUser(self) :
        """
        Run Stonix with the currently logged in user
        
        @author: Roy Nielsen
        """
        fullStonixPath = os.path.join(getResourcesDir(), "stonix.app/Contents/MacOS/stonix")
        
        if self.args:
            command = [fullStonixPath] + self.args
        else:
            command = [fullStonixPath, "-G", "-dv"]
        

        retval = ""
        reterr = ""
        
        child_pid = os.fork()
        if child_pid == 0 :
            print "Child Process: PID# %s" % os.getpid()
            retval, reterr = system_call_retval(command, self.message_level)

        else:
            print "Exiting parent process: PID# %s" % os.getpid()
            QtCore.QCoreApplication.instance().quit()
        #time.sleep(2)
        sys.exit()
        #self.close()
        #QtCore.QCoreApplication.instance().quit()

    def processAdminUser(self):
        """
        Run Stonix as an admin user - load AdministratorCredentials dialog
        with the current user as the default username.
        
        Have AdministratorCredentials handle it's own buttons.
        
        @author: Roy Nielsen
        """
        retval = self.admin_creds.exec_()
        self.admin_creds.raise_()
        
        if retval == 1 :
            self.accept()

        log_message("processAdminUser complete...", "verbose", self.message_level)

        self.reject()
