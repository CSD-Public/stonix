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
#               Filename          $RCSfile: admin_creds.py,v $
#               Description       Class to handle GUI for authentication of an
#                                 admin user, with the purpose of running stonix 
#                                 as that admin user.  User may be different 
#                                 from the user that is launching the class.
#               OS                Mac OS X
#               Author            Roy Nielsen
#               Last updated by   $Author: $
#               Notes             
#               Release           $Revision: 1.0 $
#               Modified Date     $Date:  $
# ============================================================================ #

import os
import sys
import getpass

# PyQt libraries
#from PyQt4.QtGui import QDialog, QMessageBox
#from PyQt4.QtCore import SIGNAL
from PyQt4.QtCore import *
from PyQt4.QtGui import *

##########
# local app libraries
from admin_credentials_ui import Ui_AdministratorCredentials

from darwin_funcs import getMacOSDir, \
                         checkIfUserIsAdmin, \
                         isUserOnLocalSystem

from log_message import log_message
from lib.run_commands import RunWith
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp
from lib.manage_user.manage_user import ManageUser

class AdministratorCredentials(QDialog) :
    """
    Class to manage the dialog to get the property number

    @author: Roy Nielsen
    """
    def __init__(self, args, message_level="debug", parent=None) :
        """
        Initialization method

        @author: Roy Nielsen
        """
        super(AdministratorCredentials, self).__init__(parent)
        self.ui = Ui_AdministratorCredentials()
        self.ui.setupUi(self)
        self.args = args
        
        self.logger = CyLogger(debug_mode=True)
        self.mu = ManageUser(logger=self.logger)
        self.rw = RunWith(self.logger)
        self.message_level = message_level
        self.username = ""
        self.password = ""
        self.cmd = ""
        self.tmpDir = ""

        self.progress_bar = QProgressDialog()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(0)
        self.progress_bar.setLabelText("Checking Password...")

        #####
        # Set up signals and slots
        self.connect(self.ui.authUserButton, SIGNAL("clicked()"), self.isPassValid)
        self.connect(self.ui.cancelButton, SIGNAL("clicked()"), self.rejectApp)

        #####
        # Commented out putting in the current logged in user as the default
        # user - to make more Mac-like
        #user = getpass.getuser()
        #self.ui.adminName.setText(user)

        log_message("Finished initializing AdministratorCredentials Class...", "debug", self.message_level)


    def rejectApp(self) :
        """
        Reject slot, print a message before sending the reject signal...
        
        Author: Roy Nielsen
        """
        QMessageBox.warning(self, "Warning", "You hit Cancel, exiting program.", QMessageBox.Ok)
        self.reject()


    def isPassValid(self) :
        """
        Set the admin username and password values of the class.
        
        Author: Roy Nielsen
        """
        log_message("Entering isPassValid in admin_creds...", "verbose", self.message_level)
        #####
        # Grab the QString out of the QLineEdit field
        myuser = self.ui.adminName.text()

        #####
        # Convert myuser into a string
        self.username = "%s" % myuser

        #####
        # Grab the QString out of the QLineEdit field
        mypass = self.ui.passwordLineEdit.text()
        
        #####
        # Convert mypass into a string
        self.password = "%s" % mypass
        
        self.progress_bar.show()
        self.progress_bar.raise_()

        if self.mu.isUserInGroup(self.username, "admin"):
        
            result = self.mu.authenticate(self.username, self.password)
            self.logger.log(lp.DEBUG, str(self.username) + " is an admin...")
        
            if result :
                log_message("Authentication success...", "debug", self.message_level)
                #####
                # Got a valid user, with valid password, call stonix with
                # self.rw.runAsWithSudo - stonixPath is a link to the stonix app
                # that is in the resources directory
                stonix4macPath = os.path.join(getMacOSDir(), "stonix4mac")

                #####
                # Attempt fork here, so we don't have the wrapper and stonix
                # running and in the Dock at the same time.
                child_pid = os.fork()
                if child_pid == 0 :
                    print "Child Process: PID# %s" % os.getpid()
                    #####
                    # Set up the command
                    if self.args:
                        command = ["\"" + stonix4macPath + "\""] + self.args
                    else:
                        command = ["\"" + stonix4macPath + "\"", "-G", "-dv"]

                    #####
                    # Run the command
                    self.rw.setCommand(command)
                    self.rw.runAsWithSudo(self.username, self.password)
                else:
                    print "Exiting parent process: PID# %s" % os.getpid()

                self.progress_bar.hide()

                QCoreApplication.quit()
            else :
                #####
                # User is an admin, report invalid password and try again...
                self.progress_bar.hide()
                log_message("Authentication test FAILURE...", "normal", self.message_level)
                QMessageBox.warning(self, "Warning", "...Incorrect Password, please try again.", QMessageBox.Ok)                
    
        else :
            self.progress_bar.hide()
            log_message("User: \"" + str(self.username) + "\" is not a valid " + \
                        "user on this system.", "normal", self.message_level)
            QMessageBox.warning(self, "Warning", "\"" + str(self.username) + \
                                      "\" is not a valid user on this " + \
                                      "system, please try again.", \
                                      QMessageBox.Ok)

        log_message("Finished isPassValid...", "verbose", self.message_level)

