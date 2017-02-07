#!/usr/bin/python
"""
Controller for gui elevation of privileges.
"""
#####
# Import standard python libraries
import os
import sys
import time
import getpass

#####
# PyQt5 libraries
from PyQt5 import QtWidgets

from manage_user import ManageUser
from loggers import CyLogger
from loggers import LogPriority as lp
#from libMacOSHelperFunctions import getMacOSDir, get_script
from tmp_enc  import tmp_enc as te
from run_commands import RunWith
from general_warning import GeneralWarning

from elevator_ui import Ui_Elevator


class Elevator(QtWidgets.QDialog):
    """
    Authentication dialog parent.  isPassValid and handleSuccessfulAuth methods
    to be overriden by child.  Skeleton start of isPassValid included as a
    a template for the start of the child method.

    @author: Roy Nielsen
    """
    def __init__(self, logger):
        """
        Initialization method

        @author: Roy Nielsen
        """
        QtWidgets.QDialog.__init__(self)
        self.ui = Ui_Elevator()
        self.ui.setupUi(self)

        self.logger = logger
        self.password = ""

        #my_macosdir = getMacOSDir()
        self.script = get_script() 

        self.logger.log(lp.DEBUG, "path: " + str(self.script))

        self.mu = ManageUser(self.logger)
        self.runWith = RunWith(self.logger)
        self.elevatorGroup = "admin"

        #####
        # Set the text cursor to the password field
        self.ui.adminName.setFocus()

        #####
        # Initialize class password
        self.password = ""

        #####
        # Set up signals and slots for buttons
        self.ui.authUserButton.clicked.connect(self.isPassValid)
        self.ui.cancelButton.clicked.connect(self.rejectApp)

        self.logger.log(lp.INFO, "Finished initializing the Elevator...")

    def rejectApp(self) :
        """
        Reject slot, print a message before sending the reject signal...

        Author: Roy Nielsen
        """
        #QtWidgets.QMessageBox.warning(self, "Warning", 
        #                                    "You hit Cancel, exiting program.",
        #                                    QtWidgets.QMessageBox.Ok)
        self.reject()

    def isPassValid(self):
        """
        Set the admin username and password values of the class.

        Author: Roy Nielsen
        """
        #####
        # Grab the QString out of the QLineEdit field in case the username
        # field was changed
        myuser = self.ui.adminName.text()

        #####
        # Convert myuser into a string
        self.username = "%s" % myuser

        #####
        # Grab the QString out of the QLineEdit field
        mypass = self.ui.passwordLineEdit.text()

        #####
        # Convert mypass into a string
        self.password = '%s'%mypass

        self.logger.log(lp.INFO, "Acquired credentials...")

        result = self.mu.authenticate(self.username, self.password)
        self.logger.log(lp.DEBUG, str(self.username) + " is an admin...")

        if result:
            self.logger.log(lp.INFO, "Authentication success...")
            self.accept()
        else:
            #####
            # User is an admin, report invalid password and try again...
            self.logger.log(lp.INFO, "Authentication test FAILURE...")
            QtWidgets.QMessageBox.warning(self, "Warning",
                                                "...Incorrect Password," + \
                                                " please try again.",
                                                QtWidgets.QMessageBox.Ok)

        self.logger.log(lp.INFO, "Finished isPassValid...")

    def getCreds(self):
        return self.password


if __name__ == '__main__':
    '''
    Use this script to acquire a password with a pyqt interface, and return
    the password to the calling program.

    Intended for use as the SUDO_ASKPASS graphical method for acquiring a 
    password for sudo.

    @author: Roy Nielsen
    '''
    logger = CyLogger(debug_mode=True)
    logger.initializeLogs()
    mu = ManageUser(logger)

    myuid = mu.getUserUid(getpass.getuser())

    creds = ""

    if int(myuid) == 0:
        logger.log(lp.INFO, "You already have elevated privileges")
    else:
        #####
        # Instantiate & execute application...
        app = QtWidgets.QApplication(sys.argv)

        credential_check = Elevator(logger)
        retcode = credential_check.exec_()
        credential_check.raise_()

        if retcode == credential_check.Accepted:
            creds = credential_check.getCreds()
            print creds
            sys.exit()
            #app.exit()
        else:
            logger.log(lp.INFO, "Canceled authentication dialog.")

        sys.exit(app.exec_())

