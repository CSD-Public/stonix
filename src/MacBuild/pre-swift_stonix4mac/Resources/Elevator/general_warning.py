"""
Class to manage a dialog to warn if the app is not on /dev/disk2

Date originated: 4/26/2013
Author: Roy Nielsen
"""
from __future__ import absolute_import

#####
# Native python libraries
import re
import pwd

#####
# Installed with 'pip install psutil'
import psutil

#####
# PyQt libraries
from PyQt5 import QtWidgets

#####
# local app libraries
from general_warning_ui import Ui_GeneralWarning
from loggers import LogPriority as lp
from run_commands import RunWith

class GeneralWarning(QtWidgets.QDialog):
    """
    Class to manage the dialog to get the property number

    Author: Roy Nielsen
    """
    def __init__(self, conf, parent=None):
        """
        Initialization method

        Author: Roy Nielsen
        """
        super(GeneralWarning, self).__init__(parent)
        self.ui = Ui_GeneralWarning()

        self.ui.setupUi(self)

        self.conf = conf        
        self.logger = self.conf.get_logger()
        self.runwith = RunWith(self.logger)

        self.ui.label.setOpenExternalLinks(False)

        self.ui.buttonBox.accepted.connect(self.accept)
        self.ui.label.linkActivated.connect(self.openWebPage)

        self.user = self.conf.get_user()
        self.validUser = self.conf.get_valid_user()

        self.links = []

        self.logger.log(lp.DEBUG, "Finished initializing GeneralWarning " + \
                                  "Class...")

    ############################################################################

    def setWarningMessage(self, message=""):
        """
        Set the warning message label
        
        Author: Roy Nielsen
        """
        self.ui.label.setText(message)

    ############################################################################

    def setOpenExternalLinks(self, set_state=True):
        """
        Use the OS method of opening Links
        
        @author: Roy Nielsen
        """
        success = False
        if isinstance(set_state, bool):
            if set_state is True:
                self.ui.label.setOpenExternalLinks(True)
                self.logger.log(lp.DEBUG, "Label links activated...")
                success = True
            else:
                self.ui.label.setOpenExternalLinks(False)
                self.logger.log(lp.DEBUG, "Label links deactivated...")
                success = True
        else:
            self.logger.log(lp.WARNING, "Invalid value passed in to " + \
                                        "this method: " + str(set_state))

        return success

    ############################################################################

    def openWebPage(self, link=""):
        """
        Open a web page in the passed in user's context...

        @author: Roy Nielsen
        """
        if not link:
            raise Exception("Need to define a link...")
        else:
            pid = self.getLoginWindowPid()
            if pid:
                try:
                    #####
                    # Elevator down from root to user to open web link in 
                    # user context
                    cmd = ["/usr/bin/sudo", "-u", self.validUser,
                           "/usr/bin/open",
                           "/Applications/Safari.app/Contents/MacOS/Safari",
                           link]
                    self.runwith.setCommand(cmd)
                    self.runwith.communicate()
                except Exception, err:
                    self.logger.log(lp.WARNING, "DAMN IT JIM!!! bsexec " + \
                                                "exception: " + str(err))

    ############################################################################

    def getLoginWindowPid(self):
        """
        Returns the PID of the login window process, which can be acquired by
        going through the process list, looking for the 'loginwindow' process,
        and acquiring the effective uid of the process.  Used in the creation
        of a 'launchctl bsexec <pid> <command>... ' command to launch something
        in the context of the user that is logged in at the MacOS GUI, from the
        context of a process running in root context.

        https://pythonhosted.org/psutil/#psutil.Process
        https://docs.python.org/2/library/pwd.html

        @NOTE: If there are multiple people logged in to the GUI, this can
        return multiple results.  For PNpass, it should never be run when there
        is more than the self.conf.get_valid_user() user, so just acquiring the
        first user with the uids().effective attribute will be adiquate to then
        use the pwd library to do a backward uid -> moniker lookup. Can't just
        use the proc['username'] as that is the real user, not the effective
        user for the process.  Effective user required for the launchctl bsexec
        function.

        @NOTE: This method looks specifically if the process has an effective
               uid of self.conf.get_valid_user(), if it does not, it will return
               False.

        @returns: success - False if the routine cannot acquire the loginwindow
                            information, the defined psutil.Process information
                            defined by the dictionary returned by the
                            p.as_dict(attrs=[..., ..., ..., ... ]) retrieval.

        @author: Roy Nielsen
        """
        success = False
        #####
        # use the psutil.process_iter() to acquire and iterate over all 
        # the running processes
        for p in psutil.process_iter():
            #####
            # for each process, check if it is what we are looking for
            proc =  p.as_dict(attrs=['pid', 'name', 'username', 'uids'])
            if re.search("[Ll]ogin[Ww]indow", str(proc['name'])):
                #####
                # Validate the user is the self.conf.get_valid_user user
                firstLoginWindowUid = p.uids().effective
                userinfo = pwd.getpwuid(firstLoginWindowUid)
                if re.match("^%s$"%self.validUser, userinfo.pw_name):
                    success = str(proc['pid'])
                    message = "loginwindow: (moniker) " + \
                              str(userinfo.pw_name) + \
                              " : (uid) " + str(firstLoginWindowUid) +\
                              " : (pid) " + str(proc['pid'])
                    self.logger.log(lp.DEBUG, message)
                    break
        return success
