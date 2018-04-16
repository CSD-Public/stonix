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
import re
import pwd
import sys
import time
import getpass
import tempfile
from subprocess import Popen, PIPE, STDOUT
# PyQt libraries
#from PyQt4.QtGui import QDialog, QMessageBox
#from PyQt4.QtCore import SIGNAL
#from PyQt4.QtCore import *
#from PyQt4.QtGui import *
from PyQt5 import QtCore, QtGui, QtWidgets

##########
# local app libraries
from admin_credentials_ui import Ui_AdministratorCredentials

from lib.run_commands import RunWith, RunThread, runMyThreadCommand
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp
from lib.manage_user.manage_user import ManageUser
from lib.launchjob import LaunchCtl

class AdministratorCredentials(QtWidgets.QDialog) :
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
        self.lctl = LaunchCtl(self.logger)

        self.message_level = message_level
        self.username = ""
        self.password = ""
        self.cmd = ""
        self.tmpDir = ""

        #self.progress_bar = QtWidgets.QProgressDialog()
        #self.progress_bar.setMinimum(0)
        #self.progress_bar.setMaximum(0)
        #self.progress_bar.setLabelText("Checking Password...")

        #####
        # Set up signals and slots
        self.ui.authUserButton.clicked.connect(self.isPassValid)
        self.ui.cancelButton.clicked.connect(self.rejectApp)
        #self.connect(self.ui.authUserButton, SIGNAL("clicked()"), self.isPassValid)
        #self.connect(self.ui.cancelButton, SIGNAL("clicked()"), self.rejectApp)

        #####
        # Commented out putting in the current logged in user as the default
        # user - to make more Mac-like
        #user = getpass.getuser()
        #self.ui.adminName.setText(user)

        self.logger.log(lp.DEBUG, "Finished initializing AdministratorCredentials Class...")


    def rejectApp(self) :
        """
        Reject slot, print a message before sending the reject signal...
        
        Author: Roy Nielsen
        """
        QtWidgets.QMessageBox.warning(self, "Warning", "You hit Cancel, exiting program.", QtWidgets.QMessageBox.Ok)
        QtCore.QCoreApplication.instance().quit()
        #self.close()

    def isPassValid(self) :
        """
        Set the admin username and password values of the class.
        
        Author: Roy Nielsen
        """
        self.logger.log(lp.DEBUG, "Entering isPassValid in admin_creds...")
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
        
        #self.progress_bar.show()
        #self.progress_bar.raise_()

        #if self.mu.isUserInGroup(self.username, "admin"):
        
        result = self.mu.authenticate(self.username, self.password)
        self.logger.log(lp.DEBUG, str(self.username) + " is an admin...")
    
        if result :
            self.logger.log(lp.DEBUG, "Authentication success...")
            #####
            # Got a valid user, with valid password, call stonix with
            # self.rw.runAsWithSudo - stonixPath is a link to the stonix app
            # that is in the resources directory
            stonix4macPath = os.path.join(self.getMacOSDir(), "stonix4mac")

                
            consoleUserName = self.getConsoleUserLoginWindowId()
            consoleUserUid = pwd.getpwnam(consoleUserName)[2]
            
            resources = self.getResourcesDir()
            
            stonixPath = os.path.join(resources, "/stonix.app/Contents/MacOS/stonix")

            if self.args:
                command = [stonixPath] + self.args
            else:
                command = [stonixPath, "-G", "-dv"]

            self.logger.log(lp.DEBUG, "full stonix cmd: " + str(command))
            
            internal_command = ["/usr/bin/su", str("-"), str(self.username).strip(), str("-c")]

            #####
            # NOTE: the '-v -u #0' in the sudo commands below are required to 
            # handle the default behavior of sudo's tty_tickets in a default
            # install of macOS Sierra.

            if isinstance(command, list) :
                cmd = []
                for i in range(len(command)):
                    try:
                        cmd.append(str(command[i].decode('utf-8')))
                    except UnicodeDecodeError :
                        cmd.append(str(command[i]))

                internal_command.append(str("/usr/bin/sudo -E -S -s '" + \
                                            " ".join(cmd) + "'"))
            elif isinstance(command, basestring):
                try:
                    internal_command.append(str("/usr/bin/sudo -E -S -s " + \
                                                "'" + \
                                                str(command.decode('utf-8')) + \
                                                "'"))
                except UnicodeDecodeError:
                    internal_command.append(str("/usr/bin/sudo -E -S -s " + \
                                                "'" + \
                                                str(command) + "'"))

            myenv = os.environ.copy()
            
            myenv['SUDO_ASKPASS'] = '/tmp/askpass.py'
            
            lines = []
            
            tmpfile_fp, tmpfile_name = tempfile.mkstemp()
            tmp_fp = os.fdopen(tmpfile_fp, 'w')
            second = open('/tmp/test', 'w')
            
            second.write(tmpfile_name + "\n")
            tmp_fp.write(self.password + "\n")
            
            second.close()
            tmp_fp.close()
            
            #####
            # Attempt fork here, so we don't have the wrapper and stonix
            # running and in the Dock at the same time.
            #child_pid = os.fork()
            #if child_pid == 0 :
                #self.logger.log(lp.DEBUG, "Child Process: PID# %s" % os.getpid())

            #####
            # Run the command
            p = Popen(internal_command,
                      stdout=PIPE,
                      stderr=STDOUT,
                      stdin=PIPE,
                      shell=False,
                      bufsize=0,
                      env=myenv)
            
            #p.stdin.write('\n')
            #p.stdin.flush()
            out = p.stdout.readline()
            #while p.poll() is not None:
            
            while out:
              line = out
              line = line.rstrip("\n")
              lines.append(line)
              print line
              if "Password" in line:
            
                  pr = 1
                  p.stdin.write(self.password + '\n')
                  p.stdin.flush()
                  out = p.stdout.readline()
                  continue
              else:
                  out = p.stdout.readline()
                  continue
            
            p.wait()

            QtCore.QCoreApplication.instance().quit()
            #self.accept()
        else :
            #####
            # User is an admin, report invalid password and try again...
            #self.progress_bar.hide()
            self.logger.log(lp.DEBUG, "Authentication test FAILURE...")
            QtWidgets.QMessageBox.warning(self, "Warning", "...Incorrect Password, please try again.", QtWidgets.QMessageBox.Ok)
        '''
        else :
            #self.progress_bar.hide()
            self.logger.log(lp.DEBUG, "User: \"" + str(self.username) + \
                                      "\" is not a valid " + \
                                      "user on this system.")
            QtWidgets.QMessageBox.warning(self, "Warning", "\"" + str(self.username) + \
                                      "\" is not a valid user on this " + \
                                      "system, please try again.", \
                                      QtWidgets.QMessageBox.Ok)
        '''
        self.logger.log(lp.DEBUG, "Finished isPassValid...")

    def getStonixAdminPlist(self, cmd=[]):
        '''
        Create a launchjob plist for running stonix, create a temporary directory
        for it and launch it from there.
        
        @param: List of the full stonix command to run.
        
        @returns: full path to the plist written.
        
        @author: Roy Nielsen
        '''
        #####
        # Set up the name of the plist
        # stonixPlistFilename = "/var/run/gov.lanl.stonix.run.plist"

        #####
        # Get a tempfilename
        fileDescriptor, stonixPlistFilename = tempfile.mkstemp(suffix=".plist", prefix='gov.lanl.stonix.', dir='/tmp')

        domain = stonixPlistFilename.split('/')[-1]

        #####
        # Construct the header and footer of the plist
        stonixPlistHeader = '''<?xml version="1.0" encoding="UTF-8"?>''' + \
                            '''\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">''' + \
                            '''\n<plist version="1.0">''' + \
                            '''\n<dict>\n\t<key>Label</key>''' + \
                            '''\n\t<string>''' + domain + '''</string>''' + \
                            '''\n\t<key>UserName</key>''' + \
                            '''\n\t<string>root</string>''' + \
                            '''\n\t<key>GroupName</key>''' + \
                            '''\n\t<string>wheel</string>''' + \
                            '''\n\t<key>EnvironmentVariables</key>''' + \
                            '''\n\t<dict>''' + \
                            '''\n\t\t<key>PATH</key>''' + \
                            '''\n\t\t<string>/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin</string>''' + \
                            '''\n\t</dict>''' + \
                            '''\n\t<key>ProgramArguments</key>''' + \
                            '''\n\t<array>'''
    
        stonixPlistFooter = '''\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>''' + \
                            '''\n</dict>\n</plist>'''
    
        #####
        # Build the plist
        stonixPlist = stonixPlistHeader
        stonixPlist += """\n\t\t<string>sudo</string>"""
        for arg in cmd:
            stonixPlist += """\n\t\t<string>""" + arg + """</string>"""
        stonixPlist += stonixPlistFooter
    
        #####
        # Write the contents of the plist to the file
        os.write(fileDescriptor, stonixPlist)
        os.close(fileDescriptor)
        
        os.chmod(stonixPlistFilename, 0o644)
        #os.chown(stonixPlistFilename, 0, 0)
        
        self.logger.log(lp.DEBUG, "stonixPlistFilename: " + str(stonixPlistFilename))
    
        #####
        # Return the full path filename of the plist
        return stonixPlistFilename

    def getConsoleUserLoginWindowId(self):
        """
        Get the user that owns the console on the Mac.  This user is the user that
        is logged in to the GUI.
        """
        user = False
    
        cmd = ["/usr/bin/stat", "-f", "'%Su'", "/dev/console"]
    
        try:
            self.rw.setCommand(cmd)
            retval, reterr, retcode = self.rw.communicate()

            space_stripped = str(retval).strip()
            quote_stripped = str(space_stripped).strip("'")
    
        except Exception, err:
            #logger.log(lp.VERBOSE, "Exception trying to get the console user...")
            #logger.log(lp.VERBOSE, "Associated exception: " + str(err))
            raise err
        else:
            """
            LANL's environment has chosen the regex below as a valid match for
            usernames on the network.
            """
            if re.match("^[A-Za-z][A-Za-z1-9_]+$", quote_stripped):
                user = str(quote_stripped)
        #logger.log(lp.VERBOSE, "user: " + str(user))
        
        return user

    def getResourcesDir(self) :
        """ 
        Get the full path to the Resources directory of the current app 
        
        Author: Roy Nielsen
        """
        # Gets the <app-path>/Contents/MacOS full path
        selffile = os.path.abspath(__file__)
        selfdir = os.path.dirname(selffile)
        resource_dir = ""
    
        parents = selfdir.split("/")
    
        # Remove the "MacOS" dir from the list
        parents.pop()
    
        # Append "Contents" & "cmu" to the end of the list
        #parents.append("Contents")
        
        # Append "Resources" & "cmu" to the end of the list
        parents.append("Resources")
        
        # Join up the directory with slashes
        resource_dir = "/".join(parents)
    
        self.logger.log(lp.DEBUG, "resources dir: " + str(resource_dir))
    
        return resource_dir
    
    def getMacOSDir(self) :
        """ 
        Get the full path to the Resources directory of the current app 
        
        Author: Roy Nielsen
        """
        # Gets the <app-path>/Contents/MacOS full path
        selfdir = os.path.abspath(os.path.dirname(__file__))
        resource_dir = ""
    
        parents = selfdir.split("/")
    
        # Remove the "MacOS" dir from the list
        parents.pop()
    
        # Append "Resources" & "cmu" to the end of the list
        parents.append("MacOS")
        
        # Join up the directory with slashes
        resource_dir = "/".join(parents) + "/"
    
        return resource_dir
    
