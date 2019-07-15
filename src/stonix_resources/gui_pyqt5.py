#!/usr/bin/env python
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



#============================================================================ #
#               Filename          $RCSfile: stonix/gui.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2011/10/24 14:00:00 $
#============================================================================ #
'''
Created Jun 20, 2012

This is the GUI interface for STONIX (project Dylan). This file and its related
imports implement the STONIX GUI.

@author: David Kennel
@note: 2015-09-11 - rsn - Adding initial attempt at a help browser.
@change: 2017-12-21 - Breen Malmberg - added search box implementation;
        (methods: getSearchText(), resizeEvent(), clearText(), updateSearchResults();
        as well as lines in __init__ creating the searchbox and running self.getSearchText())
@change: 2018-06-21 - Brandon Gonzales - Change tupdate and supdate to use
        status as a dictionary instead of a QString; Change runThread.run() to
        send dictionary to tupdate and supdate instead of a QString
'''

import os
import sys
import traceback
import webbrowser

from view import View
from logdispatcher import LogPriority

import main_window_pyqt5 as main_window
#####
# PyQt specific imports - Needs importing:
# QThread (QtCore)
# QObject (QtCore)
# QMainWindow (QtWidgets)
# QMessageBox (QtWidgets)
# QMetaObject (QtCore)
##### was
# from PyQt4.QtCore import *
# from PyQt4.QtGui import *
from PyQt5 import QtWidgets
from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5.QtCore import Qt


class GUI (View, QtWidgets.QMainWindow, main_window.Ui_MainWindow):
    '''Main GUI class for the stonix GUI. This class inherits from
    main_window.Ui_MainWindow which was created in QTDesigner.
    
    @author: David Kennel


    '''
    def __init__(self, controller, environment, logger):
        """
        Constructor for the GUI class. The following __init__ statements pull
        in functionality from the parent classes. The constructor requires
        the controller and environment objects be passed in.

        @param controller: The stonix controller object
        @param environment: The stonix environment object
        @author: David Kennel
        @change: 2017/13/9 Brandon Gonzales Added calls to setenableci on
            CiFrame creation.
        """
        View.__init__(self)
        QtWidgets.QMainWindow.__init__(self)
        main_window.Ui_MainWindow.__init__(self)

        self.controller = controller
        self.environ = environment
        self.logger = logger
        self.icon_path = self.environ.get_icon_path()
        self.setupUi(self)
        # Edit pane should be hidden / disabled by default
        self.frame_rule_details.hide()
        self.revert_button.setEnabled(False)
        self.fix_button.setEnabled(False)
        self.report_button.setEnabled(False)

        # Set the title of the main window to stonix and version number
        try:
            self.euid = os.geteuid()
        except OSError:
            detailedresults = traceback.format_exc()
            self.logger.log(LogPriority.DEBUG, detailedresults)
        self.stonixversion = self.environ.getstonixversion()
        userstr = ''
        if self.euid == 0:
            # for macs we say admin instead of root
            userstr = 'admin'
        else:
            userstr = 'user'
        self.setWindowTitle("STONIX-" + str(self.stonixversion) + \
                            " (running in " + str(userstr) + " context)")

        # Connect UI events to actions
        if not self.rule_list_widget.count():
            sys.exit("STONIX: No applicable rules for this system")
        self.rule_list_widget.setSortingEnabled(True)
        self.rule_list_widget.itemSelectionChanged.connect(self.rulelistselchange)
        self.rule_list_widget.itemDoubleClicked.connect(self.reportrule)
        self.actionQuit.triggered.connect(self.guiexit)
        self.actionRun_All.triggered.connect(self.runall)
        self.actionReport_All.triggered.connect(self.reportall)
        self.actionRevert_All.triggered.connect(self.revertall)
        self.actionStop.triggered.connect(self.abortrun)
        self.actionGuiHelp.triggered.connect(self.openHelpBrowser)
        self.fix_button.clicked.connect(self.runrule)
        self.report_button.clicked.connect(self.reportrule)
        self.revert_button.clicked.connect(self.revertrule)
        self.save_button.clicked.connect(self.savechanges)
        self.cancel_button.clicked.connect(self.clearchanges)
        self.actionAbout.triggered.connect(self.helpabout)
        self.actionLog.triggered.connect(self.showlogbrowser)

        # set up search box
        self.searchbox = QtWidgets.QLineEdit(self)
        self.searchbox.resize(250, 30)
        self.searchbox.move(self.width() - self.searchbox.width() - 2, 2)
        self.searchbox.setPlaceholderText('Search')
        self.searchbox.textEdited.connect(self.updateSearchResults)
        self.searchbox.setToolTip("Search rule names and descriptions")
        self.searchbox.show()

        # Initialize icon variables
        logicon = os.path.join(self.icon_path, "message-news.png")
        exiticon = os.path.join(self.icon_path, "application-exit.png")
        fixallicon = os.path.join(self.icon_path, "system-software-update.png")
        reportallicon = os.path.join(self.icon_path, "system-search.png")
        revertallicon = os.path.join(self.icon_path, "warning_48.png")
        cancelrunicon = os.path.join(self.icon_path, "cancel.png")
        helpquestionmark = os.path.join(self.icon_path, "help.ico")
        # Commented out setStatusTip calls to keep them from stomping on run
        # messages
        self.actionLog.setIcon((QtGui.QIcon(logicon)))
        self.actionLog.setObjectName("actionLog")
        self.actionLog.setShortcut('Ctrl+L')
        #self.actionLog.setStatusTip('View Run Log')
        self.actionQuit.setIcon(QtGui.QIcon(exiticon))
        self.actionQuit.setMenuRole(QtWidgets.QAction.QuitRole)
        self.actionQuit.setObjectName("actionQuit")
        self.actionQuit.setShortcut('Ctrl+Q')
        #self.actionQuit.setStatusTip('Quit application')
        self.actionAbout.setObjectName("actionAbout")
        self.actionRun_All.setIcon(QtGui.QIcon(fixallicon))
        self.actionRun_All.setObjectName("actionRun_All")
        self.actionRun_All.setShortcut('Ctrl+R')
        #self.actionRun_All.setStatusTip('Run Fix All')
        self.actionReport_All.setIcon(QtGui.QIcon(reportallicon))
        self.actionReport_All.setObjectName("actionReport_All")
        self.actionReport_All.setShortcut('Ctrl+G')
        #self.actionReport_All.setStatusTip('Run Report All')
        self.actionRevert_All.setIcon(QtGui.QIcon(revertallicon))
        self.actionRevert_All.setObjectName("actionRevert_All")

        self.actionGuiHelp.setIcon(QtGui.QIcon(helpquestionmark))
        self.actionGuiHelp.setObjectName("actionGuiHelp")
        self.actionGuiHelp.setShortcut('Ctrl+H')

        #self.actionRevert_All.setStatusTip('Attempt to Revert All Changes')
        #self.actionEdit_Selected = QtGui.QAction(MainWindow)
        #self.actionEdit_Selected.setObjectName("actionEdit_Selected")
        self.actionStop.setIcon(QtGui.QIcon(cancelrunicon))
        self.actionStop.setObjectName("actionStop")
        self.actionStop.setShortcut('Ctrl+K')
        #self.actionStop.setStatusTip('Stop Current Run')
        self.questionmark = os.path.join(self.icon_path, "questionmark_48.png")
        self.compliant = os.path.join(self.icon_path, "security-high.png")
        self.notcompliant = os.path.join(self.icon_path, "security-low.png")
        self.warning = os.path.join(self.icon_path, "security-medium.png")

        self.toolbar = self.addToolBar('Run Controls')
        self.toolbar.addAction(self.actionRun_All)
        self.toolbar.addAction(self.actionReport_All)
        self.toolbar.addAction(self.actionStop)
        self.toolbar.addAction(self.actionGuiHelp)
        self.toolbar.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        # Build rule list
        self.rule_data = self.controller.getallrulesdata()
        rnamelist = []
        # empty rule set safety
        if len(self.rule_data) == 0:
            self.app_exit("********************\n\nSTONIX: No applicable rules for this system\n\n********************")
        for rnum in self.rule_data:
            icon = QtGui.QIcon()
            icon.addPixmap(QtGui.QPixmap(os.path.join(self.icon_path,
                                                self.questionmark)),
                                                QtGui.QIcon.Normal, QtGui.QIcon.Off)
            item = QtWidgets.QListWidgetItem(self.rule_list_widget)
            brush = QtGui.QBrush(QtGui.QColor(211, 211, 211, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            item.setBackground(brush)
            item.setIcon(icon)
            item.setText(self.rule_data[rnum][0])
            rnamelist.append(item.text())
        self.rule_list_widget.sortItems()
        self.red = QtGui.QColor(255, 102, 112)
        self.green = QtGui.QColor(153, 255, 153)
        self.yellow = QtGui.QColor(255, 255, 0)

        # Setup a frame inside the scroll area
        self.ci_container = QtWidgets.QFrame()
        self.ci_contlayout = QtWidgets.QVBoxLayout()
        # create the ciFrames
        self.ruleci = {}
        # print rnamelist
        for rulename in rnamelist:
            self.logger.log(LogPriority.DEBUG,
                            ['gui.GUI.init',
                             'processing options for: ' + rulename])
            rulenum = self.controller.getrulenumbyname(rulename)
            self.ruleci[rulename] = CiFrame(self, rulenum, self.controller,
                                            self.logger)
            self.ci_contlayout.addWidget(self.ruleci[rulename])
            if self.environ.geteuid() == 0:
                self.ruleci[rulename].setenableci(True)
            else:
                self.ruleci[rulename].setenableci(False)
            self.ruleci[rulename].hide()
        self.ci_container.setLayout(self.ci_contlayout)
        self.conf_items_scroll_area.setWidget(self.ci_container)

        self.err = None

        self.rule_list_widget.setCurrentRow(0)
        self.rulelistselchange()
        self.threads = []

        # Set up the status and progress bars
        self.statusBar().showMessage('Ready')
        self.pbar = QtWidgets.QProgressBar(self.statusBar())
        self.statusBar().addPermanentWidget(self.pbar)
        self.raise_()
        self.show()
        self.searchbox.raise_()
        self.getSearchText()

    def getSearchText(self):
        '''retrieve the list of text (both descriptions
        and rule names) once, to search through


        :returns: void
        @author: Breen Malmberg

        '''

        self.logger.log(LogPriority.DEBUG, "\nBuilding Search database...\n")

        self.search_text = {}

        for rnum in self.rule_data:

            cisearchtext = ""
            rule_config_opts = self.controller.getruleconfigoptions(rnum)
            for opt in rule_config_opts:
                cisearchtext += " " + str(opt.getkey())
                cisearchtext += " " + str(opt.getinstructions())

            rname = self.controller.getrulenamebynum(rnum)
            self.search_text[rname] = self.rule_data[rnum][0] + ' ' + self.rule_data[rnum][1] + ' ' + cisearchtext

    def resizeEvent(self, event):
        '''keep the searchbox in the same position -
        relative to the parent application window

        :param event: 
        :returns: void
        @author: Breen Malmberg

        '''

        self.searchbox.move(self.width() - self.searchbox.width() - 2, 2)

    def clearText(self):
        '''clear searchbox text if it has the
        default 'Search' text in it when a user clicks
        inside it


        :returns: void
        @author: Breen Malmberg

        '''

        # self.logger.log(LogPriority.DEBUG, "\n\nclearText( method) called\n\n")

        if self.searchbox.text() == 'Search':
            self.searchbox.clear()

    def updateSearchResults(self):
        '''show only rules which match the search term
        against either their rule name or their rule description;
        hide all rules which don't contain a match of the search term;
        show all rules if the search box is cleared


        :returns: void
        @author: Breen Malmberg

        '''

        # self.logger.log(LogPriority.DEBUG, "\n\nupdateSearchResults() method called\n\n")

        foundin = []
        allrules = self.rule_list_widget.findItems('.*', Qt.MatchRegExp)
        searchTerm = ''
        searchTerm = self.searchbox.text()

        # if a user clears the searchbox, show all rules
        if len(self.searchbox.text()) == 0:
            for r in allrules:
                r.setHidden(False)
        else:
            for rname in self.search_text:
                if str(searchTerm).lower() in str(self.search_text[rname]).lower():
                    foundin.append(rname)
                else:
                    if rname in foundin:
                        foundin.remove(rname)

            for item in allrules:
                item.setHidden(True)
            for rname in foundin:
                items = self.rule_list_widget.findItems(rname, Qt.MatchExactly)
                for item in items:
                    item.setHidden(False)


    def openHelpBrowser(self):
        '''Open the html based gui help system
        
        @author: Roy Nielsen
        @change: 2015/12/09 eball Changed to webbrowser
        @change: 2018/02/07 Breen Malmberg - (see inline comments below)


        '''
        debug = "Opening help in browser"
        self.logger.log(LogPriority.DEBUG, ["GUI", debug])
        # discontinued using the selfdir dynamic path getting method
        # due to an issue where if the user runs the stonix application from the terminal
        # the path retrieved by the below 'selfdir' method does not get the correct path
        # also, the path is always the same anyway, so for now just hard-coding this path works
        #selfdir = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0])))
        tocpath = "file:///Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix_resources/help/toc.html"
        webbrowser.open(tocpath)
        debug = "webbrowser.open called for " + tocpath
        self.logger.log(LogPriority.DEBUG, ["GUI", debug])

    def update_progress(self, curr, total):
        '''Progress updater for the progress bar.

        :param curr: int - current position in the total set
        :param total: int -  size of total set
        @author: David Kennel

        '''
        if total == 1 and curr == 0:
            self.pbar.setRange(0, 0)
        else:
            self.pbar.setRange(0, total)
            self.pbar.setValue(curr)

    def rulelistselchange(self):
        '''Show frames containing the rule details and configuration items
        appropriate to the selected rule.
        
        @author: David Kennel
        @change: 2017/13/9 Brandon Gonzales Hide save_cancel_frame in user mode


        '''
        if len(self.rule_list_widget.selectedItems()) > 0:
            if self.environ.geteuid() == 0:
                self.revert_button.setEnabled(True)
            else:
                self.revert_button.setEnabled(False)
                self.save_cancel_frame.hide()
            self.fix_button.setEnabled(True)
            self.report_button.setEnabled(True)

            self.rule_name_label.setText("<div style='font-size:16pt; \
                                         font-weight:600;'>%s</div>" %
                                         self.rule_list_widget.selectedItems()[0].text())
            rule_name = self.rule_list_widget.selectedItems()[0].text()
            rule_num = self.controller.getrulenumbyname(rule_name)

            # check whether the currently selected rule is audit only
            auditonly = self.controller.getruleauditonly(rule_num)
            # disable or enable the fix button, based on audit only status
            if auditonly:
                self.fix_button.setEnabled(False)
            else:
                self.fix_button.setEnabled(True)

            self.rule_instructions_text.setPlainText(QtWidgets.QApplication.translate("MainWindow",
                                                                            self.rule_data[rule_num][1],
                                                                            None))
            detailedresults = self.controller.getruledetailedresults(rule_num)
            self.rule_results_text.setPlainText(QtWidgets.QApplication.translate("MainWindow",
                                                                       detailedresults,
                                                                       None))
            for rulename in self.ruleci:
                self.ruleci[rulename].hide()
            rulename = self.rule_list_widget.selectedItems()[0].text()
            self.ruleci[rulename].show()
            self.frame_rule_details.show()
        else:
            self.frame_rule_details.hide()
            self.revert_button.setEnabled(False)
            self.fix_button.setEnabled(False)
            self.report_button.setEnabled(False)

    def guiexit(self, msg=None):
        '''Program quit from GUI called. Clean up lock files and post reports.
        
        @author: David Kennel


        '''
        self.controller.releaselock()
        self.logger.postreport()
        QtCore.QCoreApplication.instance().quit()

    def app_exit(self, msg=None):
        """
        Exit the application (not just the event loop)

        :param msg: exit code or message to send to sys.exit()
        :return: void
        """

        self.guiexit()
        sys.exit(msg)

    def set_listview_item_bgcolor(self, item_text, qcolor_rgb):
        '''Changes the background color of a list view item based on it's
        case-sensitive name. There should only ever be one, however if there
        is a duplicate it will be changed as well.

        :param item_text: The name of the item to look for.
        :param qcolor_rgb: An instance of QColor -
                http://doc.qt.nokia.com/4.7-snapshot/qcolor.html
        :returns: void
        @author: scmcleni

        '''

        brush = QtGui.QBrush(qcolor_rgb)
        brush.setStyle(QtCore.Qt.SolidPattern)
        items = self.rule_list_widget.findItems(item_text, QtCore.Qt.MatchExactly)
        for item in items:
            item.setBackground(brush)

    def set_listview_item_icon(self, item_text, iconame):
        '''Updates the icon associated with an entry in the list view.
        The icon name (iconame) is a enum indicating one of the four possible
        icon types: grn, red, warn, quest. The item_text should be the rule
        name.

        :param string: item_text (rule name)
        :param string: icon name (grn, red, warn, quest)
        @author: David Kennel
        :param item_text: 
        :param iconame: 

        '''
        myicon = os.path.join(self.icon_path, self.questionmark)
        if iconame == 'grn':
            myicon = os.path.join(self.icon_path, self.compliant)
        elif iconame == 'red':
            myicon = os.path.join(self.icon_path, self.notcompliant)
        elif iconame == 'warn':
            myicon = os.path.join(self.icon_path, self.warning)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(myicon), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        items = self.rule_list_widget.findItems(item_text, QtCore.Qt.MatchExactly)
        for item in items:
            item.setIcon(icon)

    def tupdate(self, status):
        '''This method is called by runThread objects. In response
        we need to refresh all dynamic components of the UI.

        :param status: dictionary containing the string values for "rulename",
            "ruleid", "compliant", "completed", and "total"
        @author: David Kennel

        '''
        try:
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "Tupdate called. Args: " + str(status)])
            rule = status["rulename"]
            # ruleid = int(status["ruleid"])
            ruleenabled = ""
            count = int(status["completed"])
            total = int(status["total"])
            try:
                ruleenabled = status['ruleenabled']
            except:
                pass

            if status["compliant"] == 'True':
                compliant = True
            else:
                compliant = False

            if compliant:
                qcolor_rgb = self.green
                iconame = 'grn'
            else:
                qcolor_rgb = self.red
                iconame = 'red'

            if ruleenabled == 'False':
                qcolor_rgb = self.yellow
                iconame = 'warn'

            self.set_listview_item_bgcolor(rule, qcolor_rgb)
            self.set_listview_item_icon(rule, iconame)

            self.rulelistselchange()
            self.statusBar().showMessage('Completed: ' + str(rule))
            self.update_progress(count, total)
            if count > 1 and count == total:
                self.statusBar().showMessage('Run Completed')
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            trace = traceback.format_exc()
            self.logger.log(LogPriority.ERROR, ['GUI', "Problem in tupdate: " + trace])

    def supdate(self, status):
        '''This method is called by the runThread objects. In response this method
        updates the statusBar and progress bars with updated info.

        :param status: dictionary containing the string values for "rulename",
            "completed", and "total"
        @author: David Kennel

        '''
        try:
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "supdate: status " + str(status)])
            rule = status["rulename"]
            count = int(status["completed"])
            total = int(status["total"])
            self.statusBar().showMessage('Executing: ' + str(rule))
            self.update_progress(count, total)

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            trace = traceback.format_exc()
            self.logger.log(LogPriority.ERROR,
                            ['GUI', "Problem in supdate: " + trace])

    def abortrun(self):
        '''This Method will abort a Fix all, Report all or Revert all run.
        It does this by clearing the self.threads property which allows the
        currently executing thread to finish.
        
        @author: David Kennel


        '''
        for thread in self.threads:
            thread.stopflag = True
        self.statusBar().showMessage('Run Canceled')
        self.update_progress(1, 1)

    def runall(self):
        '''Slot for the menu action Rule -> Run all. Passes through to the
        controller's run all rules method.
        
        @author: David Kennel


        '''

        self.update_progress(0, 0)
        self.threads = []
        thread = runThread(self.controller, 'fix', self.logger)
        #####
        # Converting pyqt4 signal/slot connect to pyqt5
        # self.connect(thread, SIGNAL('tupdate(QString)'), self.tupdate)
        # self.connect(thread, SIGNAL('supdate(QString)'), self.supdate)
        thread.tupdate.connect(self.tupdate)
        thread.supdate.connect(self.supdate)
        self.threads.append(thread)
        for waitingthread in self.threads:
            waitingthread.start()
        self.statusBar().showMessage('Fix Run Complete')
        self.logger.log(LogPriority.DEBUG, ['GUI', "Run All Fix complete"])

    def reportall(self):
        '''Slot for the menu action Rule -> Report All. Passes through to the
        controller's report all rules method.
        
        @author: David Kennel


        '''

        self.update_progress(0, 0)
        self.threads = []
        thread = runThread(self.controller, 'report', self.logger)
        #####
        # Converting pyqt4 signal/slot connect to pyqt5
        # self.connect(thread, SIGNAL('tupdate(QString)'), self.tupdate)
        # self.connect(thread, SIGNAL('supdate(QString)'), self.supdate)
        thread.tupdate.connect(self.tupdate)
        thread.supdate.connect(self.supdate)
        self.threads.append(thread)
        for waitingthread in self.threads:
            waitingthread.start()
        self.statusBar().showMessage('Report Run Complete')
        self.logger.log(LogPriority.DEBUG, ['GUI', "Run All Report complete"])

    def revertall(self):
        '''Slot for the menu action Rule -> Revert All. Passes through to the
        controller's revert all rules method.
        
        @author: David Kennel


        '''
        self.update_progress(0, 0)
        self.threads = []
        if self.environ.geteuid() == 0:
            reply = QtWidgets.QMessageBox.warning(self, 'Revert Changes',
                                        "Are you sure you want to revert the changes for all rules?",
                                        QtWidgets.QMessageBox.Yes, QtWidgets.QMessageBox.No)
            if reply == QtWidgets.QMessageBox.Yes:
                thread = runThread(self.controller, 'undo', self.logger)
                #####
                # Converting pyqt4 signal/slot connect to pyqt5
                # self.connect(thread, SIGNAL('tupdate(QString)'), self.tupdate)
                # self.connect(thread, SIGNAL('supdate(QString)'), self.supdate)
                thread.tupdate.connect(self.tupdate)
                thread.supdate.connect(self.supdate)
                self.threads.append(thread)
                for waitingthread in self.threads:
                    waitingthread.start()
                self.statusBar().showMessage('Revert Run Complete')
                self.logger.log(LogPriority.DEBUG,
                                ['GUI', "Run All Revert complete"])
        else:
            discard = QtWidgets.QMessageBox.warning(self, 'Revert Changes',
                                          'Root level privileges are required to undo changes!',
                                          QtWidgets.QMessageBox.Ok)

    def helpabout(self):
        '''Display the about Stonix window
        
        @author: David Kennel


        '''
        window = aboutStonix(self.stonixversion, self)
        window.show()
        window.raise_()

    def showlogbrowser(self):
        '''Display the log browser window and load it with the log from the last
        run.
        
        @author: David Kennel


        '''
        window = Ui_logBrowser(self)
        window.displaytext(self.controller.displaylastrun())
        window.show()
        window.raise_()

    def runrule(self):
        '''Slot for the fix_button visible in the rule details pane. Calls in
        turn the controller's method to run one rule.
        
        @author: David Kennel


        '''
        self.logger.log(LogPriority.DEBUG,
                        ['GUI', "Run Rule Fix called."])
        self.threads = []
        if len(self.rule_list_widget.selectedItems()) > 0:
            rule_name = self.rule_list_widget.selectedItems()[0].text()
            self.pbar.setRange(0, 0)
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "Run Rule Fix running: " + rule_name])
            rule_num = self.controller.getrulenumbyname(rule_name)
            thread = runThread(self.controller, 'fix', self.logger, rule_num)
            #####
            # Converting pyqt4 signal/slot connect to pyqt5
            # self.connect(thread, SIGNAL('tupdate(QString)'), self.tupdate)
            # self.connect(thread, SIGNAL('supdate(QString)'), self.supdate)
            thread.tupdate.connect(self.tupdate)
            thread.supdate.connect(self.supdate)
            self.threads.append(thread)
            for waitingthread in self.threads:
                waitingthread.start()
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "Exit Rule Fix."])

    def reportrule(self):
        '''Slot for the report_button visible in the rule details pane. Calls in
        turn the controller's method to run one rule.
        
        @author: David Kennel


        '''
        self.logger.log(LogPriority.DEBUG,
                        ['GUI', "Run Rule Report called."])
        self.threads = []
        if len(self.rule_list_widget.selectedItems()) > 0:
            rule_name = self.rule_list_widget.selectedItems()[0].text()
            self.pbar.setRange(0, 0)
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "Run Rule Report running: " + rule_name])
            rule_num = self.controller.getrulenumbyname(rule_name)
            thread = runThread(self.controller, 'report', self.logger,
                               rule_num)
            #####
            # Converting pyqt4 signal/slot connect to pyqt5
            # self.connect(thread, SIGNAL('tupdate(QString)'), self.tupdate)
            # self.connect(thread, SIGNAL('supdate(QString)'), self.supdate)
            thread.tupdate.connect(self.tupdate)
            thread.supdate.connect(self.supdate)
            self.threads.append(thread)
            for waitingthread in self.threads:
                waitingthread.start()
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "Exit Rule Report."])

    def revertrule(self):
        '''Slot for the revert_button visible in the rule details pane. Calls in
        turn the controller's method to revert one rule.
        
        @author: David Kennel


        '''
        self.logger.log(LogPriority.DEBUG,
                        ['GUI', "Run Rule Revert called."])
        self.threads = []
        if len(self.rule_list_widget.selectedItems()) > 0:
            rule_name = self.rule_list_widget.selectedItems()[0].text()
            self.statusBar().showMessage('Executing: ' + str(rule_name))
            self.pbar.setRange(0, 0)
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "Run Rule Revert running: " + rule_name])
            rule_num = self.controller.getrulenumbyname(rule_name)
            if self.environ.geteuid() == 0:
                reply = QtWidgets.QMessageBox.warning(self, 'Revert Changes',
                                          "Are you sure you want to revert changes for rule " \
                                          + rule_name + " ?",
                                          QtWidgets.QMessageBox.Yes, QtWidgets.QMessageBox.No)
                if reply == QtWidgets.QMessageBox.Yes:
                    thread = runThread(self.controller, 'undo', self.logger,
                                       rule_num)
                    #####
                    # Converting pyqt4 signal/slot connect to pyqt5
                    # self.connect(thread, SIGNAL('tupdate(QString)'), self.tupdate)
                    # self.connect(thread, SIGNAL('supdate(QString)'), self.supdate)
                    thread.tupdate.connect(self.tupdate)
                    thread.supdate.connect(self.supdate)
                    self.threads.append(thread)
                    for waitingthread in self.threads:
                        waitingthread.start()
            else:
                discard = QtWidgets.QMessageBox.warning(self, 'Revert Changes',
                                              'Root level privileges are required to undo changes!',
                                              QtWidgets.QMessageBox.Ok)
            self.logger.log(LogPriority.DEBUG,
                            ['GUI', "Exit Rule Revert."])

    def savechanges(self):
        '''Slot for the save button visible in the ciFrame pane. Saves changes to
        the stonix config file and updates the current values of the
        configuration items currently held by the rule objects.
        
        @author: David Kennel


        '''
        for citem in self.ruleci:
            self.ruleci[citem].updatecivalues()
        self.controller.regenerateconfig(True)

    def clearchanges(self):
        '''Slot for the cancel button visible in the ciFrame pane. Clears all
        changes and resets the values to what is held in the currvalue of the
        ci objects.
        
        @author: David Kennel


        '''
        for citem in self.ruleci:
            self.ruleci[citem].clearchanges()

    def closeEvent(self, event):
        '''Capture the window closeEvent and clean up our lock file before
        accepting the event.
        
        @author: David Kennel

        :param event: 

        '''
        self.guiexit()
        event.accept()


class CiFrame(QtWidgets.QFrame):
    '''The ciFrame manages the display for the config items for each rule. Each
    rule is tied to it's ciFrame via the ruleci dictionary.
    
    @author: David Kennel
    @change: 2017/13/9 Brandon Gonzales Added function setenableci.


    '''
    def __init__(self, parent, rulenum, controller, logger):
        """
        Constructor for the ciFrame. Expects to receive a rule number and a
        reference to the controller at time of instantiation.

        @param int: rulenum - rule number that this ciFrame belongs to
        @param controller: the controller object
        @author: David Kennel
        """
        super(CiFrame, self).__init__(parent)
        self.setFrameShadow(QtWidgets.QFrame.Raised)
        self.cframelayout = QtWidgets.QVBoxLayout()
        self.rulenum = rulenum
        self.rulename = controller.getrulenamebynum(rulenum)
        self.rule_config_opts = controller.getruleconfigoptions(rulenum)
        for opt in self.rule_config_opts:
            self.ciname = QtWidgets.QLabel()
            self.ciname.setObjectName('name' + opt.getkey())
            self.ciname.setText("<b>" + opt.getkey() + "</b>")
            self.cidescription = QtWidgets.QPlainTextEdit()
            self.cidescription.setPlainText(opt.getinstructions())
            self.cidescription.setReadOnly(True)
            self.ci_value_label = QtWidgets.QLabel()
            self.ci_datatype = opt.getdatatype()
            if self.ci_datatype == 'string':
                self.ci_value_label.setText("Value:")
                self.ci_value = QtWidgets.QLineEdit()
                self.ci_value.setText(opt.getcurrvalue())
            if self.ci_datatype == 'int':
                self.ci_value_label.setText("Value:")
                self.ci_value = QtWidgets.QLineEdit()
                self.ci_value.setText(str(opt.getcurrvalue()))
            elif self.ci_datatype == 'bool':
                try:
                    self.ci_value_label.setText('')
                    self.ci_value = QtWidgets.QCheckBox('&Enabled')
                    self.ci_value.setChecked(opt.getcurrvalue())
                except(TypeError):
                    logger.log(LogPriority.ERROR,
                               ['gui.CiFrame.init',
                                'Bool check box received bad data from ' + str(rulenum)])
                    # print 'gui,CiFrame.init: Bool check box received bad data from ' + str(rulenum)
            elif self.ci_datatype == 'list':
                self.ci_value_label.setText('Value:')
                self.ci_value = QtWidgets.QLineEdit()
                rawlist = opt.getcurrvalue()
                strlist = ''
                for item in rawlist:
                    strlist = strlist + item + ' '
                self.ci_value.setText(strlist)
            self.ci_value.setObjectName('value' + opt.getkey())
            self.ci_usercomment_label = QtWidgets.QLabel()
            self.ci_usercomment_label.setText("User Comment:")
            self.ci_usercomment_value = QtWidgets.QPlainTextEdit()
            self.ci_usercomment_value.setPlainText(opt.getusercomment())
            self.ci_usercomment_value.setObjectName('ucvalue' + opt.getkey())
            self.line = QtWidgets.QFrame()
            self.line.setFrameStyle(QtWidgets.QFrame.HLine | QtWidgets.QFrame.Sunken)
            self.cframelayout.addWidget(self.ciname)
            self.cframelayout.addWidget(self.cidescription)
            self.cframelayout.addWidget(self.ci_value_label)
            self.cframelayout.addWidget(self.ci_value)
            self.cframelayout.addWidget(self.ci_usercomment_label)
            self.cframelayout.addWidget(self.ci_usercomment_value)
            self.cframelayout.addWidget(self.line)
        self.setLayout(self.cframelayout)

    def updatecivalues(self):
        '''This method will write the current values of the ci_value and the
        ci_usercomment back to the configuration item object from which they
        came.
        
        @author: David Kennel
        @change: Breen Malmberg - 09/04/2018 - cannot str() typecast certain
                unicode characters (for ex: 'ascii' codec can't encode character u'\u0301')
                so str() was replaced with encode() method to handle
                unreadable unicode characters


        '''

        for opt in self.rule_config_opts:

            datatype = opt.getdatatype()
            ciname = opt.getkey()
            myuc = self.findChild(QtWidgets.QPlainTextEdit, 'ucvalue' + ciname)

            if datatype == 'string' or datatype == 'int' or datatype == 'float':
                mydata = self.findChild(QtWidgets.QLineEdit, 'value' + ciname)
                mydataval = mydata.text().encode('ascii', 'ignore')
            elif datatype == 'bool':
                mydata = self.findChild(QtWidgets.QCheckBox, 'value' + ciname)
                mydataval = mydata.isChecked()
            elif datatype == 'list':

                mydata = self.findChild(QtWidgets.QLineEdit, 'value' + ciname)
                mydataval = mydata.text().encode('ascii', 'ignore')
                mydataval = mydataval.split()

            myucval = myuc.toPlainText()
            valid = opt.updatecurrvalue(mydataval)

            if not valid:
                QtWidgets.QMessageBox.warning(self, "Validation Error", "Invalid value for Rule: " + self.rulename + " CI: " + ciname + ".")
                mydata.setFocus()
                return

            opt.setusercomment(myucval)

    def clearchanges(self):
        '''This method will undo any changes that the user has made to any of the
        ci feilds in the gui.
        @author: David Kennel


        '''
        for opt in self.rule_config_opts:
            datatype = opt.getdatatype()
            name = opt.getkey()
            myuc = self.findChild(QtWidgets.QPlainTextEdit, 'ucvalue' + name)
            if datatype == 'string':
                mydata = self.findChild(QtWidgets.QLineEdit, 'value' + name)
                mydata.setText(opt.getcurrvalue())
            elif datatype == 'bool':
                mydata = self.findChild(QtWidgets.QCheckBox, 'value' + name)
                mydata.setChecked(opt.getcurrvalue())
            elif datatype == 'list':
                mydata = self.findChild(QtWidgets.QLineEdit, 'value' + name)
                rawlist = opt.getcurrvalue()
                strlist = ''
                for item in rawlist:
                    strlist = strlist + item + ' '
                mydata.setText(strlist)
            myuc.setPlainText(opt.getusercomment())

    def setenableci(self, enabled):
        '''This function will either enable or disable the editable QtWidgets in
        this ci frame.

        :param enabled: boolean to enable or disable
        @author: Brandon Gonzales

        '''
        for opt in self.rule_config_opts:
            datatype = opt.getdatatype()
            name = opt.getkey()
            myuc = self.findChild(QtWidgets.QPlainTextEdit, 'ucvalue' + name)
            if datatype == 'string':
                mydata = self.findChild(QtWidgets.QLineEdit, 'value' + name)
                mydata.setEnabled(enabled)
            elif datatype == 'bool':
                mydata = self.findChild(QtWidgets.QCheckBox, 'value' + name)
                mydata.setEnabled(enabled)
            elif datatype == 'list':
                mydata = self.findChild(QtWidgets.QLineEdit, 'value' + name)
                mydata.setEnabled(enabled)
        return


class aboutStonix(QtWidgets.QDialog):
    '''The aboutStonix class displays a simple popup dialog containing basic
    information about the stonix app.
    @author: David Kennel


    '''

    def __init__(self, stonixversion, parent=None):
        """
        aboutStonix constructor. Sets up a simple popup with text
        """
        QtWidgets.QDialog.__init__(self, parent)

        self.stonixversion = stonixversion

        self.textLabel3 = QtWidgets.QLabel(self)
        self.textLabel3.setWordWrap(True)
        self.textLabel3.setGeometry(QtCore.QRect(10, 10, 400, 201))

        self.closebutton = QtWidgets.QPushButton('Close', self)
        self.closebutton.clicked.connect(self.close)

        mainlayout = QtWidgets.QVBoxLayout()
        mainlayout.addWidget(self.textLabel3)
        mainlayout.addStretch()
        mainlayout.addWidget(self.closebutton)

        self.setLayout(mainlayout)
        self.languageChange()

        self.resize(QtCore.QSize(700, 550).expandedTo(self.minimumSizeHint()))
        # self.clearWState(QtCore.QtCore.Qt.WState_Polished)

    def languageChange(self):
        '''set window's title, stonix version and copyright text'''

        self.setWindowTitle("About LANL-STONIX")

        copyrightText = '''Copyright 2015-2019.  Los Alamos National Security, LLC. This material was \n
produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos \n
National Laboratory (LANL), which is operated by Los Alamos National \n
Security, LLC for the U.S. Department of Energy. The U.S. Government has \n
rights to use, reproduce, and distribute this software.  NEITHER THE \n
GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY, \n
EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE. \n
If software is modified to produce derivative works, such modified software \n
should be clearly marked, so as not to confuse it with the version \n
available from LANL. \n

Additionally, this program is free software; you can redistribute it and/or \n
modify it under the terms of the GNU General Public License as published by \n
the Free Software Foundation; either version 2 of the License, or (at your \n
option) any later version. Accordingly, this program is distributed in the \n
hope that it will be useful, but WITHOUT ANY WARRANTY; without even the \n
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. \n
See the GNU General Public License for more details.'''

        self.textLabel3.setText(self.__tr("<p align=\"center\"><b><font size=\"+1\">LANL-stonix-" + str(self.stonixversion) + "</font></b></p><br><p align=\"center\">Los Alamos National Laboratory Security Tool On *NIX</p><br><p align=\"center\">" + copyrightText + "</p>"))

    def __tr(self, s, c=None):
        '''

        @param s:
        @param c:
        @return:
        '''

        return QtWidgets.qApp.translate("aboutStonix", s, c)


class Ui_logBrowser(QtWidgets.QDialog):
    '''The Ui_logBrowser class displays a read only text browser which displays
    the stonix logs.
    
    @author: David Kennel


    '''
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        # self.sizeGripEnabled(True)
        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        # self.buttonBox.setGeometry(QRect(50, 260, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Close)
        self.textBrowser = QtWidgets.QTextBrowser(self)
        # self.textBrowser.setGeometry(QRect(0, 0, 401, 261))
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.textBrowser)
        layout.addWidget(self.buttonBox)
        self.setLayout(layout)
        self.retranslateUi()
        #####
        # Converting signal/slot connect to PyQt5
        # QtCore.QObject.connect(self.buttonBox, SIGNAL("clicked(QAbstractButton*)"),
        #                self.close)
        self.buttonBox.clicked.connect(self.close)
        QtCore.QMetaObject.connectSlotsByName(self)
        self.resize(QtCore.QSize(800, 600).expandedTo(self.minimumSizeHint()))

    def retranslateUi(self):
        self.setWindowTitle("Log Viewer")

    def displaytext(self, text):
        '''Display the submitted text in the textBrowser.

        :param string: or list:
        @author David Kennel
        :param text: 

        '''
        if type(text) is list:
            temptext = ''
            for line in text:
                temptext = temptext + line
            text = temptext
        self.textBrowser.setPlainText(text)
        self.textBrowser.setReadOnly(True)


class runThread(QtCore.QThread):
    '''Thread to manage the running of the full Report, Fix and Undo runs. Running
    this in a thread keeps the main loop available to update the GUI. A
    reference to the controller object is required at class instantiation. An
    action to be performed is also required and must be one of 'report', 'fix',
    or 'undo'.

    :param controller: a reference to the controller object.
    :param action: report', 'fix', 'undo'
    :param ruleid: int - id number of the rule to run. Will default to a none
    object which this class will interpret to mean run all rules.
    @author: David Kennel

    '''
    #####
    # New for PyQt5
    supdate_signal = QtCore.pyqtSignal('PyQt_PyObject', name="supdate")
    tupdate_signal = QtCore.pyqtSignal('PyQt_PyObject', name="tupdate")
    #####

    def __init__(self, controller, action, logger, ruleid=None):
        super(runThread, self).__init__()
        self.controller = controller
        self.action = action
        self.ruleidlist = []
        self.logger = logger
        self.stopflag = False
        if ruleid == None:
            self.rule_data = self.controller.getallrulesdata()
            for rnum in self.rule_data:
                ruleid = rnum
                self.ruleidlist.append(ruleid)
        else:
            self.ruleidlist.append(ruleid)
        self.logger.log(LogPriority.DEBUG,
                        ['GUI.runThread',
                         'runThread constructed. ruleid=' + str(ruleid)])

    def run(self):
        '''The run method will run the rules calling their fix, report or undo
        methods as directed by the action.
        
        @author: David Kennel


        '''
        if self.stopflag:
            return
        total = len(self.ruleidlist)
        completed = 0
        for ruleid in self.ruleidlist:
            name = self.controller.getrulenamebynum(ruleid)
            sstatus = {"rulename": name,
                       "completed": str(completed),
                       "total": str(total)}
            #####
            # Signal/slot change for PyQt5
            # self.emit(SIGNAL('supdate(QString)'), sstatus)
            self.supdate_signal.emit(sstatus)
            self.logger.log(LogPriority.DEBUG,
                            ['GUI.runThread.run',
                             'Sent supdate signal: ' + str(sstatus)])
            # Look for the stop flag and cleanly terminate processing
            if self.stopflag:
                compliant = self.controller.getrulecompstatus(ruleid)
                tstatus = {"rulename": 'Canceled',
                           "ruleid": str(ruleid),
                           "compliant": str(compliant),
                           "completed": str(100),
                           "total": str(100)}
                #####
                # Signal/slot change for PyQt5
                # self.emit(SIGNAL('tupdate(QString)'), status)
                self.tupdate_signal.emit(tstatus)
                self.logger.log(LogPriority.DEBUG,
                                ['GUI.runThread.run',
                                 'Sent tupdate signal for stop flag: ' + str(tstatus)])
                return
            elif self.action == 'fix':
                self.controller.runruleharden(ruleid)
            elif self.action == 'report':
                self.controller.runruleaudit(ruleid)
            elif self.action == 'undo':
                self.controller.undorule(ruleid)
            compliant = self.controller.getrulecompstatus(ruleid)
            completed = completed + 1
            tstatus = {"rulename": name,
                       "ruleid": str(ruleid),
                       "compliant": str(compliant),
                       "completed": str(completed),
                       "total": str(total),
                       "ruleenabled": "False"}

            ruleconfigoptions = self.controller.getruleconfigoptions(ruleid)

            # check if there were any CIs at all
            if len(ruleconfigoptions) > 0:
                primaryci = ruleconfigoptions[0]
                cidtype = primaryci.getdatatype()
                ciname = primaryci.getkey()

                civalue = primaryci.getcurrvalue()
                if cidtype == 'bool':
                    if civalue:
                        tstatus['ruleenabled'] = 'True'
                else:
                    # This rule has no fix function
                    tstatus['ruleenabled'] = 'True'

                if self.action == 'fix':
                    if tstatus['ruleenabled'] == 'False':
                        self.controller.set_rule_detailedresults(ruleid, "fix", False,
                                                                 "Fix was not run and nothing was changed, because the configuration item '" + str(
                                                                     ciname) + "' was not enabled.")
                else:
                    # fix didn't actually run, but since it wasn't a 'fix' action
                    # in the first place, we don't want to imply an anomaly with fix
                    # which doesn't exist under that condition
                    tstatus['ruleenabled'] = 'True'

            else:
                # This rule had no CI
                # we don't want to imply an anomaly with fix
                # which doesn't exist under that condition
                tstatus['ruleenabled'] = 'True'

            # This is a one-off because schedulestonix is the only rule
            # with a CI that doesn't require any CIs to be enabled in order to run fix
            if name.lower() == 'schedulestonix':
                tstatus['ruleenabled'] = 'True'

            #####
            # Signal/slot change for PyQt5
            # self.emit(SIGNAL('tupdate(QString)'), status)
            self.tupdate_signal.emit(tstatus)
            self.logger.log(LogPriority.DEBUG,
                            ['GUI.runThread.run',
                             'Sent tupdate signal: ' + str(tstatus)])
