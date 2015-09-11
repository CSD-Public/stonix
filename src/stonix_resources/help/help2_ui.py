# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'help2.ui'
#
# Created: Thu Sep 10 12:50:46 2015
#      by: PyQt4 UI code generator 4.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_HelpDialog2(object):
    def setupUi(self, HelpDialog2):
        HelpDialog2.setObjectName(_fromUtf8("HelpDialog2"))
        HelpDialog2.resize(610, 421)
        self.gridLayout_4 = QtGui.QGridLayout(HelpDialog2)
        self.gridLayout_4.setObjectName(_fromUtf8("gridLayout_4"))
        self.gridLayout_3 = QtGui.QGridLayout()
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.homeButton = QtGui.QPushButton(HelpDialog2)
        self.homeButton.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("house_2.ico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.homeButton.setIcon(icon)
        self.homeButton.setIconSize(QtCore.QSize(24, 24))
        self.homeButton.setObjectName(_fromUtf8("homeButton"))
        self.gridLayout_3.addWidget(self.homeButton, 0, 0, 1, 1)
        self.backButton = QtGui.QPushButton(HelpDialog2)
        self.backButton.setText(_fromUtf8(""))
        self.backButton.setObjectName(_fromUtf8("backButton"))
        self.gridLayout_3.addWidget(self.backButton, 0, 1, 1, 1)
        self.search = QtGui.QLineEdit(HelpDialog2)
        self.search.setObjectName(_fromUtf8("search"))
        self.gridLayout_3.addWidget(self.search, 0, 3, 1, 1)
        self.gridLayout_2 = QtGui.QGridLayout()
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem, 1, 0, 1, 1)
        self.okButton = QtGui.QPushButton(HelpDialog2)
        self.okButton.setObjectName(_fromUtf8("okButton"))
        self.gridLayout_2.addWidget(self.okButton, 1, 4, 1, 1)
        self.splitter = QtGui.QSplitter(HelpDialog2)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName(_fromUtf8("splitter"))
        self.tabWidget = QtGui.QTabWidget(self.splitter)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Maximum, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(200)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tabWidget.sizePolicy().hasHeightForWidth())
        self.tabWidget.setSizePolicy(sizePolicy)
        self.tabWidget.setMaximumSize(QtCore.QSize(300, 16777215))
        self.tabWidget.setAccessibleName(_fromUtf8(""))
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.ToC = QtGui.QWidget()
        self.ToC.setObjectName(_fromUtf8("ToC"))
        self.gridLayout = QtGui.QGridLayout(self.ToC)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.ToCBrowser = QtGui.QTextBrowser(self.ToC)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Maximum, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.ToCBrowser.sizePolicy().hasHeightForWidth())
        self.ToCBrowser.setSizePolicy(sizePolicy)
        self.ToCBrowser.setMinimumSize(QtCore.QSize(100, 200))
        self.ToCBrowser.setMaximumSize(QtCore.QSize(296, 16777215))
        self.ToCBrowser.setObjectName(_fromUtf8("ToCBrowser"))
        self.gridLayout.addWidget(self.ToCBrowser, 0, 0, 1, 1)
        self.tabWidget.addTab(self.ToC, _fromUtf8(""))
        self.Index = QtGui.QWidget()
        self.Index.setObjectName(_fromUtf8("Index"))
        self.gridLayout_5 = QtGui.QGridLayout(self.Index)
        self.gridLayout_5.setObjectName(_fromUtf8("gridLayout_5"))
        self.IndexBrowser = QtGui.QTextBrowser(self.Index)
        self.IndexBrowser.setMinimumSize(QtCore.QSize(100, 0))
        self.IndexBrowser.setMaximumSize(QtCore.QSize(396, 16777215))
        self.IndexBrowser.setObjectName(_fromUtf8("IndexBrowser"))
        self.gridLayout_5.addWidget(self.IndexBrowser, 0, 0, 1, 1)
        self.tabWidget.addTab(self.Index, _fromUtf8(""))
        self.extendedHelpBrowser = QtGui.QTextBrowser(self.splitter)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.MinimumExpanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(30)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.extendedHelpBrowser.sizePolicy().hasHeightForWidth())
        self.extendedHelpBrowser.setSizePolicy(sizePolicy)
        self.extendedHelpBrowser.setMinimumSize(QtCore.QSize(300, 200))
        self.extendedHelpBrowser.setObjectName(_fromUtf8("extendedHelpBrowser"))
        self.gridLayout_2.addWidget(self.splitter, 0, 0, 1, 5)
        spacerItem1 = QtGui.QSpacerItem(17, 17, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem1, 1, 2, 1, 1)
        spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem2, 1, 3, 1, 1)
        self.gridLayout_3.addLayout(self.gridLayout_2, 1, 0, 1, 4)
        self.forwardButton = QtGui.QPushButton(HelpDialog2)
        self.forwardButton.setText(_fromUtf8(""))
        self.forwardButton.setObjectName(_fromUtf8("forwardButton"))
        self.gridLayout_3.addWidget(self.forwardButton, 0, 2, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout_3, 0, 0, 1, 1)

        self.retranslateUi(HelpDialog2)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(HelpDialog2)

    def retranslateUi(self, HelpDialog2):
        HelpDialog2.setWindowTitle(_translate("HelpDialog2", "Dialog", None))
        self.homeButton.setToolTip(_translate("HelpDialog2", "Home", None))
        self.backButton.setToolTip(_translate("HelpDialog2", "Back", None))
        self.search.setToolTip(_translate("HelpDialog2", "Search", None))
        self.okButton.setToolTip(_translate("HelpDialog2", "Exit help", None))
        self.okButton.setText(_translate("HelpDialog2", "Ok", None))
        self.tabWidget.setToolTip(_translate("HelpDialog2", "Table of Contents", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.ToC), _translate("HelpDialog2", "Table of Contents", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.Index), _translate("HelpDialog2", "Index", None))
        self.forwardButton.setToolTip(_translate("HelpDialog2", "Forward", None))

