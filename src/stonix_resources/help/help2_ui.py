# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'help2.ui'
#
# Created: Wed Sep 23 14:25:40 2015
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

class Ui_Help2(object):
    def setupUi(self, Help2):
        Help2.setObjectName(_fromUtf8("Help2"))
        Help2.resize(680, 514)
        self.gridLayout = QtGui.QGridLayout(Help2)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 2, 5, 1, 1)
        self.search = QtGui.QLineEdit(Help2)
        self.search.setObjectName(_fromUtf8("search"))
        self.gridLayout.addWidget(self.search, 0, 4, 1, 4)
        self.splitter = QtGui.QSplitter(Help2)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName(_fromUtf8("splitter"))
        self.tabWidget = QtGui.QTabWidget(self.splitter)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab = QtGui.QWidget()
        self.tab.setObjectName(_fromUtf8("tab"))
        self.gridLayout_2 = QtGui.QGridLayout(self.tab)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.ToCBrowser = QtGui.QTextBrowser(self.tab)
        self.ToCBrowser.setObjectName(_fromUtf8("ToCBrowser"))
        self.gridLayout_2.addWidget(self.ToCBrowser, 0, 0, 1, 1)
        self.tabWidget.addTab(self.tab, _fromUtf8(""))
        self.tab_2 = QtGui.QWidget()
        self.tab_2.setObjectName(_fromUtf8("tab_2"))
        self.gridLayout_3 = QtGui.QGridLayout(self.tab_2)
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.IndexBrowser = QtGui.QTextBrowser(self.tab_2)
        self.IndexBrowser.setObjectName(_fromUtf8("IndexBrowser"))
        self.gridLayout_3.addWidget(self.IndexBrowser, 0, 0, 1, 1)
        self.tabWidget.addTab(self.tab_2, _fromUtf8(""))
        self.webView = QtWebKit.QWebView(self.splitter)
        self.webView.setUrl(QtCore.QUrl(_fromUtf8("about:blank")))
        self.webView.setObjectName(_fromUtf8("webView"))
        self.gridLayout.addWidget(self.splitter, 1, 0, 1, 8)
        self.homeButton = QtGui.QPushButton(Help2)
        self.homeButton.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("house_2.ico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.homeButton.setIcon(icon)
        self.homeButton.setObjectName(_fromUtf8("homeButton"))
        self.gridLayout.addWidget(self.homeButton, 0, 0, 1, 1)
        spacerItem1 = QtGui.QSpacerItem(121, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem1, 0, 3, 1, 1)
        self.okButton = QtGui.QPushButton(Help2)
        self.okButton.setObjectName(_fromUtf8("okButton"))
        self.gridLayout.addWidget(self.okButton, 2, 7, 1, 1)
        self.forwardButton = QtGui.QPushButton(Help2)
        self.forwardButton.setText(_fromUtf8(""))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8("right.ico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.forwardButton.setIcon(icon1)
        self.forwardButton.setObjectName(_fromUtf8("forwardButton"))
        self.gridLayout.addWidget(self.forwardButton, 0, 2, 1, 1)
        self.backButton = QtGui.QPushButton(Help2)
        self.backButton.setText(_fromUtf8(""))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8("left.ico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.backButton.setIcon(icon2)
        self.backButton.setObjectName(_fromUtf8("backButton"))
        self.gridLayout.addWidget(self.backButton, 0, 1, 1, 1)
        spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem2, 2, 6, 1, 1)
        spacerItem3 = QtGui.QSpacerItem(313, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem3, 2, 0, 1, 4)

        self.retranslateUi(Help2)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Help2)

    def retranslateUi(self, Help2):
        Help2.setWindowTitle(_translate("Help2", "Help", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Help2", "Table Of Contents", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Help2", "Index", None))
        self.okButton.setText(_translate("Help2", "Ok", None))

from PyQt4 import QtWebKit
