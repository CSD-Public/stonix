# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'stonix_wrapper.ui'
#
# Created: Tue Nov  3 14:49:47 2015
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

class Ui_StonixWrapper(object):
    def setupUi(self, StonixWrapper):
        StonixWrapper.setObjectName(_fromUtf8("StonixWrapper"))
        StonixWrapper.resize(371, 134)
        self.gridLayout = QtGui.QGridLayout(StonixWrapper)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.label_2 = QtGui.QLabel(StonixWrapper)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setWordWrap(True)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.label = QtGui.QLabel(StonixWrapper)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setObjectName(_fromUtf8("label"))
        self.gridLayout.addWidget(self.label, 1, 1, 1, 1)
        self.userButton = QtGui.QPushButton(StonixWrapper)
        self.userButton.setObjectName(_fromUtf8("userButton"))
        self.gridLayout.addWidget(self.userButton, 2, 0, 1, 1)
        self.adminButton = QtGui.QPushButton(StonixWrapper)
        self.adminButton.setObjectName(_fromUtf8("adminButton"))
        self.gridLayout.addWidget(self.adminButton, 2, 1, 1, 1)
        self.quitButton = QtGui.QPushButton(StonixWrapper)
        self.quitButton.setObjectName(_fromUtf8("quitButton"))
        self.gridLayout.addWidget(self.quitButton, 2, 2, 1, 1)
        self.label_3 = QtGui.QLabel(StonixWrapper)
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.gridLayout.addWidget(self.label_3, 0, 0, 1, 3)

        self.retranslateUi(StonixWrapper)
        QtCore.QMetaObject.connectSlotsByName(StonixWrapper)

    def retranslateUi(self, StonixWrapper):
        StonixWrapper.setWindowTitle(_translate("StonixWrapper", "Stonix4Mac", None))
        self.label_2.setText(_translate("StonixWrapper", "Run as normal User", None))
        self.label.setText(_translate("StonixWrapper", "Run as an Admin", None))
        self.userButton.setStatusTip(_translate("StonixWrapper", "Run as a normal User", None))
        self.userButton.setWhatsThis(_translate("StonixWrapper", "Run as a normal User", None))
        self.userButton.setText(_translate("StonixWrapper", "User", None))
        self.adminButton.setToolTip(_translate("StonixWrapper", "Run as an Admin User", None))
        self.adminButton.setWhatsThis(_translate("StonixWrapper", "Run as an Admin User", None))
        self.adminButton.setText(_translate("StonixWrapper", "Admin", None))
        self.quitButton.setText(_translate("StonixWrapper", "Quit", None))
        self.label_3.setText(_translate("StonixWrapper", "Stonix for Mac", None))

