# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'general_warning.ui'
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

class Ui_GeneralWarning(object):
    def setupUi(self, GeneralWarning):
        GeneralWarning.setObjectName(_fromUtf8("GeneralWarning"))
        GeneralWarning.setWindowModality(QtCore.Qt.ApplicationModal)
        GeneralWarning.resize(411, 220)
        GeneralWarning.setWindowTitle(_fromUtf8(""))
        self.gridLayout = QtGui.QGridLayout(GeneralWarning)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.label = QtGui.QLabel(GeneralWarning)
        self.label.setText(_fromUtf8(""))
        self.label.setObjectName(_fromUtf8("label"))
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.buttonBox = QtGui.QDialogButtonBox(GeneralWarning)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setCenterButtons(True)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.gridLayout.addWidget(self.buttonBox, 1, 0, 1, 1)

        self.retranslateUi(GeneralWarning)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), GeneralWarning.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), GeneralWarning.reject)
        QtCore.QMetaObject.connectSlotsByName(GeneralWarning)

    def retranslateUi(self, GeneralWarning):
        pass

