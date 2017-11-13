# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'general_warning.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_GeneralWarning(object):
    def setupUi(self, GeneralWarning):
        GeneralWarning.setObjectName("GeneralWarning")
        GeneralWarning.setWindowModality(QtCore.Qt.ApplicationModal)
        GeneralWarning.resize(411, 220)
        GeneralWarning.setWindowTitle("")
        self.gridLayout = QtWidgets.QGridLayout(GeneralWarning)
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtWidgets.QLabel(GeneralWarning)
        self.label.setText("")
        self.label.setOpenExternalLinks(True)
        self.label.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByKeyboard|QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextBrowserInteraction|QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(GeneralWarning)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setCenterButtons(True)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 1, 0, 1, 1)

        self.retranslateUi(GeneralWarning)
        self.buttonBox.accepted.connect(GeneralWarning.accept)
        self.buttonBox.rejected.connect(GeneralWarning.reject)
        QtCore.QMetaObject.connectSlotsByName(GeneralWarning)

    def retranslateUi(self, GeneralWarning):
        pass

