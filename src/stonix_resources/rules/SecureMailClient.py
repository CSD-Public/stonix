###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was  #
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
'''
This method runs all the report methods for RuleKVEditors defined in the
dictionary
@copyright: 2014-2016 Los Alamos National Security, LLC All rights reserved
@author: ekkehard j. koch
@change: 2014/03/25 Original Implementation
@change: 2014/10/17 ekkehard OS X Yosemite 10.10 Update
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2015/09/14 eball Fixed paths, separated user and root functionality
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2018/09/11 Brandon R. Gonzales - remove applicability for Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''
from __future__ import absolute_import
import os
import re
from ..ruleKVEditor import RuleKVEditor
from ..localize import APPLEMAILDOMAINFORMATCHING
from ..stonixutilityfunctions import setPerms, getOctalPerms, getOwnership


class SecureMailClient(RuleKVEditor):
    '''

    @author: ekkehard j. koch
    '''

###############################################################################

    def __init__(self, config, environ, logdispatcher, statechglogger):
        RuleKVEditor.__init__(self, config, environ, logdispatcher,
                              statechglogger)
        self.rulenumber = 264
        self.rulename = 'SecureMailClient'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = False
        self.guidance = []
        # This rule is being made not applicable to 10.14 Mojave because the
        # user plist required for fix is now sip protected. We are waiting for
        # a solution to this issue either through research or Apple support.
        self.applicable = {'type': 'white',
                           'os': {'Mac OS X': ['10.12', 'r', '10.13.6']}}

        mailplist = "/Library/Containers/com.apple.mail/Data/Library/" + \
            "Preferences/com.apple.mail.plist"
        sharedplist = "/Library/Preferences/com.apple.mail-shared.plist"
        self.permsdict = {}
        if not self.environ.getosfamily() == "darwin":
            return

        users = []
        if self.environ.geteuid() == 0:
            if os.path.exists('/Users'):
                users = os.listdir("/Users")
            for user in users:
                fullpath1 = "/Users/" + user + mailplist
                fullpath2 = "/Users/" + user + sharedplist
                if not re.search("^\.", user) and \
                   not re.search("^Shared$", user):
                    if os.path.exists(fullpath1):
                        self.getPerms(fullpath1)
                        self.addKVEditor("DisableAppleMailURLLoading",
                                         "defaults",
                                         fullpath1,
                                         "",
                                         {"DisableURLLoading":
                                          ["1", "-bool yes"]},
                                         "present",
                                         "",
                                         "Turn Off URLLoading for the Apple " +
                                         "Mail Client.",
                                         None,
                                         False,
                                         {"DisableURLLoading":
                                          ["0", "-bool no"]})
                        self.addKVEditor("DisableAppleMailInlineAttachmentViewing",
                                         "defaults",
                                         fullpath1,
                                         "",
                                         {"DisableInlineAttachmentViewing":
                                          ["1", "-bool yes"]},
                                         "present",
                                         "",
                                         "Turn Off InlineAttachmentViewing " +
                                         "for the Apple Mail Client.",
                                         None,
                                         False,
                                         {"DisableInlineAttachmentViewing":
                                          ["0", "-bool no"]})
                    if os.path.exists(fullpath2):
                        self.getPerms(fullpath2)
                        self.addKVEditor("AppleMailAlertForNonmatchingDomains",
                                         "defaults",
                                         fullpath2,
                                         "",
                                         {"AlertForNonmatchingDomains":
                                          ["1", "-bool yes"]},
                                         "present",
                                         "",
                                         "Alert User about nonmatching " +
                                         "domains for the Apple Mail Client.",
                                         None,
                                         False,
                                         {"AlertForNonmatchingDomains":
                                          ["0", "-bool no"]})
                        if self.checkConsts([APPLEMAILDOMAINFORMATCHING]):
                            self.addKVEditor("AppleMailDomainForMatching",
                                             "defaults",
                                             fullpath2,
                                             "",
                                             {"DomainForMatching":
                                              [APPLEMAILDOMAINFORMATCHING,
                                               "-array " +
                                               APPLEMAILDOMAINFORMATCHING]},
                                             "present",
                                             "",
                                             "Alert User about email addresses " +
                                             "that do not match " +
                                             APPLEMAILDOMAINFORMATCHING +
                                             " domain for the Apple Mail Client.",
                                             None,
                                             False,
                                             {"DomainForMatching":
                                              [re.escape("~" + sharedplist +
                                                         ", DomainForMatching " +
                                                         "does not exist"), None]})
                        else:
                            self.detailedresults += "\nThe functionality for Apple Mail Domain Matching requires the following constant be defined and not None, in localize.py : APPLEMAILDOMAINFORMATCHING."

        else:
            fullpath1 = self.environ.geteuidhome() + mailplist
            fullpath2 = self.environ.geteuidhome() + sharedplist
            if os.path.exists(fullpath1):
                self.addKVEditor("DisableAppleMailURLLoading",
                                 "defaults",
                                 fullpath1,
                                 "",
                                 {"DisableURLLoading": ["1", "-bool yes"]},
                                 "present",
                                 "",
                                 "Turn Off URLLoading for the Apple " +
                                 "Mail Client.",
                                 None,
                                 False,
                                 {"DisableURLLoading": ["0", "-bool no"]})
                self.addKVEditor("DisableAppleMailInlineAttachmentViewing",
                                 "defaults",
                                 fullpath1,
                                 "",
                                 {"DisableInlineAttachmentViewing":
                                  ["1", "-bool yes"]},
                                 "present",
                                 "",
                                 "Turn Off InlineAttachmentViewing for " +
                                 "the Apple Mail Client.",
                                 None,
                                 False,
                                 {"DisableInlineAttachmentViewing":
                                  ["0", "-bool no"]})
            if os.path.exists(fullpath2):
                self.addKVEditor("AppleMailAlertForNonmatchingDomains",
                                 "defaults",
                                 fullpath2,
                                 "",
                                 {"AlertForNonmatchingDomains":
                                  ["1", "-bool yes"]},
                                 "present",
                                 "",
                                 "Alert User about nonmatching domains " +
                                 "for the Apple Mail Client.",
                                 None,
                                 False,
                                 {"AlertForNonmatchingDomains":
                                  ["0", "-bool no"]})
                if self.checkConsts([APPLEMAILDOMAINFORMATCHING]):
                    self.addKVEditor("AppleMailDomainForMatching",
                                     "defaults",
                                     fullpath2,
                                     "",
                                     {"DomainForMatching":
                                      [APPLEMAILDOMAINFORMATCHING,
                                       "-array " + APPLEMAILDOMAINFORMATCHING]},
                                     "present",
                                     "",
                                     "Alert User about email addresses that " +
                                     "do not match " +
                                     APPLEMAILDOMAINFORMATCHING + " domain " +
                                     "for the Apple Mail Client.",
                                     None,
                                     False,
                                     {"DomainForMatching":
                                      [re.escape("~" + sharedplist +
                                                 ", DomainForMatching does " +
                                                 "not exist"), None]})
                else:
                    self.detailedresults += "\nThe functionality for Apple Mail Domain Matching requires the following constant be defined and not None, in localize.py : APPLEMAILDOMAINFORMATCHING."

    def afterfix(self):
        for path in self.permsdict:
            setPerms(path, self.permsdict[path], self.logdispatch,
                     self.statechglogger)

    def getPerms(self, path):
        startperms = getOwnership(path)
        octalInt = getOctalPerms(path)
        octPerms = int(str(octalInt), 8)
        startperms.append(octPerms)
        self.permsdict[path] = startperms
