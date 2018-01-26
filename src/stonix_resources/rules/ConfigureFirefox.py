###############################################################################
#                                                                             #
# Copyright 2015-2017.  Los Alamos National Security, LLC. This material was  #
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
Created on Nov 23, 2016

@author: dkennel
@change: 2017/07/07 ekkehard - make eligible for macOS High Sierra 10.13
'''
from __future__ import absolute_import

import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority


class ConfigureFirefox(Rule):
    '''
    The ConfigureFirefox rule deploys a managed Firefox preferences .js file
    into the location from which the default configuration is read. This is to
    provide a reasonable default configuration for the Firefox browser. Many
    of these configurations are not strictly security related.
    '''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 93
        self.rulename = 'ConfigureFirefox'
        self.formatDetailedResults("initialize")
        self.mandatory = False
        self.helptext = '''The ConfigureFirefox rule will configure \
the Firefox web browser with reasonable defaults for use inside LANL. This
includes the following settings:
Set the home page to int.lanl.gov
Disable remember signons
Configure the proxy settings
Configure SPNEGO for web SSO
Disable telemetry and crash reports
Install the LANL WIN OLT Cert
'''
        self.rootrequired = True
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.9', 'r', '10.13.10']}}
        self.guidance = ['Local']
        datatype = 'bool'
        key = 'configurefirefox'
        instructions = '''To disable this rule set the value of \
CONFIGUREFIREFOX to False.'''
        default = True
        self.cffci = self.initCi(datatype, key, instructions, default)
        self.defprefpath = None
        self.binpath = None
        self.stonixprefpath = None
        self.stonixautoconfpath = None
        self.stonixpref = "astonix-v2.js"
        self.stonixautoconf = 'stonixfirefox.cfg'
        self.discoverPaths()

    def discoverPaths(self):
        ''' The discoverPath methods will attempt to locate the path
        to the Firefox preferences folder and the location of the Firefox
        binary (the location is similar but not identical on the various
        *NIXes). If found it will return the paths, if not found it will
        return NONE. None usually indicates that Firefox
        isn't installed or is not installed in the expected location.

        @return: string|None, string is fully qualified path to the directory.
        '''
        prefpath = None
        binpath = None
        if os.path.exists('/Applications'):
            # This is MacOS
            if os.path.exists('/Applications/Firefox.app/Contents/Resources/defaults/pref'):
                prefpath = '/Applications/Firefox.app/Contents/Resources/defaults/pref'
            if os.path.exists('/Applications/Firefox.app/Contents/Resources'):
                binpath = '/Applications/Firefox.app/Contents/Resources'
        elif os.path.exists('/usr/lib64'):
            # Linux with lib64
            if os.path.exists('/usr/lib64/firefox'):
                binpath = '/usr/lib64/firefox'
                if os.path.exists('/usr/lib64/firefox/defaults/preferences'):
                    prefpath = '/usr/lib64/firefox/defaults/preferences'
                elif os.path.exists('/usr/lib64/firefox/defaults/pref'):
                    prefpath = '/usr/lib64/firefox/defaults/pref'
        elif os.path.exists('/usr/lib/firefox'):
            binpath = '/usr/lib/firefox'
            if os.path.exists('/usr/lib/firefox/defaults/preferences'):
                prefpath = '/usr/lib/firefox/defaults/preferences'
            elif os.path.exists('/usr/lib/firefox/defaults/pref'):
                prefpath = '/usr/lib/firefox/defaults/pref'
        self.defprefpath = prefpath
        self.binpath = binpath
        try:
            self.stonixprefpath = os.path.join(self.defprefpath,
                                               self.stonixpref)
        except(AttributeError):
            self.stonixprefpath = None
        try:
            self.stonixautoconfpath = os.path.join(self.binpath,
                                               self.stonixautoconf)
        except(AttributeError):
            self.stonixautoconfpath = None
        return True

    def report(self):
        """
        Report on whether the Firefox configuration meets expectations.

        @return: bool
        @author: D.Kennel
        """
        self.discoverPaths()

        compliant = False
        self.detailedresults = ""
        oldcount = 0

        try:
            if not self.defprefpath:
                compliant = True
                self.detailedresults = 'No Firefox installation detected. Is it not installed or installed in a non-standard location?'
            elif os.path.exists(self.stonixprefpath) and os.path.exists(self.stonixautoconfpath):
                compliant = True
                self.detailedresults = 'STONIX Firefox preferences file detected. Everything looks OK.'
            elif os.path.exists(self.defprefpath):
                for prefs in os.listdir(self.defprefpath):
                    if re.search('astonix-', prefs):
                        compliant = False
                        oldcount = oldcount +1
                        self.detailedresults = "STONIX preferences detected but it's an old version and should be updated."
                if oldcount == 0:
                    compliant = False
                    self.detailedresults = 'Firefox found but there is no STONIX preference file.'
            if compliant:
                self.targetstate = 'configured'
                self.compliant = True
            else:
                self.targetstate = 'notconfigured'
                self.compliant = False

        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = 'ConfigureFirefox: '
            self.detailedresults = self.detailedresults + \
                traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        """
        If needed drop the STONIX Firefox preference file.

        @author: D. Kennel
        """
        self.detailedresults = ""
        if self.cffci.getcurrvalue():
            self.rulesuccess = True
            try:
                prefs = """// Call to STONIX configured preferences
pref('general.config.obscure_value', 0);
pref('general.config.filename', '""" + self.stonixautoconf + """');
"""
                autoconf = '''//put everything in a try/catch
try {

//Privacy & Security
defaultPref("signon.rememberSignons", false);

// 1) env variables
if(getenv("USER") != "") {
  // *NIX settings
  var env_user = getenv("USER");
  var env_home = getenv("HOME");
} else {
  // Windows settings
  var env_user = getenv("USERNAME");
  var env_home = getenv("HOMEPATH");
}
var env_mozdebug = getenv("MOZILLA_DEBUG");

defaultPref("browser.startup.homepage", "data:text/plain,browser.startup.homepage=http://int.lanl.gov");
pref("network.negotiate-auth.trusted-uris", "lanl.gov");
pref("network.negotiate-auth.using-native-gsslib", true);
defaultPref("network.proxy.autoconfig_url", "http://wpad.lanl.gov/wpad.dat");
defaultPref("network.proxy.type", 2);

// Disable updater
lockPref("app.update.enabled", false);
// make absolutely sure it is really off
lockPref("app.update.auto", false);
lockPref("app.update.mode", 0);
lockPref("app.update.service.enabled", false);

// Don't show 'know your rights' on first run
pref("browser.rights.3.shown", true);

// Don't show WhatsNew on first run after every update
pref("browser.startup.homepage_override.mstone","ignore");

// Disable health reporter
lockPref("datareporting.healthreport.service.enabled", false);

// Disable all data upload (Telemetry and FHR)
lockPref("datareporting.policy.dataSubmissionEnabled", false);

// Disable crash reporter
lockPref("toolkit.crashreporter.enabled", false);

// Close the try, and call the catch()
} catch(e) {displayError("lockedPref", e);}

// Install the WIN OLT Certificate Authority
var Cc = Components.classes;
var Ci = Components.interfaces;
var certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
var certdb2 = certdb;
try {
   certdb2 = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB2);
} catch (e) {}
cert = "MIIDGTCCAgGgAwIBAgIQOFerAOrQH5dA/lfx140o2zANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDExRMQU5MIFdJTiBPTFQgUm9vdCBDQTAeFw0xNTA3MzAxNzUzNTFaFw0zNTA3MzAxODAzNTBaMB8xHTAbBgNVBAMTFExBTkwgV0lOIE9MVCBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj1ujSUaiJz4IL3NQtGPVErepJbCApnhJDOyXSVluo6I+HoUfniFZoPKQjlw1IEUX0ssbkc9C0385xwX06t3tmgDODRpqPwHtyxg6MNs2hE5pulfvgQV22Ujvv3svpyM4RkZql+lySxq7/sniP6+BDP3WFdfHVaTU/LblzwhfpO7rNUr3sY7q3vjSVonzZkWOqg/jhWAYVhb0sLxk18/qWRH+W12aHUSq0COC8lU8J1fq80cUx36HqTpkCXd2KtPcNjUVr7Xl3riFrWFBy/JwwD++d69v5IhjxKPvrwoCEqW2uZXLMBy/IFvs3jggkHdYkxEAjo8+wi3Ca43Ai4Xm8QIDAQABo1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJagoh2sz6wKJxXwT1pQMshSBylEwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggEBAIuZqgt4v+Dp4rcOO3f3UibSHKVFUW0q2RwCkKa1BD3v5pGUeLZeOpA8se03z5NcODyGaq3NeZmR8vsVdeujBhSHaQiWw5eTeV6L7MOxMkGiCm4rjdEINGoz1xPhYJVi5MVWR410lhjCcwG9ac1aB0pc43YXZ0aa0mmrdJr5yTGakpXhLsUTmZLv/fekCuiCDHcxqrlEF59MMn1Pu3Nep1N6bgudzuIEtBDTjQeyxaro27ecQrnYmUVNZPLUqqy87DfBcavLc6SlPDmSMEXwlqgzO6s1z47Q/jS635d404SbpS7k/kArAJADF7GLon5NuCEvFiKyAz3TjOzWh2UhfEU="; // This should be the certificate content with no line breaks at all.
certdb.addCertFromBase64(cert, "C,C,C", "");
'''
                # Get filenames for any STONIX preference files that might
                # already exist
                if os.path.exists(self.defprefpath):
                    for prefile in os.listdir(self.defprefpath):
                        if re.search('astonix-', prefile):
                            rmpath = os.path.join(self.defprefpath, prefile)
                            os.remove(rmpath)
                            os.remove(self.stonixautoconfpath)
                defaultconfig = os.path.join(self.binpath, 'mozilla.cfg')
                defaultpref = os.path.join(self.defprefpath, 'autoconfig.js')
                for conffile in [defaultconfig, defaultpref]:
                    if os.path.exists(conffile):
                        os.remove(conffile)
                # create new preference file
                whandle = open(self.stonixprefpath, 'w')
                whandle.write(prefs)
                whandle.close()
                os.chmod(self.stonixprefpath, 0644)
                whandle2 = open(self.stonixautoconfpath, 'w')
                whandle2.write(autoconf)
                whandle.close()
                os.chmod(self.stonixautoconfpath, 0644)

            except (KeyboardInterrupt, SystemExit):
                # User initiated exit
                raise
            except Exception:
                self.rulesuccess = False
                self.detailedresults = 'ConfigureFirefox: '
                self.detailedresults = self.detailedresults + \
                    traceback.format_exc()
                self.rulesuccess = False
                self.logger.log(LogPriority.ERROR,
                                self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def undo(self):
        """
        Undo Configure Firefox changes

        @author: dkennel
        """
        self.targetstate = 'notconfigured'
        try:
            if os.path.exists(self.stonixprefpath):
                os.remove(self.stonixprefpath)
            if os.path.exists(self.stonixautoconfpath):
                os.remove(self.stonixautoconfpath)
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = 'ConfigureFirefoxs: '
            self.detailedresults = self.detailedresults + \
                traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            ['ConfigureFirefoxs.undo',
                             self.detailedresults])
            return False
        self.report()
        if self.currstate == self.targetstate:
            self.detailedresults = 'ConfigureFirefox: Changes ' + \
                'successfully reverted'
        return True
