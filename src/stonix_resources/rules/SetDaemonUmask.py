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

'''
Created on Nov 8, 2012

The settings file /etc/sysconfig/init contains settings which apply to all
processes started at boot time. The system umask must be set to at least 022,
or daemon processes may create world-writable files. The more restrictive setting
027 protects files, including temporary files and log files, from unauthorized
reading by unprivileged users on the system.
The SetDaemonUmask class searches for each of the relevant config files and
sets the process daemon umask to 022 (0022) to prevent world
writability/readability on the system.

@author: bemalmbe
@change: 04/21/2014 dkennel Updated CI invocation, fixed bug where CI was not
referenced in fix.
@change: 2015/04/17 dkennel updated for new isApplicable
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
'''


import os
import re
import traceback

from ..rule import Rule
from ..logdispatcher import LogPriority
from ..stonixutilityfunctions import iterate


class SetDaemonUmask(Rule):
    '''The settings file /etc/sysconfig/init contains settings which apply to all
    processes started at boot time. The system umask must be set to at least 022,
    or daemon processes may create world-writable files. The more restrictive setting
    027 protects files, including temporary files and log files, from unauthorized
    reading by unprivileged users on the system.
    The SetDaemonUmask class searches for each of the relevant config files and
    sets the process daemon umask to 022 (0022) to prevent world
    writability/readability on the system.
    
    @author bemalmbe


    '''
    def __init__(self, config, environ, logger, statechglogger):

        Rule.__init__(self, config, environ, logger, statechglogger)
        self.formatDetailedResults("initialize")
        self.logger = logger
        self.rulenumber = 68
        self.rulename = 'SetDaemonUmask'
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.detailedresults = 'The SetDaemonUmask rule has not yet been run'
        self.guidance = ['CCE 4220-0']

        # init CIs
        datatype = 'bool'
        key = 'SETDAEMONUMASK'
        instructions = 'To prevent stonix from setting the umask for system services, \
set the value of SetDaemonUmask to False.'
        default = True
        self.SetDaemonUmask = self.initCi(datatype, key, instructions, default)

        datatype2 = 'string'
        key2 = 'UMASK'
        instructions2 = 'Set the umask value you wish to use for daemon processes.'
        default2 = '022'
        self.umaskvalue = self.initCi(datatype2, key2, instructions2, default2)

        self.configfilelist = ['/etc/pam.d/common-session',
                               '/etc/sysconfig/init',
                               '/etc/default/init',
                               '/etc/login.defs',
                               '/etc/launchd.conf']

        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.12', 'r', '10.14.10']}}

    def fix(self):
        '''The fix method will apply the required settings to the system.
        self.rulesuccess will be updated if the rule does not succeed.
        Search for files /etc/sysconfig/init and/or /etc/default/init (on
        Solaris systems), and if one of them exists
        
        @author dkennel, bemalmbe


        '''

        # defaults
        self.detailedresults = ''
        self.iditerator = 0

        try:

            if self.SetDaemonUmask.getcurrvalue():

                if self.environ.getosfamily() == 'darwin':
                    fixsuccessful = self.fixmac()
                elif self.environ.getosfamily() == 'linux':
                    fixsuccessful = self.fixlinux()

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            fixsuccessful = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", fixsuccessful,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return fixsuccessful

    def fixlinux(self):
        '''private method to handle the configuration of *nix based clients
        
        @author bemalmbe


        '''

        # defaults
        rfile = '/etc/sysconfig/init'
        solfile = '/etc/default/init'
        debianfile = '/etc/login.defs'
        debianfile2 = '/etc/pam.d/common-session'
        umaskvalue = str(self.umaskvalue.getcurrvalue())

        try:

            # fix rhel
            if os.path.exists(rfile):

                replacedline = self.replaceLine('^umask ', 'umask ' + umaskvalue + '\n', rfile, [0, 0], 0o644)
                if not replacedline:
                    self.appendLine('\numask ' + umaskvalue + '\n', rfile, [0, 0], 0o644)

            # fix solaris
            elif os.path.exists(solfile):

                replacedline = self.replaceLine('^CMASK ', 'CMASK ' + umaskvalue + '\n', solfile, [0, 0], 0o644)
                if not replacedline:
                    self.appendLine('\nCMASK ' + umaskvalue + '\n', solfile, [0, 0], 0o644)

            # fix debian
            elif os.path.exists(debianfile2):

                replacedline = self.replaceLine('^#session optional\s*pam_umask.so', 'session optional pam_umask.so\n', debianfile2, [0, 0], 0o644)
                if not replacedline:
                    self.appendLine('\nsession optional pam_umask.so\n', debianfile2, [0, 0], 0o644)

                if os.path.exists(debianfile):

                    replacedline = self.replaceLine('^UMASK', 'UMASK ' + umaskvalue + '\n', debianfile, [0, 0], 0o644)
                    if not replacedline:
                        self.appendLine('\nUMASK ' + umaskvalue + '\n', debianfile, [0, 0], 0o644)

            # if all else fails, and mostly for fedora 27 ~
            else:
                if not os.path.exists("/etc/sysconfig"):
                    os.makedirs("/etc/sysconfig", 0o755)
                f = open("/etc/sysconfig/init", "w")
                f.write("umask " + umaskvalue + "\n")
                f.close()

                os.chmod("/etc/sysconfig/init", 0o644)
                os.chown("/etc/sysconfig/init", 0, 0)

            self.rulesuccess = True

        except Exception:
            self.rulesuccess = False
            raise
        return self.rulesuccess

    def fixmac(self):
        '''private method to handle the configuration for mac systems
        
        @author bemalmbe


        '''

        # defaults
        macfile = '/etc/launchd.conf'
        umaskvalue = str(self.umaskvalue.getcurrvalue())

        try:

            if os.path.exists(macfile):

                replacedline = self.replaceLine('^umask', 'umask ' + umaskvalue + '\n', macfile, [0, 0], 0o644)
                if not replacedline:
                    self.appendLine('\numask ' + umaskvalue + '\n', macfile, [0, 0], 0o644)
            else:

                f = open(macfile, 'w')
                f.write('umask 022\n')
                f.close()

                os.chmod(macfile, 0o644)
                os.chown(macfile, 0, 0)

            self.rulesuccess = True

        except Exception:
            self.rulesuccess = False
            raise
        return self.rulesuccess

    def report(self):
        '''The report method examines the current configuration and determines
        whether or not it is correct. If the config is correct then the
        self.compliant, self.detailedresults and self.currstate properties are
        updated to reflect the system status. self.rulesuccess will be updated
        if the rule does not succeed.


        :returns: bool
        @author bemalmbe

        '''

        # defaults
        rfile = '/etc/sysconfig/init'
        solfile = '/etc/default/init'
        debianfile2 = '/etc/login.defs'
        debianfile1 = '/etc/pam.d/common-session'
        macfile = '/etc/launchd.conf'
        self.detailedresults = ''
        umaskvalue = str(self.umaskvalue.getcurrvalue())

        try:

            # check config of rhel file
            if os.path.exists(rfile):

                self.compliant = self.searchString('^umask\s*' + umaskvalue, rfile)

                if not self.compliant:
                    self.detailedresults += '\nConfig string not found in ' + rfile
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)

            # check config of solaris file
            elif os.path.exists(solfile):

                self.compliant = self.searchString('^CMASK\s*' + umaskvalue, solfile)

                if not self.compliant:
                    self.detailedresults += '\nConfig string not found in ' + solfile
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)

            # check config of debian file
            elif os.path.exists(debianfile1):

                self.compliant = self.searchString('^session optional\s*pam_umask.so', debianfile1)

                if not self.compliant:
                    self.detailedresults += '\nConfig string not found in ' + debianfile1
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)

                # if the first debian file exists, check the second one also
                if os.path.exists(debianfile2):

                    self.compliant = self.searchString('^UMASK\s*' + umaskvalue, debianfile2)

                    if not self.compliant:
                        self.detailedresults += '\nConfig string not found in ' + debianfile2
                        self.logger.log(LogPriority.DEBUG, self.detailedresults)

            # check config of mac file
            elif os.path.exists(macfile):

                self.compliant = self.searchString('^umask\s*' + umaskvalue, macfile)

                if not self.compliant:
                    self.detailedresults += '\nConfigure string not found in ' + macfile
                    self.logger.log(LogPriority.DEBUG, self.detailedresults)

            # no config file was found. return False
            else:
                self.compliant = False
                self.detailedresults += '\nNo config file was found!'
                self.logger.log(LogPriority.DEBUG, self.detailedresults)

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
            " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
            return self.rulesuccess
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def searchString(self, searchRE, searchfile):
        '''private method for performing iterative (looping) searches for regular
        expression. Return true if found, false if not found.

        :param searchRE: str regex to search for
        :param searchfile: str string name of file to search contents of
        :returns: bool
        @author bemalmbe

        '''

        # defaults
        foundRE = False
        self.detailedresults = ''

        try:

            f = open(searchfile, 'r')
            configlines = f.readlines()
            f.close()

            for line in configlines:
                if re.search(searchRE, line):
                    foundRE = True

        except IOError:
            self.detailedresults += '\nSpecified searchfile could not be found!'
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        except NameError:
            self.detailedresults += "\nconfiglines variable is undefined. Maybe the specified searchfile doesn't exist?"
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

        return foundRE

    def replaceLine(self, searchRE, replaceValue, targetFile, ownership, perms):
        '''private method for replacing a line in a searchFile's contents with
        value. return true if line is found and replaced, else return false.

        :param searchRE: the regex string to search for
        :param replaceValue: string to replace the matched search term with
        :param targetFile: string file name of file to search
        :param ownership: 2-element list containing: [uid, gid]
        :param perms: 4-digit integer representing the octal format of file permissions
        :returns: bool
        @author: bemalmbe

        '''

        # defaults
        replacedline = False
        tempfile = targetFile + '.stonixtmp'
        self.detailedresults = ''

        try:

            if not isinstance(ownership, list):
                self.detailedresults += '\nownership argument for appendLine must be of type: list'
            if len(ownership) != 2:
                self.detailedresults += '\nownership argument for appendLine must be size 2'
            if not isinstance(perms, int):
                self.detailedresults += '\nperms argument for appendLine must be an integer'
            if len(str(perms)) != 4:
                self.detailedresults += '\nperms argument for appendLine must be in octal format (4 digits)'

            if self.detailedresults != '':
                self.logger.log(LogPriority.DEBUG, self.detailedresults)

            f = open(targetFile, 'r')
            contentlines = f.readlines()
            f.close()

            for line in contentlines:
                if re.search(searchRE, line):
                    contentlines = [c.replace(line, replaceValue) for c in contentlines]
                    replacedline = True

            tf = open(tempfile, 'w')
            tf.writelines(contentlines)
            tf.close()

            event = {'eventtype': 'conf',
                     'filepath': targetFile}
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)

            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(targetFile,
                                                 tempfile,
                                                 myid)

            os.rename(tempfile, targetFile)
            os.chmod(targetFile, perms)
            os.chown(targetFile, ownership[0], ownership[1])

            return replacedline

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)

    def appendLine(self, appendValue, targetFile, ownership, perms):
        '''private method for appending a line (appendValue) to a file
        (targetFile)

        :param appendValue: str string to append to the targetFile
        :param targetFile: str name of the file to append appendValue to
        :param ownership: list 2-element list containing: [uid, gid]
        :param perms: int 4-digit integer representing the octal format of file permissions
        @author: bemalmbe

        '''

        # defaults
        tempfile = targetFile + '.stonixtmp'
        self.detailedresults = ''

        try:

            if not isinstance(ownership, list):
                self.detailedresults += '\nownership argument for appendLine must be of type: list'
            if len(ownership) != 2:
                self.detailedresults += '\nownership argument for appendLine must be size 2'
            if not isinstance(perms, int):
                self.detailedresults += '\nperms argument for appendLine must be an integer'
            if len(str(perms)) != 4:
                self.detailedresults += '\nperms argument for appendLine must be in octal format (4 digits)'

            if self.detailedresults != '':
                self.logger.log(LogPriority.DEBUG, self.detailedresults)

            f = open(targetFile, 'r')
            contentlines = f.readlines()
            f.close()

            contentlines.append('\n# This line added by STONIX')
            contentlines.append(appendValue)

            tf = open(tempfile, 'w')
            tf.writelines(contentlines)
            tf.close()

            event = {'eventtype': 'conf',
                     'filepath': targetFile}
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)

            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(targetFile,
                                                 tempfile,
                                                 myid)

            os.rename(tempfile, targetFile)
            os.chmod(targetFile, perms)
            os.chown(targetFile, ownership[0], ownership[1])

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
