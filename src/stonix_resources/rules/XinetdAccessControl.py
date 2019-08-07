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
Created on Aug 5, 2015

The Xinetd access control mechanism should be securely configured, if xinetd is
present.

@author: Breen malmberg
@change: 2015/10/08 eball Help text/PEP8 cleanup
@change: 2016/06/21 eball Fixed perm undo event, full PEP8 compliance
@change: 2017/07/17 ekkehard - make eligible for macOS High Sierra 10.13
@change: 2017/11/13 ekkehard - make eligible for OS X El Capitan 10.11+
@change: 2018/06/08 ekkehard - make eligible for macOS Mojave 10.14
@change: 2019/03/12 ekkehard - make eligible for macOS Sierra 10.12+
@change: 2019/08/07 ekkehard - enable for macOS Catalina 10.15 only
'''



from ..rule import Rule
from ..logdispatcher import LogPriority
from ..localize import XINETDALLOW
from ..stonixutilityfunctions import getOctalPerms
from ..stonixutilityfunctions import getOwnership
from ..stonixutilityfunctions import iterate
import traceback
import os
import re
import stat


class XinetdAccessControl(Rule):
    '''classdocs'''

    def __init__(self, config, environ, logger, statechglogger):
        '''
        Constructor
        '''
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 36
        self.rulename = 'XinetdAccessControl'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.compliant = False
        self.guidance = ['']
        self.iditerator = 0
        self.applicable = {'type': 'white',
                           'family': ['linux', 'solaris', 'freebsd'],
                           'os': {'Mac OS X': ['10.15', 'r', '10.15.10']}}
        # init CIs
        datatype = 'bool'
        key = 'XINETDACCESSCONTROL'
        instructions = "To disable the configuring of the xinetd access " + \
            "control mechanism, set the value of XinetdAccessControl to False."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.constlist = [XINETDALLOW]

        # set up class var's
        if self.checkConsts(self.constlist):  
            self.setvars()

    def setvars(self):
        '''set the values for all the class variables to be used
        
        @author: Breen Malmberg


        '''

        self.confpath = '/etc/xinetd.conf'
        self.partialopt = 'only_from\s*='
        try:
            self.fullopt = '^\s*only_from\s*=\s*' + str(XINETDALLOW)
            self.fixopt = '\tonly_from\t= ' + str(XINETDALLOW) + '\n'
        except UnboundLocalError:
            self.logger.log(LogPriority.DEBUG,
                            "XINETDALLOW constant has not been defined in " +
                            "localize.py, or the import failed")
        except Exception:
            raise

    def readFile(self, path):
        '''read the specified path's contents and return them in a list

        :param path: string the full path to the file to be read
        :returns: contentlines
        :rtype: list
@author: Breen Malmberg

        '''

        self.logger.log(LogPriority.DEBUG, "inside readFile() method")

        contentlines = []

        try:
            self.logger.log(LogPriority.DEBUG,
                            "opening and reading file " + str(path))
            f = open(path, 'r')
            contentlines = f.readlines()
            f.close()
        except IOError:
            self.logger.log(LogPriority.DEBUG,
                            "specified path does not exist, or insufficient " +
                            "permissions to access it")
            return contentlines
        self.logger.log(LogPriority.DEBUG, "finished reading file contents " +
                        "into contentlines. returning.")
        return contentlines

    def findopt(self, path, opt):
        '''search the specified path for the specified option (opt). if found,
        return True, else False.

        :param path: string full path to the file to be searched
        :param opt: string regex or option to search the file for
        :returns: found
        :rtype: bool
@author: Breen Malmberg

        '''

        self.logger.log(LogPriority.DEBUG, "inside findopt() method")

        found = False

        self.logger.log(LogPriority.DEBUG,
                        "getting the file contents of " + str(path))
        contentlines = self.readFile(path)

        try:
            self.logger.log(LogPriority.DEBUG,
                            "searching for " + str(opt) + " in " + str(path))
            for line in contentlines:
                if re.search(opt, line):
                    self.logger.log(LogPriority.DEBUG, "found " + str(opt) +
                                    " in line " + str(line))
                    found = True
        except Exception:
            raise
        self.logger.log(LogPriority.DEBUG, "returning found=" + str(found))
        return found

    def replaceopt(self, path, partialopt, fullopt, perms=[0o600, 0, 0]):
        '''search the specified file for the option partialopt and replace it with
        the option fullopt, if found.

        :param path: string full path to the file to be searched
        :param partialopt: string the regex/option text to search the file for
        :param fullopt: string the full option text to replace the found
        partialopt text with
        :param perms:  (Default value = [0600)
        :param 0: 
        :param 0]: 
        :returns: replaced
        :rtype: bool
@author: Breen Malmberg

        '''

        self.logger.log(LogPriority.DEBUG, "inside replaceopt() method")

        replaced = False

        self.logger.log(LogPriority.DEBUG,
                        "getting the file contents of " + str(path))
        contentlines = self.readFile(path)

        try:

            if not path:
                self.logger.log(LogPriority.DEBUG, "parameter 'path' is blank")
                replaced = False
                return replaced

            if not os.path.exists(path):
                self.logger.log(LogPriority.DEBUG,
                                "parameter 'path' does not exist")
                replaced = False
                return replaced

            tmppath = path + '.stonixtmp'

            self.logger.log(LogPriority.DEBUG, "searching for " +
                            str(partialopt) + " in contentlines")
            for line in contentlines:
                if re.search(partialopt, line):

                    self.logger.log(LogPriority.DEBUG, "found match in line " +
                                    str(line) + " ; replacing it with " +
                                    str(fullopt))
                    contentlines = [c.replace(line, fullopt)
                                    for c in contentlines]
                    self.logger.log(LogPriority.DEBUG,
                                    "replaced the line in contentlines")

            self.logger.log(LogPriority.DEBUG,
                            "opening file " + str(path) + " to write")
            tf = open(tmppath, 'w')

            self.logger.log(LogPriority.DEBUG,
                            "writing contentlines to file " + str(path))
            tf.writelines(contentlines)
            tf.close()

            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)
            event = {'eventtype': 'conf',
                     'filepath': path}
            self.statechglogger.recordchgevent(myid, event)
            self.statechglogger.recordfilechange(tmppath, path, myid)

            os.rename(tmppath, path)

            statdata = os.stat(path)
            mode = stat.S_IMODE(statdata.st_mode)
            self.iditerator += 1
            myid = iterate(self.iditerator, self.rulenumber)

            event = {'eventtype': 'perm',
                     'filepath': path,
                     'startstate': [0, 0, mode],
                     'endstate': [perms[1], perms[2], perms[0]]}

            os.chmod(path, perms[0])
            os.chown(path, perms[1], perms[2])

            self.statechglogger.recordchgevent(myid, event)

            self.logger.log(LogPriority.DEBUG, "done writing to file")
            replaced = True
        except Exception:
            raise
        self.logger.log(LogPriority.DEBUG, "finished running replaceopt() " +
                        "method; returning replaced=" + str(replaced))
        return replaced

    def writeFile(self, path, opt, perms=[0o600, 0, 0]):
        '''append the option opt to the contents of the file specified by path,
        and write them out to the file path

        :param path: string full path to the file to write to
        :param opt: string option text to write to the file
        :param perms:  (Default value = [0600)
        :param 0: 
        :param 0]: 
        :returns: written
        :rtype: bool
@author: Breen Malmberg

        '''

        self.logger.log(LogPriority.DEBUG, "inside writeFile() method")

        written = False
        replaced = False

        try:

            tmppath = path + '.stonixtmp'

            self.logger.log(LogPriority.DEBUG, "attempting to replace any " +
                            "incomplete or erroneous existing config lines")
            if self.replaceopt(path, self.partialopt, self.fixopt, perms):
                replaced = True
                self.logger.log(LogPriority.DEBUG, "replaced an existing " +
                                "incomplete or incorrect config line with " +
                                "the correct one. done.")
                written = True

            if not replaced:

                secopt = '# Define access restriction defaults'
                secrepopt = '# Define access restriction defaults' + \
                    '\n\tonly_from\t= ' + str(XINETDALLOW) + '\n'
                if self.replaceopt(path, secopt, secrepopt, perms):
                    replaced = True
                    written = True

                self.logger.log(LogPriority.DEBUG, "did not replace " +
                                "anything; appending config option " +
                                str(opt) + " to contentlines")
                contentlines = self.readFile(path)

                contentlines.append(opt + '\n')
                self.logger.log(LogPriority.DEBUG,
                                "opening file " + str(path) + " to write")

                tf = open(tmppath, 'w')
                self.logger.log(LogPriority.DEBUG,
                                "writing contentlines to file " + str(path))
                tf.writelines(contentlines)
                tf.close()

                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)
                event = {'eventtype': 'conf',
                         'filepath': path}
                self.statechglogger.recordchgevent(myid, event)
                self.statechglogger.recordfilechange(tmppath, path, myid)

                os.rename(tmppath, path)

                statdata = os.stat(path)
                mode = stat.S_IMODE(statdata.st_mode)
                self.iditerator += 1
                myid = iterate(self.iditerator, self.rulenumber)

                event = {'eventtype': 'perm',
                         'filepath': path,
                         'startstate': [0, 0, mode],
                         'endstate': [perms[1], perms[2], perms[0]]}

                os.chmod(path, perms[0])
                os.chown(path, perms[1], perms[2])

                self.statechglogger.recordchgevent(myid, event)

                self.logger.log(LogPriority.DEBUG, "done writing to file")
                written = True

        except Exception:
            raise
        self.logger.log(LogPriority.DEBUG, "finished running writeFile() " +
                        "method. returning written=" + str(written))
        return written

    def report(self):
        '''determine whether the xinetd configuration file contains the correct
        configuration settings
        determine whether the xinetd configuration file has the correct
        permissions set
        determine whether the xinetd configuration file has the correct
        ownership set


        :returns: self.compliant

        :rtype: bool
@author: Breen Malmberg

        '''

        self.detailedresults = ""

        # UPDATE THIS SECTION IF THE CONSTANTS BEING USED IN THIS CLASS CHANGE
        if not self.checkConsts(self.constlist):
            self.compliant = False
            self.detailedresults += "\nThis rule requires that the following constants, in localize.py, be defined and not None: XINETDALLOW"
            self.formatDetailedResults("report", self.compliant, self.detailedresults)
            return self.compliant

        self.logger.log(LogPriority.DEBUG,
                        "inside report() method for XinetdAccessControl class")

        self.compliant = True
        self.detailedresults = ""

        try:
            self.logger.log(LogPriority.DEBUG, "checking if configuration " +
                            "file exists at expected location " +
                            str(self.confpath))
            if os.path.exists(self.confpath):
                self.logger.log(LogPriority.DEBUG, "configuration file " +
                                "found; checking for correct configuration")
                if not self.findopt(self.confpath, self.fullopt):
                    self.compliant = False
                    self.detailedresults += 'correct configuration not ' + \
                        'found in ' + str(self.confpath) + '\n'
                perms = getOctalPerms(self.confpath)
                self.logger.log(LogPriority.DEBUG, "checking configuration " +
                                "file for correct permissions")
                self.logger.log(LogPriority.DEBUG,
                                "required perms: 644; current perms: "
                                + str(perms))
                if perms != 600:
                    self.compliant = False
                    self.detailedresults += 'permissions not set ' + \
                        'correctly on ' + str(self.confpath) + '\n'
                ownership = getOwnership(self.confpath)
                self.logger.log(LogPriority.DEBUG, "checking configuration " +
                                "file for correct ownership")
                if ownership != [0, 0]:
                    self.compliant = False
                    self.detailedresults += 'ownership not set correctly on ' + \
                        str(self.confpath) + '\n'
            else:
                self.detailedresults += 'configuration file does not exist; ' + \
                    'xinetd not installed\n'
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        self.logger.log(LogPriority.DEBUG, "finished running report() " +
                        "method for XinetdAccessControl class\nreturning " +
                        "self.compliant=" + str(self.compliant))
        return self.compliant

    def fix(self):
        '''write correction xinetd configuration to xinetd configuration file
        ensure correct permissions set on xinetd configuration file
        ensure correct ownership set on xinetd configuration file


        :returns: self.rulesuccess

        :rtype: bool
@author: Breen Malmberg

        '''

        # UPDATE THIS SECTION IF THE CONSTANTS BEING USED IN THIS CLASS CHANGE
        if not self.checkConsts(self.constlist):
            self.rulesuccess = False
            self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
            return self.rulesuccess

        self.logger.log(LogPriority.DEBUG,
                        "inside fix() method for XinetdAccessControl class")

        self.rulesuccess = True
        self.detailedresults = ""
        self.iditerator = 0

        try:
            if self.ci.getcurrvalue():
                self.logger.log(LogPriority.DEBUG,
                                "CI is enabled; proceeding with fix actions")
                if not self.compliant:
                    self.logger.log(LogPriority.DEBUG, "config option not " +
                                    "found; writing it to " +
                                    str(self.confpath))
                    if not self.writeFile(self.confpath, self.fixopt,
                                          [0o600, 0, 0]):
                        self.rulesuccess = False
                        self.detailedresults += 'failed to write ' + \
                            'configuration to ' + str(self.confpath) + '\n'
            else:
                self.detailedresults += '\nCI is not currently enabled. ' + \
                    'fix will not be performed.'
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.rulesuccess = False
            self.detailedresults = self.detailedresults + "\n" + str(err) + \
                " - " + str(traceback.format_exc())
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        self.logger.log(LogPriority.DEBUG, "finished running fix() method " +
                        "for XinetdAccessControl class\nreturning " +
                        "self.rulesuccess=" + str(self.rulesuccess))
        return self.rulesuccess
