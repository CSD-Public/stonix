#!/usr/bin/env python3
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




# ============================================================================ #
#               Filename          $RCSfile: stonix/configuration.py,v $
#               Description       Security Configuration Script
#               OS                Linux, Mac OS X, Solaris, BSD
#               Author            Dave Kennel
#               Last updated by   $Author: $
#               Notes             Based on CIS Benchmarks, NSA RHEL 
#                                 Guidelines, NIST and DISA STIG/Checklist
#               Release           $Revision: 1.0 $
#               Modified Date     $Date: 2011/10/24 14:00:00 $
# ============================================================================ #

"""
Created on Aug 24, 2010

@author: Dave Kennel

The Configuration object handles the STONIX config file. The config file is
organized into sections by rule name as follows:
['MAIN']
The main section contains the version of the config file.
['rule name']
Each rule has a section under it's rule name
ruleconfig  = True|False|str|int|other
Each directive is in a keyword = value format. Values may be any python data
type and it is up to the rule to validate the contents.
ruleconfiguc = "string"
Each directive has a user comment (uc) directive associated with it.
Calls to getconfvalue for non-existent entries will generate a KeyError.

@change: 2017/03/07 Added fismacat to [MAIN]
"""

import configparser
import sys
import os
import re
import inspect

from .localize import STONIXVERSION


class Configuration:
    """Manages the stonix configuration data. Constructor takes no arguments"""

    def __init__(self, environment):
        """
        private method to initialize the module

        :param environment: environment object instance
        """

        self.environment = environment
        self.configpath = self.environment.get_config_path()
        # print 'DEBUG: CONFIGURATION: Config_path: ' + self.configpath
        self.programconfig = self.__loadconfig()
        # print self.programconfig

    def getconfvalue(self, rulename, confkey):
        """Fetch the value for a given rule and key

        :param string rulename: name of the rule
        :param string confkey: Keyword for configuration value
        :param rulename: 
        :param confkey: 
        :returns: string

        """

        try:
            value = self.programconfig[rulename][confkey]
        except KeyError:
            confkey = confkey.lower()
            value = self.programconfig[rulename][confkey]
        return value

    def writeconfig(self, simpleconf, ruledata):
        """Writes current configuration data to the config file. If simpleconf is
        True we only write values that are changed or values that are marked
        as being in the simple configuration.

        :param bool simpleconf: whether or not the configuration file
                generated should be simple or full.
        :param dict ruledata: a dictionary of lists keyed by rulename and
                containing a packed list where index 0 is the rule help text and all
                remaining entries (if any) are configurationitem instances.
        :param simpleconf: 
        :param ruledata: 

        """

        confheader = """# STONIX.CONF
# STONIX configuration file
# This file is documented in the STONIX documentation. You may also review the
# documentation for this file with man stonix.conf.
[MAIN]
version = """ + str(STONIXVERSION) + """

# fismacat
# Global variable that affects the rules selection and behavior.
# fismacat is the FIPS 199 risk categorization for the system on which STONIX
# is running. Valid values are 'low', 'med' and 'high'. The value cannot be set
# lower than the default set in localize.py. The higher the fismacat value
# the more stringent STONIX's behavior becomes.
# fismacat = 'low'"""

        conf = ''
        newline = '\n'
        conf = conf + confheader + newline
        for rule in ruledata:
            sectionhead = '[' + rule + ']' + newline
            helptext = ruledata[rule][0]
            helptext = re.sub('^', '# ', helptext)
            helptext = re.sub('\\n', '\n# ', helptext)
            conf = conf + sectionhead
            conf = conf + helptext + newline

            for item in ruledata[rule]:
                try:
                    key = item.getkey()
                    value = item.getcurrvalue()
                    datatype = item.getdatatype()
                    defvalue = item.getdefvalue()
                    instruct = item.getinstructions()
                    instruct = re.sub('^', '# ', instruct)
                    instruct = re.sub('\\n', '\n# ', instruct)
                    usrcomment = item.getusercomment()
                    if datatype == 'list':
                        newval = ''
                        for element in value:
                            newval = newval + str(element) + ' '
                        value = newval
                except AttributeError:
                    continue
                except:
                    raise

                uckey = key + '_UserComments'
                kvline = key + ' = ' + str(value) + newline
                instruct = instruct + newline
                usrcomment = usrcomment.replace("\n", r"\n")
                ucline = uckey + ' = ' + usrcomment + newline
                if not simpleconf:
                    conf = conf + instruct
                    conf = conf + kvline
                    conf = conf + ucline
                elif simpleconf and item.insimple():
                    conf = conf + instruct
                    conf = conf + kvline
                    conf = conf + ucline
                elif value != defvalue:
                    conf = conf + instruct
                    conf = conf + kvline
                    conf = conf + ucline
                elif usrcomment != '':
                    conf = conf + ucline
            conf = conf + newline
        try:
            fhandle = open(self.configpath, 'w')
            fhandle.write(conf)
            fhandle.close()
            os.chmod(self.configpath, 0o644)
        except IOError as err:
            print("ERROR: " + __name__ + ": line number " + str(inspect.currentframe().f_lineno) + ": " + type(err).__name__ + ": " + str(err))
            sys.exit(1)
        except:
            raise

    def getusercomment(self, rulename, confkey):
        """Returns the user comment text associated with a given rule and
        configuration key.

        :param string rulename: name of the rule
        :param string confkey:
        :param rulename: 
        :param confkey: 
        :returns: string

        """

        uckey = confkey.lower() + "_usercomments"
        usercomment = self.programconfig[rulename][uckey]
        usercomment = usercomment.replace(r"\n", "\n")
        return usercomment

    def __loadconfig(self):
        """
        Private method to read in the current config file and return the values
        as a list of dictionaries.

        @return  list of dictionaries :
        @author D. Kennel
        @change: 03/08/2018 - Breen Malmberg - added debug output; added functionality to
                create an empty stonix.conf if one does not already exist - before attempting
                to read it (will only attempt to create if running as euid 0)
        """

        progconfig = {}
        config = configparser.SafeConfigParser()
        euid = os.geteuid()

        try:
            if euid == 0:
                # this will NOT alter any existing stonix.conf file
                open(self.configpath, 'a').close()
                os.chmod(self.configpath, 0o644)
            config.readfp(open(self.configpath))
        except IOError as err:
            print("ERROR: " + __name__ + ": line number " + str(inspect.currentframe().f_lineno) + ": " + type(err).__name__ + ": " + str(err))
            sys.exit(1)
        # print config.sections()
        # print config.options('MAIN')
        for section in config.sections():
            # print 'Section: ' + section
            progconfig[section] = {}
            for key in config.options(section):
                # print 'Key: ' + key
                value = config.get(section, key)
                # print 'Value: ' + value
                progconfig[section][key] = value
        return progconfig
