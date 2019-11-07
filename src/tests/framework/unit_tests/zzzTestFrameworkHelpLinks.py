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

"""
@created: 4/18/2019

@author: Breen Malmberg
"""

import sys
import os
import re
import urllib.request, urllib.error, urllib.parse
import unittest
import ssl

sys.path.append("../../../..")
from src.stonix_resources.environment import Environment
from src.tests.lib.logdispatcher_lite import LogDispatcher, LogPriority
from src.stonix_resources.localize import PROXY


class zzzTestFrameworkHelpLinks(unittest.TestCase):
    '''Class for testing the HelpLinks'''

    def setUp(self):
        '''set up handlers and objects and any other conditions for use in the class'''

        self.environ = Environment()
        self.logger = LogDispatcher(self.environ)

        # build proxy (if needed), handlers and opener for urllib2.urlopen connections
        context = ssl._create_unverified_context()
        if PROXY:
            proxy = urllib.request.ProxyHandler({"http": PROXY,
                                          "https": PROXY})
            opener = urllib.request.build_opener(urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(context=context), proxy)
        else:
            opener = urllib.request.build_opener(urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(context=context))

        urllib.request.install_opener(opener)

    def get_links(self):
        '''return a (unique) list of all web links in all html help files in
        stonix help folder


        :returns: help_files_list

        :rtype: list
@author: Breen Malmberg

        '''

        help_files_list = self.get_help_files()
        help_links = []

        # search each file for web links
        for hf in help_files_list:
            f = open(hf, "r")
            contentlines = f.readlines()
            f.close()

            # append web link help_links when found
            for line in contentlines:
                urls = re.findall("https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+", line)
                for u in urls:
                    help_links.append(u)

        # remove any duplicates from links list
        # (we don't need to check each link more than once...)
        help_links = list(dict.fromkeys(help_links))

        return help_links

    def get_help_files(self):
        '''return a list of all html help files within stonix help folder


        :returns: help_files_list

        :rtype: list
@author: Breen Malmberg

        '''

        help_files_list = []

        # set help directory path from stonix source tree
        currpath = os.path.abspath(os.path.dirname(__file__))
        helpdir = os.path.join(currpath, "../../../stonix_resources/help/")

        # add all html files in help directory
        for dir,_,filen in os.walk(helpdir):
            for f in filen:
                full_file_path = os.path.join(dir, f)
                try:
                    if os.path.splitext(full_file_path)[1] == ".html":
                        help_files_list.append(full_file_path)
                except IndexError:
                    pass
                except:
                    raise

        return help_files_list

    def test_links(self):
        '''test all web links to make sure each one is reachable/valid
        
        @author: Breen Malmberg


        '''

        help_links = self.get_links()

        try:

            for link in help_links:
                connection = urllib.request.urlopen(link)
                print(("\nTESTING CONNECTION TO: " + link + "\n"))
                if not self.assertIsNotNone(connection):
                    print("connection established\n")
                print("\nTESTING GETURL() OF CONNECTION\n")
                url = connection.geturl()
                self.assertNotEqual(url, "")
                self.assertIsNotNone(url)
                print(("url = " + url + "\n"))
                # close each connection after use
                if connection:
                    connection.close()
                # test output separator
                print("=================================================")

        except AttributeError:
            # python version 2.6* and earlier does not support assertIsNotNone()
            self.logger.log(LogPriority.DEBUG, "Current system's version of python does not support the assertion calls used in this unit test")
            pass
        except:
            raise

if __name__ == "__main__":
    unittest.main()
