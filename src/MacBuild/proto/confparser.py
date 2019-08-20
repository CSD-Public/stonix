#!/usr/bin/env python3

from configparser import SafeConfigParser
import os
import re
import sys

def getConfOptions():
    '''Get values from a basic ini style configuration file
    using ConfigParser (python 2.7)
    
    Logic retrieved from:
    https://pymotw.com/2/ConfigParser/
    
    @author: Roy Nielsen


    '''
    success = False
    parser = SafeConfigParser()
    candidates =  ['macbuild.conf', 'not_a_real_conf.conf']
    found = parser.read(candidates)
    missing = set(candidates) - set(found)

    optionsDict = {}
    for section_name in parser.sections():
        print('Section : ' + str(section_name))
        print('    opts: ' + str(parser.options(section_name)))
        for name, value in parser.items(section_name):
            print('          %s = %s'%(name, value))
        print()

getConfOptions()

