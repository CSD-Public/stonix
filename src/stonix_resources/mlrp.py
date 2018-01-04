#! /usr/bin/python
'''
Created on Jun 29, 2015

This program sets the values in Localize.py to neutral defaults. Mostly
because our settings are unlikely to work for anyone else.

This expects to be run in the same directory as localize.py

@author: dkennel
'''
import re


if __name__ == '__main__':
    LOCALIZEPY = open('localize.py', 'r')
    LOCALIZECONTENTS = LOCALIZEPY.read()
    LOCALIZEPY.close()
    LOCALIZECONTENTS = re.sub('\w+\.lanl.gov|\w+-\w+\.lanl.gov',
                              'foo.bar.com', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('@lanl.gov', '@bar.com', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('dkennel@', 'stonixerr@', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('ALLOWNET = ................',
                              "ALLOWNET = '192.168.0.1/24'",
                              LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub("'/var/lanl/puppet/run'", '', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('"lanl.gov"', '"bar.com"', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('.lanl.gov = lanl.gov',
                              '.example.com = EXAMPLE.COM', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('.lanl.org = lanl.gov',
                              'example.com = EXAMPLE.COM', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('eia-ecs-', '', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('= lanl.gov', '= bar.com', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('lanl.gov =', 'bar.com =', LOCALIZECONTENTS)
    LOCALIZECONTENTS = re.sub('= WIN.LANL.GOV', '= FOO.BAR.COM', LOCALIZECONTENTS)

    LOCALIZEOUT = open('localize.out', 'w')
    LOCALIZEOUT.write(LOCALIZECONTENTS)
    LOCALIZEOUT.close()
    #print LOCALIZECONTENTS