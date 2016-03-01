#!/usr/bin/env python
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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
Created on Dec 5, 2013

This utility should be installed on the server that receives and processes the
STONIX reports. It processes the XML and inserts the results into a database.

@author: dkennel
'''

# from xml.dom.minidom import parseString
import xml.etree.ElementTree as ET
import os
import errno
import sys
import MySQLdb as mdb
import traceback
import time
import shutil


class ReportParser(object):
    '''The ReportParser object is instantiated for each report file being
    parsed.

    @author: dkennel
    '''
    def __init__(self, path=None):
        '''Constructor for the ReportParser. A path to the report to be parsed
        may be passed at the time of instantiation.

        @param path: path to the file to be parsed
        @author: dkennel
        '''
        self.path = path
        self.tree = ''
        if self.path is not None:
            self.tree = ET.parse(self.path)

    def openreport(self, path):
        '''ReportParser.openReport will open a report file and load the data
        for processing.

        @param path: path to the report file
        @author: dkennel
        '''
        if os.path.exists(path):
            self.tree = ET.parse(path)

    def parsereport(self):
        '''ReportParser.parseReport() will parse the xml report and return a
        dictionary of key:value pairs for the contents of the report.

        @author: dkennel
        '''
        repdict = {}
        findings = {}
        elem = self.tree.getroot()
        for child in elem:
            if child.tag == 'metadata':
                for grandchild in child:
                    repdict[grandchild.tag] = grandchild.attrib['val']
            if child.tag == 'findings':
                for grandchild in child:
                    findings[grandchild.tag] = grandchild.attrib['val']
        # print repdict
        # print findings

        return [repdict, findings]


class DBhandler(object):
    '''
    The dbhandler class handles the work of managing the db connection and
    performing the insert

    @author: dkennel
    '''
    def __init__(self):
        '''
        dbhandler constructor

        @author: dkennel
        '''
        self.con = None
        try:
            self.con = mdb.Connect('localhost', 'stonixdb',
                                   '********', 'stonix')
        except mdb.Error, err:
            print "Error %d: %s" % (err.args[0], err.args[1])
            sys.exit(1)

    def loaddata(self, metadata, findings):
        '''
        This is the main worker of the dbhandler. It requires the metadata
        dictonary and the findings list of tuples.

        @param metadata: dict dictionary of metadata elements for the run
        @param findings: list of tuples containing findings for the run
        @author: dkennel
        '''
        try:
            if 'RuleCount' in metadata:
                cur = self.con.cursor()
                cur.execute("""INSERT INTO RunMetaData(RunTime, HostName,
                UploadAddress, IPAddress, OS, PropertyNumber,
                SystemSerialNo, ChassisSerialNo, SystemManufacturer,
                ChassisManufacturer, UUID, MacAddress, xmlFileName, STONIXversion,
                RuleCount)
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (metadata['RunTime'],
                 metadata['Hostname'],
                 metadata['UploadAddress'],
                 metadata['IPAddress'],
                 metadata['OS'],
                 metadata['PropertyNumber'],
                 metadata['SystemSerialNo'],
                 metadata['ChassisSerialNo'],
                 metadata['SystemManufacturer'],
                 metadata['ChassisManufacturer'],
                 metadata['UUID'],
                 metadata['MACAddress'],
                 metadata['xmlFileName'],
                 metadata['STONIXversion'],
                 metadata['RuleCount']))
    
                cur.execute("SELECT RowId from RunMetaData WHERE xmlFileName = %s",
                            metadata['xmlFileName'])
                row = cur.fetchone()
                runid = row[0]
    
                for key in findings:
                    # print key
                    # print findings[key]
                    cur.execute("""INSERT INTO RunData(MetaDataId, Rule, Finding)
                    VALUES(%s, %s, %s)""",
                    (runid,
                     key,
                     findings[key]))
            else:
                cur = self.con.cursor()
                cur.execute("""INSERT INTO RunMetaData(RunTime, HostName,
                UploadAddress, IPAddress, OS, PropertyNumber,
                SystemSerialNo, ChassisSerialNo, SystemManufacturer,
                ChassisManufacturer, UUID, MacAddress, xmlFileName, STONIXversion,
                RuleCount)
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (metadata['RunTime'],
                 metadata['Hostname'],
                 metadata['UploadAddress'],
                 metadata['IPAddress'],
                 metadata['OS'],
                 metadata['PropertyNumber'],
                 metadata['SystemSerialNo'],
                 metadata['ChassisSerialNo'],
                 metadata['SystemManufacturer'],
                 metadata['ChassisManufacturer'],
                 metadata['UUID'],
                 metadata['MACAddress'],
                 metadata['xmlFileName'],
                 metadata['STONIXversion'],
                 '999999'))
    
                cur.execute("SELECT RowId from RunMetaData WHERE xmlFileName = %s",
                            metadata['xmlFileName'])
                row = cur.fetchone()
                runid = row[0]
    
                for key in findings:
                    # print key
                    # print findings[key]
                    cur.execute("""INSERT INTO RunData(MetaDataId, Rule, Finding)
                    VALUES(%s, %s, %s)""",
                    (runid,
                     key,
                     findings[key]))

        except mdb.Error, err:
            # print "Error %d: %s" % (err.args[0], err.args[1])
            if self.con:
                self.con.close()
            sys.exit(1)

    def close(self):
        '''Instruct the DBhandler to close the database connection. Attempts
        to use the DBhandler object after this is called will fail.

        @author: dkennel
        '''
        if self.con:
            self.con.close()


def main():
    '''
    Main program loop. Flow is as follows: Instantiate objects and variables.
    List report files uploaded.

    @author: dkennel
    '''
    parser = ReportParser()
    stonixdb = DBhandler()
    now = time.localtime()
    destdir = os.path.join('/var/local/stonix-server/', str(now[0]),
                           str(now[1]), str(now[2]))
    if not os.path.exists(destdir):
        try:
            os.makedirs(destdir)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(destdir):
                pass
            else:
                raise
    reportdir = '/var/www/html/stonix/results'
    reportfiles = os.listdir(reportdir)
    for reportfile in reportfiles:
        repfile = os.path.join(reportdir, reportfile)
        try:
            parser.openreport(repfile)
            reportdata = parser.parsereport()
            metadata = reportdata[0]
            findings = reportdata[1]
        except Exception, err:
            detailedresults = traceback.format_exc()
            print err
            print detailedresults
            shutil.move(repfile, destdir)
            continue
        uploadip = reportfile.split('-')
        uploadip = uploadip[0]
        metadata['UploadAddress'] = uploadip
        metadata['xmlFileName'] = reportfile
        # print metadata
        try:
            stonixdb.loaddata(metadata, findings)
        except Exception, err:
            print err
            print metadata
            shutil.move(repfile, destdir)
            continue
        if os.path.exists(repfile):
            shutil.move(repfile, destdir)
    stonixdb.close()

if __name__ == '__main__':
    main()
