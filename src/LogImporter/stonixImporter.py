#!/usr/bin/env python

'''
Created on Dec 5, 2013

This utility should be installed on the server that receives and processes the
STONIX reports. It processes the XML and inserts the results into a database.

Script's Log File: /var/log/stoniximport.log

@author: Dave Kennel

@change: Breen Malmberg - 10/19/2018 - fixed a typo in the macaddress field name key
@change: Breen Malmberg - 10/24/2018 - added try/except blocks around everything;
            added logging method and log file and configuration on server; fixed
            a string conversion error in loaddata method
'''

import xml.etree.ElementTree as ET
import os
import errno
import sys
import MySQLdb as mdb
import traceback
import time
import shutil

from datetime import datetime


class ReportParser(object):
    '''The ReportParser object is instantiated for each report file being
    parsed.
    
    @author: Dave Kennel


    '''

    def __init__(self, path=None):
        '''
        Constructor for the ReportParser. A path to the report to be parsed
        may be passed at the time of instantiation.

        @param path: path to the file to be parsed
        @author: Dave Kennel
        '''

        try:

            self.path = path
            self.tree = ''
            if self.path is not None:
		# sometimes a blank path is passed and that causes
		# ET.parse to barf and subsequently the script to die
		if self.path != '':
                	self.tree = ET.parse(self.path)

        except Exception:
            message = traceback.format_exc()
            log_error(message)
            # sys.exit(1)

    def openreport(self, path):
        '''ReportParser.openReport will open a report file and load the data
        for processing.

        :param path: string; path to the report file
        @author: Dave Kennel

        '''

        try:

            if os.path.exists(path):
                self.tree = ET.parse(path)

        except ET.ParseError as err:
            row, column = err.position
            log_error("Catastrophic failure")
            log_error("error on row", row, "column", column, ":", v)
        except Exception:
            message = traceback.format_exc()
            log_error(message)
            # sys.exit(1)

    def parsereport(self):
        '''ReportParser.parseReport() will parse the xml report and return a
        dictionary of key:value pairs for the contents of the report.
        
        @author: Dave Kennel


        '''

        repdict = {}
        findings = {}

        try:

            elem = self.tree.getroot()
            for child in elem:
                if child.tag == 'metadata':
                    for grandchild in child:
                        repdict[grandchild.tag] = grandchild.attrib['val']
                if child.tag == 'findings':
                    for grandchild in child:
                        findings[grandchild.tag] = grandchild.attrib['val']

        except Exception:
            message = traceback.format_exc()
            log_error(message)
            sys.exit(1)

        return [repdict, findings]


class DBhandler(object):
    '''The dbhandler class handles the work of managing the db connection and
    performing the insert
    
    @author: Dave Kennel


    '''

    def __init__(self):
        '''
        dbhandler constructor

        @author: Dave Kennel
        '''

        self.con = None
        try:
            self.con = mdb.Connect('localhost', 'stonixdb',
                                   'He4vyKandi0ad', 'stonix')

        except Exception:
            message = traceback.format_exc()
            log_error(message)
            sys.exit(1)

    def loaddata(self, metadata, findings):
        '''This is the main worker of the dbhandler. It requires the metadata
        dictonary and the findings list of tuples.

        :param metadata: dict dictionary of metadata elements for the run
        :param findings: list of tuples containing findings for the run
        @author: Dave Kennel
        	    @change: Breen Malmberg - 10/19/2018 - Updated sql insert statement to
        		reflect correct fieldname MACAddress as it appears in the database;
        		previous incorrect entry was MacAddress
        	    @change: Breen Malmberg - 10/24/2018 - Removed default '999999' value from
        	    sql insert call if no rulecount present (as this was causing the
        	    script to fail/traceback)

        '''

        try:

            if 'RuleCount' in metadata:
                cur = self.con.cursor()
                cur.execute("""INSERT INTO RunMetaData(RunTime, HostName,
                UploadAddress, IPAddress, OS, PropertyNumber,
                SystemSerialNo, ChassisSerialNo, SystemManufacturer,
                ChassisManufacturer, UUID, MACAddress, xmlFileName, STONIXversion,
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
                ChassisManufacturer, UUID, MACAddress, xmlFileName, STONIXversion)
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
                 metadata['STONIXversion']))
    
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

        except Exception:
            raise

    def close(self):
        '''Instruct the DBhandler to close the database connection. Attempts
        to use the DBhandler object after this is called will fail.
        
        @author: Dave Kennel


        '''

        try:

            if self.con:
                self.con.close()

        except Exception:
            message = traceback.format_exc()
            log_error(message)
            sys.exit(1)

def log_error(trace_msg):
    '''

    :param trace_msg: string; the traceback output
    
    @author: Breen Malmberg

    '''

    try:

        log_time = str(datetime.now())

        # if you alter this path, ensure that you make the
        # necessary logrotate configuration changes on the server
        # as well
        log_path = "/var/log/stoniximport.log"

        f = open(log_path, 'a')
        f.write(log_time + " - " + trace_msg + "\n\n")
        f.close()

        print(trace_msg)

    except Exception:
        message = traceback.format_exc()
        print("UNABLE TO LOG ERROR. LOG METHOD FAILURE")
        print(message)
        sys.exit(1)

def main():
    '''Main program loop. Flow is as follows: Instantiate objects and variables.
    List report files uploaded.
    
    @author: Dave Kennel


    '''

    try:

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

    except Exception:
        message = traceback.format_exc()
        log_error(message)
        sys.exit(1)

    for reportfile in reportfiles:

        try:

            repfile = os.path.join(reportdir, reportfile)
            log_error("repfile: " + str(repfile))
            parser.openreport(repfile)
            reportdata = parser.parsereport()
            metadata = reportdata[0]
            findings = reportdata[1]

            uploadip = reportfile.split('-')
            uploadip = uploadip[0]
            metadata['UploadAddress'] = uploadip
            metadata['xmlFileName'] = reportfile

            stonixdb.loaddata(metadata, findings)

            if os.path.exists(repfile):
                shutil.move(repfile, destdir)

        except KeyError:
            message = traceback.format_exc()
            log_error(message)
            if os.path.exists(repfile):
                shutil.move(repfile, destdir)
            continue
        except Exception:
            message = traceback.format_exc()
            log_error(message)
            # sys.exit(1)

    try:

        stonixdb.close()

    except Exception:
        message = traceback.format_exc()
        log_error(message)
        sys.exit(1)

if __name__ == '__main__':
    main()
