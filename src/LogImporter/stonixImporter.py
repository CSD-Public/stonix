#!/usr/bin/env python3

"""
Created on Dec 5, 2013

This utility should be installed on the server that receives and processes the
STONIX reports. It processes the XML and inserts the results into a database.

Script's Log File: /var/log/stoniximport.log

:author: Dave Kennel

"""

import xml.etree.ElementTree as ET
import os
import errno
import sys
import MySQLdb as mdb
import traceback
import time
import re

from datetime import datetime


class ReportParser(object):
    """
    The ReportParser object is instantiated for each report file being
    parsed.

    """

    def __init__(self, path=None):
        """
        Constructor for the ReportParser. A path to the report to be parsed
        may be passed at the time of instantiation.

        :param path: path to the file to be parsed

        """

        if self.validate_path(path):
            self.load_report_data(path)

    def validate_path(self, path):
        """
        validate a given path is ok to perform operations on -
        namely that it:
        1) is not blank/none
        2) is indeed a file (as opposed to a directory)
        3) is not empty

        :param path: string full path to obj
        :return: valid
        :rtype: bool
        """

        valid = True

        if not path:
            valid = False
            return valid

        if not os.path.isfile(path):
            valid = False
            return valid

        if not os.stat(path).st_size:
            valid = False
            os.remove(path)
            return valid

        return valid

    def load_report_data(self, path):
        """
        load the data from the given path into an elementtree object,
        for processing

        :param path: string; path to the report file
        """

        loaded = True

        try:

            if self.validate_path(path):
                self.tree = ET.parse(path)
                if self.tree:
                    self.root = self.tree.getroot()
            else:
                log_error("Could not validate path: " + str(path))
                loaded = False
        except Exception:
            message = traceback.format_exc()
            log_error(message)

        if not self.tree:
            log_error("Failed to get tree from ET.parse(path)")
            loaded = False

        return loaded

    def parsereport(self):
        """
        ReportParser.parseReport() will parse the xml report and return a
        dictionary of key:value pairs for the contents of the report.

        """

        repdict = {}
        findings = {}

        try:

            elem = self.root

            if not elem:
                log_error("Could not get tree root")
                return [repdict, findings]

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

        if not repdict:
            log_error("Failed to get metadata")

        return [repdict, findings]


class DBhandler(object):
    """
    The DBhandler class handles the work of managing the database connection and
    performing the sql insert

    """

    def __init__(self):
        """
        DBhandler class constructor

        """

        self.con = None

        try:

            self.con = mdb.Connect(host='localhost', user='stonixdb', passwd='He4vyKandi0ad', db='stonix')

            if not self.con:
                log_error("Failed to establish connection to stonix log database")

        except Exception:
            message = traceback.format_exc()
            log_error(message)
            sys.exit(1)

    def loaddata(self, metadata, findings):
        """
        This is the main worker of the dbhandler. It requires the metadata
        dictonary and the findings list of tuples.

        :param metadata: dict dictionary of metadata elements for the run
        :param findings: list of tuples containing findings for the run
        :return: success
        :rtype: bool

        """

        success = True

        # we don't want to add just any xml field found in the report to the sql statement
        valid_md_fields = ['RunTime', 'Hostname', 'UploadAddress', 'IPAddress', 'OS', 'PropertyNumber', 'SystemSerialNo', 'ChassisSerialNo', 'SystemManufacturer',
                            'UUID', 'MACAddress', 'xmlFileName', 'STONIXversion', 'RuleCount', 'ChassisManufacturer']
        cols = ""
        vals = ""
        cur = self.con.cursor()
        vals_tuple = ()

        try:

            # dynamic sql statement building, based on which values are available
            # in report file data (from self.tree)
            for item in metadata:
                if item in valid_md_fields:
                    cols += item + ", "
                    vals_tuple += (metadata[item], )
            if cols:
                cols = cols[:-2]
            for c in cols.split(','):
                vals += "%s, "
            if vals:
                vals = vals[:-2]

        except:
            log_error("Failed to dynamically build sql query")
            log_error(traceback.format_exc())

        try:

            try:
                if cols:
                    cur.execute("""INSERT INTO RunMetaData(""" + cols + """) VALUES(""" + vals + """)""", vals_tuple)
                else:
                    log_error("No valid metadata columns detected")
            except KeyError as ke:
                log_error("Key: " + str(ke.args[0]) + " was not found in metadata")
            except:
                log_error(traceback.format_exc())

            try:
                if metadata['xmlFileName']:
                    cur.execute("SELECT RowId from RunMetaData WHERE xmlFileName = %s", metadata['xmlFileName'])
                    row = cur.fetchone()
                    runid = row[0]

                    for key in findings:
                        cur.execute("""INSERT INTO RunData(MetaDataId, Rule, Finding) VALUES(%s, %s, %s)""", (runid, key, findings[key]))
            except KeyError as ke:
                log_error("Key: " + str(ke.args[0]) + " was not found in findings")

        except:
            message = traceback.format_exc()
            log_error(message)
            success = False

        return success

    def close(self):
        """
        Instruct the DBhandler to close the database connection. Attempts
        to use the DBhandler object after this is called will fail.

        """

        try:

            if self.con:
                self.con.close()

        except Exception:
            message = traceback.format_exc()
            log_error(message)
            sys.exit(1)

def log_error(message):
    """
    log error messages related to this utility

    :param message: string; the traceback output

    """

    try:

        log_time = str(datetime.now())

        # if you alter this path, ensure that you make the
        # necessary logrotate configuration changes on the server
        log_path = "/var/log/stoniximport.log"

        f = open(log_path, 'a')
        f.write(log_time + " - " + message + "\n\n")
        f.close()
    except Exception:
        print("UNABLE TO LOG ERROR. LOG METHOD FAILURE")
        print(str(traceback.format_exc()))
        sys.exit(1)

def main():
    """
    Main program loop. Flow is as follows: Instantiate objects and variables.
    List report files uploaded.

    """

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

        repfile = ""

        try:

            # don't process htaccess
            if re.search("^\.", reportfile, re.I):
                continue

            repfile = os.path.join(reportdir, reportfile)

            parser.load_report_data(repfile)
            #log_error("Could not validate file: " + str(repfile))
            #os.remove(repfile)

            reportdata = parser.parsereport()

            try:
                metadata = reportdata[0]
                if len(metadata) == 0:
                    log_error("Could not retrieve metadata from file: " + str(repfile))
                    os.remove(repfile)
                    continue
            except KeyError:
                log_error(traceback.format_exc())
                os.remove(repfile)
                # no metadata retrievd from file. skip file and go to next one
                continue

            findings = reportdata[1]

            uploadip = reportfile.split('-')
            uploadip = uploadip[0]
            metadata['UploadAddress'] = uploadip
            metadata['xmlFileName'] = reportfile

            try:
                # failed to load data into db; try next file
                if not stonixdb.loaddata(metadata, findings):
                    log_error("Failed to upload metadata from file: " + str(repfile))
                    os.remove(repfile)
                    continue
            except:
                log_error(traceback.format_exc())
                # error occurred; try next file
                continue

            if os.path.isfile(repfile):
                if os.path.isfile(os.path.join(destdir, reportfile)):
                    os.remove(repfile)
                else:
                    os.rename(repfile, os.path.join(destdir, reportfile))
            else:
                log_error("Given path: " + str(repfile) + " is not a file or does not exist")

        except:
            message = traceback.format_exc()
            log_error(message)
            continue

    try:

        stonixdb.close()

    except Exception:
        message = traceback.format_exc()
        log_error(message)
        sys.exit(1)

if __name__ == '__main__':
    main()
