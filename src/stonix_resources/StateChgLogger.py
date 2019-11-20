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
Created on Aug 22, 2012

@author: dkennel

@change: 2014/07/22 dkennel - Added -f flag to patch command call to eliminate
prompt and wait issues during undo.
@change: 2015/07/08 eball - Updated documentation for recordchgevent method
@change: 2015/11/18 eball - Fixed recording of deletion event
@change: 2016/06/10 dkennel - Updated recordfilechange to handle case where
oldfile does not exist
@change: 2017/10/23 rsn - change to new service helper interface
@change: 2018/12/06 Brandon R. Gonzales - Fixed issue where patch files are
        created without a trailing endline character
'''
import shelve
import shutil
import os
import re
import traceback
import filecmp
import time
import difflib
import weakref
import subprocess

from stonix_resources.logdispatcher import LogPriority


class StateChgLogger(object):

    '''The state change logger assists rules in tracking changes made so that they
     can be reverted at a later date.
    
    :version: 1.0
    :author: D. Kennel


    '''
    def __init__(self, logdispatcher, environment):
        """ ATTRIBUTES

         Location where diffs are stored. The diffs are used to revert changes
         to complex configuration files.

        diffdir  (public)

         The eventlog database. This file contains a record of change events.
         The change event record can be referenced to determine whether or not a
         change occured and/or the initial value of objects before the change
         occured.

        eventlog  (public)

         This is the location where the original copies of config files are
         stored in case they are needed by system admins.

        archive  (public)

         The logdispatcher object, available so that debug messages may be
         sent as appropriate.

        logdispatcher (public)

        """
        logref = weakref.ref(logdispatcher)
        self.logger = logref()
        self.environment = environment
        self.verbose = self.environment.getverbosemode()
        self.debug = self.environment.getdebugmode()
        self.diffdir = '/var/db/stonix/diffdir'
        self.archive = '/var/db/stonix/archive'
        self.privmode = True
        try:
            if not os.path.exists('/var/db/stonix') and \
               self.environment.geteuid() == 0:
                os.makedirs('/var/db/stonix', 0o700)
            if self.environment.geteuid() == 0:
                try:
                    self.eventlog = shelve.open('/var/db/stonix/eventlog', 'c', None, True)
                except:
                    # if a python 3 version of stonix attempts to access an eventlog file
                    # created or written to in a python 2 version of stonix, there is an incompatibility
                    # which results in a traceback; catch this traceback and backup the old python 2 version
                    # of the file and create a new python 3 version of it
                    if not os.path.isfile('/var/db/stonix/eventlog.old'):
                        if os.path.isfile('/var/db/stonix/eventlog'):
                            shutil.copy2('/var/db/stonix/eventlog', '/var/db/stonix/eventlog.old')
                    if os.path.isfile('/var/db/stonix/eventlog'):
                        os.remove('/var/db/stonix/eventlog')
                    self.eventlog = shelve.open('/var/db/stonix/eventlog', 'c', None, True)
            else:
                self.privmode = False
            for node in [self.diffdir, self.archive]:
                if not os.path.exists(node) and self.environment.geteuid() == 0:
                    os.makedirs(node, 0o700)
        except OSError:
            raise

    def __del__(self):
        """
        This class has an explicit destructor in order to ensure that the
        connection to the change event log gets closed correctly.
        @author: D. Kennel
        """
        if not self.privmode:
            return(True)
        try:
            self.closelog()
        except(AttributeError):
            # This error will get thrown when running w/o privilege.
            pass

    def recordfilechange(self, oldfile, newfile, eventid):
        '''Recordfilechange does the following actions. Make a copy of the
        unaltered original file and store it. Using the newfile (expected to be
        the post change version of the file) create a unified diff that can be
        used to undo the changes that were made and store the diff.

        :param string: oldfile : The origin file path pre-change. This should be
        the canonical location for the file on disk.
        :param string: newfile : The path to the new version of the file,
        post-changes.
        :param string: eventid : The change event id associated with this file
        change
        :param oldfile: 
        :param newfile: 
        :param eventid: 
        :returns: void
        @author D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''recordfilechange method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        if not oldfile or not newfile:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger', "recordfilechange called but no filename received"])
            return False
        if not eventid:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger', "recordfilechange called but no eventid received"])
            return False
        if self.environment.geteuid() != 0:
            # If we don't hold privs we can't backup
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger',
                             "Can't handle " + oldfile + " running unprivileged"])
            return False

        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger',
                         "Recording changes in %s" % oldfile])
        self.archivefile(oldfile)
        if os.path.exists(oldfile):
            oldfilehandle = open(oldfile, 'r')
            oldfiledata = oldfilehandle.readlines()
            oldfilehandle.close()
        else:
            oldfiledata = []
        newfilehandle = open(newfile, 'r')
        newfiledata = newfilehandle.readlines()
        newfilehandle.close()
        path, filename = os.path.split(oldfile)
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger',
                         "Finding patch path elements: " + path + ' ' + filename])
        patchpath = self.diffdir + path
        patchdest = os.path.join(patchpath, filename)
        patchdest = patchdest + ".patch-" + eventid
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger',
                         "Complete path to patchfile: %s" % patchdest])
        if not os.path.exists(patchpath):
            os.makedirs(patchpath, 448)
        patchhandle = open(patchdest, 'w')
        for line in difflib.unified_diff(newfiledata, oldfiledata,
                                         fromfile=newfile,
                                         tofile=oldfile):
            patchhandle.write(line)
        patchhandle.write("\n")
        patchhandle.close()
        return True

    def revertfilechanges(self, filename, eventid):
        '''revertfilechanges removes changes made to complex configuration files
        by stonix. It uses the patch utility and a diff file created by
        recordfilechange to restore the configuration file without altering
        other customizations.

        :param string: file : Path to the configuration file that should have
        changes made by stonix reverted to a pre-alteration state.
        :param string: eventid: The event id associated with the original change
        to the file being reverted
        :param filename: 
        :param eventid: 
        :returns: Bool for success
        @author D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''recordfilechange method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        fullpath = filename
        path, filename = os.path.split(filename)
        if self.debug:
            self.logger.log(LogPriority.DEBUG,
                            ['StateChgLogger.revert',
                             "Finding patch path elements: " + path + ' ' + filename])
        patchpath = self.diffdir + path
        patchsource = os.path.join(patchpath, filename)
        patchsource = patchsource + ".patch-" + eventid
        if self.debug:
            self.logger.log(LogPriority.DEBUG,
                            ['StateChgLogger.revert',
                             "Complete path to patchfile: %s" % patchsource])

        patchcmd = '/usr/bin/patch -p0 -u -f ' + fullpath + ' ' + patchsource
        if self.environment.getosfamily() == 'solaris':
            patchcmd = '/usr/bin/patch -p0 -u -i ' + patchsource + ' ' + fullpath
        if not os.path.exists(patchsource):
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger.revert',
                             "Patchfile not found, unable to revert: %s" % fullpath])
            return False
        if not os.path.exists(fullpath):
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger.revert',
                             "Conf file not found, unable to revert: %s" % fullpath])
        if not os.path.exists('/usr/bin/patch'):
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger.revert',
                             "Patch utility not found, unable to revert: %s" % fullpath])
            return False

        patchproc = subprocess.call(patchcmd, shell=True)
        if patchproc != 0:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger.revertfilechange',
                             "Problem patching: %s" % fullpath])

    def recordfiledelete(self, filename, eventid):
        '''recordfiledelete will make a backup copy of a file that is being
        deleted. The backed up file may later be restored with the
        revertfiledelete method.

        :param string: oldfile : The origin file path. This should be
        the canonical location for the file on disk.
        :param string: eventid : The change event id associated with this file
        deletion
        :param filename: 
        :param eventid: 
        :returns: void
        @author D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''recordfiledelete method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        if not filename:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger',
                             "recordfiledelete called but no filename received"])
            return False
        if not eventid:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger',
                             "recordfiledelete called but no eventid received"])
            return False
        if self.environment.geteuid() != 0:
            # If we don't hold privs we can't backup
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger',
                             "Can't handle " + filename +
                             " running unprivileged"])
            return False

        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger',
                         "Recording deletion of %s" % filename])
        self.archivefile(filename)
        mytype = 'deletion'
        mydict = {'eventtype': mytype,
                  'filepath': filename}
        self.recordchgevent(eventid, mydict)
        return True

    def revertfiledelete(self, filepath):
        '''revertfiledelete restores deleted files back to their original
         location. This method will try to restore the newest archived version
         of the file.

        :param string: file : Path to the configuration file that should be
        restored.
        :param string: eventid: The event id associated with the original change
        to the file being reverted
        :param filepath: 
        :returns: Bool for success
        @author D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''revertfiledelete method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        path, filename = os.path.split(filepath)
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger.revertfiledelete',
                         "Finding path elements: " + path + ' ' +
                         filename])
        path = re.sub('^/', '', path)
        recoverypath = os.path.join(self.archive, path)
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger.revertfiledelete',
                         "Recovery path: " + str(recoverypath)])
        recoveryfile = filename + '.ovf'
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger.revertfiledelete',
                         "Recovery file: " + str(recoveryfile)])
        possibles1 = os.listdir(recoverypath)
        possibles2 = []
        hinum = None
        tstamps = []
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger.revertfiledelete',
                         "Possibles: " + str(possibles1)])
        for fname in possibles1:
            if re.search(filename, fname):
                possibles2.append(fname)
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger.revertfiledelete',
                         "Possibles filtered: " + str(possibles2)])
        for poss in possibles2:
            posssplit = poss.split(".ovf")
            try:
                timestamp = posssplit[1]
                tstamps.append(float(timestamp))
            except(IndexError, TypeError, ValueError):
                continue
        if len(tstamps) != 0:
            tstamps.sort(cmp=None, key=None, reverse=True)
            hinum = tstamps[0]
            self.logger.log(LogPriority.DEBUG,
                            ['StateChgLogger.revertfiledelete',
                             "HIGH NUM: " + str(hinum)])
        if hinum:
            recoveryfile = filename + '.ovf' + str(hinum)
            self.logger.log(LogPriority.DEBUG,
                            ['StateChgLogger.revertfiledelete',
                             "HIGH NUM recovery file: " + str(recoveryfile)])
        fullrecoverypath = os.path.join(recoverypath, recoveryfile)
        try:
            shutil.copy(fullrecoverypath, filepath)
        except IOError:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger.revertfiledelete',
                             "Problem reading file: " + traceback.format_exc()])
            return False
        return True

    def recordchgevent(self, eventcode, eventdict):
        '''Record change event records a change event along with a unique id so
        that the rule can retrieve information about a change that it may be
        reverted at a later date if called for.

        :param string: eventcode : The eventcode is a unique identifier that is
        used to record and locate information about a specific change. Format
        is a four digit zero padded rule number and a three digit zero padded
        number selected by the rule author.
        :param dictionary: eventdict : The event dict is a python dictionary that
        contains the following key:data element sets:
        eventtype: conf | creation | deletion
        filepath: string
        ==========================================
        eventtype: comm | commandstring (same function)
        command: string | list
        ==========================================
        eventtype: perm
        filepath: string
        startstate: [owner_uid, group_gid, mode]
        endstate: [owner_uid, group_gid, mode]
        ==========================================
        eventtype: pkghelper
        pkgname: string
        startstate: installed | removed
        endstate: installed | removed
        ==========================================
        eventtype: servicehelper
        servicename: string
        startstate: enabled | disabled
        endstate: enabled | disabled
        :param eventcode: 
        :param eventdict: 
        :returns: void
        @author D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''recordfilechange method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        self.eventlog[eventcode] = eventdict
        debug = "Recorded new change event with event code " + eventcode
        self.logger.log(LogPriority.DEBUG, debug)
        self.eventlog.sync()

    def getchgevent(self, eventcode):
        '''Get change event takes an eventcode and returns a dictionary containing
        information about that specific change event. The rule can then use
        that information to revert back to a previous system state.

        :param string: eventcode : Eventcode to retreive data for. See
        documentation for recordchgevent for eventcode format.
        :param eventcode: 
        :returns: dictionary : eventdict
        @author D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''recordfilechange method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        eventdict = self.eventlog[eventcode]
        return eventdict

    def closelog(self):
        '''Close the logfile. This prepares the StateChgLogger for going out of
        scope or manual closure.
        
        @author: D. Kennel


        '''
        if not self.privmode:
            raise RuntimeError('''recordfilechange method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        self.eventlog.close()

    def archivefile(self, oldfile):
        '''Private method to archive a copy of a file into the file archive. This
        is intended to be called by the recordfilechanges method.

        :param string: oldfile - full path to the file to be archived
        :param oldfile: 
        :returns: True unless an error was encountered
        @author: D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''recordfilechange method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        if not oldfile:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger',
                             "archivefile called but no filename received"])
            return False
        path, filename = os.path.split(oldfile)
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger',
                         "Finding backup path elements: " + path + ' ' +
                         filename])
        backuppath = self.archive + path
        backupdest = os.path.join(backuppath, filename)
        backupdest = backupdest + ".ovf"
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger',
                         "Complete backup path: %s" % backuppath])
        if not os.path.exists(backuppath):
            os.makedirs(backuppath, 448)
        if not os.path.exists(oldfile):
            self.logger.log(LogPriority.DEBUG,
                            ['StateChgLogger',
                             "Source file doesn't exist skipping backup."])
            return True
        if not os.path.exists(backupdest):
            self.logger.log(LogPriority.DEBUG,
                            ['StateChgLogger',
                             'Copying ' + oldfile + ' to ' + backupdest])
            shutil.copy(oldfile, backupdest)
        else:
            if not filecmp.cmp(oldfile, backupdest):
                backupdest = backupdest + str(time.time())
                self.logger.log(LogPriority.DEBUG,
                                ['StateChgLogger',
                                 'Copying ' + oldfile + ' to ' + backupdest])
                shutil.copy(oldfile, backupdest)
        return True

    def findrulechanges(self, ruleid):
        '''Public method that when called will search for all state change
        events known to the state change logger for the identified rule.
        Requires a rule id either formatted as a 4 digit zero padded string or
        as an integer. The return will be a list of strings that are full event
        identifiers. Missing or invalid rule ids will result in a TypeError.

        :param string: int: ruleid number
        :param ruleid: 
        :returns: list of strings - eventids
        @author: D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''findrulechanges method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        myruleid = ''
        eventlist = []
        if not ruleid:
            raise TypeError('Null Rule ID')
        if type(ruleid) == int:
            myruleid = str(ruleid).zfill(4)
        elif type(ruleid) == str and re.search('\d{4}', ruleid):
            myruleid = ruleid
        else:
            raise TypeError('ID invalid or wrong type')
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger.findrulechanges',
                         "Searching for: %s" % ruleid])
        for key in self.eventlog:
            try:
                keyruleid = key[0:4]
                # self.logger.log(LogPriority.DEBUG,
                #                 ['StateChgLogger.findrulechanges',
                #                  "Comparing to keyruleid: %s" % keyruleid])
                if keyruleid == myruleid:
                    eventlist.append(key)
            except(IndexError):
                self.logger.log(LogPriority.ERROR,
                                ['StateChgLogger.findrulechanges',
                                 'Bad key detected in eventlog: ' + key])
        self.logger.log(LogPriority.DEBUG,
                        ['StateChgLogger.findrulechanges',
                         "returning eventlist: %s" % eventlist])
        return eventlist

    def deleteentry(self, eventid):
        '''Public method to delete records from the event log. This is required
        for rules that have sections that make N+1 number of changes. We only
        guarantee to undo the last recorded set of changes. This method helps
        prevent situation where on one run we make 5 changes, then on a
        following run we make 2 changes. A revert request after the second run
        would undo the 2 changes from the second run and the last three changes
        from the first, potentially leading to unexpected results. This method
        requires an eventid as an argument and returns True for success or if
        the passed eventid does not exist in the event log.

        :param string: eventid
        :param eventid: 
        :returns: bool: True for success
        @author D. Kennel

        '''
        if not self.privmode:
            raise RuntimeError('''deleteentry method called without privilege.
If you are a rule developer you should guard against this. If you
are an end user please report a bug.''')
        if not eventid or not type(eventid) == str:
            raise TypeError('Null eventid or wrong type')
        try:
            del self.eventlog[eventid]
        except(KeyError):
            # key was not found in the event log
            return True
        except Exception:
            self.logger.log(LogPriority.ERROR,
                            ['StateChgLogger.deleteentry',
                             'Error deleting ' + str(eventid) + ' ' + traceback.format_exc()])
            return False
        return True
