from __future__ import absolute_import
import sys
import json
import contextlib
from StringIO import StringIO
from optparse import OptionParser, SUPPRESS_HELP

sys.path.append("..")

#####
# 3rd party libraries
from pylint.lint import Run
from pylint.reporters.json import JSONReporter

#####
# cds libraries
from stonix_resources.loggers import CyLogger
from stonix_resources.loggers import LogPriority as lp


@contextlib.contextmanager
def _patch_streams(out):
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stderr = sys.stdout = out
    try:
        yield
    except:
        print "DAMN IT JIM!!!"
    finally:
        sys.stderr = old_stdout
        sys.stdout = old_stderr
    
class AjsonReporter(JSONReporter):
    """ Add a getter for messages..."""
    def get_messages(self):
        """ Getter for messages """
        return self.messages

def processFile(filename):
    '''
    Process a file and aquire data from the pylint parser
    '''
    jsonOut = {}

    myfile = '.'.join(filename.split('.')[1:])

    #####
    # Set up reporting for pylint functionality
    out = StringIO(None)
    reporter = AjsonReporter(out)

    with _patch_streams(out):
        Run([filename], reporter=reporter)

    if reporter:
        jsonOut = reporter.get_messages()
        #self.acquiredData[filename] = jsonOut

    return jsonOut

class PylintIface():

    acquiredData = {}

    def __init__(self, logger):
        #####
        # Set up logging
        # self.logger = CyLogger(level=loglevel)
        self.logger = logger
        #self.logger.initializeLogs(logdir=options.logPath)


    @contextlib.contextmanager
    def _patch_streams(self, out):
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stderr = sys.stdout = out
        try:
            yield
        except:
            print "DAMN IT JIM!!!"
        finally:
            sys.stderr = old_stdout
            sys.stdout = old_stderr
        
    class AjsonReporter(JSONReporter):
        """ Add a getter for messages..."""
        def get_messages(self):
            """ Getter for messages """
            return self.messages
    
    def processFile(self, filename):
        '''
        Process a file and aquire data from the pylint parser
        '''
        jsonOut = {}
    
        myfile = '.'.join(filename.split('.')[1:])
    
        #####
        # Set up reporting for pylint functionality
        out = StringIO(None)
        reporter = self.AjsonReporter(out)
    
        with self._patch_streams(out):
            Run([filename], reporter=reporter)
    
        if reporter:
            jsonOut = reporter.get_messages()
            #self.acquiredData[filename] = jsonOut
    
        return jsonOut
