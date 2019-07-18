
import sys
import json
import contextlib
from io import StringIO
from optparse import OptionParser, SUPPRESS_HELP

#####
# 3rd party libraries
from pylint.lint import Run
from pylint.reporters.json import JSONReporter

#####
# cds libraries
from src.stonix_resources.loggers import CyLogger
from src.stonix_resources.loggers import LogPriority as lp


@contextlib.contextmanager
def _patch_streams(out):
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stderr = sys.stdout = out
    try:
        yield
    except:
        print("DAMN IT JIM!!!")
    finally:
        sys.stderr = old_stdout
        sys.stdout = old_stderr

class AjsonReporter(JSONReporter):
    '''Add a getter for messages...'''
    def get_messages(self):
        '''Getter for messages'''
        return self.messages

'''
The variable below - compiledPackage:
A comma-separated list of package or module names
from where C extensions may be loaded. Extensions are
loading into the active Python interpreter and may run
arbitrary code
'''
def processFile(filename, compiledPackages="PyQt5,PyQt4"):
    jsonOut = {}

    myfile = '.'.join(filename.split('.')[1:])

    #####
    # Set up reporting for pylint functionality
    out = StringIO(None)
    reporter = AjsonReporter(out)

    with _patch_streams(out):
        Run([filename, "--extension-pkg-whitelist="+compiledPackages], reporter=reporter)

    if reporter:
        jsonOut = reporter.get_messages()
        #self.acquiredData[filename] = jsonOut

    return jsonOut

class PylintIface():
    '''The variable below - compiledPackage:
    A comma-separated list of package or module names
    from where C extensions may be loaded. Extensions are
    loading into the active Python interpreter and may run
    arbitrary code


    '''

    acquiredData = {}

    def __init__(self, logger, compiledPackages="PyQt5,PyQt4"):
        #####
        # Set up logging
        # self.logger = CyLogger(level=loglevel)
        self.logger = logger
        #self.logger.initializeLogs(logdir=options.logPath)
        self.args = ["--extension-pkg-whitelist="+compiledPackages]


    @contextlib.contextmanager
    def _patch_streams(self, out):
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stderr = sys.stdout = out
        try:
            yield
        except:
            print("DAMN IT JIM!!!")
        finally:
            sys.stderr = old_stdout
            sys.stdout = old_stderr

    class AjsonReporter(JSONReporter):
        '''Add a getter for messages...'''
        def get_messages(self):
            '''Getter for messages'''
            return self.messages

    def processFile(self, filename):
        '''Process a file and aquire data from the pylint parser

        :param filename: 

        '''
        jsonOut = {}

        myfile = '.'.join(filename.split('.')[1:])

        #####
        # Set up reporting for pylint functionality
        out = StringIO(None)
        reporter = self.AjsonReporter(out)

        with self._patch_streams(out):
            Run([filename]+self.args, reporter=reporter)

        if reporter:
            jsonOut = reporter.get_messages()
            #self.acquiredData[filename] = jsonOut

        return jsonOut
