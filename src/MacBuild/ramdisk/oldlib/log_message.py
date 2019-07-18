"""
Simple logging mechanism.

Need to convert to using the python "logging" library.

@author Roy Nielsen
"""
import re
import sys
import inspect

from subprocess import call

def logMessage(message="", level="normal", priority="debug", syslog_level=None) :
    '''Logs a message to both stdout and to syslog via logger
    
    message - the message to log
    
    level - print the message if this value is less than or equal to
            the \"priority\"
    
    priority - defined value to used to compare with the \"level\".  If
               the level is less than or equal to the priority value,
               the message will be printed to stdout and via logger
    
    syslog_level - the syslog level to log with
    
    Author: Roy Nielsen

    :param message:  (Default value = "")
    :param level:  (Default value = "normal")
    :param priority:  (Default value = "debug")
    :param syslog_level:  (Default value = None)

    '''
    if syslog_level is None :
        syslog_level = ""
    else :
        syslog_level = "-p " + syslog_level + " "

    if not re.match("^normal$", level) :
        prog = sys.argv[0]
        # message to be in the format: 
        # <calling_script_name> : <name_of_calling_function> (<line number of calling function>) - <LEVEL>: <message to print>
        message = str(prog) + " : " + \
        inspect.stack()[1][3] + " (" + str(inspect.stack()[1][2]) + ") - " + \
        level.upper() + ": " + str(message)
    else :
        prog = sys.argv[0]
        message = str(prog) + " - " + inspect.stack()[1][3] + \
        " (" + str(inspect.stack()[1][2]) + ") - " + " : " + str(message)
    
    levels = ['quiet', 'normal', 'verbose', 'debug']
    
    if levels.index(level) <= levels.index(priority) :

        print(message)
        cmd_string = "/usr/bin/logger " + syslog_level + "\"" + message +"\""
        retcode = ""
        try :
            retcode = call(cmd_string, shell=True)
            if retcode < 0 :
                print("logger Child was terminated by signal", \
                        -retcode, file=sys.stderr)
            else :
                pass

        except OSError as err :
            print("Execution of " + \
                     str(cmd_string) + \
                     " failed: ", \
                     err, file=sys.stderr)        


