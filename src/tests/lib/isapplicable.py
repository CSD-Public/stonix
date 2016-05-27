"""

Class to determine applicability at runtime of code.

@author: dkennel
"""
import re
import sys
from distutils.version import LooseVersion

from src.tests.lib.logdispatcher_lite import LogPriority
from src.tests.lib.logdispatcher_lite import LogDispatcher
from src.stonix_resources.environment import Environment

class ApplicableCheck(object):

    def __init__(self, logger=False, environ=False):
        """
        initialization method
        """
        #####
        # Perform input validation and ensure we have an Environment instance.
        if isinstance(environ, Environment):
            self.environ = environ
        else:
            self.environ = Environment()
        self.logdispatch = LogDispatcher(self.environ)

        #####
        # Initialize the class applicable variable.
        self.applicable = {"default": "default"}

    def setCheckParams(self, applicableCheck={"default": "default"}):
        """
        Set the applicable instance variable.  The passed in value will be used
        by the isApplicable method.

        @author: Roy Nielsen
        """
        success = False
        #####
        # Need to figure out proper input validation for the "check" parameter.
        # Current check is insufficient
        if isinstance(check, dict):
            self.applicable = check
            success = True
        return success

    def isApplicable(self):
        """
        This method returns true if the rule applies to the platform on which
        stonix is currently running. The method in this template class will
        return true by default. The class property applicable will be
        referenced when this method is called and should be set by classes
        inheriting from the rule class including sub-template rules and
        concrete rule implementations.

        The format for the applicable property is a dictionary. The dictionary
        will be interpreted as follows:
        Key    Values        Meaning
        type    black/white  Whether the rest of the entries will be
                             interpreted as a whitelist (apply to) or a
                             blacklist (do not apply to). Blacklist is the
                             default.
        family  [list, valid environment.getosfamily() return types] The listed
                             os family will be whitelisted or blacklisted
                             according to the value of the type key.
        os    [Dict: key is a valid regex string that will match against return
                            from environment.getostype(), value is a list
                            containing version numbers, the - symbol, the +
                            symbol, or the letter "r" +|- may only be combined
                            with a single version number. "r" indicates a range
                            and expects 2 version numbers.]
                            This key is for matching specific os versions.
                             To match all Mac OS 10.9 and newer:
                             os: {'Mac OS X': ['10.9', '+']}
                             To match all Mac OS 10.8 and older:
                             os: {'Mac OS X': ['10.8', '-']}
                             To match only RHEL 6:
                             os: {'Red Hat Enterprise Linux': ['6.0']}
                             To match only Mac OS X 10.9.5:
                             os: {'Mac OS X': ['10.9.5']
                             To match a series of OS types:
                             os: {'Mac OS X': ['10.9', 'r', '10.10'],
                                  'Red Hat Enterprise Linux': ['6.0', '+'],
                                  'Ubuntu: ['14.04']}
        noroot   True|False This is an option, needed on systems like OS X,
                            which are "rootless". Meaning the root user isn't
                            used like a regular user. On these systems some
                            rules aimed at the user environment may not work or
                            actually cause problems. If this option is set to
                            True (python bool) then this method will return
                            false if EUID == 0. The default is False.
        default  default    This is the default value in the template class and
                            always causes the method to return true. The
                            default only takes affect if the family and os keys
                            are not defined.

        An Example dictionary might look like this:
        self.applicable = {'type': 'white',
                           'family': Linux,
                           'os': {'Mac OS X': ['10.9', 'r', '10.10.5']}
        That example whitelists all Linux operating systems and Mac OS X from
        10.9.0 to 10.10.5.

        The family and os keys may be combined. Note that specifying a family
        will mask the behavior of the more specific os key.

        Note that version comparison is done using the distutils.version
        module. If the stonix environment module returns a 3 place version
        string then you need to provide a 3 place version string. I.E. in this
        case 10.9 only matches 10.9.0 and does not match 10.9.3 or 10.9.5.

        This method may be overridden if required.

        @return bool :
        @author D. Kennel
        @change: 2015/04/13 added this method to template class
        @change: 2016/04/27 rsn Created a class specificly surrounding 
                                this method.
        """
        # return True
        # Shortcut if we are defaulting to true
        #self.logdispatch.log(LogPriority.DEBUG,
        #                     'Check applicability for ' + self.rulename)
        self.logdispatch.log(LogPriority.DEBUG,
                             'Dictionary is: ' + str(self.applicable))
        try:
            if 'os' not in self.applicable and 'family' not in self.applicable:
                amidefault = self.applicable['default']
                if amidefault == 'default':
                    self.logdispatch.log(LogPriority.DEBUG,
                                         'Defaulting to True')
                    return True
        except KeyError:
            pass

        # Determine whether we are a blacklist or a whitelist, default to a
        # blacklist
        if 'type' in self.applicable:
            listtype = self.applicable['type']
        else:
            listtype = 'black'
        # Set the default return as appropriate to the list type
        # FIXME check for valid input
        assert listtype in ['white', 'black'], 'Invalid list type specified: %r' % listtype
        if listtype == 'black':
            applies = True
        else:
            applies = False

        # get our data in local vars
        myosfamily = self.environ.getosfamily()
        myosversion = self.environ.getosver()
        myostype = self.environ.getostype()

        # Process the os family list
        if 'family' in self.applicable:
            if myosfamily in self.applicable['family']:
                if listtype == 'black':
                    applies = False
                else:
                    applies = True
                self.logdispatch.log(LogPriority.DEBUG,
                                     'Family match, applies: ' + str(applies))

        # Process the OS list
        if 'os' in self.applicable:
            for ostype, osverlist in self.applicable['os'].iteritems():
                if re.search(ostype, myostype):
                    # Process version and up
                    if '+' in osverlist:
                        assert len(osverlist) is 2, "Wrong number of entries for a +"
                        if osverlist[1] == '+':
                            baseversion = osverlist[0]
                        else:
                            baseversion = osverlist[1]
                        if LooseVersion(myosversion) >= LooseVersion(baseversion):
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Plus match, applies: ' + str(applies))
                    # Process version and lower
                    elif '-' in osverlist:
                        assert len(osverlist) is 2, "Wrong number of entries for a -"
                        if osverlist[1] == '-':
                            baseversion = osverlist[0]
                        else:
                            baseversion = osverlist[1]
                        if LooseVersion(myosversion) <= LooseVersion(baseversion):
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Minus match, applies: ' + str(applies))
                    # Process inclusive range
                    elif 'r' in osverlist:
                        assert len(osverlist) is 3, "Wrong number of entries for a range"
                        vertmp = osverlist
                        vertmp.remove('r')
                        if LooseVersion(vertmp[0]) > LooseVersion(vertmp[1]):
                            highver = vertmp[0]
                            lowver = vertmp[1]
                        elif LooseVersion(vertmp[0]) < LooseVersion(vertmp[1]):
                            highver = vertmp[1]
                            lowver = vertmp[0]
                        else:
                            raise ValueError('Range versions are the same')
                        if LooseVersion(myosversion) <= LooseVersion(highver) \
                        and LooseVersion(myosversion) >= LooseVersion(lowver):
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Range match, applies: ' + str(applies))
                    # Process explicit match
                    else:
                        if myosversion in osverlist:
                            if listtype == 'black':
                                applies = False
                            else:
                                applies = True
                            self.logdispatch.log(LogPriority.DEBUG,
                                                 'Version match, applies: ' + str(applies))

        # Perform the rootless check
        if applies and self.environ.geteuid() == 0:
            if 'noroot' in self.applicable:
                if self.applicable['noroot'] == True:
                    applies = False

        return applies
