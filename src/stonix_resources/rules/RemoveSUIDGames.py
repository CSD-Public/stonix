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
This rule removes all detected games.

@author: Eric Ball
@change: 2015/08/20 eball Original implementation
@change: 2016/09/14 eball Added autoremove command to apt-get systems fix
@change: 2018/08/20 Brandon R. Gonzales Added protections for functions using
                    '/usr/games' in case the directory doesn't exist
'''

import os
import traceback
from stonixutilityfunctions import iterate
from pkghelper import Pkghelper
from rule import Rule
from logdispatcher import LogPriority


class RemoveSUIDGames(Rule):

    def __init__(self, config, enviro, logger, statechglogger):
        Rule.__init__(self, config, enviro, logger, statechglogger)
        self.logger = logger
        self.rulenumber = 244
        self.rulename = "RemoveSUIDGames"
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.applicable = {'type': 'white', 'family': 'linux'}

        # Configuration item instantiation
        datatype = "bool"
        key = "REMOVESUIDGAMES"
        instructions = "To disable this rule, set the value of " + \
                       "REMOVESUIDGAMES to false."
        default = True
        self.ci = self.initCi(datatype, key, instructions, default)

        self.guidance = ["LANL 15.7"]
        self.iditerator = 0
        self.ph = Pkghelper(self.logger, self.environ)

        self.gamelist = ['atlantik',
                        'bomber',
                        'bovo',
                        'gnuchess',
                        'kapman',
                        'kasteroids',
                        'katomic',
                        'kbackgammon',
                        'kbattleship',
                        'kblackbox',
                        'kblocks',
                        'kbounce',
                        'kbreakout',
                        'kdiamond',
                        'kenolaba',
                        'kfouleggs',
                        'kfourinline',
                        'kgoldrunner',
                        'killbots',
                        'kiriki',
                        'kjumpingcube',
                        'klickety',
                        'klines',
                        'kmahjongg',
                        'kmines',
                        'knetwalk',
                        'kolf',
                        'kollision',
                        'konquest',
                        'kpat',
                        'kpoker',
                        'kreversi',
                        'ksame',
                        'kshisen',
                        'ksirk',
                        'ksirkskineditor',
                        'ksirtet',
                        'ksmiletris',
                        'ksnake',
                        'kspaceduel',
                        'ksquares',
                        'ksudoku',
                        'ktron',
                        'ktuberling',
                        'kubrick',
                        'kwin4',
                        'kwin4proc',
                        'lskat',
                        'lskatproc',
                        'gnome-games',
                        'kdegames',
                        'gnome-taquin']

    def report(self):
        try:
            compliant = True
            self.gamesfound = []
            self.gamedirsfound = []

            for game in self.gamelist:
                if self.ph.check(game):
                    self.gamesfound.append(game)
                    compliant = False
                    self.detailedresults += game + " installed on system\n"
                if os.path.exists("/usr/bin/" + game):
                    self.gamedirsfound.append("/usr/bin/" + game)
                    compliant = False
                    self.detailedresults += "/usr/bin/" + game + "path exists\n"
            if(os.path.exists("/usr/games")):
                usrgames = os.listdir("/usr/games")
                if len(usrgames) > 0:
                    compliant = False
                    self.detailedresults += "/usr/games directory is not empty\n"
            self.compliant = compliant
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        try:
            if not self.ci.getcurrvalue():
                return
            success = True
            debug = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            for game in self.gamesfound:
                # pkgName = self.ph.getPackageFromFile(game)
                # if pkgName is not None and str(pkgName) is not "":
                if self.ph.remove(game):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "pkghelper",
                             "pkgname": game,
                             "startstate": "installed",
                             "endstate": "removed"}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
                    self.detailedresults += "Unable to remove " + game + "\n"
            for game in self.gamedirsfound:
                #did not put state change event recording here due to python
                #not sending valid return code back for success or failure
                #with os.remove command therefore not knowing if successful
                #to record event
                if os.path.exists(game):
                    os.remove(game)
            if os.path.exists("/usr/games/"):
                if not self.__cleandir("/usr/games/"):
                    success = False
                    self.detailedresults += "Unable to remove all games from /usr/games\n"

            self.rulesuccess = success
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.rulesuccess = False
            self.detailedresults += "\n" + traceback.format_exc()
            self.logdispatch.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess,
                                   self.detailedresults)
        self.logdispatch.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def __cleandir(self, directory, depth=0):
        '''Recursively finds the package name for each file in a directory,
        and all child directories, and uninstalls the package. Ignores links.
        This is best-effort; no error checking is done for the uninstall
        requests.

        @param directory: Name of the directory to search
        @return: False if a package name is not found for any file, True
                 otherwise.
        @author: Eric Ball
        '''
        success = True
        dirlist = os.listdir(directory)
        for path in dirlist:
            path = directory + path
            if os.path.isfile(path):
                pkgName = self.ph.getPackageFromFile(path)
                if pkgName is not None:
                    if self.ph.remove(pkgName):
                        self.iditerator += 1
                        myid = iterate(self.iditerator, self.rulenumber)
                        event = {"eventtype": "pkghelper",
                                 "pkgname": pkgName,
                                 "startstate": "installed",
                                 "endstate": "removed"}
                        self.statechglogger.recordchgevent(myid, event)
                    else:
                        debug = "Could not remove package " + pkgName
                        self.logger.log(LogPriority.DEBUG, debug)
                        success = False
                else:
                    debug = "Could not find package name for " + path
                    self.logger.log(LogPriority.DEBUG, debug)
                    success = False
            elif os.path.isdir(path):
                if depth < 6:
                    success &= self.__cleandir(path, depth+1)
        dirlist = os.listdir(directory)
        if dirlist:
            # There is a possibility that removing some packages will result in
            # other packages being installed. We will attempt to remove these
            # additional packages, but limit this to avoid infinite loops.
            if depth < 6:
                success &= self.__cleandir(directory, depth+1)
        return success