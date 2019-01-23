###############################################################################
#                                                                             #
# Copyright 2015-2018.  Los Alamos National Security, LLC. This material was  #
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
This rule removes all detected games.

@author: Eric Ball
@change: 2015/08/20 eball Original implementation
@change: 2016/09/14 eball Added autoremove command to apt-get systems fix
@change: 2018/08/20 Brandon R. Gonzales Added protections for functions using
                    '/usr/games' in case the directory doesn't exist
'''
from __future__ import absolute_import
import os
import traceback
from ..stonixutilityfunctions import iterate
from ..pkghelper import Pkghelper
from ..rule import Rule
from ..logdispatcher import LogPriority


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

        self.gamelist = ['/usr/bin/atlantik',
                         '/usr/bin/bomber',
                         '/usr/bin/bovo',
                         '/usr/bin/gnuchess',
                         '/usr/bin/kapman',
                         '/usr/bin/kasteroids',
                         '/usr/bin/katomic',
                         '/usr/bin/kbackgammon',
                         '/usr/bin/kbattleship',
                         '/usr/bin/kblackbox',
                         '/usr/bin/kblocks',
                         '/usr/bin/kbounce',
                         '/usr/bin/kbreakout',
                         '/usr/bin/kdiamond',
                         '/usr/bin/kenolaba',
                         '/usr/bin/kfouleggs',
                         '/usr/bin/kfourinline',
                         '/usr/bin/kgoldrunner',
                         '/usr/bin/killbots',
                         '/usr/bin/kiriki',
                         '/usr/bin/kjumpingcube',
                         '/usr/bin/klickety',
                         '/usr/bin/klines',
                         '/usr/bin/kmahjongg',
                         '/usr/bin/kmines',
                         '/usr/bin/knetwalk',
                         '/usr/bin/kolf',
                         '/usr/bin/kollision',
                         '/usr/bin/konquest',
                         '/usr/bin/kpat',
                         '/usr/bin/kpoker',
                         '/usr/bin/kreversi',
                         '/usr/bin/ksame',
                         '/usr/bin/kshisen',
                         '/usr/bin/ksirk',
                         '/usr/bin/ksirkskineditor',
                         '/usr/bin/ksirtet',
                         '/usr/bin/ksmiletris',
                         '/usr/bin/ksnake',
                         '/usr/bin/kspaceduel',
                         '/usr/bin/ksquares',
                         '/usr/bin/ksudoku',
                         '/usr/bin/ktron',
                         '/usr/bin/ktuberling',
                         '/usr/bin/kubrick',
                         '/usr/bin/kwin4',
                         '/usr/bin/kwin4proc',
                         '/usr/bin/lskat',
                         '/usr/bin/lskatproc']

    def report(self):
        try:
            compliant = True
            self.gamesfound = []
            for game in self.gamelist:
                if os.path.exists(game):
                    self.gamesfound.append(game)
                    compliant = False
                    self.detailedresults += game + " found on system\n"

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
            results = ""
            self.iditerator = 0
            eventlist = self.statechglogger.findrulechanges(self.rulenumber)
            for event in eventlist:
                self.statechglogger.deleteentry(event)

            gamePkgs = ["gnome-games", "kdegames"]
            for pkg in gamePkgs:
                if self.ph.remove(pkg):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "pkghelper",
                             "pkgname": pkg,
                             "startstate": "installed",
                             "endstate": "removed"}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    self.detailedresults += "Unable to remove " + pkg + "\n"

            for game in self.gamesfound:
                pkgName = self.ph.getPackageFromFile(game)
                if pkgName is not None and self.ph.remove(pkgName):
                    self.iditerator += 1
                    myid = iterate(self.iditerator, self.rulenumber)
                    event = {"eventtype": "pkghelper", "pkgname": pkgName,
                             "startstate": "installed", "endstate": "removed"}
                    self.statechglogger.recordchgevent(myid, event)
                else:
                    success = False
                    results += "Unable to remove " + game + "\n"

            if os.path.exists("/usr/games/"):
                if not self.__cleandir("/usr/games/"):
                    success = False
                    results += "Unable to remove all games from /usr/games\n"

            self.rulesuccess = success
            self.detailedresults = results
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
