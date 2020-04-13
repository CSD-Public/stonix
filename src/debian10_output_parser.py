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
#! /usr/bin/python3
"""
Created on Apr 13, 2020

This module parses the and output file of a stonix run for Debian 10 systems
for rule failures and rules resulting in non compliant reports since an
effective GUI is not applicable on these systems

@author: Derek Walker
"""
import optparse
import sys
import re

def main():
    usage = "usage -f outputFile"
    parser = optparse.OptionParser(usage=usage)
    (options, args) = parser.parse_args()
    outputfile = None
    if len(args) == 0 or len(args) > 1:
        print("Wrong number of arguments passed")
        sys.exit(1)
    else:
        outputfile = args[0]
    parseoutput(outputfile)

def parseoutput(outputfile):
    filehandle = open(outputfile, "r")
    output = filehandle.readlines()
    filehandle.close()
    failedrules = {}
    print("inside parseoutput\n")
    for line in output:
        print("line: \n")
        print(line, "\n")
        if re.search("^DEBUG:\*{18}RULE START:\ ", line):
            print("Found a new rule\n")
            print(line, "\n")
            iterator = 0
            templist = output[iterator + 1:]
            print("templist: \n")
            print(str(templist), "\n")
            reportCount = 0
            singleruleoutput = []
            for line2 in templist:
                singleruleoutput.append(line2)
                if re.search("^DEBUG:={19}START REPORT: ", line2):
                    reportCount += 1
                if re.search("report results: Rule is not Compliant"):
                    if reportCount == 2:
                        failedrules[line] = singleruleoutput
                        break
                elif re.search("report results: Rule is Compliant"):
                    break

    if failedrules:
        print("The following rules failed: \n")
        print(str(failedrules))
        newoutputfile = "~/ncafstonix.out"
        filehandle = open(newoutputfile, "w")
        for rule in faiedrules:
            filehandle.write(rule)
            filehandle.write(failedrules[rule])
        filehandle.close()
if __name__ == "__main__":
    main()