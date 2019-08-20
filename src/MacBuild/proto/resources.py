#!/usr/bin/env python3

import os
def getResourcesDir() :
    '''Get the full path to the Resources directory of the current app
    
    Author: Roy Nielsen


    '''
    # Gets the <app-path>/Contents/MacOS full path
    selffile = os.path.abspath(__file__)
    selfdir = os.path.dirname(selffile)
    resource_dir = ""

    print(selffile)
    print(selfdir)
    print("\n\n")


    parents = selfdir.split("/")

    # Remove the "MacOS" dir from the list
    parents.pop()

    # Append "Contents" & "cmu" to the end of the list
    #parents.append("Contents")
    
    # Append "Resources" & "cmu" to the end of the list
    parents.append("Resources")
    
    # Join up the directory with slashes
    resource_dir = "/".join(parents)

    return resource_dir


print(getResourcesDir())
