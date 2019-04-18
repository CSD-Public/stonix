#!/usr/bin/env xcrun swift

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

//
//  AppleNotificationHandler.swift
//
//  Created by Brandon R. Gonzales on 3/22/19.
//  Copyright © 2019 Brandon R. Gonzales. All rights reserved.
//
import AppKit
import Darwin
import Foundation

public class StonixNotificationHandler
{
    var processPID: Int32
    
    init(_processPID: Int32)
    {
        self.processPID = _processPID
        
        registerForNotifications()
    }
    
    @objc private func onPowerOffNotification(_ aNotification: Notification)
    {
        print("Power Off notification received:")
        print("Terminating STONIX...")
        let task = Process()
        task.launchPath = "/bin/kill"
        task.arguments = ["-SIGTERM", String(processPID)]
        task.launch()
        task.waitUntilExit()
        exit(0)
    }
    
    @objc private func onSleepNotification(_ aNotification: Notification)
    {
        print("Sleep notification received:")
        print("Terminating STONIX...")
        let task = Process()
        task.launchPath = "/bin/kill"
        task.arguments = ["-SIGTERM", String(processPID)]
        task.launch()
        task.waitUntilExit()
        exit(0)
    }
    
    func registerForNotifications()
    {
        // Register for power off notifications
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(self.onPowerOffNotification(_:)),
            name: NSWorkspace.willPowerOffNotification,
            object: nil
        )
        
        // Register for sleep notifications
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(self.onSleepNotification(_:)),
            name: NSWorkspace.willSleepNotification,
            object: nil
        )
    }
}

if CommandLine.arguments.count > 1
{
    if let actualPID = Int32(CommandLine.arguments[1])
    {
        let notificationHandler = StonixNotificationHandler(_processPID: actualPID)
        
        print(notificationHandler.processPID)
        
        // Puts the receiver in a permanent loop so it may process events,
        // like wake and sleep notifications
        RunLoop.current.run()
    }
}
