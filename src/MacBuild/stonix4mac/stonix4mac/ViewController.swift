//
//  ViewController.swift
//  stonix4mac
//
//  Created by rsn_local on 11/4/16.
//  Copyright © 2016 Los Alamos National Laboratory. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }

    @IBAction func userAction(_ sender: NSButton) {
        let path = "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix"
        let arguments = ["-d"]
        sender.isEnabled = false
        let task = Process.launchedProcess(launchPath: path, arguments: arguments)
        task.waitUntilExit()
        sender.isEnabled = true
    }

    @IBAction func adminAction(_ sender: NSButton) {
        sender.isEnabled = false
        NSAppleScript(source: "do shell script \"/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix\" with administrator privileges")!.executeAndReturnError(nil)
        sender.isEnabled = true
    }
    
    @IBAction func quitAction(_ sender: NSButton) {
        NSApplication.shared().terminate(self)
    }
    
}

