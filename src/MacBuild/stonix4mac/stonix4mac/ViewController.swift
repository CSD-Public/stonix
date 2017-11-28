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

    override func viewDidAppear() {
        super.viewDidAppear()
        self.view.window?.title = "stonix4mac 1001"
    }
    
    @IBAction func userAction(_ sender: NSButton) {
        let path = "/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix"
        let arguments = ["-d"]
        sender.isEnabled = false
        let task = Process.launchedProcess(launchPath: path, arguments: arguments)
        NSApplication.shared().terminate(self)
        task.waitUntilExit()
        sender.isEnabled = true
    }

    @IBAction func adminAction(_ sender: NSButton) {
        sender.isEnabled = false
        // http://macscripter.net/viewtopic.php?id=19303
        //
        // Camelot
        // Member
        // From: San Jose, CA
        // Registered: 2002-12-14
        // Posts: 629
        // Re: Non blocking do shell script?
        // AppleScript's do shell script holds the process' stdout and stderr hooks waiting for the
        // output of the command. That's why it appears to hang - it's doing what it's designed to do.
        //
        // The solution is simple - you redirect stderr and stdout to some other location and send
        // the shell process to the background:
        //
        // Open this Scriplet in your Editor:
        //     do shell script "/bin/sleep 60 > /dev/null 2>&1 &"
        //
        // the > /dev/null redirects the process' stdout to /dev/null (you can use some other file path
        // if you want to capture its output). 2>&1 redirects stderr to the same place as stderr (in
        // this case, /dev/null) and the trailing & sends the process to the background.
        //
        // You'll find that this effectively returns control back to your script while the
        // shell process runs in the background.
        //
        // Last edited by Camelot (2006-11-25 10:02:49 pm)
        NSAppleScript(source: "do shell script \"/Applications/stonix4mac.app/Contents/Resources/stonix.app/Contents/MacOS/stonix > /dev/null 2>&1 &\" with administrator privileges")!.executeAndReturnError(nil)
        NSApplication.shared().terminate(self)
        sender.isEnabled = true
    }
    
    @IBAction func quitAction(_ sender: NSButton) {
        NSApplication.shared().terminate(self)
    }
    
}


