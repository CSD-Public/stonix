STONIX
======



0. Overview
-----------

  STONIX is an operating system configuration hardening tool for Unix and Unix
  like (e.g. Linux) operating systems. This tool implements a hybrid of
  guidance from NSA, DISA STIGs, USGCB and the CIS. To as great of a degree as
  possible each guidance element for each platform is evaluated on the other
  platforms for applicability and applied if possible.

  The STONIX program is a modular codebase implemented in Python (currently
  using the 2.x dialect, a port to Python 3.0 is in future planning). Python
  was selected due to it being part of the default install on all target
  platforms. The program is primarily a command-line utility but there is a
  robust GUI built in. The GUI is implemented in PyQt. Many platform packages
  will not express a dependecy on PyQt due to the GUI's optional nature.
  
  At the present time (revision 0.9.4) the following platforms are used for
  development and test: Red Hat Enterprise Linux 6 and 7, Fedora Linux
  22, OpenSuSE 13.2, Debian 7 and 8 (stable), Ubuntu 14.04 LTS, CentOS 7,
  Apple's OS X Mavericks 10.9, OS X Yosemite 10.10, and OS X El Capitan 10.11.
  Close derivatives of these operating systems should be well supported, 
  more distant cousins less so.
  
1. Documentation
----------------

  README	This file
  INSTALL	Installation instructions
  PACKAGERS	Information to packagers
  LICENSE	GNU General Public Licsense v2
  AUTHORS	The main authors of STONIX
  THANKS	An incomplete list of people who contributed to this software
  ChangeLog	Detailed list of changes
  TODO		Known bugs and to-do listing
  DEVELOPERS Detailed documentation for people who want to contribute to STONIX
  
2. Version numbering
--------------------

  STONIX uses a Major.Minor.Release versioning scheme.

  At present STONIX is in an Alpha, not feature complete stage. Every attempt
  is made to ensure that the code is production ready, but the features are not
  yet complete and there will be functionality changes in future revisions.

3. Reporting bugs
-----------------

  When reporting issues in STONIX please fully document the specific
  functionality that is causing a problem. We will likely need sample
  configuration files that cause the section of STONIX to have issues. A copy
  of the debug output is also very valuable.

  Report your issue via the STONIX github issue tracker.

4. Known Issues
---------------

   1. Developers have observed behavior on CentOS where DisableThumbnailers
   returns non-compliant after the fix is run. This appears to be due to
   issues in gconf or dbus and the rule is working as designed.
