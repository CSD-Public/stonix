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

  At the present time (revision 0.8.16) the following platforms are used for
  development and test: Red Hat Enterprise Linux v6 and v7. Fedora Linux v20 &
  21. OpenSuSE 12.2. Debian (stable). Ubuntu 14.04. CentOS v7. Apple OS X v10.9
  and v 10.10. Close derivitaves of these Operating Systems should be well
  supported, more distant cousins less so.

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