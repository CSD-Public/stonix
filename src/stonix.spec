###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
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

Name: stonix
Summary: Cross platform hardening tool for *NIX platforms
Version: 0.9.8
Release: 0%{dist}
License: GPL v. 2.0
Group: System administration tools
Source0: %{name}-%{version}.tgz
BuildRoot: %{_builddir}/%{name}-%{version}-%{release}-root
Requires: python, LANL-csdreg, curl
BuildArch: noarch

%description
STONIX: The Security Tool for *NIX. STONIX is designed to harden and configure Unix/linux installations to USGCB/CIS/NSA/DISA STIG standards. 

%prep
%setup -q
%build
%install
mkdir -p $RPM_BUILD_ROOT/etc
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources/rules
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources/gfx
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources/files
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/FileStateManager/pam/0.9.6.13/darwin/MacOSX/10.11/stateAfter/etc/pam.d
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/FileStateManager/pam/0.9.5.99/darwin/MacOSX/10.11/stateAfter/etc/pam.d
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources/help
mkdir -p $RPM_BUILD_ROOT/usr/bin/stonix_resources/help/images
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man8

/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/*.py $RPM_BUILD_ROOT/usr/bin/stonix_resources/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/rules/*.py $RPM_BUILD_ROOT/usr/bin/stonix_resources/rules/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/gfx/* $RPM_BUILD_ROOT/usr/bin/stonix_resources/gfx/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/files/*.mobileconfig $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/files/*.mobileconfigfake $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/files/passwordprofile-10.11 $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/files/*.plist $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/
/usr/bin/cp -R $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/files/* $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/
/usr/bin/cp -R $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/help/* $RPM_BUILD_ROOT/usr/bin/stonix_resources/help/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/help/images/* $RPM_BUILD_ROOT/usr/bin/stonix_resources/help/images/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/usr/share/man/man8/stonix.8 $RPM_BUILD_ROOT/usr/share/man/man8/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix.py $RPM_BUILD_ROOT/usr/bin/
touch $RPM_BUILD_ROOT/etc/stonix.conf

pushd $RPM_BUILD_ROOT/usr/bin
ln -s stonix.py stonix
popd

mkdir -p $RPM_BUILD_ROOT/var/www/html/stonix/results/
mkdir -p $RPM_BUILD_ROOT/var/local/stonix-server/
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/share/stonix/diffdir
mkdir -p $RPM_BUILD_ROOT/usr/share/stonix/archive
mkdir -p $RPM_BUILD_ROOT/usr/share/stonix
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/LogImporter/stonixImporter.py $RPM_BUILD_ROOT/usr/sbin/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/LogImporter/results.php $RPM_BUILD_ROOT/var/www/html/stonix/


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr (755,root,root)
/usr/bin/stonix
/usr/bin/stonix.py
/usr/bin/stonix_resources/


%config(noreplace) %attr(0644,root,root) /etc/stonix.conf
%doc %attr(0644,root,root) /usr/share/man/man8/stonix.8.gz


%dir %attr(0755,root,root) /usr/bin/stonix_resources
%dir %attr(0700,root,root) /usr/share/stonix/diffdir
%dir %attr(0700,root,root) /usr/share/stonix/archive
%dir %attr(0700,root,root) /usr/share/stonix
%dir %attr(0755,root,root) /usr/share/man
%dir %attr(0755,root,root) /usr/share/man/man8

%post
# Register the installation of this product

/usr/local/sbin/csdreg -p STONIX-%{version}-install

%postun

%package importer
Summary: Stonix report importer component
Group: System Environment/Applications
Requires: python, MySQL-python
%description importer
The stonix importer program is expected to run from cron and is used to import
stonix report logs into a properly prepared MySQL database. The cron job is not
automatically established. The SQL statements to create the MySQL database are
installed at /usr/local/stonix/stonixdb.sql

%files importer
%defattr (755,root,root)
%dir %attr(0700,root,root) /var/local/stonix-server/
%dir %attr(0750,root,apache) /var/www/html/stonix/
%dir %attr(0775,root,apache) /var/www/html/stonix/results
%attr(0750,root,root) /usr/sbin/stonixImporter.py
%attr(0750,root,apache) /var/www/html/stonix/results.php

%changelog
* Tue Jun 6 2017 Breen Malmberg <bemalmbe@lanl.gov> - 0.9.8
- Fixed a broken utility method
- Fixed a logic issue in DisableGUILogon which was causing it to incorrectly report not compliant
- SSH service should no longer be turned on if not already on
- Fixed a traceback in SetFSMountOptions
- Fixed a traceback in SoftwarePatching
- Fixed an issue with opensuse 42 which was causing STONIX to choose the wrong package manager
- Fixed package name for debian 32 bit in EnablePAEandNX
- Fixed an issue in EnablePAEandNX which was causing it to look for a non-existent package in ubuntu 16 (32 bit)
- Added better user feedback to BootLoaderPerms rule about what is not compliant when it is not compliant
- Cleaned up and re-factored SetFSMountOptions for better code maintenance
- ConfigurePasswordPolicy now adheres to the new FISMA High / Low setting in localize.py
- Fixed incorrect file contents being added, in Fedora, for rule ConfigureLANLLDAP
- Fixed package conflicts issue with opensuse, for rule ConfigureLANLLDAP
- Fixed an incorrect return code comparison issue in helper class zypper.py

* Tue Apr 4 2017 David Kennel <dkennel@lanl.gov> - 0.9.7
- Public code base now has placeholders for certain constants, in localize and informs the user when attempting to use rules which require these constants, i$
- Stonix now has a new "FISMA" setting in localize, which can be overridden in each rule if necessary, which determines which rules are run by default, when $
- Debian/Ubuntu package will now no longer overwrite existing stonix.conf
- MinimizeServices - Will no longer disable ntp, chrony or syslog, by default
- SecureATCron - Now assigns the correct permissions to cron.log
- RemoveSoftware - Fixed a typo which was resulting in 2 service names being concatenated in the CI list
- ConfigureLANLLDAP - Fixed a bug which was preventing required packages sssd, krb5, pam_ldap from being installed, related services from being started/enabl$
- ConfigureLogging - Fixed a traceback error which was preventing the rule from running on CentOS 6
- Added filter mechanism and variables to support fine tuned actions and rule filtering based on FISMA risk categorization
- Corrected issue with duplicate rule id numbers affecting ConfigureProcessAccounting and EncryptSwap
- Corrected multiple issues with MacOS STIG rules
- Updated MinimizeServices to correct issues on Debian systems
- Corrected permissions problem with SecureATCRON
- Fixed issues with the way that some rules responded to default values in localize.py
- Fixed traceback in DisableInactiveAccounts that affected MacOS
- Fixed multiple issues in ConfigureLogging
* Fri Feb 3 2017 David Kennel <dkennel@lanl.gov> - 0.9.5
- Corrected bug that caused STONIX to not recognize when firewalld was running.
- New rule added: ConfigureFirefox. The configure Firefox rule will disable all automatic update and "phone home" behavior and configure the browser for SSO authentication.
- New rule added: ConfigureFirewall. This rule will enable the system firewall on supported platforms and configure it with reasonable rules. In most cases this means block all inbound except SSH and permit all outbound.
- New rule ForceIdleLogout. This optional rule will force idle Gnome and KDE sessions to log off
- Corrected an issue where the State Change Logger did not record file changes correctly when the "old" file did not exist.
- BootSecurity(18): Changed method of reporting to audit the service rather than just checking a list of services (which included disabled and removed services), making report results more accurate.
- CheckRootPath(44): Now includes a fix, to ensure that root's PATH matches the vendor default.
- ConfigureLANLLDAP(254): Running the rule multiple times on NSLCD systems will no longer result in repeated lines in nsswitch.conf
- ConfigureScreenLocking(74): Originally based on gconftool-2, this was updated to work with the newer gsettings command. Fixed potential bugs in GNOME 3 systems, where the picture-uri variable was not being set. Fixed idle-delay being off (set to 0) appearing as compliant. Rule now checks for "No such key" as gconftool-2/gsettings output, which indicates a compliant state (this was previously seen as a failure).
- FilePermissions(25): Cleaned up and clarified feedback.
- MinimizeServices(12): Added psacct, iptables, ip6tables, ssh, ssh.service, lvm2-activation-early.service, lvm2-activation.service to approved services.
- PasswordExpiration(42): Accounts will be disabled 35 days after the password expires.
- RemoveSUIDGames(244): An issue was found where removing certain games resulted in other games being installed. Made removal function recursive, with a depth limit of 6 to avoid infinite loops.
- SecureHomeDir(45): Added try/except to avoid errors if /home/{user} does not exist.
- SecureMDNS(135): Updated to disable zeroconf networking, per CCE-RHEL7-CCE-TBD 2.5.2.
- SecureNFS(39): Improved help text.
- Rule NetworkTuning(15) renamed SecureIPV4(15)
- ConfigureLogging - now properly logs for authentication events on .deb systems
- PasswordExpiration - PASS_MIN_LEN directive no longer applicable for login.defs file on .deb and opensuse systems.
- RemoveSoftware – New rule
- SecureIPV6 – Now configures Mac OSX
- Fixed bug in PasswordExpiration rule
- Fixed bug in ConfigureScreenLocking rule
- Fixed bug in ConfigureSystemAuthentication rule
- Fixed bug in DisableIPV6 rule
- Fixed bug in NoCoreDumps rule
- Fixed bug in SecureNFS rule
- Fixed bug in SSHTimeout rule
- New STIG specific rules for Mac: STIGConfigureApplicationRestrictionsPolicy, STIGConfigureBluetoothPolicy, STIGConfigureLoginWindowPolicy, STIGConfigurePasswordPolicy	STIGConfigureRestrictionsPolicy, STIGDisableCloudPolicy
- ConfigureSystemAuthentication – complete refactor of rule for a more robust and thorough run.  Now has different specs for password requirements bettween the red and yellow network.
- ConfigurePasswordPolicy – rule is being removed for yellow network due to issues with OSX.
- SetTFTPDSecureMode – new rule
- New Rule – RestrictAccessToKernelMessageBuffer
- New Rule – MinimizeAcceptedDHCPOptions
- New Rule – AuditSSHKeys
- New Rule – AuditNetworkSniffing
- New Rule – EnablePAEandNX
- New Rule – LinuxPackageSigning
- New Rule – DisableInactiveAccounts
- Fixed an issue where InstallBanners would, under certain conditions, append a new configuration line to the same line as another configuration option, resulting in bad syntax
- SSH banner file changed (in InstallBanners) from /etc/motd to /etc/issue so that the text will display before/during ssh login
- Fixed a chmod issue, on the banner text file, in InstallBanners
- Fixed a missing configuration option disable-user-list in InstallBanners, for Debian 7
- InstallBanners banner text updated to meet compliance standards on RHEL 7
- Fixed a typo in one of the underlying framework classes (kveditor) which resolved multiple issues in multiple rules, across multiple systems
- Fixed a pathing error in InstallBanners, for OpenSuSE 13.2
- SystemAccounting will now show as passing, during compliance run, if not enabled. Added doc strings to each method. Rule will now check to see if its CI is enabled or not, in report. Changed CI instructions to be more clear to the end user. Added several in-line comments. Added messaging to indicate to the end user, whether the rule will run its fix or not, based on whether the CI is enabled or not
- SystemAccounting's Unit test will now auto enable its CI when run, in order to properly test the rule's full functionality.
- Fixed an issue with a regular expression in SecureNFS, looking for class A addresses
- SecureNFS New Feature – Will now ensure there are no overly broad NFS exports (exports to an entire class B or larger subnet; exports to an entire DNS domain; etc.)
- Fixed an issue in SecureNFS which was allowing it to start the nfsd service even if it was not already started
- Updated SecureNFS rule with support for host access lists for each export
- SetFSMountOptions rule will now check samba mounts for packet signing; added nodev option to any nfs mounts; added nosuid option to any nfs mounts
- New rule: AuditFirefoxUsage(84): Checks the root account's Firefox history to check for dangerous non-local browsing.
- New rule: ConfigureProcessAccounting(97): Enables the process accounting service, psacct.
- New rule: DisablePrelinking(89)
- New rule: InstallRootCert(10): Adds and activates the LANL root certificate
- logdispatcher: Now handles errors caused by a non-existent e-mail address. This relieves hanging on non-network-connected machines.
- stonix4mac: There will no longer be a symlink stonix.conf in the /Applications/stonix4mac/... path. The installer will only create, and only look for, /etc/stonix.conf
- SHupdaterc: Added '$' to end of regex in auditservice() method, so that searches are more accurate.
- stonix4mac: Added ownership changes to postinstall script to ensure that all files are owned by root
- GUI: Configuration items (CIs) no longer show up when STONIX is run in User context
- PAM stack variables are now part of localize.py, so that they can be easily localized for non-LANL users
- Changed Fedora to dnf packagehelper; updated rules DisableInteractiveStartup, InstallVLock, SecureDHCPServer, SecureNFS, SecurePOPIMAP for this change.
- There is currently a bug with Debian8/python which prevents
- ConfigureMACPolicy from running correctly on that OS
- Fixed an issue which was causing apparmor to not load on restart (on systems which use apparmor) after running fix in ConfigureMACPolicy (note: there is still a bug with Debian python which prevents this rule from ever being compliant after fix. This is not a stonix bug/issue. It will remain this way untilt he Debian folks fix this issue.)
- Fixed a typo in a method call, in ConfigureMACPolicy which was preventing the rule from loading on rhel 6 systems
- There is an issue in Debian's version of gdm3 which prevents certain required security configuration options from being enabled at the same time. As a result, STONIX will now force the use of lightdm as the display manager for Debian systems found running gdm3 as their display manager
- MuteMic now mutes mics on systemd and init systems at boot time
- Fixed a referenced before a assignment variable problem in EnablePAEandNX (this was causing a traceback under certain circumstances)
- Fixed an error in the fix() method of EnablePAEandNX rule, and removed an invalid test from its Unit test
- Initialized commandhelper object before calling it, in all cases for the EnablePAEandNX Unit tests
- Fixed sshd allow hosts syntax in TCPWrappers rule
- Fixed traceback in LinuxPackageSigning Unit test
- Added support for debian and ubuntu pathing in MuteMic
- Fixed a SetDaemonUmask Unit test traceback
- Fixed an issue in RootMailAlias which was causing duplicate line entries in the aliases file
- MinimizeServices will now no longer kill the lightdm.service (which would result in a black screen with a blinking cursor)
- Fixed a PasswordExpiration non-compliant after fix condition on Ubuntu 16
- Issues with both the underlying framework and the rule itself were fixed to resolve multiple issues with SecureCUPS rule
- Fixed a configuration file path for Fedora 24, in ForceIdleLogout
- Fixed an issue with SetNTP where it would not install ntp or chrony if neither existed on the system, and would simply report compliant. It now installs the correct package, depending on the system, and configures it
- Fixed an issue with EnableKernelAuditing which was preventing audit rules from being loaded
- Fixed a configuration issue, in EnableKernelAuditing, with ausyscall stime only having a 32-bit syscall (was issuing an arch=b64 call which was causing a traceback)
- EnableKernelAuditing New Feature – EnableKernelAuditing will now audit a configuration slightly exceeding the LSPP
- Fixed a reporting issue with EnableKernelAuditing which was causing it to wrongly report that the fix had failed
- Fixed multiple pathing issues for MinimizeAcceptedDHCPOptions, for rhel, fedora, centos, opensuse
- Fixed an issue with the regular expression in report method of RestrictAccessToKernelMessageBuffer
- Fixed a syntax error in ConfigureAIDE's cron job entry
- Fixed an issue with DisableInactiveAccounts Unit test
- Made the help text for DisableInactiveAccounts more clear and complete
- Fixed an issue with DisableInactiveAccounts not recognizing when an account had never had a password set before
- Fixed a typo in the disableaccount command in DisableInactiveAccounts
- Changed the help text for DisableInactiveAccounts to be much more clear to the end user about what is being disabled and when and why
- Fixed a race condition between VerifySysFilePerms and SymlinkDangerFiles rules, by leaving /private/etc/hosts.equiv as a file and just ensuring it remains empty
- Fixed an issue with SymlinkDangerFiles which was causing VerifySysFilePerms to report as NCAF on some Mac OS X systems (different than the above race condition)
- Updated DisableAFPFileSharing rule with commands to make it compatible with 10.11 and 10.12. Updated the commands in the Unit test for this rule as well
- ssh and sshd configurations will now be written to the correct “/etc/ssh/” directory, instead of “/etc/”
- Fixed an init traceback of MinimizeAcceptedDHCPOptions on Mac OS X systems
- ConfigureNetworks will now properly disable wi-fi devices on the system when in an area not appropriate for wi-fi – even if the device is not listed in the service list (this is a workaround for an el capitan OS bug)
- Fixed a missing function call in one of the framework classes, for ConfigureNetworks which was causing false negative reporting after the rule's fix had been run
- Fixed many doc strings, added debug logging for, and fixed numerous log issues for – ConfigureNetworks rule and the associated networksetup helper class
- SecureWinFileSharing New Feature – OS X SMB signing enabled and required
- Fixed an issue in SecureWinFileSharing where the applicability of the rule was never getting set
- Fixed some broken logic in report method of DisableCamera rule. Fixed several doc strings. Added debug logging. Removed unused code and imports. Minor refactor of code in report and fix methods. This fixed an NCAF on OS X 10.12 machines
- Added support for Mac OS X systems, in SecureATCRON
- Added support for Mac OS X systems, in SecureCUPS

* Thu Feb 4 2016 David Kennel <dkennel@lanl.gov> - 0.9.4
- Fixed issue where filehelper object did not configure statechglogger correctly when the file to be removed does not exist
- New rule for OS X - ConfigureDiagnosticReporting
- SetSScorners enabled for OS X 10.11
- Corrected index errors in ConfigureDotFiles rule
- Refactor of the SecureMTA rule
- Multiple fixes to unit tests
- Correction of NCAF condition in DisableCamera on OS X 10.11

* Mon Dec 21 2015 David Kennel <dkennel@lanl.gov> - 0.9.3
- Clarified Kerberos entries in localize.py
- Corrected cosmetic issues in results feedback in some rules
- Fixed issue where saved user comments were not showing in the GUI
- Fixed issue where user comments were not saved unless the CI had been changed from the default
- Corrected an issue in the ConsoleRootOnly rule that affected OpenSuSE
- Fixed issue where user comments with embedded newlines cause the program to crash
- Implemented GUI help framework and a start to GUI help text
- Corrected issues with output returns from CommandHelper

* Tue Dec 1 2015 David Kennel <dkennel@lanl.gov> - 0.9.2
- ConfigureMacPolicy updated to work around broken behavior in Debian 8's implementation of AppArmor
- Updated FileHelper object adding return value to fixFile and removing unused imports
- Logic bug where SecureIPv6 created files during report mode corrected
- SecureMDNS undo failures corrected
- SystemAccounting undo failure corrected
- Fixed ConfigureKerberos undo issues
- Undo method of rule.py updated to handle removal of directories
- Undo issues in ScheduleStonix corrected
- XinetdAccessControl undo problems corrected
- Fixed issues in the undo of ConsoleRootOnly
- Corrected undo issues with InstallBanners
- Fixed traceback in DisableWeakAuthentication
- Improved user feedback in SecureATCRON

* Tue Oct 27 2015 David Kennel <dkennel@lanl.gov> - 0.9.1
- Corrected traceback in MuteMic rule when run in user context
- Corrected PAM stack on RHEL 7 so that Sudo works with Kerberos
- Updated apt-get install command sytax in aptGet module of package helper
- Multiple fixes to unit tests and test infrastructure
- Corrected traceback in RootMailAlias
- Corrected traceback in ConfigureSudo
- Improved feedback in VerifyAccPerms rule
- Corrected permissions flapping in ConfigureLogging
- Corrected traceback in EnableKernelAuditing
- Corrected traceback in SecureCups
- Updated applicability filters for EnableSELinux rule

* Wed Sep 30 2015 David Kennel <dkennel@lanl.gov> - 0.9.0
- Updated isApplicable() to filter on whether rules should or should not run under the root users context
- Fix to bug in the interaction of installBAnners and SecureSSH that was causing oversized sshd_conf files
- New Rule BootSecurity, mutes the microphone, turns off wireless and turns off bluetooth at every system boot
- Fix subtle bug in ruleKVEditor that caused false positives
- New Rule SecureLDAP checks security on the LDAP server
- Improved feedback in multiple rules
- SecureApacheWebserver now correctly handles RHEL 7 style module layouts
- New Rule EnableKernelAuditing configures auditd according to guidance
- Fixed bug that caused the 'About Stonix' window to be unclosable on gnome 3

* Mon Aug 31 2015 David Kennel <dkennel@lanl.gov> - 0.8.20
- New rule: Remove SUID Games
- New rule: Disable Admin Login Override
- New rule: Disable Login Prompts on Serial Ports
- New rule: Installed Software Verification
- New rule: Xinetd access control
- Fixed multiple issues with Install Banners
- Added wifi to list of allowed names for ConfigureNetworks network locations
- Corrected man page permissions on .deb versions
- Added error handling to Configure Dot Files to suppress errors in edge conditions
- Corrected permissions on /etc/profile.d/tmout.sh for ShellTimeout

* Thu Jul 30 2015 Eric Ball <eball@lanl.gov> - 0.8.19
- New rule: Disable GUI Logon
- New rule: Restrict Mounting
- New rule: Time-out for Login Shells
- New rule: Secure Squid Proxy
- New rule: No Cached FDE Keys
- Added framework unit testing to stonixtest.py
- Unit test added for DisableFTP
- Unit test added for SecureDHCP
- Added undo functionality for DisableCamera
- Fixed issue that caused tracebacks in ConfigureNetworks
- Fixed issue that caused tracebacks in ConfigurePowerManagement
- Improved reliability of ConfigureAIDE
- Heavily refactored InstallBanners
- Improved feedback for ConfigureSystemAuthentication non-compliance


* Tue Jun 30 2015 David Kennel <dkennel@lanl.gov> - 0.8.18
- New rule: Secure the ISC DHCP server
- Fixed an issue that caused tracebacks in SecureMDNS
- Fixed an issue that would cause STONIX to quit if mail relay was not available when a traceback occured
- Fixed unit test issues in the zzzTestFrameworkconfiguration and zzzTestFrameworkServiceHelper
- Corrected traceback in ConfigureLogging
- Unit test added for DisableThumbnailers

* Fri May 29 2015 David Kennel <dkennel@lanl.gov> - 0.8.17
- Fixed multiple issues with SetSSCorners
- Observed behavior on CentOS where DisableThumbnailers is non-compliant after fix
  due to issues with gconf/dbus.
- Fixed bug in MinimizeServices caused by missing commas in a Python list that affected
  non-systemd Linux distributions.

* Thu Apr 30 2015 David Kennel <dkennel@lanl.gov> - 0.8.16
- Major refactor of the isApplicable method and workflow
- Corrected bug in the behavior of RootMailAlias
- SoftwarePatching rule now checks rpmrc files for the nosignature option
- Optional rule to enable system accounting via sysstat and sar
- Refactor of KVADefault for clarity

* Mon Mar 30 2015 David Kennel <dkennel@lanl.gov> - 0.8.15
- Short circut logic added to FilePermissions, report capped at 30,000 bad files
- Corrected bug on OpenSUSE where SHsystemctl was using wrong path
- Guidance update for SecureMTA; postfix now configuring a relayhost

* Mon Mar 2 2015 David Kennel <dkennel@lanl.gov> - 0.8.14

* Thu Jan 29 2015 David Kennel <dkennel@lanl.gov> - 0.8.13
- Corrected logic errors in SecureMDNS
- Eliminated errant email from DisableScreenSavers
- Add unix man page for stonix
- Corrected cosmetic issue with SetNTP
- Fixed NCAF in ConfigureLoggin on OpenSuSE
- Corrected issue in the Service Helper for systemd services
- Corrected cosmetic issue in DisableIPV6

* Tue Jan 6 2015 David Kennel <dkennel@lanl.gov> - 0.8.12
- Fixed permissions on stonix.conf that prevented use of user mode
- Fixed dependency issues on /bin/env in OpenSUSE
- Corrected traceback issues in isApplicable on Fedora
- Fixed stalling in SecureMDNS on RHEL 7
- Fixed discoveros failure in CentOS
- Corrected missing try/catch for cases where PyQT is not available
- BootloaderPerms updated for RHEL 7/CentOS 7
- Stop run button and toolbar added to STONIX GUI

* Mon Dec 1 2014 David Kennel <dkennel@lanl.gov> - 0.8.11

* Mon Nov 3 2014 David Kennel <dkennel@lanl.gov> - 0.8.10
- Fixed ConsoleRootOnly rule on RHEL 7
- Fixed DisableIPV6 rule on RHEL 7
- Fixed EnableSELinux rule on RHEL 7
- Fixed ConfigureLogging rule on Fedora

* Wed Oct 1 2014 David Kennel <dkennel@lanl.gov> - 0.8.9
- Resolved issue in InstallVlock rule
- Added metrics to STONIX execution
- Resolved GUI timing glitches
- Resolved issue where the DisableBluetooth rule killed the GUI on RHEL 7
- Known issue with OpenSUSE 13.1 and minimize services due to a bug in OpenSUSE where some services do not actually turn off via the chkconfig command.
- Resolved non-compliant after fix issues in SetFSMountOptions
- Clarified non-compliance messages in InstallBanners
- DisableUSBStorage refactored and renamed to DisableRemovableStorage
- DOEWARNINGBANNER variable renamed.
- New rule added: Enable Stack Protection
- Resolved issue where the Zypper package helper component did not handle permission denied on repo access correctly.

* Thu Aug 28 2014 David Kennel <dkennel@lanl.gov> - 0.8.8

* Tue Jul 29 2014 David Kennel <dkennel@lanl.gov> - 0.8.7

* Fri Jun 27 2014 David Kennel <dkennel@lanl.gov> - 0.8.6
- 7th Alpha release
- Fixed issue with CIs not showing up in OS X
- Fixed LoginWindow configuration on OS X
- Fixed non-compliant after fix issue in ConfigureSudo
- Fixed Admin SSH restriction in OS X
- Resolved multiple issues in ConfigureLoggin rule
- Fixed unable to restart sysctl messages
- Resolved non-compliant after fix with SecureMTA rule
- Fixed bug that could result in multiple copies of the same rule running
- FilePermissions now has a blacklist feature to ignore file systems
- Fixed non-compliant after fix in TCPWrappers rule
- Fixed traceback in SecureSNMP on OS X
- Fixed non-compliant after fix in SecureCUPS rule
- Fixed SymlinkDangerFiles on OS X
- Fixed non-compliant after fix in EnableSELinux on Ubuntu
- Fixed non-compliant after fix in InstallVLock on Ubuntu
- Fixed non-compliant after fix in SSHTimeout
- Fixed traceback in SSHTimeout
- Fixed SecureHomeDir showing error but reporting compliant
- Fixed multiple bugs in SecureSU
- FilePermissions rule will now remove world write permissions in roots path
- OS Version information now submitted in STONIX error messages
- Fixed traceback in DisableUnusedFS rule
- Fixed traceback in ConfigureKerberos on Debian

* Mon Jun 02 2014 David Kennel <dkennel@lanl.gov> - 0.8.5
- 6th Alpha release
- ConfigureAIDE should now initialize the Database
- SecureATCRON traceback on CentOS fixed
- SetDaemonUmask Traceback on CentOS fixed
- Install Puppet traceback fixed
- ReqAuthSingleUserMode fixed
- RootMailAlias multiple bugs fixed
- SecureHomeDir refactored to elminate bugs
- Fixed cosmetic issue with missing newline at the end of the warning banner
- ScheduleStonix now reports compliant on first fix
- StateChgLogger component now supports logging/recovery of deleted files
- EnableSELinux rule now allows permissive/enforcing mode selection

* Mon Apr 28 2014 David Kennel <dkennel@lanl.gov> - 0.8.4
- Bumped version for 5th alpha.
- Numerous changes:
- Fixed traceback in InstallVlock
- Allowed shorter than 15 min lockouts for screensavers
- Fixed non-compliant after fix bug in screen locking
- Fixed insecure command useage in configure system authentication
- Fixed traceback in DisableIPv6
- Fixed fix mode failure in PasswordExpiration
- Fixed non-compliant after fix bug in PreventXListen
- Fixed multiple bugs in SecureMTA
- Fixed non-compliant after fix bug in SecureSSH
- Fixed traceback in SoftwarePatching on CentOS
- Fixed blocking behavior in GUI. UI now updates while executing.
- Changed CI implementation and invocation in all rules.
- Fixed DisableInteractiveStartup traceback on CentOS.
- Fixed ScheduleStonix traceback on CentOS.
- Fixed DisableScreenSavers non-compliant after fix bug.
- Fixed bug in SetDefaultUserUmask where CI was not referenced in Fix
- Fixed bug in SetFSMountOptions where CI was not referenced in Fix
- Fixed bug in SetNTP where CI was not referenced in Fix
- Fixed bug in setRootDefaults where CI was not referenced in Fix
- Fixed bug in SetupLogwatch where CI was not referenced in Fix
- Fixed bug in TCPWrappers where CI was not referenced in Fix
- Fixed bug in VerifyAccPerms where CI was not referenced in Fix
- Fixed bug in BootloaderPerms where CI was not referenced in Fix
- Fixed bug in InstallBanners where CI was not referenced in Fix
- Fixed bug in ConfigureAIDE where CI was not referenced in Fix
- Fixed bug in DisableUSBStorage where CI was not referenced in Fix
- Fixed bug in CommandHelper that resulted in attribute errors in certain cases.
- Fixed multiple bugs in SecureMDNS.

* Mon Mar 24 2014 David Kennel <dkennel@lanl.gov> - 0.8.3
- Initial release in RPM format.

