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
Version: 0.8.16
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
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man8

/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/*.py $RPM_BUILD_ROOT/usr/bin/stonix_resources/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/rules/*.py $RPM_BUILD_ROOT/usr/bin/stonix_resources/rules/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/gfx/* $RPM_BUILD_ROOT/usr/bin/stonix_resources/gfx/
/usr/bin/install $RPM_BUILD_DIR/%{name}-%{version}/stonix_resources/files/* $RPM_BUILD_ROOT/usr/bin/stonix_resources/files/
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

