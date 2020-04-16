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

"""
Created on Aug 9, 2012

@author: Dave Kennel
@change: Dave Kennel 04/18/2014 Replaced old-style CI invocation
@change: 06/02/2014 Dave Kennel: Added services to linuxdefault set based on .deb
@change: 2014/07/23 Dave Kennel: Added additional services to systemd list based on
        RHEL 7
@change: 2015/04/15 Dave Kennel: updated for new isApplicable
@change: 2015/10/07 Eric Ball Help text cleanup
@change: 2015/10/30 Derek Walker: added additional services to allowed list.
@change: 2016/04/26 Ekkehard Results Formatting
@change: 2016/04/09 Eric Ball Updated service lists per RHEL 7 STIG
@change: 2016/10/06 Dave Kennel Updates service lists and minor hacking to support
        ubuntu 16.04.
@change: 2016/10/19 Eric Ball Added ssh and ssh.service for Deb8 compatibility
@change: 2016/12/16 Eric Ball Added lvm2-activation{.,-early.}service to whitelist
@change: 2017/10/24 Roy Nielsen changing to use service helper, second gen
@change: 2018/1/17 Brandon Gonzales Add sddm.service and sddm to the
        systemd whitelist
"""



import traceback
import re
import os
import sys # for testing

from ServiceHelper import ServiceHelper
from rule import Rule
from logdispatcher import LogPriority
from CommandHelper import CommandHelper


class MinimizeServices(Rule):
    '''The MinimizeServices class sets the system so that only approved services
    are running at any given time.


    '''

    def __init__(self, config, environ, logger, statechglogger):
        """
        Constructor
        """
        Rule.__init__(self, config, environ, logger, statechglogger)
        self.config = config
        self.environ = environ
        self.logger = logger
        self.statechglogger = statechglogger
        self.rulenumber = 12
        self.rulename = 'MinimizeServices'
        self.formatDetailedResults("initialize")
        self.mandatory = True
        self.sethelptext()
        self.rootrequired = True
        self.applicable = {'type': 'black',
                           'family': ['darwin']}
        self.servicehelper = ServiceHelper(self.environ, self.logger)
        self.guidance = ['NSA 2.1.2.2', 'NSA 2.2.2.3', 'NSA 2.4.3', 'NSA 3.1',
                         'CCE-3416-5', 'CCE-4218-4', 'CCE-4072-5', 'CCE-4254-9',
                         'CCE-3668-1', 'CCE-4129-3', 'CCE-3679-8', 'CCE-4292-9',
                         'CCE-4234-1', 'CCE-4252-3', 'CCE-3390-2', 'CCE-3974-3',
                         'CCE-4141-8', 'CCE-3537-8', 'CCE-3705-1', 'CCE-4273-9',
                         'CCE-3412-4', 'CCE-4229-1', 'CCE-4123-6', 'CCE-4286-1',
                         'CCE-3425-6', 'CCE-4211-9', 'CCE-3854-7', 'CCE-4356-2',
                         'CCE-4369-5', 'CCE-4100-4', 'CCE-3455-3', 'CCE-4421-4',
                         'CCE-4302-6', 'CCE-3822-4', 'CCE-4364-6', 'CCE-4355-4',
                         'CCE-4377-8', 'CCE-4289-5', 'CCE-4298-6', 'CCE-4051-9',
                         'CCE-4324-0', 'CCE-4406-5', 'CCE-4268-9', 'CCE-4303-4',
                         'CCE-4365-3', 'CCE-3755-6', 'CCE-4425-5', 'CCE-4191-3',
                         'CCE-4336-4', 'CCE-4376-0', 'CCE-4416-4', 'CCE-3501-4',
                         'CCE-4396-8', 'CCE-3535-2', 'CCE-3568-3', 'CCE-4533-6',
                         'CCE-4550-0', 'CCE-4473-5', 'CCE-4491-7', 'CCE-3578-2',
                         'CCE-3919-8', 'CCE-4338-0', 'CCE-3847-1', 'CCE-4551-8',
                         'CCE-4556-7', 'CCE-3765-5', 'CCE-4508-8', 'CCE-4327-3',
                         'CCE-4468-5', 'CCE-4512-0', 'CCE-4375-2', 'CCE-4393-5',
                         'CCE-3662-4', 'CCE-4442-0', 'CCE-4596-3', 'CCE-4486-7',
                         'CCE-4362-0', 'CCE-3622-8', 'CCE-4299-4', 'CCE-4592-2',
                         'CCE-4614-4', 'CCE-4279-6', 'CCE-4557-5', 'CCE-4588-0',
                         'CCE-4354-7', 'CCE-4240-8', 'CCE-4517-9', 'CCE-4284-6',
                         'CCE-4429-7', 'CCE-4306-7', 'CCE-4499-0', 'CCE-4266-3',
                         'CCE-4411-5', 'CCE-4305-9', 'CCE-4477-6', 'CCE-3650-9',
                         'CCE-4571-6', 'CCE-3950-3', 'CCE-4470-1', 'CCE-4598-9',
                         'CCE-4620-1', 'CCE-4333-1', 'CCE-3857-0', 'CCE-4359-6',
                         'CCE-4615-1', 'CCE-4007-1', 'CCE-3901-6', 'CCE-4553-4',
                         'CCE-4584-9', 'CCE-4611-0', 'CCE-3655-8', 'CCE-4541-9',
                         'CCE-4483-4', 'CCE-3663-2', 'CCE-4037-8']
        self.bsddefault = ['background_fsck', 'cleanvar', 'cron', 'devd',
                           'dmesg', 'gptboot', 'hostid', 'ip6addrctl',
                           'mixer', 'newsyslog', 'ntpd', 'sendmail_submit',
                           'sendmail_submit', 'sendmail_msp_queue', 'sshd',
                           'syslogd', 'virecover']
        self.linuxdefault = ['acpi-support', 'acpid',
                             'alsa-restore', 'alsa-store', 'alsasound',
                             'anacron',
                             'apmd',
                             'atd',
                             'audit', 'auditd',
                             'autofs',
                             'blk-availability',
                             'bootlogd',
                             'cpuspeed',
                             'cron', 'crond',
                             'cups',
                             'dbus',
                             'earlysyslog',
                             'exim4',
                             'fbset',
                             'firstboot',
                             'gdm3',
                             'grub-common',
                             'haldaemon',
                             'haveged',
                             'iptables', 'ip6tables',
                             'irqbalance',
                             'kbd',
                             'libnss-ldap',
                             'lm_sensors',
                             'lvm2-monitor',
                             'mcstrans',
                             'mdmonitor',
                             'messagebus',
                             'minissdpd',
                             'motd',
                             'netfs',
                             'network', 'network-manager',
                             'NetworkManager',
                             'network-remotefs',
                             'nfs-common', 'nfslock',
                             'nscd', 'nslcd',
                             'ntpd',
                             'oddjobd',
                             'osad',
                             'ondemand',
                             'portmap',
                             'postfix',
                             'psacct',
                             'pulseaudio',
                             'purge-kernels',
                             'random',
                             'rasagent',
                             'rc.local',
                             'rdma',
                             'restorecond',
                             'rhnsd',
                             'rmnologin',
                             'rpcgssd', 'rpcidmapd', 'rpcbind',
                             'rsyslog',
                             'rsyslogd',
                             'sendmail',
                             'setroubleshoot',
                             'smartd',
                             'splash', 'splash-early',
                             'sshd',
                             'sssd',
                             'syslog',
                             'sysstat',
                             'udev-post',
                             'xfs']
        self.specials = ['apparmor', 'urandom', 'x11-common', 'sendsigs',
                         'unmountnfs.sh', 'networking', 'umountfs',
                         'umountroot', 'reboot', 'halt', 'killprocs',
                         'single', 'unattended-upgrades', 'devfs', 'dmesg',
                         'bootmisc', 'fsck', 'hostname', 'hwclock',
                         'keymaps', 'localmount', 'modules', 'mount-ro',
                         'mtab', 'net.lo', 'procfs', 'root', 'savecache',
                         'swap', 'sysctl', 'termencoding', 'udev']
        self.soldefault = ['lrc:/etc/rc2_d/S10lu', 'lrc:/etc/rc2_d/S20sysetup',
                           'lrc:/etc/rc2_d/S40llc2',
                           'lrc:/etc/rc2_d/S42ncakmod',
                           'lrc:/etc/rc2_d/S47pppd', 'lrc:/etc/rc2_d/S70uucp',
                           'lrc:/etc/rc2_d/S72autoinstall',
                           'lrc:/etc/rc2_d/S73cachefs_daemon',
                           'lrc:/etc/rc2_d/S81dodatadm_udaplt',
                           'lrc:/etc/rc2_d/S89PRESERVE',
                           'lrc:/etc/rc2_d/S89bdconfig',
                           'lrc:/etc/rc2_d/S91ifbinit',
                           'lrc:/etc/rc2_d/S91jfbinit',
                           'lrc:/etc/rc2_d/S94ncalogd',
                           'lrc:/etc/rc2_d/S98deallocate',
                           'lrc:/etc/rc3_d/S16boot_server',
                           'lrc:/etc/rc3_d/S50apache', 'lrc:/etc/rc3_d/S52imq',
                           'lrc:/etc/rc3_d/S80mipagent',
                           'lrc:/etc/rc3_d/S84appserv',
                           'svc:/system/svc/restarter:default',
                           'svc:/system/installupdates:default',
                           'svc:/network/pfil:default',
                           'svc:/network/tnctl:default',
                           'svc:/network/loopback:default',
                           'svc:/system/filesystem/root:default',
                           'svc:/system/scheduler:default',
                           'svc:/network/physical:default',
                           'svc:/system/identity:node',
                           'svc:/system/boot-archive:default',
                           'svc:/system/filesystem/usr:default',
                           'svc:/system/keymap:default',
                           'svc:/system/device/local:default',
                           'svc:/system/filesystem/minimal:default',
                           'svc:/system/resource-mgmt:default',
                           'svc:/system/name-service-cache:default',
                           'svc:/system/rmtmpfiles:default',
                           'svc:/system/identity:domain',
                           'svc:/system/coreadm:default',
                           'svc:/system/cryptosvc:default',
                           'svc:/system/sysevent:default',
                           'svc:/system/device/fc-fabric:default',
                           'svc:/milestone/devices:default',
                           'svc:/system/sar:default',
                           'svc:/system/picl:default',
                           'svc:/network/ipsec/ipsecalgs:default',
                           'svc:/network/ipsec/policy:default',
                           'svc:/milestone/network:default',
                           'svc:/network/initial:default',
                           'svc:/network/service:default',
                           'svc:/network/dns/client:default',
                           'svc:/milestone/name-services:default',
                           'svc:/system/pkgserv:default',
                           'svc:/network/iscsi/initiator:default',
                           'svc:/system/manifest-import:default',
                           'svc:/system/patchchk:default',
                           'svc:/milestone/single-user:default',
                           'svc:/system/filesystem/local:default',
                           'svc:/network/shares/group:default',
                           'svc:/system/cron:default',
                           'svc:/system/sysidtool:net',
                           'svc:/system/boot-archive-update:default',
                           'svc:/network/routing-setup:default',
                           'svc:/network/rpc/bind:default',
                           'svc:/system/sysidtool:system',
                           'svc:/milestone/sysconfig:default',
                           'svc:/system/sac:default',
                           'svc:/system/filesystem/autofs:default',
                           'svc:/network/inetd:default',
                           'svc:/application/font/fc-cache:default',
                           'svc:/system/utmp:default',
                           'svc:/system/console-login:default',
                           'svc:/system/dumpadm:default',
                           'svc:/system/system-log:default',
                           'svc:/network/ssh:default',
                           'svc:/network/sendmail-client:default',
                           'svc:/network/smtp:sendmail',
                           'svc:/application/management/wbem:default',
                           'svc:/system/postrun:default',
                           'svc:/network/rpc/gss:default',
                           'svc:/application/font/stfsloader:default',
                           'svc:/network/rpc/cde-calendar-manager:default',
                           'svc:/network/rpc/cde-ttdbserver:tcp',
                           'svc:/network/rpc/smserver:default',
                           'svc:/network/security/ktkt_warn:default',
                           'svc:/network/rpc-100235_1/rpc_ticotsord:default',
                           'svc:/system/filesystem/volfs:default',
                           'svc:/milestone/multi-user:default',
                           'svc:/system/boot-config:default',
                           'svc:/system/fmd:default',
                           'svc:/milestone/multi-user-server:default',
                           'svc:/system/zones:default',
                           'svc:/system/fpsd:default',
                           'svc:/system/basicreg:default',
                           'svc:/application/stosreg:default',
                           'svc:/application/graphical-login/cde-login:default',
                           'svc:/application/cde-printinfo:default',
                           'svc:/application/autoreg:default',
                           'svc:/system/webconsole:console',
                           'svc:/network/cswpuppetd:default']
        self.systemddefault = ['accounts-daemon.service',
                               'after-local.service',
                               'alsa-restore.service', 'alsasound',
                               'alsa-store.service',
                               'alsa-state.service',
                               'alsa-state.service',
                               'anacron.service',
                               'autovt@.service',
                               'arp-ethers.service', 'atd.service',
                               'auditd.service',
                               'auth-rpcgss-module.service',
                               'brandbot.service',
                               'chronyd.service', 'chronyd',
                               'chrony.service', 'chrony',
                               'colord.service',
                               'cron', 'cron.service',
                               'crond.service', 'cups', 'cups.service',
                               'debian-fixup.service',
                               'dbus.service', 'dbus',
                               'dbus-daemon.service',
                               'dbus-broker.service',
                               'display-manager.service',
                               'dm-event.service',
                               'dmraid-activation.service',
                               'dnf-makecache.service',
                               'dracut-shutdown.service',
                               'emergency.service', 'encase.service',
                               'fedora-autorelabel-mark.service',
                               'fedora-autorelabel.service',
                               'fedora-configure.service',
                               'fedora-import-state.service',
                               'fedora-loadmodules.service',
                               'fedora-readonly.service',
                               'fedora-storage-init-late.service',
                               'fedora-storage-init.service',
                               'fedora-wait-storage.service',
                               'firewalld.service',
                               'gdm.service',
                               'gdm3.service',
                               'gdm3',
                               'getty@tty1.service',
                               'getty@tty2.service',
                               'getty@tty3.service',
                               'getty@tty5.service',
                               'getty@.service',
                               'getty-static.service',
                               'halt.service', 'localfs.service',
                               'ip6tables.service', 'iptables.service',
                               'irqbalance.service',
                               'iprdump.service', 'iprinit.service',
                               'iprupdate.service',
                               'iscsi-shutdown.service',
                               'kmod',
                               'kmod-static-nodes.service',
                               'ksm.service', 'ksmtuned.service',
                               'ldconfig.service',
                               'lightdm.service',
                               'lightdm',
                               'lvm2-activation.service',
                               'lvm2-activation-early.service',
                               'lvm2-monitor.service',
                               'mcelog',
                               'mcelog.service', 'mdmonitor-takeover.service',
                               'mdmonitor.service',
                               'named-setup-rndc.service',
                               'netconsole.service', 'network.service',
                               'networking.service',
                               'networking', 'network-manager',
                               'network-manager.service',
                               'NetworkManager.service',
                               'NetworkManager',
                               'org.freedesktop.NetworkManager',
                               'org.freedesktop.NetworkManager.service',
                               'dbus-org.freedesktop.NetworkManager',
                               'dbus-org.freedesktop.NetworkManager.service',
                               'NetworkManager-dispatcher',
                               'NetworkManager-dispatcher.service',
                               'NetworkManager-wait-online',
                               'NetworkManager-wait-online.service',
                               'network', 'netcf-transaction.service',
                               'nfs-blkmap.service', 'nfs-config.service',
                               'nfs-idmapd.service', 'nfs-mountd.service',
                               'nfs-utils.service', 'nessusagent.service',
                               'nfs-lock.service', 'nslcd.service',
                               'ntpd.service', 'ntpdate.service',
                               'ntp.service', 'ntp', 'ntpd',
                               'ondemand.service', 'osad.service',
                               'pcscd', 'pcscd.service', 'postfix',
                               'polkit.service', 'purge-kernels.service',
                               'plymouth-quit-wait.service',
                               'plymouth-quit.service',
                               'plymouth-read-write.service',
                               'plymouth-start.service',
                               'polkit.service', 'postfix.service',
                               'postfix@-.service',
                               'poweroff.service', 'prefdm.service',
                               'procps.service',
                               'procps', 'psacct.service',
                               'psacct', 'rc-local.service',
                               'rc.local',
                               'reboot.service',
                               'remount-rootfs.service', 'rescue.service',
                               'resolvconf.service', 'resolvconf',
                               'rhel-autorelabel',
                               'rhel-configure.service',
                               'rhel-import-state.service',
                               'rhel-loadmodules.service',
                               'rhel-readonly.service', 'rhnsd.service',
                               'rhel-autorelabel-mark.service',
                               'rhel-autorelabel.service',
                               'rhsmcertd.service',
                               'rsyslog.service', 'rsyslog', 'rsyslogd',
                               'rtkit-daemon.service', 'rhnsd',
                               'rngd.service', 'rpcbind.service',
                               'rpc-gssd.service', 'rpc-statd-notify.service',
                               'rpc-statd.service', 'rpc-svcgssd.service',
                               'sddm.service', 'sddm',
                               'sendmail.service', 'sm-client.service',
                               'spice-vdagentd.service',
                               'ssh', 'ssh.service',
                               'sshd', 'sshd.service',
                               'sshd-keygen.service',
                               'stonix-mute-mic.service',
                               'stonix-mute-mic',
                               'SuSEfirewall2.service',
                               'SuSEfirewall2_init.service',
                               'syslog.service',
                               'systemd-firstboot.service',
                               'systemd-fsck-root.service',
                               'systemd-hostnamed.service',
                               'systemd-hwdb-update.service',
                               'systemd-journal-catalog-update.service',
                               'systemd-machine-id-commit.service',
                               'systemd-setup-dgram-qlen.service',
                               'systemd-sysusers.service',
                               'systemd-update-done.service',
                               'systemd-journal-flush.service',
                               'systemd-random-seed.service',
                               'systemd-tmpfiles-setup-dev.service',
                               'systemd-udev-root-symlink.service',
                               'systemd-udev-settle.service',
                               'systemd-udev-trigger.service',
                               'systemd-udev.service', 'systemd-udevd.service',
                               'systemd-update-utmp.service',
                               'sssd.service', 'system-setup-keyboard.service',
                               'smartd.service', 'sysstat.service',
                               'systemd-fsck-root.service',
                               'systemd-journal-flush.service',
                               'systemd-random-seed.service',
                               'systemd-reboot.service',
                               'systemd-tmpfiles-setup-dev.service',
                               'systemd-udev-settle.service',
                               'systemd-udev-trigger.service',
                               'systemd-udevd.service',
                               'systemd-update-utmp.service',
                               'systemd-ask-password-console.service',
                               'systemd-ask-password-plymouth.service',
                               'systemd-ask-password-wall.service',
                               'systemd-binfmt.service',
                               'systemd-initctl.service',
                               'systemd-journald.service',
                               'systemd-logind.service',
                               'systemd-modules-load.service',
                               'systemd-networkd-wait-online.service',
                               'systemd-networkd.service',
                               'systemd-random-seed-load.service',
                               'systemd-random-seed-save.service',
                               'systemd-readahead-collect.service',
                               'systemd-readahead-done.service',
                               'systemd-readahead-replay.service',
                               'systemd-remount-api-vfs.service',
                               'systemd-remount-fs.service',
                               'systemd-shutdownd.service',
                               'systemd-sysctl.service',
                               'systemd-tmpfiles-clean.service',
                               'systemd-tmpfiles-setup.service',
                               'systemd-update-utmp-runlevel.service',
                               'systemd-update-utmp-shutdown.service',
                               'systemd-user-sessions.service',
                               'systemd-vconsole-setup.service',
                               'systemd-resolved.service',
                               'systemd-resolved',
                               'dbus-org.freedesktop.resolve1.service',
                               'tcsd.service', 'tuned.service',
                               'udev',
                               'udev.service',
                               'udev-settle.service',
                               'udev-trigger.service', 'udev.service',
                               'udev-finish.service',
                               'udev-finish',
                               'udisks2.service',
                               'ufw.service',
                               'upower.service',
                               'unbound-anchor.service',
                               'urandom.service',
                               'urandom',
                               'virtlockd.service',
                               'wicked.service',
                               'xdm', 'xdm.service',
                               'YaST2-Second-Stage.service',
                               'ypbind.service',
                               'sysstat-collect.service',
                               'sysstat-summary.service']

        datatype = 'bool'
        key = 'MINIMIZESVCS'
        instructions = "To prevent STONIX from disabling all non-white-listed services, set the value of MINIMIZESVCS to False."
        default = True
        self.minimizeci = self.initCi(datatype, key, instructions, default)

        datatype2 = 'list'
        key2 = 'SERVICEENABLE'
        instructions2 = """This list contains services that are permitted to \
run on this platform. If you need to run a service not currently in this \
list, add the service to the list and STONIX will not disable it. List \
elements should be space separated."""

        self.serviceTarget = ""

        self.logger.log(LogPriority.DEBUG, "Starting platform detection")

        self.environ.setsystemtype()
        systemtype = self.environ.getsystemtype()
        self.ch = CommandHelper(self.logger)

        if systemtype == "systemd":
            self.logger.log(LogPriority.DEBUG, ['MinimizeServices.__init__', "systemctl found. Using systemd white list"])
            self.svcslistci = self.initCi(datatype2, key2, instructions2, self.systemddefault)

        elif self.environ.getosfamily() == 'linux':
            self.logger.log(LogPriority.DEBUG, ['MinimizeServices.__init__', "Linux OS found. Using Linux default white list"])
            self.svcslistci = self.initCi(datatype2, key2, instructions2, self.linuxdefault)

        elif self.environ.getosfamily() == 'solaris':
            self.logger.log(LogPriority.DEBUG, ['MinimizeServices.__init__', "Solaris OS found. Using Solaris list"])
            self.svcslistci = self.initCi(datatype2, key2, instructions2, self.soldefault)

        elif self.environ.getosfamily() == 'freebsd':
            self.logger.log(LogPriority.DEBUG, ['MinimizeServices.__init__', "FreeBSD OS found. Using BSD white list"])
            self.svcslistci = self.initCi(datatype2, key2, instructions2, self.bsddefault)

        else:
            self.logger.log(LogPriority.DEBUG, ['MinimizeServices.__init__', "Detection fell through. Return from ENV:" + self.environ.getosfamily()])
            self.svcslistci = self.initCi(datatype2, key2, instructions2, self.linuxdefault)

        #what's in stonix.conf
        x = self.svcslistci.getcurrvalue()

        #self.systemddefault - x
        y = [li for li in self.systemddefault if li not in x]

        if systemtype == "systemd":
            #the set of what's in stonix.conf added to what's in self.systemddefault that isn't in stonix.conf
            self.svcslistci.updatecurrvalue(x + y)

    def whiteListAliases(self):
        """
        add all alias names of white listed services to white list

        :return: void
        """

        dirs = ["/usr/share/dbus-1/services/*", "/usr/share/dbus-1/system-services/*", "/etc/systemd/system/*", "/usr/lib/systemd/system/*"]
        grep_alias_cmd = "/bin/grep -rih Alias= "
        aliaslines = []
        services = self.svcslistci.getcurrvalue()

        for d in dirs:
            self.ch.executeCommand(grep_alias_cmd + d)
            output = self.ch.getOutput()
            retcode = self.ch.getReturnCode()
            if retcode == 0:
                aliaslines += output

            for al in aliaslines:
                try:
                    aliases = al.split("=")
                    aliases = aliases[1].split()
                    for i in range(len(aliases)):
                        if ".target" in aliases[i]:
                            continue
                        else:
                            services.append(aliases[i])
                except IndexError:
                    continue

        services = list(set(services))

        self.svcslistci.updatecurrvalue(services)

    def report(self):
        '''Report on whether any services not in the baseline or configured set
        are running.

        :return: self.compliant
        :rtype: bool
        '''

        self.compliant = True
        self.detailedresults = ""
        unauthorizedservices = []
        authorizedservices = []
        if self.environ.getsystemtype() == "systemd":
            self.whiteListAliases()

        try:

            servicelist = self.servicehelper.listServices()
            allowedlist = self.svcslistci.getcurrvalue()
            corelist = self.svcslistci.getdefvalue()

            self.logger.log(LogPriority.DEBUG, "AllowedList: " + str(allowedlist))

            for service in servicelist:
                if service in allowedlist or re.search('user@[0-9]*.service', service):
                    if service in allowedlist:
                        authorizedservices.append(str(service))
                        # user@foo.service are user managers started by PAM
                        # on Linux. They are GRAS (generally regarded as safe)
                    if service not in corelist and \
                    not re.search('user@[0-9]*.service', service):
                        self.logger.log(LogPriority.DEBUG, 'Non-core service running: ' + service)
                else:
                    if self.servicehelper.auditService(service, serviceTarget = self.serviceTarget):
                        self.compliant = False
                        unauthorizedservices.append(str(service))

            self.logger.log(LogPriority.DEBUG, "The following white-listed services were found and will NOT be disabled:\n+ " + "\n+ ".join(authorizedservices) + "\n")

            if self.compliant:
                self.detailedresults += 'No unauthorized services were detected'
                self.targetstate = 'configured'
            else:
                self.detailedresults += "Unauthorized running services detected:\n- " + "\n- ".join(unauthorizedservices) + "\n"
            self.targetstate = 'notconfigured'

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.compliant = False
            self.detailedresults += traceback.format_exc()
            self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("report", self.compliant, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.compliant

    def fix(self):
        '''Disable all services not in the 'enable services' list.

        :return: self.rulesuccess
        :rtype: bool
        '''

        self.detailedresults = ""
        self.rulesuccess = True
        changes = []

        if self.minimizeci.getcurrvalue():
            try:
                servicelist = self.servicehelper.listServices()
                allowedlist = self.svcslistci.getcurrvalue()

                # make sure you're not dealing with any return garbage
                # in the comparisons below
                allowedlist = [i.rstrip() for i in allowedlist]
                servicelist = [i.rstrip() for i in servicelist]

                for service in servicelist:
                    if service in allowedlist:
                        continue
                    elif re.search('user@[0-9]*.service', service):
                        # these are systemd usermanagers started by PAM
                        # they are OK.
                        continue
                    else:
                        running = self.servicehelper.auditService(service, serviceTarget=self.serviceTarget)
                        if running and service not in self.specials:
                            changes.append(service)
                            self.servicehelper.disableService(service, serviceTarget=self.serviceTarget)

                mytype = 'command'
                mystart = []
                myend = changes
                myid = '0013001'
                event = {'eventtype': mytype,
                         'startstate': mystart,
                         'endstate': myend}
                self.statechglogger.recordchgevent(myid, event)

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                self.rulesuccess = False
                self.detailedresults += traceback.format_exc()
                self.logger.log(LogPriority.ERROR, self.detailedresults)
        self.formatDetailedResults("fix", self.rulesuccess, self.detailedresults)
        self.logger.log(LogPriority.INFO, self.detailedresults)
        return self.rulesuccess

    def undo(self):
        '''Attempt to reset the service state for all the services that we changed
        back to their original states.
        
        @author: Dave Kennel


        '''
        self.targetstate = 'notconfigured'
        try:
            event1 = self.statechglogger.getchgevent('0013001')
            for service in event1['endstate']:
                self.servicehelper.enableService(service, serviceTarget=self.serviceTarget)
        except(IndexError, KeyError):
            self.logger.log(LogPriority.DEBUG,
                            ['MinimizeServices.undo',
                             "EventID 0013001 not found"])
        except (KeyboardInterrupt, SystemExit):
            # User initiated exit
            raise
        except Exception:
            self.detailedresults = 'MinimizeServices: '
            self.detailedresults = self.detailedresults + \
                traceback.format_exc()
            self.rulesuccess = False
            self.logger.log(LogPriority.ERROR,
                            ['MinimizeServices.fix',
                             self.detailedresults])
            return False
        self.report()
        if self.currstate == self.targetstate:
            self.detailedresults = 'MinimizeServices: Changes ' + \
                'successfully reverted'
        return True
