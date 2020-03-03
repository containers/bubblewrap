#!/usr/bin/env python

import os, subprocess, sys, time

live_mount = os.pipe()
userid = os.getuid()
groupid = os.getgid()
p = subprocess.Popen(['getent', 'passwd', '%i' % userid, '65534'], stdout=subprocess.PIPE)
passwd, _ = p.communicate()
p = subprocess.Popen(['getent', 'group', '%i' % groupid, '65534'], stdout=subprocess.PIPE)
group, _ = p.communicate()
bwrap = "./bwrap"

pid = os.fork()

if pid != 0:
    os.close(live_mount[0])

    time.sleep(3)

    # Tell bwrap to bind mount /home from the host to /home in the container
    # after we waited 3 seconds. You should observe no home directory in the
    # first 3 seconds.
    os.write(live_mount[1], b'/home\0/home\0')
    os.waitpid(pid, 0)
else:
    os.close(live_mount[1])

    if sys.version_info >= (3, 4):
        os.set_inheritable(live_mount[0], True)

    args = [bwrap,
            bwrap,
            "--ro-bind", "/usr", "/usr",
            "--dir", "/tmp",
            "--dir", "/var",
            "--symlink", "../tmp", "var/tmp",
            "--proc", "/proc",
            "--dev", "/dev",
            "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/sbin", "/sbin",
            "--chdir", "/",
            "--unshare-all",
            "--share-net",
            "--dir", "/run/user/%i" % userid,
            "--setenv", "XDG_RUNTIME_DIR", "/run/user/%i" %userid,
            "--setenv", "PS1", "bwrap-demo$ ",
            #"--file", "%i" % passwdfd, "/etc/passwd",
            #"--file", "%i" % groupfd, "/etc/group",
            "--live-mount-fd", "%i" % live_mount[0],
            "/bin/sh"]

    os.execlp(*args)

