#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The parts of --forward-signals that need a terminal, as the kernel sends
# SIGINT and SIGWINCH to the foreground process group of one.

import fcntl
import importlib.util
import os
import pty
import signal
import struct
import sys
import tempfile
import termios
import time
import unittest

_spec = importlib.util.spec_from_file_location(
    'test_helper',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test-helper.py'),
)
_helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helper)

BWRAP = _helper.BWRAP
can_run_bwrap = _helper.can_run_bwrap
run_tap_tests = _helper.run_tap_tests

# Reports the signals it receives and keeps running
COMMAND = r'''
trap 'echo got-int >> "$1"' INT
trap 'echo got-winch >> "$1"' WINCH
echo ready >> "$1"
while :; do sleep 0.2; done
'''


@unittest.skipUnless(can_run_bwrap(), 'bwrap not available or not functional')
class TestForwardSignalsTty(unittest.TestCase):
    def sandbox(self, *extra_args):
        """bwrap in a pseudo-terminal, as its own session and foreground group"""
        d = tempfile.TemporaryDirectory(prefix='bwrap-tty-test.')
        self.addCleanup(d.cleanup)
        self.log = os.path.join(d.name, 'log')
        script = os.path.join(d.name, 'command.sh')
        with open(script, 'w') as f:
            f.write(COMMAND)
        self.pid, self.terminal = pty.fork()
        if self.pid == 0:
            try:
                os.execv(BWRAP, [
                    BWRAP, '--forward-signals', '--unshare-user',
                    '--uid', '0', '--gid', '0', '--bind', '/', '/',
                    '--proc', '/proc', '--dev', '/dev', *extra_args,
                    '--', '/bin/sh', script, self.log,
                ])
            finally:
                os._exit(127)
        self.addCleanup(self.kill)
        self.assertTrue(self.wait_for('ready'), 'command did not start')

    def kill(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        os.close(self.terminal)

    def wait_for(self, text, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with open(self.log) as f:
                    if text in f.read():
                        return True
            except FileNotFoundError:
                pass
            time.sleep(0.02)
        return False

    def check_ctrl_c(self, *extra_args):
        self.sandbox(*extra_args)
        os.write(self.terminal, b'\x03')
        self.assertTrue(self.wait_for('got-int', 3), 'SIGINT did not arrive')
        # the command handles it, so bwrap must not have died in its place
        self.assertEqual(os.waitpid(self.pid, os.WNOHANG), (0, 0))

    def test_ctrl_c(self):
        self.check_ctrl_c('--unshare-pid')

    def test_ctrl_c_as_pid_1(self):
        self.check_ctrl_c('--unshare-pid', '--as-pid-1')

    def resize(self):
        fcntl.ioctl(self.terminal, termios.TIOCSWINSZ,
                    struct.pack('HHHH', 40, 100, 0, 0))

    def test_resize(self):
        """With --new-session the command is in a session of its own, so a
        resize only reaches it if bwrap forwards SIGWINCH."""
        self.sandbox('--unshare-pid', '--new-session')
        self.resize()
        self.assertTrue(self.wait_for('got-winch', 3), 'SIGWINCH did not arrive')


if __name__ == '__main__':
    run_tap_tests(sys.modules[__name__])
