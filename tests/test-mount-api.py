#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.0-or-later
"""Exercise mount API selection and failure handling before sandbox exec."""

import ctypes
import ctypes.util
import errno
import importlib.util
import os
import subprocess
import sys
import unittest

try:
    import seccomp
except ImportError:
    print('1..0 # SKIP cannot import seccomp Python module')
    sys.exit(0)

_spec = importlib.util.spec_from_file_location(
    'test_helper', os.path.join(os.path.dirname(__file__), 'test-helper.py'))
_helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helper)


def mount_apis_available():
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    for name in ('open_tree', 'mount_setattr', 'move_mount'):
        number = seccomp.resolve_syscall(seccomp.Arch.NATIVE, name)
        # Invalid arguments cannot create or attach a mount. Other errors,
        # including EPERM before entering a user namespace, show presence.
        ctypes.set_errno(0)
        result = libc.syscall(number, -1, ctypes.c_void_p(), -1,
                              ctypes.c_void_p(), 0, 0)
        if result < 0 and ctypes.get_errno() == errno.ENOSYS:
            return False
    return True


@unittest.skipUnless(_helper.can_run_bwrap(), 'bwrap not functional')
@unittest.skipUnless(mount_apis_available(), 'kernel lacks descriptor mount APIs')
class TestMountApi(unittest.TestCase):
    def run_filtered(self, syscall, error, *extra,
                     mounts=('--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp'),
                     match=()):
        def load_filter():
            policy = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
            policy.add_rule(seccomp.ERRNO(error), syscall, *match)
            policy.load()

        # A root overmount keeps this fixture on the original root lifecycle.
        return subprocess.run(
            [_helper.BWRAP, '--unshare-user', '--unshare-pid',
             '--ro-bind', '/', '/', *mounts, *extra, '--', sys.executable, '-c', 'pass'],
            preexec_fn=load_filter, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=20)

    def test_absent_bind_syscalls(self):
        for syscall in ('open_tree', 'mount_setattr', 'move_mount'):
            with self.subTest(syscall=syscall):
                result = self.run_filtered(syscall, errno.ENOSYS)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_denied_bind_syscalls(self):
        for syscall in ('open_tree', 'mount_setattr', 'move_mount'):
            with self.subTest(syscall=syscall):
                result = self.run_filtered(syscall, errno.EPERM)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'Operation not permitted', result.stderr)

    def test_unsupported_clone(self):
        result = self.run_filtered('open_tree', errno.EINVAL)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_attach_is_fatal(self):
        result = self.run_filtered('move_mount', errno.EINVAL)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Invalid argument', result.stderr)

    def test_forced_fallback(self):
        for syscall in ('open_tree', 'move_mount'):
            with self.subTest(syscall=syscall):
                result = self.run_filtered(syscall, errno.EPERM,
                    '--debug-opt=force-mount-setattr-fallback')
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.environ.get('BWRAP_TEST_FILESYSTEM_MOUNTS') == '1',
                         'filesystem mount APIs not compiled in')
    def test_absent_filesystem_syscalls(self):
        for syscall in ('fsopen', 'fsconfig', 'fsmount'):
            with self.subTest(syscall=syscall):
                result = self.run_filtered(syscall, errno.ENOSYS)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.environ.get('BWRAP_TEST_FILESYSTEM_MOUNTS') == '1',
                         'filesystem mount APIs not compiled in')
    def test_denied_filesystem_syscalls(self):
        for syscall in ('fsopen', 'fsconfig', 'fsmount'):
            with self.subTest(syscall=syscall):
                result = self.run_filtered(syscall, errno.EPERM)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(syscall.encode(), result.stderr)
                self.assertIn(b'tmpfs', result.stderr)
                self.assertIn(b'Operation not permitted', result.stderr)

    @unittest.skipUnless(os.environ.get('BWRAP_TEST_FILESYSTEM_MOUNTS') == '1',
                         'filesystem mount APIs not compiled in')
    def test_proc_syscalls(self):
        for syscall in ('fsopen', 'fsconfig', 'fsmount'):
            for error in (errno.ENOSYS, errno.EPERM):
                with self.subTest(syscall=syscall, error=error):
                    result = self.run_filtered(syscall, error, mounts=('--proc', '/proc'))
                    if error == errno.ENOSYS:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(b'proc', result.stderr)
                        self.assertIn(syscall.encode(), result.stderr)

    @unittest.skipUnless(os.environ.get('BWRAP_TEST_FILESYSTEM_MOUNTS') == '1',
                         'filesystem mount APIs not compiled in')
    def test_devpts_syscalls(self):
        # Only devpts uses FSCONFIG_SET_FLAG (newinstance), so the tmpfs
        # creation for /dev succeeds before this injected failure.
        for error in (errno.ENOSYS, errno.EPERM):
            with self.subTest(error=error):
                result = self.run_filtered('fsconfig', error,
                    match=(seccomp.Arg(1, seccomp.EQ, 0),))
                if error == errno.ENOSYS:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b'fsconfig newinstance for devpts on /dev/pts', result.stderr)


if __name__ == '__main__':
    _helper.run_tap_tests(sys.modules[__name__])
