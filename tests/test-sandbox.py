#!/usr/bin/env python3
# Copyright 2024 Alexander Larsson
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Integration tests for bwrap sandbox setup. Methods decorated with
# @in_sandbox(...) define assertions that run inside the sandbox;
# the @sandbox_test_class decorator auto-generates the host-side
# test_* methods that launch bwrap and run them.

import ctypes
import ctypes.util
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest

_spec = importlib.util.spec_from_file_location(
    'test_helper',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test-helper.py'),
)
_helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helper)

BWRAP = _helper.BWRAP
can_run_bwrap = _helper.can_run_bwrap
in_sandbox = _helper.in_sandbox
list_mounts = _helper.list_mounts
DataFd = _helper.DataFd
OpenFd = _helper.OpenFd
run_bwrap = _helper.run_bwrap
run_tap_tests = _helper.run_tap_tests
sandbox_test_class = _helper.sandbox_test_class


class SourceTree:
    """Creates a temporary tree with various file types for testing."""

    def __init__(self, tmp_dir):
        self.root = os.path.join(tmp_dir, 'src')
        os.makedirs(self.root)

        self.file = os.path.join(self.root, 'regular_file')
        with open(self.file, 'w') as f:
            f.write('hello')

        self.other_file = os.path.join(self.root, 'other_file')
        with open(self.other_file, 'w') as f:
            f.write('other')

        self.dir = os.path.join(self.root, 'subdir')
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, 'child'), 'w') as f:
            f.write('child content')

        self.dir2 = os.path.join(self.root, 'subdir2')
        os.makedirs(self.dir2)
        with open(os.path.join(self.dir2, 'child2'), 'w') as f:
            f.write('child2 content')

        self.symlink_to_file = os.path.join(self.root, 'link_to_file')
        os.symlink(self.file, self.symlink_to_file)

        self.symlink_to_dir = os.path.join(self.root, 'link_to_dir')
        os.symlink(self.dir, self.symlink_to_dir)

        self.symlink_relative = os.path.join(self.root, 'link_relative')
        os.symlink('regular_file', self.symlink_relative)


@sandbox_test_class
@unittest.skipUnless(can_run_bwrap(), 'bwrap not available or not functional')
class TestSandbox(unittest.TestCase):
    """Integration tests for bwrap sandbox setup options."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.src = SourceTree(self.tmp)

    def tearDown(self):
        self._tmp.cleanup()

    def assertIsRegFile(self, path):
        self.assertTrue(stat.S_ISREG(os.lstat(path).st_mode),
                        f'{path} is not a regular file')

    def assertIsChrDev(self, path):
        self.assertTrue(stat.S_ISCHR(os.lstat(path).st_mode),
                        f'{path} is not a character device')

    def assertIsDir(self, path):
        self.assertTrue(stat.S_ISDIR(os.lstat(path).st_mode),
                        f'{path} is not a directory')

    def assertIsSymlink(self, path):
        self.assertTrue(stat.S_ISLNK(os.lstat(path).st_mode),
                        f'{path} is not a symlink')

    def assertSymlinkContent(self, path, expected):
        self.assertIsSymlink(path)
        self.assertEqual(os.readlink(path), expected,
                         f'{path} points to {os.readlink(path)!r}, expected {expected!r}')

    def assertInStderr(self, needle, result):
        self.assertIn(needle, result.stderr,
                      f'expected {needle!r} in stderr, got: {result.stderr!r}')

    def assertFileContent(self, path, expected):
        with open(path) as f:
            self.assertEqual(f.read(), expected)

    _libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    TMPFS_MAGIC = 0x01021994

    def _statfs_type(self, path):
        class statfs_t(ctypes.Structure):
            _fields_ = [('f_type', ctypes.c_long), ('f_bsize', ctypes.c_long)]
        buf = statfs_t()
        rc = self._libc.statfs(path.encode(), ctypes.byref(buf))
        self.assertEqual(rc, 0, f'statfs({path}) failed')
        return buf.f_type

    def assertIsTmpfs(self, path):
        fs_type = self._statfs_type(path)
        self.assertEqual(fs_type, self.TMPFS_MAGIC,
                         f'{path} is not tmpfs (f_type=0x{fs_type:x})')

    def assertIsMountpoint(self, path):
        self.assertIn(path, list_mounts(),
                      f'{path} is not a mountpoint')

    def assertBwrapFailed(self, result):
        self.assertNotEqual(result.returncode, 0,
                            f'expected bwrap to fail, stderr: {result.stderr!r}')

    def assertMountFlags(self, path, expected, unexpected):
        flags = os.statvfs(path).f_flag
        for f in expected:
            self.assertTrue(flags & f, f'{path}: expected flag {f:#x} not set')
        for f in unexpected:
            self.assertFalse(flags & f, f'{path}: unexpected flag {f:#x} set')

    # ------ Source is a regular file ------

    @in_sandbox('--ro-bind', lambda self: self.src.file, '/tmp/f')
    def test_ro_bind_file(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'hello')
        self.assertIsMountpoint('/tmp/f')
        self.assertMountFlags('/tmp/f',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    @in_sandbox('--bind', lambda self: self.src.file, '/tmp/f')
    def test_bind_file(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'hello')
        self.assertIsMountpoint('/tmp/f')
        self.assertMountFlags('/tmp/f',
                              [os.ST_NOSUID, os.ST_NODEV], [os.ST_RDONLY])

    @in_sandbox('--dev-bind', '/dev/null', '/tmp/devnull')
    def test_dev_bind_file(self):
        self.assertIsChrDev('/tmp/devnull')
        self.assertIsMountpoint('/tmp/devnull')
        self.assertMountFlags('/tmp/devnull',
                              [os.ST_NOSUID], [os.ST_RDONLY, os.ST_NODEV])

    # ------ Source is a directory ------

    @in_sandbox('--ro-bind', lambda self: self.src.dir, '/tmp/d')
    def test_ro_bind_dir(self):
        self.assertIsDir('/tmp/d')
        self.assertFileContent('/tmp/d/child', 'child content')
        self.assertIsMountpoint('/tmp/d')
        self.assertMountFlags('/tmp/d',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    @in_sandbox('--bind', lambda self: self.src.dir, '/tmp/d')
    def test_bind_dir(self):
        self.assertIsDir('/tmp/d')
        self.assertFileContent('/tmp/d/child', 'child content')
        self.assertIsMountpoint('/tmp/d')
        self.assertMountFlags('/tmp/d',
                              [os.ST_NOSUID, os.ST_NODEV], [os.ST_RDONLY])

    @in_sandbox('--dev-bind', '/dev', '/tmp/d')
    def test_dev_bind_dir(self):
        self.assertIsDir('/tmp/d')
        self.assertIsMountpoint('/tmp/d')
        self.assertMountFlags('/tmp/d',
                              [os.ST_NOSUID], [os.ST_RDONLY, os.ST_NODEV])

    # ------ Source is a symlink (should resolve to target) ------

    @in_sandbox('--ro-bind', lambda self: self.src.symlink_to_file, '/tmp/f')
    def test_ro_bind_symlink_to_file(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'hello')
        self.assertMountFlags('/tmp/f',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    @in_sandbox('--ro-bind', lambda self: self.src.symlink_to_dir, '/tmp/d')
    def test_ro_bind_symlink_to_dir(self):
        self.assertIsDir('/tmp/d')
        self.assertFileContent('/tmp/d/child', 'child content')
        self.assertMountFlags('/tmp/d',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    @in_sandbox('--ro-bind', lambda self: self.src.symlink_relative, '/tmp/f')
    def test_ro_bind_relative_symlink(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'hello')
        self.assertMountFlags('/tmp/f',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    # ------ Destination parent creation ------

    @in_sandbox('--ro-bind', lambda self: self.src.file,
                '/tmp/deep/nested/path/file')
    def test_bind_creates_parent_dirs(self):
        self.assertIsDir('/tmp/deep/nested/path')
        self.assertFileContent('/tmp/deep/nested/path/file', 'hello')

    @in_sandbox('--ro-bind', lambda self: self.src.dir,
                '/tmp/deep/nested/dir')
    def test_bind_dir_creates_parent_dirs(self):
        self.assertIsDir('/tmp/deep/nested/dir')
        self.assertFileContent('/tmp/deep/nested/dir/child', 'child content')

    # ------ Destination already exists ------

    @in_sandbox('--dir', '/tmp/existing',
                '--ro-bind', lambda self: self.src.dir, '/tmp/existing')
    def test_bind_over_existing_dir(self):
        self.assertFileContent('/tmp/existing/child', 'child content')

    @in_sandbox('--ro-bind', lambda self: self.src.other_file, '/tmp/f',
                '--ro-bind', lambda self: self.src.file, '/tmp/f')
    def test_bind_over_existing_file(self):
        self.assertFileContent('/tmp/f', 'hello')

    # ------ Destination is a symlink (should fail) ------

    def test_bind_to_symlink_dest_fails(self):
        result = run_bwrap('--dir', '/tmp/dir',
                           '--symlink', 'dir', '/tmp/link',
                           '--ro-bind', self.src.dir, '/tmp/link',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b"Can't mount on symlink destination", result)

    def test_bind_to_symlink_dest_fails_file(self):
        result = run_bwrap('--symlink', 'dir', '/tmp/link',
                           '--ro-bind', self.src.file, '/tmp/link',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b"Can't mount on symlink destination", result)

    # ------ bind-fd / ro-bind-fd ------

    @in_sandbox('--ro-bind-fd', lambda self: OpenFd(self.src.file), '/tmp/f')
    def test_ro_bind_fd_file(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'hello')
        self.assertMountFlags('/tmp/f',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    @in_sandbox('--ro-bind-fd', lambda self: OpenFd(self.src.dir), '/tmp/d')
    def test_ro_bind_fd_dir(self):
        self.assertIsDir('/tmp/d')
        self.assertFileContent('/tmp/d/child', 'child content')
        self.assertMountFlags('/tmp/d',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    @in_sandbox('--bind-fd', lambda self: OpenFd(self.src.file), '/tmp/f')
    def test_bind_fd_file(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'hello')
        self.assertMountFlags('/tmp/f',
                              [os.ST_NOSUID, os.ST_NODEV], [os.ST_RDONLY])

    @in_sandbox('--bind-fd', lambda self: OpenFd(self.src.dir), '/tmp/d')
    def test_bind_fd_dir(self):
        self.assertIsDir('/tmp/d')
        self.assertFileContent('/tmp/d/child', 'child content')
        self.assertMountFlags('/tmp/d',
                              [os.ST_NOSUID, os.ST_NODEV], [os.ST_RDONLY])

    # ------ Multiple binds ------

    @in_sandbox('--ro-bind', lambda self: self.src.file, '/tmp/a',
                '--ro-bind', lambda self: self.src.dir, '/tmp/b')
    def test_multiple_binds(self):
        self.assertFileContent('/tmp/a', 'hello')
        self.assertIsDir('/tmp/b')
        self.assertFileContent('/tmp/b/child', 'child content')

    @in_sandbox('--ro-bind', lambda self: self.src.file, '/tmp/parent/a',
                '--ro-bind', lambda self: self.src.dir, '/tmp/parent/b')
    def test_bind_file_then_dir_same_parent(self):
        self.assertFileContent('/tmp/parent/a', 'hello')
        self.assertIsDir('/tmp/parent/b')

    # ------ Recursive mount flags ------

    @in_sandbox()
    def test_ro_bind_root_is_recursive(self):
        self._test_ro_bind_root_is_recursive()

    @in_sandbox('--debug-opt=force-mount-setattr-fallback')
    def test_ro_bind_root_is_recursive_fallback(self):
        self._test_ro_bind_root_is_recursive()

    def _test_ro_bind_root_is_recursive(self):
        """The base --ro-bind / / should apply read-only to sub-mounts."""
        skip_prefixes = ('/dev', '/proc', '/sys', '/tmp')
        for mountpoint in list_mounts():
            if any(mountpoint == p or mountpoint.startswith(p + '/')
                   for p in skip_prefixes):
                continue
            flags = os.statvfs(mountpoint).f_flag
            self.assertTrue(
                flags & os.ST_RDONLY,
                f'{mountpoint} is not read-only',
            )

    # ------ tmpfs ------

    @in_sandbox('--tmpfs', '/tmp/t')
    def test_tmpfs(self):
        self.assertIsDir('/tmp/t')
        self.assertIsMountpoint('/tmp/t')
        self.assertIsTmpfs('/tmp/t')
        self.assertMountFlags('/tmp/t',
                              [os.ST_NOSUID, os.ST_NODEV], [os.ST_RDONLY])
        with open('/tmp/t/testfile', 'w') as f:
            f.write('writable')
        self.assertFileContent('/tmp/t/testfile', 'writable')

    @in_sandbox('--perms', '0700', '--tmpfs', '/tmp/t')
    def test_tmpfs_perms(self):
        self.assertIsMountpoint('/tmp/t')
        self.assertIsTmpfs('/tmp/t')
        mode = os.lstat('/tmp/t').st_mode & 0o7777
        self.assertEqual(mode, 0o700)

    @in_sandbox('--size', str(64 * 1024), '--tmpfs', '/tmp/t')
    def test_tmpfs_size(self):
        self.assertIsMountpoint('/tmp/t')
        self.assertIsTmpfs('/tmp/t')
        st = os.statvfs('/tmp/t')
        total = st.f_blocks * st.f_frsize
        self.assertLessEqual(total, 64 * 1024 + 4096)

    # ------ proc ------

    @in_sandbox()
    def test_proc(self):
        self.assertIsSymlink('/proc/self')
        self.assertIsDir('/proc/self/')
        self.assertIsRegFile('/proc/self/status')
        for subdir in ['sys', 'sysrq-trigger', 'irq', 'bus']:
            path = f'/proc/{subdir}'
            if os.path.exists(path):
                self.assertFalse(os.access(path, os.W_OK),
                                 f'/proc/{subdir} should not be writable')

    # ------ dev ------

    @in_sandbox()
    def test_dev_nodes(self):
        for node in ['null', 'zero', 'full', 'random', 'urandom', 'tty']:
            self.assertIsChrDev(f'/dev/{node}')
        for link in ['stdin', 'stdout', 'stderr', 'fd', 'ptmx']:
            self.assertIsSymlink(f'/dev/{link}')
        self.assertIsDir('/dev/pts')
        self.assertIsDir('/dev/shm')

    # ------ dir ------

    @in_sandbox('--dir', '/tmp/d')
    def test_dir(self):
        self.assertIsDir('/tmp/d')

    @in_sandbox('--perms', '0700', '--dir', '/tmp/d')
    def test_dir_perms(self):
        self.assertIsDir('/tmp/d')
        self.assertEqual(os.lstat('/tmp/d').st_mode & 0o7777, 0o700)

    @in_sandbox('--dir', '/tmp/a/b/c')
    def test_dir_creates_parents(self):
        self.assertIsDir('/tmp/a')
        self.assertIsDir('/tmp/a/b')
        self.assertIsDir('/tmp/a/b/c')

    # ------ file ------

    @in_sandbox('--file', DataFd(b'file content'), '/tmp/f')
    def test_file(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'file content')

    @in_sandbox('--perms', '0600', '--file', DataFd(b'x'), '/tmp/f')
    def test_file_perms(self):
        self.assertIsRegFile('/tmp/f')
        self.assertEqual(os.lstat('/tmp/f').st_mode & 0o7777, 0o600)

    # ------ bind-data / ro-bind-data ------

    @in_sandbox('--bind-data', DataFd(b'bind data'), '/tmp/f')
    def test_bind_data(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'bind data')
        self.assertIsMountpoint('/tmp/f')
        self.assertMountFlags('/tmp/f',
                              [os.ST_NOSUID, os.ST_NODEV], [os.ST_RDONLY])

    @in_sandbox('--ro-bind-data', DataFd(b'ro data'), '/tmp/f')
    def test_ro_bind_data(self):
        self.assertIsRegFile('/tmp/f')
        self.assertFileContent('/tmp/f', 'ro data')
        self.assertIsMountpoint('/tmp/f')
        self.assertMountFlags('/tmp/f',
                              [os.ST_RDONLY, os.ST_NOSUID, os.ST_NODEV], [])

    # ------ symlink ------

    @in_sandbox('--symlink', '/usr', '/tmp/link')
    def test_symlink(self):
        self.assertSymlinkContent('/tmp/link', '/usr')

    @in_sandbox('--symlink', '/usr', '/tmp/link',
                '--symlink', '/usr', '/tmp/link')
    def test_symlink_idempotent(self):
        self.assertSymlinkContent('/tmp/link', '/usr')

    def test_symlink_conflict(self):
        result = run_bwrap('--symlink', '/usr', '/tmp/link',
                           '--symlink', '/etc', '/tmp/link',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b'existing destination is /usr', result)

    def test_symlink_over_file(self):
        result = run_bwrap('--file', DataFd(b''), '/tmp/f',
                           '--symlink', '/usr', '/tmp/f',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b'not a symlink', result)

    # ------ chmod ------

    @in_sandbox('--dir', '/tmp/d', '--chmod', '0700', '/tmp/d')
    def test_chmod(self):
        self.assertEqual(os.lstat('/tmp/d').st_mode & 0o7777, 0o700)

    @in_sandbox('--dir', '/tmp/d', '--chmod', '0755', '/tmp/d')
    def test_chmod_755(self):
        self.assertEqual(os.lstat('/tmp/d').st_mode & 0o7777, 0o755)

    @in_sandbox('--file', DataFd(b'x'), '/tmp/f', '--chmod', '0600', '/tmp/f')
    def test_chmod_file(self):
        self.assertEqual(os.lstat('/tmp/f').st_mode & 0o7777, 0o600)

    def test_chmod_nonexistent(self):
        result = run_bwrap('--chmod', '0700', '/tmp/noexist', 'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b"No such file or directory", result)

    # ------ remount-ro ------

    @in_sandbox('--tmpfs', '/tmp/rw', '--remount-ro', '/tmp/rw')
    def test_remount_ro(self):
        self.assertMountFlags('/tmp/rw', [os.ST_RDONLY], [])

    # ------ mqueue ------

    def test_mqueue(self):
        result = run_bwrap('--mqueue', '/tmp/mq', 'true')
        if result.returncode != 0 and b'Operation not permitted' in result.stderr:
            self.skipTest('mqueue not available in user namespace')
        self.assertEqual(result.returncode, 0)

    # ------ hostname ------

    def test_hostname(self):
        result = run_bwrap('--unshare-uts', '--hostname', 'testhost',
                           'uname', '-n')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b'testhost')

    # ------ bind-try / ro-bind-try (nonexistent source skipped) ------

    @in_sandbox('--ro-bind-try', '/nonexistent/path', '/tmp/f')
    def test_ro_bind_try_nonexistent(self):
        self.assertFalse(os.path.exists('/tmp/f'))

    @in_sandbox('--bind-try', '/nonexistent/path', '/tmp/f')
    def test_bind_try_nonexistent(self):
        self.assertFalse(os.path.exists('/tmp/f'))

    @in_sandbox('--dev-bind-try', '/nonexistent/path', '/tmp/f')
    def test_dev_bind_try_nonexistent(self):
        self.assertFalse(os.path.exists('/tmp/f'))

    @in_sandbox('--ro-bind-try', lambda self: self.src.file, '/tmp/f')
    def test_ro_bind_try_existing(self):
        self.assertFileContent('/tmp/f', 'hello')

    # ------ overlay ------

    def test_tmp_overlay(self):
        result = run_bwrap('--overlay-src', self.src.dir,
                           '--tmp-overlay', '/tmp/ov',
                           'cat', '/tmp/ov/child')
        if result.returncode != 0 and b'overlay' in result.stderr.lower():
            self.skipTest('overlayfs not available')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'child content')

    def test_ro_overlay(self):
        result = run_bwrap('--overlay-src', self.src.dir,
                           '--overlay-src', self.src.dir2,
                           '--ro-overlay', '/tmp/ov',
                           'cat', '/tmp/ov/child')
        if result.returncode != 0 and b'overlay' in result.stderr.lower():
            self.skipTest('overlayfs not available')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'child content')

    # ------ overlay-opt ------

    def test_tmp_overlay_opt_after_src(self):
        result = run_bwrap('--overlay-src', self.src.dir,
                           '--overlay-opt', 'index=off,xino=off',
                           '--tmp-overlay', '/tmp/ov',
                           'cat', '/tmp/ov/child')
        if result.returncode != 0 and b'overlay' in result.stderr.lower():
            self.skipTest('overlayfs not available')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'child content')

    def test_tmp_overlay_opt_before_src(self):
        result = run_bwrap('--overlay-opt', 'index=off,xino=off',
                           '--overlay-src', self.src.dir,
                           '--tmp-overlay', '/tmp/ov',
                           'cat', '/tmp/ov/child')
        if result.returncode != 0 and b'overlay' in result.stderr.lower():
            self.skipTest('overlayfs not available')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'child content')

    def test_tmp_overlay_opt_multiple_comma_joined(self):
        result = run_bwrap('--overlay-opt', 'index=off',
                           '--overlay-opt', 'xino=off',
                           '--overlay-src', self.src.dir,
                           '--tmp-overlay', '/tmp/ov',
                           'cat', '/tmp/ov/child')
        if result.returncode != 0 and b'overlay' in result.stderr.lower():
            self.skipTest('overlayfs not available')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'child content')

    def test_overlay_opt_dangling(self):
        result = run_bwrap('--overlay-opt', 'index=off', 'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b'--overlay-opt must be followed', result)

    def test_overlay_src_not_consumed(self):
        result = run_bwrap('--overlay-src', self.src.dir,
                           '--overlay-opt', 'index=off',
                           '--ro-bind', self.src.file, '/tmp/f', 'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b'--overlay-src must be followed', result)

    # ------ Edge cases: source path with symlinks ------

    def test_bind_source_absolute_symlink_in_path(self):
        """Source path contains a symlink with absolute target."""
        link = os.path.join(self.tmp, 'abs_link')
        os.symlink(self.src.root, link)
        result = run_bwrap('--ro-bind', link + '/regular_file', '/tmp/f',
                           'cat', '/tmp/f')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'hello')

    def test_bind_source_dotdot_in_path(self):
        """Source path with .. components."""
        path = self.src.dir + '/../regular_file'
        result = run_bwrap('--ro-bind', path, '/tmp/f',
                           'cat', '/tmp/f')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'hello')

    def test_bind_source_symlink_chain(self):
        """Source is a chain of symlinks."""
        link1 = os.path.join(self.tmp, 'link1')
        link2 = os.path.join(self.tmp, 'link2')
        os.symlink(self.src.file, link1)
        os.symlink(link1, link2)
        result = run_bwrap('--ro-bind', link2, '/tmp/f',
                           'cat', '/tmp/f')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'hello')

    # ------ Edge cases: dest parent issues ------

    def test_bind_dest_parent_is_file(self):
        """Bind where a parent component of dest is an existing file."""
        result = run_bwrap('--file', DataFd(b''), '/tmp/notadir',
                           '--ro-bind', self.src.file, '/tmp/notadir/child',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b"Not a directory", result)

    @in_sandbox('--dir', '/tmp/target',
                '--symlink', 'target', '/tmp/link',
                '--ro-bind', lambda self: self.src.file, '/tmp/link/child')
    def test_bind_dest_parent_is_symlink(self):
        """Bind where a parent component of dest is a symlink to a dir."""
        self.assertFileContent('/tmp/link/child', 'hello')

    def test_dir_dest_parent_is_file(self):
        """--dir where a parent component is an existing file."""
        result = run_bwrap('--file', DataFd(b''), '/tmp/notadir',
                           '--dir', '/tmp/notadir/sub',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b"Not a directory", result)

    # ------ Edge cases: dest type mismatches ------

    def test_bind_dir_over_existing_file(self):
        """Bind a directory source over an existing file dest."""
        result = run_bwrap('--file', DataFd(b''), '/tmp/f',
                           '--ro-bind', self.src.dir, '/tmp/f',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b'not a directory', result)

    def test_bind_file_over_existing_dir(self):
        """Bind a file source over an existing directory dest."""
        result = run_bwrap('--dir', '/tmp/d',
                           '--ro-bind', self.src.file, '/tmp/d',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b"not a file", result)

    # ------ Edge cases: nonexistent source ------

    def test_bind_nonexistent_source(self):
        result = run_bwrap('--ro-bind', '/nonexistent/path', '/tmp/f',
                           'true')
        self.assertBwrapFailed(result)
        self.assertInStderr(b"No such file or directory", result)

    # ------ Edge cases: multiple overlapping mounts ------

    @in_sandbox('--tmpfs', '/tmp/a',
                '--dir', '/tmp/a/sub',
                '--ro-bind', lambda self: self.src.file, '/tmp/a/sub/f')
    def test_mount_chain(self):
        """tmpfs, then dir inside it, then bind inside that."""
        self.assertIsDir('/tmp/a/sub')
        self.assertFileContent('/tmp/a/sub/f', 'hello')

    # ------ Edge cases: bind-fd dest is symlink ------

    def test_bind_fd_to_symlink_dest_fails(self):
        fd = os.open(self.src.dir, os.O_PATH)
        result = run_bwrap('--dir', '/tmp/dir',
                           '--symlink', 'dir', '/tmp/link',
                           '--bind-fd', str(fd), '/tmp/link',
                           'true', pass_fds=(fd,))
        os.close(fd)
        self.assertBwrapFailed(result)
        self.assertInStderr(b"Can't mount on symlink destination", result)

    # ------ Edge cases: --file creates parents ------

    @in_sandbox('--file', DataFd(b'deep'), '/tmp/a/b/c')
    def test_file_creates_parents(self):
        self.assertIsDir('/tmp/a/b')
        self.assertFileContent('/tmp/a/b/c', 'deep')

    # ------ Edge cases: --symlink creates parents ------

    @in_sandbox('--symlink', '/usr', '/tmp/a/b/link')
    def test_symlink_creates_parents(self):
        self.assertIsDir('/tmp/a/b')
        self.assertSymlinkContent('/tmp/a/b/link', '/usr')

    # ------ Edge cases: --dir over existing dir is fine ------

    @in_sandbox('--dir', '/tmp/d', '--dir', '/tmp/d')
    def test_dir_idempotent(self):
        self.assertIsDir('/tmp/d')

    # ------ Edge cases: bind-data creates parents ------

    @in_sandbox('--ro-bind-data', DataFd(b'nested'), '/tmp/a/b/f')
    def test_bind_data_creates_parents(self):
        self.assertIsDir('/tmp/a/b')
        self.assertFileContent('/tmp/a/b/f', 'nested')

    # ------ Symlink escape via /proc/self/fd ------

    def _test_proc_symlink_escape(self, extra_bwrap_args):
        """Verifies that a symlink pointing through /proc/self/fd
        to an fd outside the sandbox cannot be used to escape the root."""
        escape_target = os.path.join(self.tmp, 'escape_target')
        os.makedirs(escape_target)

        escape_fd = os.open(escape_target, os.O_PATH | os.O_DIRECTORY)
        try:
            result = run_bwrap(
                *extra_bwrap_args,
                '--dir', '/tmp/mnt',
                '--symlink', f'/proc/self/fd/{escape_fd}', '/tmp/mnt/symlink',
                '--dir', '/tmp/mnt/symlink/created',
                'true',
                pass_fds=(escape_fd,))

            self.assertBwrapFailed(result)
            self.assertFalse(os.path.exists(
                os.path.join(escape_target, 'created')),
                'directory was created outside sandbox via /proc/self/fd escape')
        finally:
            os.close(escape_fd)

    def test_proc_symlink_escape_blocked(self):
        self._test_proc_symlink_escape([])

    def test_proc_symlink_escape_blocked_fallback(self):
        self._test_proc_symlink_escape(['--debug-opt=force-openat-fallback'])


if __name__ == '__main__':
    run_tap_tests(sys.modules[__name__])
