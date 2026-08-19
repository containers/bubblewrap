#!/usr/bin/env python3
# Copyright 2024 Alexander Larsson
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test infrastructure for bwrap sandbox integration tests.
# Provides BwrapSandbox context manager, SourceTree fixture,
# @in_sandbox / @sandbox_test_class decorators, and TAP runner.

import json
import os
import socket
import subprocess
import sys
import unittest


BWRAP = os.getenv('BWRAP', 'bwrap')
HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      'sandbox_helper.py')


def in_sandbox(*sandbox_args):
    """Decorator: marks a method to run inside a bwrap sandbox.

    Args are bwrap options. Use callables (taking self) for dynamic
    values like fixture paths, e.g.:
        @in_sandbox('--ro-bind', lambda self: self.src.file, '/tmp/f')
    """
    def decorator(fn):
        fn._sandbox_args = sandbox_args
        return fn
    return decorator


def sandbox_test_class(cls):
    """Class decorator: for each @in_sandbox method, installs a
    sandboxed_* copy and replaces the original with a host-side
    wrapper that launches bwrap and runs it remotely."""
    for name in list(vars(cls)):
        fn = vars(cls)[name]
        if not hasattr(fn, '_sandbox_args'):
            continue

        sandbox_args = fn._sandbox_args
        sandboxed_name = 'sandboxed_' + name

        setattr(cls, sandboxed_name, fn)

        def make_wrapper(sname, sargs):
            def wrapper(self):
                resolved = [a(self) if callable(a) else a for a in sargs]
                with BwrapSandbox(*resolved) as sb:
                    sb.run_test(self, sname)
            return wrapper

        wrapper = make_wrapper(sandboxed_name, sandbox_args)
        wrapper.__name__ = name
        wrapper.__qualname__ = fn.__qualname__
        setattr(cls, name, wrapper)

    return cls


class OpenFd:
    """Placeholder in @in_sandbox args: opens path with O_PATH at launch time."""
    def __init__(self, path):
        self.path = path


class DataFd:
    """Placeholder in @in_sandbox/run_bwrap args: creates a pipe with content."""
    def __init__(self, content):
        self.content = content


class BwrapSandbox:
    """Context manager that runs a bwrap sandbox with a Python helper.

    Base setup is --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp,
    so test destinations that need to be created should go under /tmp.
    """

    def __init__(self, *extra_args):
        self.extra_args = list(extra_args)
        self.proc = None
        self._parent_sock = None
        self._opened_fds = []

    def __enter__(self):
        parent_sock, child_sock = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM,
        )
        self._parent_sock = parent_sock
        child_fd = child_sock.fileno()

        resolved_args = []
        for arg in self.extra_args:
            if isinstance(arg, OpenFd):
                fd = os.open(arg.path, os.O_PATH)
                self._opened_fds.append(fd)
                resolved_args.append(str(fd))
            elif isinstance(arg, DataFd):
                r, w = os.pipe()
                os.write(w, arg.content)
                os.close(w)
                self._opened_fds.append(r)
                resolved_args.append(str(r))
            else:
                resolved_args.append(arg)

        cmd = [
            BWRAP, *BASE_BWRAP_ARGS,
            *resolved_args,
            'python3', HELPER, str(child_fd),
        ]

        self.proc = subprocess.Popen(
            cmd,
            pass_fds=(child_fd, *self._opened_fds),
        )
        child_sock.close()
        for fd in self._opened_fds:
            os.close(fd)
        self._opened_fds = []

        self._buf = b''
        return self

    def __exit__(self, *exc):
        try:
            self._send({'exit': True})
        except OSError:
            pass

        self._parent_sock.close()

        if self.proc:
            self.proc.wait(timeout=5)
        return False

    def _send(self, msg):
        self._parent_sock.sendall(json.dumps(msg).encode() + b'\n')

    def _recv(self):
        while b'\n' not in self._buf:
            chunk = self._parent_sock.recv(4096)
            if not chunk:
                raise ConnectionError('sandbox helper closed connection')
            self._buf += chunk
        line, self._buf = self._buf.split(b'\n', 1)
        return json.loads(line)

    def run_test(self, test_case, method_name):
        """Run a test method from test_case's class inside the sandbox."""
        self._send({
            'run_test': {
                'module': self._test_module(test_case),
                'class': type(test_case).__name__,
                'method': method_name,
            },
        })
        resp = self._recv()
        if not resp['ok']:
            raise AssertionError(
                f'sandboxed test failed:\n{resp["error"]}',
            )

    def _test_module(self, test_case):
        """Get the file path of the module that defines the test case."""
        import inspect
        return os.path.abspath(inspect.getfile(type(test_case)))


BASE_BWRAP_ARGS = ['--ro-bind', '/', '/', '--dev', '/dev',
                   '--proc', '/proc', '--tmpfs', '/tmp']


def run_bwrap(*extra_args, pass_fds=()):
    """Run bwrap with base sandbox args plus extra_args, return CompletedProcess.

    Args may include DataFd instances, which are resolved to pipe fds.
    """
    opened_fds = []
    resolved_args = []
    for arg in extra_args:
        if isinstance(arg, DataFd):
            r, w = os.pipe()
            os.write(w, arg.content)
            os.close(w)
            opened_fds.append(r)
            resolved_args.append(str(r))
        else:
            resolved_args.append(arg)
    cmd = [BWRAP, *BASE_BWRAP_ARGS, *resolved_args]
    try:
        return subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(*pass_fds, *opened_fds),
        )
    finally:
        for fd in opened_fds:
            os.close(fd)


def list_mounts():
    """Return list of mountpoints from /proc/self/mounts."""
    with open('/proc/self/mounts') as f:
        return [line.split()[1] for line in f]


def can_run_bwrap():
    """Check if bwrap can run at all."""
    try:
        r = subprocess.run(
            [BWRAP, '--ro-bind', '/', '/', 'true'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return r.returncode == 0
    except (FileNotFoundError, OSError):
        return False


class TAPResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.index = 0

    def _test_name(self, test):
        return test._testMethodName

    def _print_diagnostics(self, test, err):
        for line in self._exc_info_to_string(err, test).splitlines():
            print(f'# {line}')

    def addSuccess(self, test):
        super().addSuccess(test)
        self.index += 1
        print(f'ok {self.index} {self._test_name(test)}')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.index += 1
        print(f'not ok {self.index} {self._test_name(test)}')
        self._print_diagnostics(test, err)

    def addError(self, test, err):
        super().addError(test, err)
        self.index += 1
        print(f'not ok {self.index} {self._test_name(test)}')
        self._print_diagnostics(test, err)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.index += 1
        print(f'ok {self.index} {self._test_name(test)} # SKIP {reason}')


def run_tap_tests(module):
    """Run all tests in module with TAP output."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(module)
    result = TAPResult()
    suite.run(result)
    print(f'1..{result.index}')
    sys.exit(0 if result.wasSuccessful() else 1)
