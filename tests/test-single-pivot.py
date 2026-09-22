#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.0-or-later
"""Exercise automatic detached mounts and legacy selection in private namespaces.

Run with BWRAP=/absolute/path/to/bwrap python3 tests/test-single-pivot.py.
The test seccomp filter is deliberately allow-all: mount policy, capability
and descriptor checks are separate from the existing seccomp tests.
"""
import os

# Capture inherited descriptors before ctypes/libffi opens runtime-owned fds.
# listdir closes its directory fd before returning; ignore that stale entry.
INHERITED_FDS = {name: os.readlink('/proc/self/fd/' + name)
                 for name in os.listdir('/proc/self/fd')
                 if int(name) > 2 and os.path.exists('/proc/self/fd/' + name)}

import ctypes
import contextlib
import errno
import json
from pathlib import Path
import platform
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
LIBC = ctypes.CDLL(None, use_errno=True)
SCRIPT = Path(__file__).resolve()
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
# These syscall numbers are shared by the two architectures supported below.
SYSCALLS = {
    "open_tree": 428,
    "move_mount": 429,
    "fsopen": 430,
    "fsconfig": 431,
    "fsmount": 432,
    "openat2": 437,
    "mount_setattr": 442,
}


def mount(source, target, flags, kind='tmpfs', data='mode=0700'):
    args = [x.encode() if x is not None else None for x in (source, str(target), kind, data)]
    if LIBC.mount(args[0], args[1], args[2], ctypes.c_ulong(flags), args[3]) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), str(target))


def inspect_sandbox():
    expected = json.loads(sys.argv[2])
    if 'cwd' in expected:
        assert os.getcwd() == expected['cwd'], os.getcwd()
    def options(path):
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            fields = line.split()
            if fields[4] == path:
                return set(fields[5].split(','))
        raise AssertionError(f'not a mount point: {path}')
    for path, required in expected['mounts'].items():
        actual = options(path)
        assert set(required) <= actual, (path, required, actual)
    for path, writable in expected.get('writes', {}).items():
        try:
            Path(path).write_text('child')
        except OSError as error:
            assert not writable and error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), (path, error)
        else:
            assert writable, f'unexpected writable path: {path}'
    if 'device' in expected:
        try:
            with open('/tmp/probe-device', 'wb') as stream:
                stream.write(b'test')
        except OSError as error:
            assert not expected['device'] and error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), error
        else:
            assert expected['device'], 'nodev did not block device access'

    for path, expected_mode in expected.get('modes', {}).items():
        assert stat.S_IMODE(os.stat(path).st_mode) == expected_mode, path
    for path, expected_size in expected.get('sizes', {}).items():
        filesystem = os.statvfs(path)
        assert filesystem.f_blocks * filesystem.f_frsize == expected_size, path
        try:
            Path(path, 'too-large').write_bytes(b'x' * (expected_size * 2))
        except OSError as error:
            assert error.errno == errno.ENOSPC, (path, error)
        else:
            raise AssertionError(f'tmpfs size limit not enforced: {path}')


def drop_caps():
    # The fixture needs mount privileges in its private namespace, but bwrap
    # must start with ordinary unprivileged credentials.
    assert LIBC.prctl(47, 4, 0, 0, 0) == 0  # PR_CAP_AMBIENT_CLEAR_ALL
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)
    data = (ctypes.c_uint32 * 6)()
    assert LIBC.capset(header, data) == 0


def deny(number, error, valid_fd=False, devpts=False):
    assert platform.machine() in ("x86_64", "aarch64")
    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]
    instructions = (Filter * 4)(Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, number),
                               Filter(0x06, 0, 0, 0x50000 | error),
                               Filter(0x06, 0, 0, 0x7fff0000))
    if valid_fd:
        instructions = (Filter * 6)(
            Filter(0x20, 0, 0, 0), Filter(0x15, 0, 3, number),
            Filter(0x20, 0, 0, 16), Filter(0x15, 1, 0, 0xffffffff),
            Filter(0x06, 0, 0, 0x50000 | error), Filter(0x06, 0, 0, 0x7fff0000))
    if devpts:
        instructions = (Filter * 6)(
            Filter(0x20, 0, 0, 0), Filter(0x15, 0, 3, number),
            Filter(0x20, 0, 0, 24), Filter(0x15, 0, 1, 0),
            Filter(0x06, 0, 0, 0x50000 | error), Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(len(instructions), instructions)
    assert LIBC.prctl(38, 1, 0, 0, 0) == 0
    assert LIBC.prctl(22, 2, ctypes.byref(program), 0, 0) == 0


def detached_mounts_supported():
    """Distinguish syscall presence from detached-tree semantics in this fixture."""
    fds = []
    def keep(fd, operation):
        if fd < 0:
            raise OSError(ctypes.get_errno(), operation)
        fds.append(fd)
        return fd
    try:
        context = keep(LIBC.fsopen(b"tmpfs", 1), "fsopen")
        if LIBC.fsconfig(context, 6, None, None, 0) < 0:  # FSCONFIG_CMD_CREATE
            raise OSError(ctypes.get_errno(), "fsconfig")
        tree = keep(LIBC.fsmount(context, 1, 2 | 4), "fsmount")
        # OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH | AT_RECURSIVE
        flags = 1 | os.O_CLOEXEC | 0x1000 | 0x8000
        clone = LIBC.open_tree(tree, b"", flags)
        if clone < 0 and ctypes.get_errno() in (errno.EINVAL, errno.ENOSYS):
            return False
        keep(clone, "open_tree")
        target = keep(LIBC.open_tree(tree, b"", flags), "open_tree target")
        if LIBC.move_mount(clone, b"", target, b"", 0x4 | 0x40) < 0:
            if ctypes.get_errno() in (errno.EINVAL, errno.ENOSYS):
                return False
            raise OSError(ctypes.get_errno(), "move_mount")
        return True
    finally:
        for fd in reversed(fds):
            os.close(fd)


def main():
    if len(sys.argv) == 1:
        sys.argv.append(os.environ.get("BWRAP", "bwrap"))
    if sys.argv[1] in ("--deny", "--deny-valid-fd", "--deny-devpts"):
        deny(int(sys.argv[2]), int(sys.argv[3]), sys.argv[1] == "--deny-valid-fd",
             sys.argv[1] == "--deny-devpts")
        os.execv(sys.argv[4], sys.argv[4:])
    if sys.argv[1] == "--inspect":
        inspect_sandbox()
        assert not Path("/tmp/input/sub/hidden").exists()
        assert not Path("/oldroot").exists() and not Path("/newroot").exists()
        for name in ("null", "zero", "full", "random", "urandom", "tty"):
            assert Path("/dev", name).is_char_device(), name
        with open("/dev/null", "wb") as output:
            output.write(b"device works")
        os.close(os.open("/dev/ptmx", os.O_RDWR | os.O_NOCTTY))
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith(("CapPrm:", "CapEff:", "CapAmb:")):
                assert int(line.split()[1], 16) == 0, line
        assert not os.read(0, 1), "unexpected stdin data"
        assert not INHERITED_FDS, f"setup descriptors leaked: {INHERITED_FDS}"
        Path("/tmp/private-output").write_text("private")
        return
    if sys.argv[1] != "--inside":
        if os.getuid() == 0 or platform.machine() not in ("x86_64", "aarch64"):
            print("SKIP: requires unprivileged x86_64/aarch64 user namespaces")
            sys.exit(77)
        helper = str(Path(shutil.which(sys.argv[1]) or sys.argv[1]).resolve(strict=True))
        namespace = ["unshare", "--user", "--map-current-user", "--keep-caps", "--mount",
                     "--propagation", "private"]
        probe = subprocess.run([*namespace, sys.executable, "-c", "pass"], capture_output=True)
        if probe.returncode != 0:
            print("SKIP: fixture namespaces unavailable:", probe.stderr.decode(errors="replace").strip())
            sys.exit(77)
        result = subprocess.run([*namespace, sys.executable, str(SCRIPT),
                        "--inside", helper])
        sys.exit(result.returncode)
    helper = sys.argv[2]
    # An old kernel can legitimately select legacy mounts for every layout.
    # Probe only invalid arguments here; no mount can be created by this check.
    for number in SYSCALLS.values():
        ctypes.set_errno(0)
        result = LIBC.syscall(number, -1, ctypes.c_void_p(), -1, ctypes.c_void_p(), 0, 0)
        if result < 0 and ctypes.get_errno() == errno.ENOSYS:
            print("SKIP: kernel lacks a syscall needed for detached mounts")
            sys.exit(77)
    detached_supported = detached_mounts_supported()
    with tempfile.TemporaryDirectory(prefix="bwrap-single-pivot-check-") as work, contextlib.ExitStack() as mounts:
        root = Path(work)
        source = root / "source"
        source.mkdir()
        mount("tmpfs", source, 2 | 4 | 8 | 1024)
        mounts.callback(LIBC.umount2, str(source).encode(), 2)
        (source / "file").write_text("source")
        (source / "sub").mkdir()
        (source / "sub/hidden").write_text("must remain covered")
        mount("tmpfs", source / "sub", 1 << 21)
        mounts.callback(LIBC.umount2, str(source / "sub").encode(), 2)
        (source / "sub/file").write_text("nested")
        (source / "locked").mkdir()
        mount("tmpfs", source / "locked", 2 | 4 | 8 | 1024)
        mounts.callback(LIBC.umount2, str(source / "locked").encode(), 2)
        (source / "locked/file").write_text("readonly")
        mount(None, source / "locked", 32 | 1 | 2 | 4 | 8 | 1024)
        policy = root / "filter"
        policy.write_bytes(struct.pack("=HBBI", 6, 0, 0, 0x7fff0000))
        base = [helper, "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc",
                "--unshare-uts", "--die-with-parent", "--clearenv", "--proc", "/proc",
                "--dev", "/dev", "--tmpfs", "/tmp"]
        # Bind only the runtime paths needed by this Python interpreter, not /.
        # Cover both conventional distro layouts and Nix-based test hosts.
        runtime = []
        for path in ("/nix/store", "/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"):
            if Path(path).exists():
                runtime += ["--ro-bind", path, path]
        checks = 0

        def run(name, kind="--ro-bind", *, prefix=(), before=(), extra=(),
                destination="/tmp/input", error=None, expectations=None,
                runtime_binds=runtime, launch_cwd=None):
            nonlocal checks
            expected = {"mounts": {
                "/tmp/input": ["nosuid", "nodev", "noexec", "noatime", "ro" if kind == "--ro-bind" else "rw"],
                "/tmp/input/sub": ["nosuid", "relatime", "ro" if kind == "--ro-bind" else "rw"]
                                  + ([] if kind == "--dev-bind" else ["nodev"]),
                "/tmp/input/locked": ["ro", "nosuid", "nodev", "noexec", "noatime"],
                "/proc": ["nosuid", "nodev", "noexec"],
                "/dev/pts": ["nosuid", "noexec"],
                "/tmp": ["nosuid", "nodev"],
            }, "writes": {"/tmp/input/file": kind != "--ro-bind",
                           "/tmp/input/sub/file": kind != "--ro-bind",
                           "/tmp/input/locked/file": False}}
            expected.update(expectations or {})
            late = [*runtime_binds, "--ro-bind", str(SCRIPT), "/tmp/test.py",
                    kind, str(source), destination, "--", sys.executable,
                    "/tmp/test.py", "--inspect", json.dumps(expected)]
            fd = os.open(policy, os.O_RDONLY | os.O_CLOEXEC)
            try:
                args = [*prefix, base[0], *before, *base[1:], *extra, "--seccomp", str(fd), *late]
                result = subprocess.run(args, input=b"", capture_output=True, timeout=20,
                                        preexec_fn=drop_caps, pass_fds=(fd,), cwd=launch_cwd)
            finally:
                os.close(fd)
            if error is not None:
                assert result.returncode != 0, (name, result)
                assert error in result.stderr, (name, result.stderr)
            else:
                assert result.returncode == 0 and result.stdout == b"", (name, result.stderr)
            checks += 1
            print(f"ok {checks} - {name}", flush=True)
            (source / "file").write_text("host still writable")
            (source / "sub/file").write_text("nested host still writable")

        for kind in ("--bind", "--ro-bind", "--dev-bind"):
            run(f"mount policy {kind}", kind)
        run("parent symlink uses legacy", extra=("--symlink", "/", "/alias"),
            destination="/alias/tmp/input")
        run("reject symlink destination", "--bind",
            extra=("--dir", "/tmp/real", "--symlink", "real", "/tmp/link"),
            destination="/tmp/link", error=b"symlink destination")

        # Check device access and tmpfs options with both setup paths.
        for fallback in (False, True):
            extra = ("--debug-opt=force-mount-setattr-fallback",) if fallback else ()
            label = "forced legacy" if fallback else "automatic"
            for kind in ("--bind", "--dev-bind"):
                run(f"device access {kind}, {label}",
                    extra=(*extra, kind, "/dev/null", "/tmp/probe-device"),
                    expectations={"device": kind == "--dev-bind"})
            run(f"tmpfs size and permissions, {label}",
                extra=(*extra, "--perms", "0700", "--size", "1048576", "--tmpfs", "/tmp/sized"),
                expectations={"modes": {"/tmp/sized": 0o700},
                              "sizes": {"/tmp/sized": 1048576}})
            run(f"preserve working directory below /tmp, {label}",
                extra=(*extra, "--bind", str(source), str(source)),
                expectations={"cwd": str(source)}, launch_cwd=str(source))

        def denied_call(name, error, valid_fd=False):
            mode = "--deny-valid-fd" if valid_fd else "--deny"
            return (sys.executable, str(SCRIPT), mode, str(SYSCALLS[name]), str(error))

        # An absent syscall selects legacy; a permission denial must stop setup.
        for syscall in SYSCALLS:
            for error in (errno.EPERM, errno.ENOSYS):
                run(f"{syscall} returns {errno.errorcode[error]}",
                    prefix=denied_call(syscall, error),
                    error=None if error == errno.ENOSYS else syscall.encode())

        # Permit invalid-FD presence probes, deny calls with real descriptors.
        # Filesystem creation and clone/attach probes precede selection.
        # Older kernels can fall back before reaching these operations.
        if detached_supported:
            run("bind failure reports source and destination",
                prefix=denied_call("mount_setattr", errno.EPERM, valid_fd=True),
                before=("--ro-bind", str(source), "/input"),
                error=f"Can't bind mount {source} on /input".encode())
            for syscall in ("open_tree", "move_mount", "fsconfig", "fsmount", "mount_setattr"):
                for error in (errno.EPERM, errno.ENOSYS):
                    fallback = syscall != "mount_setattr" and error == errno.ENOSYS
                    run(f"{syscall} with valid fd returns {errno.errorcode[error]}",
                        prefix=denied_call(syscall, error, valid_fd=True),
                        error=None if fallback else (b"single-pivot" if error == errno.ENOSYS else syscall.encode()))

        if detached_supported:
            for error in (errno.ENOSYS, errno.EPERM):
                run(f"devpts failure after selection is fatal: {errno.errorcode[error]}",
                    prefix=(sys.executable, str(SCRIPT), "--deny-devpts",
                            str(SYSCALLS["fsconfig"]), str(error)),
                    error=b"devpts")

        run("unsupported detached open_tree selects legacy",
            prefix=denied_call("open_tree", errno.EINVAL, valid_fd=True))
        # The original root lifecycle also uses move_mount for binds. A filter
        # denying every attach must remain fatal after the probe falls back.
        run("invalid attach remains fatal after detached probe fallback",
            prefix=denied_call("move_mount", errno.EINVAL, valid_fd=True),
            error=b"Invalid argument")

        # Unsupported layouts retain the original root lifecycle, which can
        # now use the descriptor mount APIs independently of single pivot.
        for dest in ("/", "//", "/.", "/tmp/.."):
            # The root bind already includes the runtime. Binding it again
            # would target symlinks such as /bin on distributions using /usr/bin.
            run(f"root overmount {dest} selects legacy",
                before=("--ro-bind", "/", dest), runtime_binds=())
        for option in ("force-openat-fallback", "force-mount-setattr-fallback"):
            run(f"{option} selects legacy", extra=("--debug-opt=" + option,))

        tracer = shutil.which("strace")
        if tracer:
            for fallback in (False, True):
                trace = root / f"pivot-{fallback}.trace"
                extra = ("--debug-opt=force-mount-setattr-fallback",) if fallback else ()
                run(f"root transition count, forced fallback={fallback}", extra=extra,
                    prefix=(tracer, "-f", "-e", "trace=pivot_root", "-o", str(trace)))
                expected = 2 if fallback or not detached_supported else 1
                assert trace.read_text().count("pivot_root(") == expected, trace.read_text()

        # New host mounts must reach both shared and slave bind sources,
        # including shared submounts cloned recursively with their parent.
        for slave in (False, True):
            for backend in ("single-pivot", "bind-fd", "legacy"):
                fallback = backend == "legacy"
                with contextlib.ExitStack() as propagation_mounts:
                    shared = root / f"shared-{slave}-{backend}"
                    shared.mkdir()
                    mount("tmpfs", shared, MS_NOSUID | MS_NODEV)
                    propagation_mounts.callback(LIBC.umount2, str(shared).encode(), 2)
                    mount(None, shared, 1 << 20)  # MS_SHARED
                    (shared / "nested").mkdir()
                    mount("tmpfs", shared / "nested", MS_NOSUID | MS_NODEV)
                    mount(None, shared / "nested", 1 << 20)
                    for path in (shared / "late", shared / "nested/late", shared / "local"):
                        path.mkdir()
                    (shared / "local/marker").write_text("host")
                    bind_source = shared
                    if slave:
                        bind_source = root / f"slave-{backend}"
                        bind_source.mkdir()
                        mount(str(shared), bind_source, 4096 | 16384)  # MS_BIND | MS_REC
                        propagation_mounts.callback(LIBC.umount2, str(bind_source).encode(), 2)
                        mount(None, bind_source, (1 << 19) | 16384)  # MS_SLAVE | MS_REC
                    extra = ["--debug-opt=force-mount-setattr-fallback"] if fallback else []
                    code = ("from pathlib import Path; import sys; "
                            "assert not Path('/data/local/marker').exists(); "
                            "print('ready', flush=True); sys.stdin.readline(); "
                            "assert Path('/data/late/marker').read_text() == 'propagated'; "
                            "assert Path('/data/nested/late/marker').read_text() == 'propagated'")
                    source_fd = os.open(bind_source, os.O_PATH | os.O_CLOEXEC)
                    propagation_mounts.callback(os.close, source_fd)
                    bind = (["--bind-fd", str(source_fd)] if backend == "bind-fd"
                            else ["--bind", str(bind_source)])
                    args = [*base, *runtime, *extra, *bind, "/data",
                            "--tmpfs", "/data/local", "--", sys.executable, "-c", code]
                    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, preexec_fn=drop_caps,
                                          pass_fds=(source_fd,)) as child:
                        try:
                            assert select.select([child.stdout], [], [], 20)[0], "sandbox startup timed out"
                            assert child.stdout.readline() == b"ready\n", child.stderr.read()
                            assert (shared / "local/marker").read_text() == "host", "mount propagated to host"
                            for path in (shared / "late", shared / "nested/late"):
                                mount("tmpfs", path, MS_NOSUID | MS_NODEV)
                                (path / "marker").write_text("propagated")
                            stdout, stderr = child.communicate(b"go\n", timeout=20)
                            assert child.returncode == 0, (slave, fallback, stdout, stderr)
                        finally:
                            if child.poll() is None:
                                child.kill()
                                child.communicate()
                    checks += 1
                    source_kind = "slave" if slave else "shared"
                    label = backend
                    print(f"ok {checks} - propagation from {source_kind} source, {label}", flush=True)
    print(f"{checks} automatic single-pivot mount checks passed (detached semantics: {detached_supported})")


if __name__ == "__main__":
    main()
