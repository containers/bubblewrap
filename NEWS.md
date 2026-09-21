bubblewrap 0.13.1
=================

Released: not yet

...

bubblewrap 0.13.0
=================

Released: 2026-09-22

Dependencies:

  * Linux kernel headers with `__NR_pivot_root` (Linux 2.3.41+)
    are required at build-time on all architectures (#789).

  * If compiled with `-Dassume_kernel=5.12.0` or newer,
    then a kernel with the `mount_setattr` syscall is required at runtime,
    and kernel headers with `__NR_mount_setattr` are required at build-time
    on most architectures.
    On the `x86_64`, `i386` and `aarch64` architectures,
    a fallback is provided to be able to compile with pre-5.12 kernel headers.
    (#756, #785)

  * If compiled with `-Dassume_kernel=6.7.0` or newer,
    then a kernel that can mount overlayfs with the `fsopen` syscall family
    is required at runtime,
    and kernel headers with `__NR_fsopen` are required at build-time
    on most architectures.
    On the `x86_64`, `i386` and `aarch64` architectures,
    a fallback is provided to be able to compile with pre-5.2 kernel headers.

Enhancements:

  * On kernels that support it (5.12+), use `mount_setattr()` to remount
    filesystems with `ro`, `nodev` and/or `nosuid`. (#756)

  * On kernels that support it (6.7+), mount overlayfs with `fsopen()` and
    one `fsconfig()` call per layer. Previously all layers had to fit in a
    single mount option string of one page, which limited `--overlay-src` to
    roughly 200 layers and reported the overflow as a spurious overlap
    between overlay directories.

  * Arguments that expect a path argument (`--bind`, `--overlay-src`, etc.)
    now reject empty strings.
    Previously they would sometimes be treated as the root directory
    due to implementation details, but this was unintended.
    (#771)

  * A new build option `-Ddebug_logging=true` can be used to enable
    verbose debug logging (not recommended for distro builds).
    These debug messages don't appear unless environment variable
    `DEBUG_INVOCATION` is set at runtime.

Bug fixes:

  * Fix build failures with older gcc or older `-std` argument (#773, #786)

  * Fix build failure with musl (#782)

  * Fix test failure on systems that lack hostname(1) (#775)

  * Fix test failure on systems with a mount point containing a backslash
    (#778)

  * Fix test failure on systems with older xdg-desktop-portal (#794)

  * Don't leave a temporary file behind after running the test suite (#775)

  * CI improvements

Thanks: abhinavmir, ao2, smcv, vaibhav8a, xxyzz

bubblewrap 0.12.0
=================

Released: 2026-08-26

Dependencies:

  * If compiled with `-Dassume_kernel=5.6.0` or newer,
    then a kernel with the `openat2` syscall is required at runtime,
    and kernel headers with `__NR_openat2` are required at build-time.

Enhancements:

 * The flag --not-a-security-boundary was added. If this is enabled
   then failure of some sandbox setup steps (like remounting a
   submount) are not fatal.

 * The license has been updated from LGPL 2.0 (or later) to LGPL 2.1
   (or later).

 * This version removes the support for building a setuid
   bubblewrap. Changes in this version made it difficult to support
   and basically all modern linux distributions now support
   unprivileged user namespaces to some extent.

 * The assume_kernel build option was added, if specified no backwards
   compatiblity for kernels older than this is built in (and will result
   in hard failures at runtime). Currently specifying 5.6.0 or
   later will disable the fallback implementation of
   openat2(RESOLVE_IN_ROOT).

Bug fixes:

  * Bubblewrap now correctly resolves absolute symlinks during the
    sandbox setup by using openat2 with RESOLVE_IN_ROOT (or a fallback
    implementation). This fixes a security issue (GHSA-pxhw-h44j-8pfx)
    where file or directories created during sandbox setup could
    follow parent symlinks out of the sandbox.

bubblewrap 0.11.2
=================

Released: 2026-04-23

Bug fixes:

  * In setuid mode, don't run the low-privileged parts parts of the setup
    as dumpable, as that allows it to be ptraced which can lead to problems.
    This is CVE-2026-41163, and was reported by François Diakhate.

Enhancements:

  * New build option `-Dsupport_setuid`, which if set to false (which
    is the default) disables the support for setuid. Binaries built
    with this will refuse to run if made setuid. We recommend building
    normal bubblewrap binaries like this, which allows you to safely
    ignore any security issues that only affect setuid mode.

bubblewrap 0.11.1
=================

Released: 2026-03-21

Bug fixes:

  * Reset disposition of `SIGCHLD`, restoring normal subprocess management
    if bwrap was run from a process that was ignoring that signal,
    such as Erlang or volumeicon (#705, Joel Pelaez Jorge)

  * Don't ignore `--userns 0`, `--userns2 0` or `--pidns 0` if used
    (#731, Daniel Cazares).
    Note that using a fd number ≥ 3 for these purposes is still
    preferred, to avoid confusion with the stdin, stdout, stderr
    that will be inherited by the command inside the container.

  * Fix grammar in an error message (#694, J. Neuschäfer)

  * Fix a broken link in the documentation (#729, Aaron Brooks)

Internal changes:

  * Enable user namespaces in Github Actions configuration, fixing a CI
    regression with newer Ubuntu (#728, Joel Pelaez Jorge)

  * Clarify comments (#737, Simon McVittie)

bubblewrap 0.11.0
=================

Released: 2024-10-30

Dependencies:

  * Remove the Autotools build system. Meson ≥ 0.49.0 is now required
    at build-time. (#625, Hugo Osvaldo Barrera)

  * For users of bash-completion, bash-completion ≥ 2.10 is recommended.
    With older bash-completion, bubblewrap might install completions
    outside its `${prefix}` unless overridden with `-Dbash_completion_dir=…`.

Enhancements:

  * New `--overlay`, `--tmp-overlay`, `--ro-overlay` and `--overlay-src`
    options allow creation of overlay mounts.
    This feature is not available when bubblewrap is installed setuid.
    (#412, #663; Ryan Hendrickson, William Manley, Simon McVittie)

  * New `--level-prefix` option produces output that can be parsed by
    tools like `logger --prio-prefix` and `systemd-cat --level-prefix=1`
    (#646, Simon McVittie)

Bug fixes:

  * Handle `EINTR` when doing I/O on files or sockets (#657, Simon McVittie)

  * Don't make assumptions about alignment of socket control message data
    (#637, Simon McVittie)

  * Silence some Meson deprecation warnings (#647, @Sertonix)

  * Update URLs in documentation to https (#566, @TotalCaesar659)

  * Improve tests' compatibility with busybox (#627, @Sertonix)

  * Improve compatibility with Meson < 1.3.0 (#664, Simon McVittie)

Internal changes:

  * Consistently use `<stdbool.h>` for booleans (#660, Simon McVittie)

  * Avoid `-Wshadow` compiler warnings (#661, Simon McVittie)

  * Update Github Actions configuration (#658, Simon McVittie)

----

See also <https://github.com/containers/bubblewrap/releases>
