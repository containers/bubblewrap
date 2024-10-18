bubblewrap 0.11.0
=================

Released: not yet

Dependencies:

  * Remove the Autotools build system. Meson is now required at build-time.
    (#625, Hugo Osvaldo Barrera)

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

Internal changes:

  * Consistently use `<stdbool.h>` for booleans (#660, Simon McVittie)

  * Avoid `-Wshadow` compiler warnings (#661, Simon McVittie)

  * Update Github Actions configuration (#658, Simon McVittie)

----

See also <https://github.com/containers/bubblewrap/releases>
