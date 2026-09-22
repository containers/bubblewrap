## Security and Disclosure Information Policy for the bubblewrap Project

The bubblewrap Project follows the [Security and Disclosure Information Policy](https://github.com/containers/common/blob/HEAD/SECURITY.md) for the Containers Projects.

### System security

bubblewrap is not a security boundary between the user and the OS,
because anything bubblewrap could do, a malicious user could equally
well do by writing their own tool equivalent to bubblewrap.

Older versions of bubblewrap were optionally setuid root. This is a
system security risk. See
https://github.com/containers/bubblewrap/blob/v0.11.2/SECURITY.md#system-security
for discussion of this historical configuration. Newer versions of
bubblewrap refuse to operate if the binary has been made setuid.

### Sandbox security

bubblewrap is a toolkit for constructing sandbox environments.
bubblewrap is not a complete, ready-made sandbox with a specific security
policy.

Some of bubblewrap's use-cases want a security boundary between the sandbox
and the real system; other use-cases want the ability to change the layout of
the filesystem for processes inside the sandbox, but do not aim to be a
security boundary.
As a result, the level of protection between the sandboxed processes and
the host system is entirely determined by the arguments passed to
bubblewrap.

Whatever program constructs the command-line arguments for bubblewrap
(often a larger framework like Flatpak, libgnome-desktop, sandwine
or an ad-hoc script) is responsible for defining its own security model,
and choosing appropriate bubblewrap command-line arguments to implement
that security model.

For example,
[CVE-2017-5226](https://github.com/flatpak/flatpak/security/advisories/GHSA-7gfv-rvfx-h87x)
(in which a Flatpak app could send input to a parent terminal using the
`TIOCSTI` ioctl) is considered to be a Flatpak vulnerability, not a
bubblewrap vulnerability.
