# Security Policy

## Security Scope

Bubblewrap is a low-level utility designed to run applications inside unprivileged sandboxes. It provides process isolation by creating mount, user, IPC, PID, network, UTS, and cgroup namespaces, and applying user-supplied seccomp filters.

### What is in Scope
- Privilege escalation vulnerabilities or host namespace breakout bugs inside `bwrap` itself.
- Information leaks or descriptor leaks from `bwrap` to the sandboxed process.

### What is Out of Scope (Not Considered a Vulnerability)
- **Caller Misuse / Argument Configuration**: Policy decisions and choice of arguments (e.g., mounting sensitive host paths like `/home` or `/sys` into the sandbox, or failing to use `--new-session` to prevent terminal injection). The calling application or script is responsible for its own security model.
- **Upstream Wrapper Policy**: Insecure defaults or behavior in wrapper frameworks (e.g., Flatpak).

## Setuid Mode Deprecated

Support for executing bubblewrap as a setuid-root binary is **deprecated** as of release 0.11.2 (due to security concerns such as CVE-2026-41163) and is unsupported in recent releases.

By default, recent releases are built with `-Dsupport_setuid=false`. Binaries built this way strictly refuse to run if they are setuid-root. Users must run bubblewrap on systems supporting unprivileged user namespaces.

## Reporting a Vulnerability

If you discover a security vulnerability in bubblewrap, please report it privately:

- Submit a private report using **GitHub Private Vulnerability Reporting** on the [containers/bubblewrap repository](https://github.com/containers/bubblewrap/security/advisories/new).

Please do not open public issues or pull requests to report security concerns.
