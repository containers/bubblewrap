#!/usr/bin/env python3
# Copyright 2024 Alexander Larsson
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Helper script that runs inside a bwrap sandbox. Receives commands
# over a socket fd and sends back JSON results.
# stdout/stderr remain free for debug logging.

import importlib.util
import json
import os
import socket
import sys
import traceback
import unittest


def load_module(module_path):
    spec = importlib.util.spec_from_file_location('_sandbox_test', module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def handle_run_test(cmd):
    info = cmd['run_test']
    mod = load_module(info['module'])
    cls = getattr(mod, info['class'])
    method_name = info['method']

    tc = cls(method_name)
    try:
        getattr(tc, method_name)()
        return {'ok': True}
    except Exception:
        return {'ok': False, 'error': traceback.format_exc()}


def handle_eval(cmd):
    code = cmd.get('eval', '')
    try:
        result = eval(code)  # noqa: S307
        return {'ok': True, 'result': result}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} SOCKET_FD', file=sys.stderr)
        sys.exit(1)

    fd = int(sys.argv[1])
    sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
    os.close(fd)

    buf = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk

        while b'\n' in buf:
            line, buf = buf.split(b'\n', 1)
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError as e:
                resp = {'ok': False, 'error': f'bad json: {e}'}
                sock.sendall(json.dumps(resp).encode() + b'\n')
                continue

            if cmd.get('exit'):
                sock.close()
                return

            if 'run_test' in cmd:
                resp = handle_run_test(cmd)
            elif 'eval' in cmd:
                resp = handle_eval(cmd)
            else:
                resp = {'ok': False, 'error': 'unknown command'}

            sock.sendall(json.dumps(resp).encode() + b'\n')

    sock.close()


if __name__ == '__main__':
    main()
