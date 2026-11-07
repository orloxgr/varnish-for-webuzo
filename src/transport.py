"""One-shot native-panel IPC; no account-owned PHP can submit requests."""
import json
import os
import pwd
import re
import secrets
import stat

import state


def consume(identity, suffix='.json', limit=1024 * 1024):
    if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity): raise ValueError('Invalid panel request')
    panel = pwd.getpwnam('webuzo')
    fd = os.open(state.RUN, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_gid != panel.pw_gid or stat.S_IMODE(info.st_mode) != 0o730:
            raise ValueError('Untrusted panel transport')
        handle = os.open(identity + suffix, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(handle)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != panel.pw_uid or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
                raise ValueError('Untrusted panel upload')
            with os.fdopen(handle, 'rb') as stream:
                handle = None; raw = stream.read(limit + 1)
            if len(raw) > limit: raise ValueError('Request exceeds the permitted size')
            os.unlink(identity + suffix, dir_fd=fd)
            return raw
        finally:
            if handle is not None: os.close(handle)
    finally: os.close(fd)


def request(identity):
    value = json.loads(consume(identity))
    if not isinstance(value, dict): raise ValueError('Expected a panel request object')
    return value


def publish(identity, payload, suffix='.response'):
    """Native wexec returns a small receipt; PHP reads the private response file."""
    if not re.fullmatch('[0-9a-f]{64}', identity): raise ValueError('Invalid response identity')
    panel = pwd.getpwnam('webuzo')
    directory = os.open(state.RUN, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = identity + suffix
    try:
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_gid != panel.pw_gid or stat.S_IMODE(info.st_mode) != 0o730:
            raise ValueError('Untrusted panel transport')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(payload); stream.flush(); os.fsync(stream.fileno())
                os.fchown(stream.fileno(), panel.pw_uid, panel.pw_gid)
        except Exception:
            os.unlink(name, dir_fd=directory); raise
    finally: os.close(directory)
