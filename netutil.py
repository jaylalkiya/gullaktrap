"""
Socket binding helpers shared by the HTTP, FTP and SSH sensors.

Why this module exists
----------------------
Every sensor used to bind with SO_REUSEADDR. On Linux that only relaxes the
TIME_WAIT restriction and is harmless, but on Windows SO_REUSEADDR lets a
socket bind an address another process is already listening on. The bind
returns success, the sensor reports itself armed, and the operating system
keeps delivering connections to whoever bound first -- so the honeypot
listens to nothing while the dashboard shows a healthy green light.

That is the worst failure mode a honeypot can have, so binding policy is
centralised here rather than repeated in three modules.
"""

import errno
import socket
import sys

WINDOWS = sys.platform.startswith('win')

# Windows only: refuses the bind outright if anybody else holds the address,
# and stops anyone hijacking ours afterwards.
_EXCLUSIVE = getattr(socket, 'SO_EXCLUSIVEADDRUSE', None)


class PortUnavailable(OSError):
    """Raised when a sensor port cannot be bound exclusively."""


def apply_bind_policy(sock):
    """Set the reuse flags appropriate to this platform.

    Windows gets SO_EXCLUSIVEADDRUSE so an occupied port fails loudly.
    POSIX keeps SO_REUSEADDR, where it is safe and avoids TIME_WAIT pain
    on restart.
    """
    if WINDOWS:
        if _EXCLUSIVE is not None:
            sock.setsockopt(socket.SOL_SOCKET, _EXCLUSIVE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return sock


def lan_ip():
    """This host's address on the local network, or None if it has none.

    Opening a UDP socket toward an off-link address makes the routing table
    pick the interface that would carry real traffic, which is the address
    an attacker on the LAN would connect to. No packet is ever sent, so
    this works with no network and no name resolution.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(('192.0.2.1', 9))      # RFC 5737, never routed
        ip = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if ip.startswith('127.') else ip


def describe_port(port):
    """Human-readable reason the port cannot be used, or None if it is free.

    Probes with the same policy the real listener will use, so a probe that
    passes means the listener will bind for real.
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return 'Port %r is not a number.' % (port,)

    if not 0 < port < 65536:
        return 'Port %d is out of range (1-65535).' % port

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        apply_bind_policy(probe)
        probe.bind(('0.0.0.0', port))
        return None
    except OSError as exc:
        return _explain(port, exc)
    finally:
        probe.close()


def _explain(port, exc):
    """Turn a bind errno into one short sentence an operator can act on.

    Windows phrases EADDRINUSE as 'Only one usage of each socket address...',
    which is accurate and useless in a dashboard toast.
    """
    err = getattr(exc, 'errno', None)

    if err in (errno.EADDRINUSE, getattr(errno, 'WSAEADDRINUSE', 10048)):
        return ('port %d is already in use by another service -- '
                'choose a different port.' % port)

    if err in (errno.EACCES, errno.EPERM,
               getattr(errno, 'WSAEACCES', 10013)):
        if port < 1024:
            return ('port %d needs administrator privileges -- '
                    'use a port above 1024.' % port)
        return 'port %d was refused by the system (permission denied).' % port

    if err == getattr(errno, 'EADDRNOTAVAIL', None):
        return 'port %d could not be bound on this interface.' % port

    return 'port %d is unavailable: %s' % (port, exc.strerror or exc)


def ensure_free(port, protocol=''):
    """Raise PortUnavailable with an actionable message if `port` is taken."""
    reason = describe_port(port)
    if reason is None:
        return int(port)

    label = ('%s sensor: ' % protocol.upper()) if protocol else ''
    raise PortUnavailable(label + reason)


def bind_listener(port, backlog=5, protocol=''):
    """Return a listening socket bound exclusively to 0.0.0.0:port."""
    ensure_free(port, protocol)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        apply_bind_policy(sock)
        sock.bind(('0.0.0.0', int(port)))
        sock.listen(backlog)
    except OSError as exc:
        sock.close()
        label = ('%s sensor: ' % protocol.upper()) if protocol else ''
        raise PortUnavailable(label + _explain(int(port), exc))
    return sock
