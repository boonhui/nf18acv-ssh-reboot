#!/usr/bin/env python3
#
# Reboot NetComm NF18ACV device via ssh interface
#
# Usage: nf18acv-ssh-reboot.py <device ip or name>
#

import netrc
import os
import re
import sys

if sys.platform == 'win32':
    import paramiko
    from paramiko_expect import SSHClientInteraction
else:
    import pexpect


def exit_with_usage():

    print("Usage: nf18acv-ssh-reboot.py <device ip or name>")
    os._exit(1)


def main():

    if len(sys.argv) != 2:
        exit_with_usage()

    valid_ip_pattern = r"""
        ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}
        ([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25\[0-5])$"""
    is_valid_ip = re.match(valid_ip_pattern, sys.argv[1], re.VERBOSE)

    valid_hostname_pattern = r"""
        ^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*
        ([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"""
    is_valid_hostname = re.match(valid_hostname_pattern, sys.argv[1],
                                 re.VERBOSE)

    if is_valid_ip is None and is_valid_hostname is None:
        exit_with_usage()

    device_addr = sys.argv[1]
    device_mach = netrc.netrc().authenticators(device_addr)

    if device_mach is None:
        print("ERROR: can't obtain netrc credentials for %s." % device_addr)
        sys.exit(1)

    device_user = device_mach[0]
    device_pass = device_mach[2]

    if sys.platform == 'win32':
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=device_addr, username=device_user,
                           password=device_pass, timeout=10)

            with SSHClientInteraction(client, timeout=10,
                                      display=False) as interact:
                interact.expect('> ', default_match_prefix='.*')
                interact.send('reboot')
                interact.expect()

        except Exception:
            print("ERROR: can't open ssh connection to %s." % device_addr)

        finally:
            try:
                client.close()
            except Exception:
                pass

    else:
        try:
            child = pexpect.spawn('ssh -oStrictHostKeyChecking=no \
                                  -oConnectTimeout=10 \
                                  -oKexAlgorithms=diffie-hellman-group1-sha1 \
                                  -oMACs=hmac-sha1 -c3des-cbc -l %s %s' %
                                  (device_user, device_addr), timeout=10)
            child.expect('(?i)password')
            child.sendline(device_pass)
            child.expect('> ')
            child.sendline('reboot')
            child.expect(pexpect.EOF)

        except Exception:
            print("ERROR: can't open ssh connection to %s." % device_addr)

        finally:
            try:
                child.close()
            except Exception:
                pass


if __name__ == '__main__':
    main()
