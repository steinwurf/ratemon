#!/usr/bin/env python

"""
Dump 802.11 power-save status

Add a monitor interface and specify channel before use:
  iw phy <phy> interface add mon0 type monitor
  iw mon0 set channel <channel> HT20

Replace <phy> and <channel> with the correct values.

Alternative setup:
  ifconfig <wlan device> down
  iwconfig <wlan device> mode monitor
  ifconfig <wlan device> up
  iw <wlan device> set channel <channel> HT20

  run wpsmon.py with <wlan device> as interface
"""

from __future__ import print_function

import sys
import os
import time
import datetime
import argparse
import socket
import re
import curses
import subprocess
import dpkt
import pcapy

import ratemon


def mac_string(mac):
    """Convert mac to string."""
    return ':'.join('{0:02X}'.format(ord(b)) for b in mac)

def parse_alias_pair(alias):
    """Parse alias mac, name pair."""
    match = re.match('(..:..:..:..:..:..)=(.*)', alias, flags=re.IGNORECASE)
    if not match:
        raise RuntimeError('Failed to parse alias: ' + alias)
    return match.group(1), match.group(2)


def alias_type(alias):
    """parse alias argument."""
    try:
        host, name = parse_alias_pair(alias)
    except Exception as e:
        raise argparse.ArgumentTypeError(e)
    return (host, name)


def main():
    """Main function."""
    formatter = argparse.RawTextHelpFormatter

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=formatter)

    parser.add_argument('interface', help='interface to sniff')
    parser.add_argument('-a', '--alias', metavar='<mac=name>',
                        action='append', type=alias_type,
                        help='alias mac with name')
    parser.add_argument('-f', '--alias-file', metavar='<file>',
                        help='read aliases from file',
                        default='steinwurf_alias.txt')
    parser.add_argument('-A', '--only-alias', action='store_true',
                        help='only show aliased nodes')
    parser.add_argument('-s', '--stale-time',
                        type=int, default=30, metavar='<sec>',
                        help='consider node stale after SEC seconds')
    parser.add_argument('-d', '--dead-time',
                        type=int, default=60, metavar='<sec>',
                        help='consider node dead after SEC seconds')

    args = parser.parse_args()

    # Create monitor object
    try:
        mon = ratemon(args.interface)
    except Exception as e:
        print("Failed to open capture: " + str(e))
        sys.exit(os.EX_NOPERM)

    # Setup timeouts
    mon.set_stale_time(args.stale_time)
    mon.set_dead_time(args.dead_time)

    # Map aliases from command line
    if args.alias is not None:
        for a in args.alias:
            host, name = a
            mon.add_alias(host, name)

    # Map aliases from file
    if args.alias_file is not None:
        with open(args.alias_file) as f:
            for line in f:
                # Skip comments and empty lines
                if re.match('^\s*(#.*)?$', line):
                    continue
                host, name = parse_alias_pair(line)
                mon.add_alias(host, name)

    mon.set_only_alias(args.only_alias)

    # Setup curses
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    curses.curs_set(0)
    stdscr.nodelay(1)

    # Setup colors
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_BLACK, -1)

    # Setup screen
    mon.set_screen(stdscr)

    last_update = 0
    while True:
        now = time.time()
        if now > last_update + 0.1:
            try:
                mon.update_screen()
            except:
                pass
            last_update = now
        try:
            mon.next()
        except KeyboardInterrupt:
            break
        except:
            pass

        ch = stdscr.getch()
        if ch == ord('q'):
            break
        if ch == ord('r'):
            mon.reset_counters()
        if ch == ord('R'):
            mon.reset_counters()
            mon.reset_nodes()

    # Cleanup curses
    curses.nocbreak()
    curses.echo()
    curses.curs_set(1)
    curses.endwin()


if __name__ == '__main__':
    main()
