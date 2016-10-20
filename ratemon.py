#!/usr/bin/env python2

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


def mac_string(mac):
    """Convert mac to string."""
    return ':'.join('{0:02X}'.format(ord(b)) for b in mac)


class ratemon():
    """Monitor object."""

    def __init__(self, interface, timeout_ms=250):
        """Initialize monitor object."""
        self.captured = 0
        self.stations = {}
        self.alias = {}
        self.ips = {}

        self.stale_time = 0
        self.dead_time = 0

        self.interface = interface
        self.only_alias = False

        self.prog = sys.argv[0].replace('./', '')

        # Setup capture
        self.pc = pcapy.open_live(interface, 65536, 1, timeout_ms)

    def set_screen(self, screen):
        """Set the screen."""
        self.screen = screen

    def set_stale_time(self, stale_time):
        """Set stale time."""
        self.stale_time = stale_time

    def set_dead_time(self, dead_time):
        """Set dead time."""
        self.dead_time = dead_time

    def set_only_alias(self, only_alias):
        """Set set only alias."""
        self.only_alias = only_alias

    def update_ip_list(self):
        """Update the ip list."""
        output = subprocess.check_output(['ip', 'neighbor', 'show'])
        ip_neigh = str(output).split('\n')
        for entry in ip_neigh:
            try:
                m = re.split('[\s]+', entry)
                ip = m[0].strip()
                lladdr = m[4].strip().lower()
                self.ips[lladdr] = ip
            except:
                pass

    def next(self):
        """Get and parse the next packet."""
        header, packet = self.pc.next()
        if header and packet:
            self.parse_packet(header, packet)

    def update_timeout(self):
        """Update timeout."""
        now = time.time()
        for station in self.stations.values():
            age = now - station['last']
            if self.stale_time > 0 and age > self.stale_time:
                station['stale'] = True
            if self.dead_time > 0 and age > self.dead_time:
                self.stations.pop(station['mac'])

    def update_screen(self):
        """Update screen."""
        self.screen.clear()

        # Update stale nodes
        self.update_timeout()

        # Update MAC to IP table
        self.update_ip_list()

        nodes = len(self.stations)

        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

        top = '[{0}][frames: {1}][nodes: {2}][date: {3}]\n\n'
        self.screen.addstr(top.format(self.prog, self.captured, nodes, now))
        header = ' {mac:18s} {ps:3s} {frames:7s} {slept:5s} ' \
                 '{tout:>7s} {tmax:>7s}  {alias}\n\n'
        self.screen.addstr(header.format(**
                           {'mac': 'mac',
                            'ps': 'ps',
                            'frames': 'frames',
                            'slept': 'slept',
                            'tout': 'tout',
                            'tmax': 'tmax',
                            'alias': 'alias/ip'}))

        # Sort stations according to creation time
        sorted_stations = sorted(
            self.stations.values(),
            key=lambda s: int(s['created'] * 1000))

        # Get window dimensions
        maxy, maxx = self.screen.getmaxyx()

        shown = 0
        for station in sorted_stations:
            # Break if we cant fit more clients on the screen
            y, x = self.screen.getyx()
            if y >= maxy - 3:
                overflow = nodes - shown
                self.screen.addstr(" {0} nodes not shown...".format(overflow))
                break
            shown += 1

            # Continue if only showing aliased nodes
            if self.only_alias and not station['alias']:
                continue

            fmt = ' {mac:18s} {ps:<3d} {frames:<7d} {slept:<5d}'\
                  '{tout:>7.1f} {tmax:>7.1f} {alias} {ip}\n'
            text = fmt.format(**station)
            if station['stale']:
                color = curses.color_pair(3) | curses.A_BOLD
            elif station['ps']:
                color = curses.color_pair(1)
            else:
                color = curses.color_pair(2)
            self.screen.addstr(text, color)

        # Show help text
        footer = "q: quit | r: reset counters | R: reset nodes"
        self.screen.addstr(maxy - 1, 1, footer)

        self.screen.refresh()

    def add_alias(self, host, name):
        """Add alias."""
        self.alias[host.lower()] = name

    def reset_counters(self):
        """Reset counters."""
        self.captured = 0
        for station in self.stations.values():
            station['frames'] = 0
            station['slept'] = 0
            station['tout'] = 0
            station['tmax'] = 0

    def reset_nodes(self):
        """Reset nodes."""
        self.stations = {}
        self.reset_counters()

    def parse_packet(self, header, packet):
        """Parse packet."""
        self.captured += 1
        # todo let's output the errors somewhere.
        tap = dpkt.radiotap.Radiotap(packet)
        tap_len = socket.ntohs(tap.length)

        # Parse IEEE80211 header
        wlan = dpkt.ieee80211.IEEE80211(packet[tap_len:])

        # Currently we only care about data frames
        if wlan.type is not dpkt.ieee80211.DATA_TYPE:
            return

        ps = wlan.pwr_mgt
        mac = mac_string(wlan.data_frame.src).lower()

        # Lookup station
        station = self.stations.get(mac)

        # Get current time
        now = time.time()

        # New station
        if not station:
            self.stations[mac] = {}
            station = self.stations[mac]
            station['mac'] = mac
            station['alias'] = self.alias.get(mac, '')
            station['ip'] = ''
            station['created'] = now
            station['frames'] = 0
            station['tout'] = 0
            station['tmax'] = 0
            station['slept'] = 0
            station['data_size_received'] = 0
            station['data_size_average'] = 0
            station['frames_pr_second'] = 0
            station['second'] = now

        # Detect if a station is going to sleep
        old_ps = station.get('ps', 0)
        station['ps'] = ps
        going_to_ps = ps and not old_ps

        # Count number of sleeps
        if going_to_ps:
            station['slept'] += 1

        # Calculate timeout if going to PS
        if 'last' in station and going_to_ps:
            diff_ms = (now - station['last']) * 1000
            station['tout'] = diff_ms

            if diff_ms > station['tmax']:
                station['tmax'] = diff_ms

        # Log last updated time
        station['last'] = now

        # Increment packet frame count
        station['frames'] += 1
        station['frames_pr_second'] += 1

        # update total data received
        # Based on: http://stackoverflow.com/a/3742428/936269
        station['data_size_received'] += header.getlen()

        # If a second has passed calculated average
        if (now - station['second']) >= 1:
            data_size = station['data_size_received']
            frames_pr_second = station['frames_pr_second']

            station['data_size_average'] = data_size / frames_pr_second

            # reset
            station['second'] = now
            station['data_size_received'] = 0
            station['frames_pr_second'] = 0

        # Try to set IP if empty
        if station['ip'] == '':
            station['ip'] = self.ips.get(mac, '')
            if station['ip'] != '' and station['alias'] != '':
                station['ip'] = ' (' + station['ip'] + ')'

        # Station is not stale
        station['stale'] = False


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
