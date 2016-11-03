#!/usr/bin/env python
"""
 Copyright (c) Steinwurf ApS 2016.
 All Rights Reserved

 Distributed under the "BSD License". See the accompanying LICENSE.rst file.
"""
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
        header = ' {mac:18s} {ps:3s} {frames:7s} {slept:5s} {average:4.3f}' \
                 '{alias}\n\n'
        self.screen.addstr(header.format(**
                           {'mac': 'mac',
                            'ps': 'ps',
                            'frames': 'frames',
                            'slept': 'slept',
                            'average': 'average',
                            'alias': 'alias/ip'
                           }))

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

            fmt = ' {mac:18s} {ps:<3d} {frames:<7d} {slept:<5d} {average:4.3f}'\
                  '{alias} {ip}\n'
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

            ## Calculate data average in kilo bytes
            station['data_size_average'] = (data_size / frames_pr_second) / 1000

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
