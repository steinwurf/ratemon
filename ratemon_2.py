#!/usr/bin/env python
"""
Copyright (c) Steinwurf ApS 2016.
All Rights Reserved

Distributed under the "BSD License". See the accompanying LICENSE.rst file.

  run ratemon.py with <wlan device> as interface
"""
class ratemon:
    """Monitor object"""

    def __init__(self, interface, timeout_ms=250):
        """Initialize monitor object"""
        self.captured = 0
        self.stations = {}
        self.alias = {}
        self.ips = {}

        self.stale_time = {}
        self.dead_time - 0

        self.interface = interface
        self.only_alias = False

        # self.prog = sys.arg[0].replace('./' '') ## need ???

        # Setup capture
        self.pc = pcapy.open_live(interface, 65536, 1, timeout_ms)

    def set_stale_time(self, stale_time):
        """Set stale time."""
        self.stale_time = stale_time

    def set_dead_time(self, dead_time):
        """Set dead time."""
        self.dead_time = dead_time

    def set_only_alias(self, only_alias):
        """Set only alias."""
        self.only_alias = only_alias

    def update_ip_list(self):
        """Update the ip list."""
        output = subprocess.check_output(['ip', 'neighbor', 'show'])
        ip_neight = str(output).split('\n')

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

    def add_alias(self, host, name):
        """Add alias."""
        self.alias[host.lower()] = name

    def reset_counters(self):
        """Reset counters."""
        self.captured = 0
        for station in self.stations.values():
            station['frames'] = 0
            station['kbs'] = 0.0
            station['received'] = 0.0

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
            station['received'] = 0.0
            station['kbs'] = 0.0
            station['fps'] = 0
            station['start'] = now

        # Log last updated time
        station['last'] = now

        # Increment packet frame count
        station['frames'] += 1
        station['fps'] += 1

        # Registre amount of data received
        station['received'] += header.getlen()

        if (now - station['start'] >= 1):
            received = station['received']
            fps = station['fps']

            ## Calculate kB/S
            station['kbs'] = received / 1000.0
            ## Reset data counters
            station['start'] = now
            station['received'] = 0.0
            station['fps'] = 0

        # Try to set IP if empty
        if station['ip'] == '':
            station['ip'] = self.ips.get(mac, '')
            if station['ip'] != '' and station['alias'] != '':
                station['ip'] = ' (' + station['ip'] + ')'

        # Station is not stale
        station['stale'] = False
