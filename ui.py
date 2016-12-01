#!/usr/bin/env python
"""
Copyright (c) Steinwurf ApS 2016.
All Rights Reserved

Distributed under the "BSD License". See the accompanying LICENSE.rst file.

  run ratemon.py with <wlan device> as interface
"""

class user_interface:

    def __init__(self, screen):
        self.screen = screen


    def update_screen(self, ratemon):
        """Update screen"""
        self.screen.clear()

        # Update stale notes
        ratemon.update_timeout()

        # Update Mac to IP table
        ratemon.update_ip_list()
