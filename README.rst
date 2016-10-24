wpsmon
======

Setup
-----
If you want to use an external (usb?) wifi dongle as your monitor device, here's
a guide on how to set it up.

First take note of the wifi channel you want to scan. This can be done using
the following command::

    iwlist wlan0 scan | egrep 'Address:|ESSID:|Channel:'




On debian you may need to install the package wireless-tools to have the iwlist
tool available::

    sudo aptitude update && aptitude install wireless-tools

The output from this command will resemble this::

    ...
    Cell 07 - Address: C0:4A:00:2D:15:C0
            Channel:36
            ESSID:"steinwurf-test-5g"
    Cell 08 - Address: 28:10:7B:8E:2A:F0
            Channel:1
            ESSID:"ChocolateCloud"
    Cell 09 - Address: B4:75:0E:D0:B5:B9
            Channel:11
            ESSID:"ccdc"
    ...

From this it can be seen that there's a cell for each ssid, e.g., the
steinwurf-test-5g network is on channel 36.

Now for setting up the monitor interface...

To make sure the network manager is not interfering with our business, we need
to add the following line to `/etc/network/interfaces` (from
http://superuser.com/q/9720)::

    iface mon0 inet manual

After adding this line, restart the network manager service to make sure it
picks up the changes::

    sudo service network-manager stop
    sudo service network-manager start

To add the mon0 monitor interface, we do the following
(from https://sandilands.info/sgordon/capturing-wifi-in-monitor-mode-with-iw):

To see the name of the physical adapter we want to add the monitor interface on,
we use the following command::

    iw dev

Add the monitor interface, where phy0 is the name found in the previous step::

    sudo iw phy phy0 interface add mon0 type monitor

We will capture with the mon0 interface, so you can delete the normal wlan0
interface::

    sudo iw dev wlan0 del

Now enable the mon0 interface using ifconfig::

    sudo ifconfig mon0 up

If you get the following error::

    SIOCSIFFLAGS: Cannot allocate memory

You may need to install the non-free ralink driver::

    sudo aptitude update && aptitude install firmware-ralink

Now we need to set the channel to monitor::

    sudo iw dev mon0 set channel 36

Here we are monitoring the steinwurf-test-5g on channel 36.

Install
-------

To use the script you need to install a few dependencies::

    sudo aptitude install libpcap-dev

and a few python packages, let's make a virtual env::

    virtualenv wpsmon
    source wpsmon/bin/activate
    pip install -r ./requirements.txt


 If you use version 6+ of ncurses you will need to make a soft link from
 version N to  version 5. Example for ncurses6::

    ln -s /usr/lib/libncursesw.so.6  /usr/lib/libncursesw.so.5

Run
---

When you have set everything up you can run the tool using the following
approach.

First, if you have the virtual env enabled, exit it by using this commmand::

    deactivate

Login as root and activate the virtualenv::

    su
    source wpsmon/bin/activate

You can now start the tool::

    ./wpsmon.py mon0

Introduction
------------
wpsmon is a tool to monitor the devices connected to a certain wifi. It can give
you information about which devices are in sleep mode and which are in active
mode.

The UI is a table with the following columns:

* bssid: the mac address of the device.
* ps: if 1 the device is in power save mode, if 0 the device is in active mode.
* frames: total number of data frames seen from device.
* slept: total number of times the devices have been in power save mode.
* tout: the time the device have been in power save mode (in milliseconds).
* tmax: the maximum time the device have been in power save mode
  (in milliseconds).
* alias/ip: the alias (human friendly name) or IP of the device (the alias can
  be specified using the alias file).

Each row is a device and the color of the text describes the status of the
device:

* green: device in active mode.
* red: device in power save mode.
* gray: device is stale i.e. we have not heard from device in SEC seconds
  (where SEC can be adjusted using the -s, --stale-time argument, default is 30)

If a device have been silent for SEC seconds, it will be removed from the list
(SEC can be adjusted using the -d, --dead-time argument, default is 60).

Sources
-------

802.11-2012 Standard::

  http://standards.ieee.org/getieee802/download/802.11-2012.pdf
  8.2.4.1.7 Power Management Field
