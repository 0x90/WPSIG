#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# WPSIG - WiFi Protected Setup Information Gathering
#    Copyright (C) 2013  Core Security Technologies
#    Copyright (C) 2015, 2016 Oleg Kupreev
#
#    This file is part of WPSIG.
#
#    WPSIG is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WPSIG is distributed in the hope that it will /home/nop/.pyenv/versions/wpsig/bin/be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WPSIG.  If not, see <http://www.gnu.org/licenses/>.
#
#    Author: Andrés Blanco 
#
#        ablanco [at coresecurity.com]
#        oss     [at coresecurity.com]
#        Oleg Kupreev <oleg.kupreev@gmail.com>

import argparse
import logging
import os
import sys
import re
import random
import signal
import struct
import subprocess

# external dependencies
from colorama import Fore
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import RandMAC, sendp
from scapy.layers.dot11 import RadioTap
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt
from impacket import dot11
from impacket.ImpactDecoder import RadioTapDecoder
import netaddr


def is_valid_mac_address(address):
    "Return True if it is a valid mac address."
    if address is None:
        return False
    macAddress = re.compile("^((?:[0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2})$")
    return macAddress.match(address)


def get_vendor(addr):
    try:
        return netaddr.OUI(addr[:8].replace(':', '-')).registration().org
    except netaddr.core.NotRegisteredError:
        return 'UNKNOW'


class WPSParser(object):
    WPS_DATA_ELEMENTS = {
        0x1001: "AP Channel",
        0x1002: "Association State",
        0x1003: "Authentication Type",
        0x1004: "Authentication Type Flags",
        0x1005: "Authenticator",
        0x1008: "Config Methods",
        0x1009: "Configuration Error",
        0x100A: "Confirmation URL4",
        0x100B: "Confirmation URL6",
        0x100C: "Connection Type",
        0x100D: "Connection Type Flags",
        0x100E: "Credential",
        0x1011: "Device Name",
        0x1012: "Device Password ID",
        0x1014: "E-Hash1",
        0x1015: "E-Hash2",
        0x1016: "E-SNonce1",
        0x1017: "E-SNonce2",
        0x1018: "Encrypted Settings",
        0x100F: "Encryption Type",
        0x1010: "Encryption Type Flags",
        0x101A: "Enrollee Nonce",
        0x101B: "Feature ID",
        0x101C: "Identity",
        0x101D: "Identity Proof",
        0x101E: "Key Wrap Authenticator",
        0x101F: "Key Identifier",
        0x1020: "MAC Address",
        0x1021: "Manufacturer",
        0x1022: "Message Type",
        0x1023: "Model Name",
        0x1024: "Model Number",
        0x1026: "Network Index",
        0x1027: "Network Key",
        0x1028: "Network Key Index",
        0x1029: "New Device Name",
        0x102A: "New Password",
        0x102C: "OOB Device Password",
        0x102D: "OS Version",
        0x102F: "Power Level",
        0x1030: "PSK Current",
        0x1031: "PSK Max",
        0x1032: "Public Key",
        0x1033: "Radio Enabled",
        0x1034: "Reboot",
        0x1035: "Registrar Current",
        0x1036: "Registrar Established",
        0x1037: "Registrar List",
        0x1038: "Registrar Max",
        0x1039: "Registrar Nonce",
        0x103A: "Request Type",
        0x103B: "Response Type",
        0x103C: "RF Bands",
        0x103D: "R-Hash1",
        0x103E: "R-Hash2",
        0x103F: "R-SNonce1",
        0x1040: "R-SNonce2",
        0x1041: "Selected Registrar",
        0x1042: "Serial Number",
        0x1044: "Wi-Fi Protected Setup State",
        0x1045: "SSID",
        0x1046: "Total Networks",
        0x1047: "UUID-E",
        0x1048: "UUID-R",
        0x1049: "Vendor Extension",
        0x104A: "Version",
        0x104B: "X.509 Certificate Request",
        0x104C: "X.509 Certificate",
        0x104D: "EAP Identity",
        0x104E: "Message Counter",
        0x104F: "Public Key Hash",
        0x1050: "Rekey Key",
        0x1051: "Key Lifetime",
        0x1052: "Permitted Config Methods",
        0x1053: "Selected Registrar Config Methods",
        0x1054: "Primary Device Type",
        0x1055: "Secondary Device Type List",
        0x1056: "Portable Device",
        0x1057: "AP Setup Locked",
        0x1058: "Application Extension",
        0x1059: "EAP Type",
        0x1060: "Initialization Vector",
        0x1061: "Key Provided Automatically",
        0x1062: "802.1X Enabled",
        0x1063: "AppSessionKey",
        0x1064: "WEPTransmitKey"
    }

    def __init__(self):
        pass

    def parse_wps(self, IEs):
        "Returns dictionary with WPS Information."
        ret = {}

        for element in IEs:
            offset = 0
            data = element[1]
            offset += 1

            dataLength = len(data)
            while (offset < dataLength):
                tagType = struct.unpack("!H", data[offset:offset + 2])[0]
                offset += 2
                tagLen = struct.unpack("!H", data[offset:offset + 2])[0]
                offset += 2
                tagData = data[offset:offset + tagLen]
                offset += tagLen

                # Get the Tag Type
                if self.WPS_DATA_ELEMENTS.has_key(tagType):
                    tagType = self.WPS_DATA_ELEMENTS[tagType]
                else:
                    tagType = None

                if tagType == "Wi-Fi Protected Setup State":
                    if tagData == '\x01':
                        tagData = "Not Configured"
                    elif tagData == '\x02':
                        tagData = "Configured"
                    else:
                        tagData = 'Reserved'

                if tagType == "UUID-E":
                    aux = ''
                    for c in tagData:
                        aux += "%02X" % ord(c)
                    tagData = aux

                if tagType == "Response Type":
                    if tagData == '\x00':
                        tagData = 'Enrollee, Info Only'
                    elif tagData == '\x01':
                        tagData = 'Enrollee, open 802.1X'
                    elif tagData == '\x02':
                        tagData = 'Registrar'
                    elif tagData == '\x03':
                        tagData = 'AP'
                    else:
                        tagData = '<unkwon>'

                if tagType == "Primary Device Type":
                    category = struct.unpack("!H", tagData[0:2])[0]
                    subCategory = struct.unpack("!H", tagData[6:8])[0]
                    if category == 1:
                        category = "Computer"
                        if subCategory == 1:
                            subCategory = "PC"
                        elif subCategory == 2:
                            subCategory = "Server"
                        elif subCategory == 3:
                            subCategory = "Media Center"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 2:
                        category = "Input Device"
                        subCategory = "<unkwon>"
                    elif category == 3:
                        category = "Printers, Scanners, Faxes and Copiers"
                        if subCategory == 1:
                            subCategory = "Printer"
                        elif subCategory == 2:
                            subCategory = "Scanner"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 4:
                        category = "Camera"
                        if subCategory == 1:
                            subCategory = "Digital Still Camera"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 5:
                        category = "Storage"
                        if subCategory == 1:
                            subCategory = "NAS"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 6:
                        category = "Network Infrastructure"
                        if subCategory == 1:
                            subCategory = "AP"
                        elif subCategory == 2:
                            subCategory = "Router"
                        elif subCategory == 3:
                            subCategory = "Switch"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 7:
                        category = "Display"
                        if subCategory == 1:
                            subCategory = "Television"
                        elif subCategory == 2:
                            subCategory = "Electronic Picture Frame"
                        elif subCategory == 3:
                            subCategory = "Projector"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 8:
                        category = "Multimedia Devices"
                        if subCategory == 1:
                            subCategory = "DAR"
                        elif subCategory == 2:
                            subCategory = "PVR"
                        elif subCategory == 3:
                            subCategory = "MCX"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 9:
                        category = "Gaming Devices"
                        if subCategory == 1:
                            subCategory = "Xbox"
                        elif subCategory == 2:
                            subCategory = "Xbox360"
                        elif subCategory == 3:
                            subCategory = "Playstation"
                        else:
                            subCategory = "<unkwon>"
                    elif category == 10:
                        category = "Telephone"
                        if subCategory == 1:
                            subCategory = "Windows Mobile"
                        else:
                            subCategory = "<unkwon>"
                    else:
                        category = "<unkwon>"
                        subCategory = "<unkwon>"
                    tagData = "%s - %s" % (category, subCategory)

                    if tagType == "Version":
                        tagData = struct.unpack("B", tagData)[0]
                        major = tagData >> 4
                        minor = tagData & 0x0F
                        tagData = "%d.%d" % (major, minor)

                    if tagType == "Config Methods":
                        methods = {
                            0x0001: "USB",
                            0x0002: "Ethernet",
                            0x0004: "Label",
                            0x0008: "Display",
                            0x0010: "External NFC Token",
                            0x0020: "Integrated NFC Token",
                            0x0040: "NFC Interface",
                            0x0080: "PushButton",
                            0x0100: "Keypad"
                        }
                        result = []
                        tagData = struct.unpack("!H", tagData)[0]
                        for key, value in methods.items():
                            if key & tagData:
                                result.append(value)
                        tagData = ", ".join(result)

                if tagType:
                    ret[tagType] = tagData

        return ret

    def has_wps(self, IEs):
        "Returns True if WPS Information Element is present."
        for element in IEs:
            oui = element[0]
            data = element[1]
            if oui == "\x00\x50\xF2" and data[0] == "\x04":  # WPS IE
                return True
        return False


class WpsScanner(object):
    def __init__(self, args):
        self.args = args
        self.accessPoints = []
        self.interface = args.interface
        self.macAddress = args.source if is_valid_mac_address(args.source) else None
        self.filename = args.write
        self.wps_parser = WPSParser()
        self.captured = []
        self.channel = None
        # self.iw.set_monitor()
        self.ap_dict = {}
        self.clients_dict = {}
        self.rtDecoder = RadioTapDecoder()

    def iwconfig_set_channel(self, channel):
        cmd = 'iwconfig %s channel %s' % (self.interface, channel)
        return subprocess.Popen(cmd, shell=True).communicate()

    def set_monitor(self):
        return subprocess.Popen('ifconfig %s down && iw %s set type monitor && ifconfig %s up' %
                                (self.interface, self.interface, self.interface), shell=True).communicate()

    def set_channel(self, channel, width=None):
        cmd = 'iw %s set channel %s ' % (self.interface, channel)
        self.channel = channel
        if width is not None:
            if width == 20:
                cmd += 'HT20'
            elif width == 40:
                cmd += 'HT40+'
            elif width == -40:
                cmd += 'HT40-'
        return subprocess.Popen(cmd, shell=True).communicate()

    def signal_handler(self, frame, code):
        print("Ctrl+C caught. Exiting..")
        sys.exit(-1)

    def __getAddressFromList(self, bytes_list):
        "Return a string of a MAC address on a bytes list."
        return ":".join(map(lambda x: "%02X" % x, bytes_list))

    def __getListFromAddress(self, address):
        "Return a list from a MAC address string."
        return map(lambda x: int(x, 16), address.split(":"))

    def _packet_filter(self, pkt):
        # wlan.fc.type == 0           Management frames
        # wlan.fc.type == 1           Control frames
        # wlan.fc.type == 2           Data frames
        # wlan.fc.type_subtype == 0   Association request
        # wlan.fc.type_subtype == 1   Association response
        # wlan.fc.type_subtype == 2   Reassociation request
        # wlan.fc.type_subtype == 3   Reassociation response
        # wlan.fc.type_subtype == 4   Probe request
        # wlan.fc.type_subtype == 5   Probe response
        # wlan.fc.type_subtype == 8   Beacon
        return True if pkt.haslayer(Dot11) and pkt.type == 0 else False
        # return True if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype in [5, 8] else False

    def _packet_handler(self, pkt):
        """Process 802.11 Packets."""
        data = str(pkt)
        try:
            self.rtDecoder.decode(data)
            beacon = self.rtDecoder.get_protocol(dot11.Dot11ManagementBeacon)
            probe = self.rtDecoder.get_protocol(dot11.Dot11ManagementProbeResponse)

            # Process Beacons and inject Probe Requests only when not passive
            if beacon is not None:
                self.handle_beacon(data)
            elif probe is not None:
                info = self.handle_probe_response(data)
                if info:
                    bssid, essid = info[0], info[1]
                    vendor, wpsInfo = info[2], info[3]
                    result = "[%s] - [%s]\t%s'\nWPS Information\n" % (bssid, essid, vendor)
                    for key, value in wpsInfo.items():
                        result += "  * %s: %s\n" % (key, repr(value))
                    result += "-" * 80 + "\n"
                    return result
            elif pkt.haslayer(Dot11ProbeReq):
                self.handle_probe_req(pkt)
        except Exception as e:
            return None

    def handle_beacon(self, pkt):
        """Process 802.11 Beacon Frame for WPS IE."""
        try:
            self.rtDecoder.decode(pkt)
            rt = self.rtDecoder.get_protocol(dot11.RadioTap)
            channel = rt.get_channel()[0]
            flags = rt.get_flags()
            tsft = rt.get_tsft()
            rate = rt.get_rate()

            management = self.rtDecoder.get_protocol(dot11.Dot11ManagementFrame)
            beacon = self.rtDecoder.get_protocol(dot11.Dot11ManagementBeacon)
            bssid = self.__getAddressFromList(management.get_bssid())
            essid = str(beacon.get_ssid())
            vendor = get_vendor(bssid)
            # vendor = self.oui.get_vendor(bssid)

            if bssid not in self.ap_dict:
                self.ap_dict[bssid] = {'essid': essid, 'channel': channel, 'clients': [], 'vendor': vendor}
                print(Fore.GREEN + '[+] New AP [%s] [%s] at %s vendor:%s TSFT: %s RATE: %s FLAGS: %s' % (
                bssid, essid, channel, vendor, tsft, rate, flags))
            # ACTIVE MODE
            if self.accessPoints.count(bssid) == 0 and self.wps_parser.has_wps(beacon.get_vendor_specific()):
                # TODO: add injection
                self.send_probe_req(essid, bssid, )

        except Exception as e:
            # print('Error while parsing beacon')
            # print(str(exc_info()))
            return None

    # Probe requests from clients
    def handle_probe_req(self, pkt):
        if pkt.haslayer(Dot11ProbeReq) and '\x00' not in pkt[Dot11ProbeReq].info:
            essid = pkt[Dot11ProbeReq].info
        else:
            essid = 'Hidden SSID'
        client = pkt[Dot11].addr2

        # if client in self.whitelist or essid in self.whitelist:
        #     TODO: add logging
        #     return

        # New client
        if client not in self.clients_dict:
            self.clients_dict[client] = []
            print(Fore.GREEN + '[!] New client:  %s ' % client)

        if essid not in self.clients_dict[client]:
            self.clients_dict[client].append(essid)
            print(Fore.GREEN + '[+] New ProbeRequest: from %s to %s' % (client, essid))

    def handle_probe_response(self, pkt):
        """Process 802.11 Probe Response Frame for WPS IE."""
        try:
            self.rtDecoder.decode(pkt)
            mgt = self.rtDecoder.get_protocol(dot11.Dot11ManagementFrame)
            probe = self.rtDecoder.get_protocol(dot11.Dot11ManagementProbeResponse)
            bssid = self.__getAddressFromList(mgt.get_bssid())
            essid = probe.get_ssid()

            # If null byte in the SSID IE, its cloacked.
            if essid.find("\x00") != -1:
                essid = "<No ssid>"
            if bssid not in self.ap_dict:
                self.rtDecoder.decode(pkt)
                rt = self.rtDecoder.get_protocol(dot11.RadioTap)
                channel = rt.get_channel()[0]
                self.ap_dict[bssid] = {'essid': essid, 'channel': channel, 'clients': [],
                                       'vendor': self.oui.get_vendor(bssid)}
                vendorIEs = probe.get_vendor_specific()
                if self.wps_parser.has_wps(vendorIEs):
                    vendor = self.oui.get_vendor(bssid)
                    wpsInfo = self.wps_parser.parse_wps(vendorIEs)
                    return [bssid, essid, vendor, wpsInfo]
        except Exception:
            # print('Error while parsing probe responsse')
            return None

    def send_probe_req(self, essid, bssid, src=None):
        if not self.args.active:
            return

        if src is None:
            src = RandMAC()
        print('[!] Sending 802.11 Probe Request: SRC=[%s] -> BSSID=[%s]\t(%s)' % (src, bssid, essid))

        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID', info=essid)
        rates = Dot11Elt(ID='Rates', info="\x03\x12\x96\x18\x24\x30\x48\x60")
        dsset = Dot11Elt(ID='DSset', info='\x01')
        pkt = RadioTap() \
              / Dot11(type=0, subtype=4, addr1=bssid, addr2=src, addr3=bssid) / param / essid / rates / dsset

        try:
            sendp(pkt, verbose=0)
        except:
            raise

    def send_probe_req_2(self, src, ssid):
        """Return 802.11 Probe Request Frame."""
        # Frame Control
        frameControl = dot11.Dot11()
        frameControl.set_version(0)
        frameControl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST)
        # Frame Control Flags
        frameControl.set_fromDS(0)
        frameControl.set_toDS(0)
        frameControl.set_moreFrag(0)
        frameControl.set_retry(0)
        frameControl.set_powerManagement(0)
        frameControl.set_moreData(0)
        frameControl.set_protectedFrame(0)
        frameControl.set_order(0)
        # Management Frame
        sequence = random.randint(0, 4096)
        broadcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        mngtFrame = dot11.Dot11ManagementFrame()
        mngtFrame.set_duration(0)
        mngtFrame.set_destination_address(broadcast)
        mngtFrame.set_source_address(src)
        mngtFrame.set_bssid(broadcast)
        mngtFrame.set_fragment_number(0)
        mngtFrame.set_sequence_number(sequence)
        # Probe Request Frame
        probeRequestFrame = dot11.Dot11ManagementProbeRequest()
        probeRequestFrame.set_ssid(ssid)
        probeRequestFrame.set_supported_rates([0x02, 0x04, 0x0b, 0x16])
        # How is your daddy?
        mngtFrame.contains(probeRequestFrame)
        frameControl.contains(mngtFrame)
        # return frameControl.get_packet()

        # src = self.__getListFromAddress(self.args.source) if args.source is not None else self.__getListFromAddress(RandMAC())
        # probe = self.__getProbeRequest(src, ssid)
        return sendp(frameControl.get_packet(), iface=self.args.interface, verbose=0)

    def start(self, timeout=10):
        # Set signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

        # Enable monitor
        if 'mon' not in self.interface:
            print("Enabling monitor interface on " + self.interface)
            self.set_monitor()

        # Startinf to sniffe
        print("Press Ctrl+C to stop. Sniffing...")
        print("-" * 80)
        while True:
            for x in [1, 6, 11, 1, 3, 5, 9, 13]:
                print(Fore.YELLOW + "[*] Switching channel to: %i" % x)
                self.set_channel(x)
                self.captured.extend(
                    sniff(iface=self.interface, prn=self._packet_handler, lfilter=self._packet_filter, store=1,
                          timeout=timeout))


if __name__ == "__main__":
    parser = argparse.ArgumentParser('WPSIG', description='Wi-Fi Protected Setup Information Gathering.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    group = parser.add_argument_group('I/O options')
    group.add_argument("-i", "--interface", help="network interface.")
    group.add_argument("-w", "--write", help="output filename.")
    group = parser.add_argument_group('Active mode (injection) options')
    group.add_argument("-a", "--active", action='store_true', help="injecting frames (passive by default)")
    group.add_argument("-s", "--source", help="source mac address.")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: root privileges are required.")
        sys.exit(-1)

    ws = WpsScanner(args)
    ws.start()
