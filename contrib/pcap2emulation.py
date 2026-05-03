#!/usr/bin/env python3
# pylint: disable=invalid-name,missing-docstring
#
# Copyright 2023 Collabora Ltd
# Author: Frédéric Danis <frederic.danis@collabora.com>
#
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import base64
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple
from zipfile import ZipFile, ZIP_DEFLATED

URB_INTERRUPT = 1
URB_CONTROL = 2
URB_BULK = 3

DESCRIPTOR_DEVICE = 1
DESCRIPTOR_CONFIGURATION = 2
DESCRIPTOR_STRING = 3
DESCRIPTOR_INTERFACE = 4
DESCRIPTOR_ENDPOINT = 5
DESCRIPTOR_EXTRA = 33

INTERFACE_CLASS_HID = 3
INTERFACE_CLASS_SMARTCARD = 11

CCID_PC_TO_RDR_SET_PARAMETERS = 0x61
CCID_PC_TO_RDR_ICC_POWER_ON = 0x62
CCID_PC_TO_RDR_ICC_POWER_OFF = 0x63
CCID_PC_TO_RDR_GET_SLOT_STATUS = 0x65
CCID_PC_TO_RDR_ESCAPE = 0x6B
CCID_PC_TO_RDR_TRANSFER_BLOCK = 0x6F
CCID_RDR_TO_PC_DATA_BLOCK = 0x80
CCID_RDR_TO_PC_SLOT_STATUS = 0x81
CCID_RDR_TO_PC_PARAMETERS = 0x82
CCID_RDR_TO_PC_ESCAPE = 0x83


def get_int(data: str) -> int:
    if data[:2] == "0x":
        return int(data, 16)
    return int(data)


def add_bytes(array: bytearray, string: str, size: int) -> None:
    array += get_int(string).to_bytes(length=size, byteorder="little")


class Pcap2Emulation:
    def __init__(self, device_ids: str):
        self.device: Dict[str, Any] = {}
        self.platform_id = ""
        self.phases: List[Any] = []
        self.device_ids: List[List[str]] = []
        self.interface_index = 0
        self.endpoint_index = 0
        self.previous_data: Optional[str]
        self.bulk_incoming_lens: Dict[str, int] = {}
        self.usb_port = None
        self.enumerate = False

        for i in range(len(device_ids)):
            device_id = device_ids[i].split(":")
            if len(device_id) > 2:
                sys.stderr.write(f"Malformed device ID: {device_ids[i]}\n\n")
                exit(1)
            if len(device_id) == 2 and len(device_id[1]) == 0:
                del device_id[1]
            if device_id not in self.device_ids:
                self.device_ids.append(device_id)

    def _save_phase(self) -> None:
        self.phases.append({"UsbDevices": [self.device]})
        self.interface_index = 0
        self.endpoint_index = 0

    def save_archive(self, path: str) -> None:
        if not self.phases:
            return

        print(f"Found {len(self.phases)} phases:")
        phase = 0

        if path.endswith(".zip"):
            emulation_file = path
        else:
            emulation_file = path + ".zip"
        with ZipFile(emulation_file, "w", compression=ZIP_DEFLATED) as write_file:
            print(f"- phase {phase} as setup.json")
            json_string = json.dumps(
                self.phases[phase], indent=2, separators=(",", " : ")
            )
            write_file.writestr("setup.json", json_string)
            phase += 1

            if len(self.phases) > 2:
                print(f"- phase {phase} as install.json")
                json_string = json.dumps(
                    self.phases[phase], indent=2, separators=(",", " : ")
                )
                write_file.writestr("install.json", json_string)
                phase += 1

            print(f"- phase {phase} as reload.json")
            json_string = json.dumps(
                self.phases[phase], indent=2, separators=(",", " : ")
            )
            write_file.writestr("reload.json", json_string)
            phase += 1

        print("Emulation file saved to " + emulation_file)

        while phase < len(self.phases):
            phase_path = f"{path}-{phase}.json"
            with open(phase_path, "w") as dump_file:
                json.dump(
                    self.phases[phase],
                    dump_file,
                    indent=2,
                    separators=(",", " : "),
                )
                print(f"- unused phase {phase} saved to {phase_path}")
            phase += 1

    def _run_tshark(self, file: str, tshark_filter: str) -> Any:
        cmd = ["tshark", "-n", "-T", "ek", "-l", "-2", "-r", file, "-R"]
        print("running: " + " ".join(cmd) + ' "' + tshark_filter + '"')
        cmd.append(tshark_filter)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE)

    def _get_usb_addrs(self, file: str) -> Tuple[str, List[str]]:
        tshark_filter = ""
        for i in range(len(self.device_ids)):
            if len(tshark_filter) == 0:
                tshark_filter += "("
            else:
                tshark_filter += " or ("
            tshark_filter += "usb.idVendor == 0x" + self.device_ids[i][0]
            if len(self.device_ids[i]) == 2 and len(self.device_ids[i][1]) > 0:
                tshark_filter += " and usb.idProduct == 0x" + self.device_ids[i][1]
            tshark_filter += ")"

        usb_bus = ""
        usb_addrs: List[str] = []
        p = self._run_tshark(file, tshark_filter)
        for line in p.stdout:
            pcap_data = json.loads(line)
            if "layers" in pcap_data:
                if not usb_bus:
                    usb_bus = pcap_data["layers"]["usb"]["usb_usb_bus_id"]
                elif usb_bus != pcap_data["layers"]["usb"]["usb_usb_bus_id"]:
                    print(
                        "* Warning: Found different USB Bus ID: expected {}, found {}".format(
                            usb_bus, pcap_data["layers"]["usb"]["usb_usb_bus_id"]
                        )
                    )
                addr = pcap_data["layers"]["usb"]["usb_usb_device_address"]
                if addr not in usb_addrs:
                    usb_addrs.append(addr)
        return usb_bus, usb_addrs

    def _get_interrupt_event(self, layers: Dict[str, Any]) -> Dict[str, str]:
        if "usb_usb_capdata" in layers:
            captured_data = str(
                base64.b64encode(
                    bytes.fromhex(layers["usb_usb_capdata"].replace(":", ""))
                ),
                "utf-8",
            )
            s = "InterruptTransfer:Endpoint=0x{:02x}".format(
                get_int(layers["usb"]["usb_usb_endpoint_address"])
            )
            if layers["usb"]["usb_usb_endpoint_address_direction"] == "1":
                if hasattr(self, "previous_data") and self.previous_data:
                    s += f",Data={self.previous_data}"
                    self.previous_data = None
                else:
                    s += ",Data="
            else:
                self.previous_data = captured_data
                s += f",Data={captured_data}"
            s += f",Length=0x{int(layers['usb']['usb_usb_data_len']):x}"
            return {"Id": s, "Data": captured_data}
        return {}

    def _get_bulk_event(self, layers: Dict[str, Any]) -> Dict[str, str]:
        captured_data = None
        if "usbccid" in layers:
            message_type = get_int(layers["usbccid"]["usbccid_usbccid_bMessageType"])
            ccid = bytearray([message_type])
            add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_dwLength"], 4)
            add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bSlot"], 1)
            add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bSeq"], 1)

            if message_type == CCID_PC_TO_RDR_SET_PARAMETERS:
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bProtocolNum"], 1)
                add_bytes(
                    ccid, layers["usbccid"]["usbccid_usbccid_hf_ccid_Reserved"], 2
                )
                ccid += bytearray.fromhex(
                    layers["data"]["data_data_data"].replace(":", "")
                )
            elif message_type == CCID_PC_TO_RDR_ICC_POWER_ON:
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bPowerSelect"], 1)
                add_bytes(
                    ccid, layers["usbccid"]["usbccid_usbccid_hf_ccid_Reserved"], 2
                )
            elif (
                message_type == CCID_PC_TO_RDR_ICC_POWER_OFF
                or message_type == CCID_PC_TO_RDR_GET_SLOT_STATUS
            ):
                add_bytes(
                    ccid, layers["usbccid"]["usbccid_usbccid_hf_ccid_Reserved"], 3
                )
            elif message_type == CCID_PC_TO_RDR_ESCAPE:
                ccid += bytearray.fromhex(
                    layers["usbccid"]["usbccid_usbccid_abRFU"].replace(":", "")
                )
                ccid += bytearray.fromhex(
                    layers["data"]["data_data_data"].replace(":", "")
                )
            elif message_type == CCID_PC_TO_RDR_TRANSFER_BLOCK:
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bBWI"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_wLevelParameter"], 2)
                ccid += bytearray.fromhex(
                    layers["data"]["data_data_data"].replace(":", "")
                )
            elif message_type == CCID_RDR_TO_PC_DATA_BLOCK:
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bStatus"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bError"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bChainParameter"], 1)
                if "data" in layers:
                    ccid += bytearray.fromhex(
                        layers["data"]["data_data_data"].replace(":", "")
                    )
            elif message_type == CCID_RDR_TO_PC_SLOT_STATUS:
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bStatus"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bError"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bClockStatus"], 1)
            elif message_type == CCID_RDR_TO_PC_PARAMETERS:
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bStatus"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bError"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bProtocolNum"], 1)
            elif message_type == CCID_RDR_TO_PC_ESCAPE:
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bStatus"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bError"], 1)
                add_bytes(ccid, layers["usbccid"]["usbccid_usbccid_bRFU"], 1)
                ccid += bytearray.fromhex(
                    layers["data"]["data_data_data"].replace(":", "")
                )
            else:
                print(f"Unknown USB CCID Bulk message type: 0x{message_type:02X}")

            captured_data = str(base64.b64encode(ccid), "utf-8")
        elif "usb_usb_capdata" in layers:
            captured_data = str(
                base64.b64encode(
                    bytes.fromhex(layers["usb_usb_capdata"].replace(":", ""))
                ),
                "utf-8",
            )

        if captured_data:
            s = "BulkTransfer:Endpoint=0x{:02x}".format(
                get_int(layers["usb"]["usb_usb_endpoint_address"])
            )
            if layers["usb"]["usb_usb_endpoint_address_direction"] == "1":
                if layers["usb"]["usb_usb_request_in"] in self.bulk_incoming_lens:
                    length = self.bulk_incoming_lens[
                        layers["usb"]["usb_usb_request_in"]
                    ]
                else:
                    length = get_int(layers["usb"]["usb_usb_data_len"])
                data = str(
                    base64.b64encode(bytes.fromhex("00" * length)),
                    "utf-8",
                )
                s += f",Data={data}"
            else:
                length = get_int(layers["usb"]["usb_usb_data_len"])
                s += f",Data={captured_data}"
            s += f",Length=0x{length:x}"
            return {"Id": s, "Data": captured_data}
        elif layers["usb"]["usb_usb_endpoint_address_direction"] == "1":
            if "usb_usb_urb_len" in layers["usb"]:
                self.bulk_incoming_lens[layers["frame"]["frame_frame_number"]] = (
                    get_int(layers["usb"]["usb_usb_urb_len"])
                )
        return {}

    def _get_interface_descriptor(
        self, layers: Dict[str, Any], descriptor_index: int
    ) -> Any:
        table = {
            "usb_usb_bInterfaceNumber": "InterfaceNumber",
            "usb_usb_bInterfaceClass": "InterfaceClass",
            "usb_usb_bInterfaceSubClass": "InterfaceSubClass",
            "usb_usb_bInterfaceProtocol": "InterfaceProtocol",
            "usb_usb_iInterface": "Interface",
            "usb_usb_bNumEndpoints": "NumEndpoints",
        }

        # Interface descriptor frame may occur multiple times,
        # it should not change unless device has been re-enumerated
        if len(layers["usb_usb_bInterfaceNumber"]) <= self.interface_index:
            return None

        interface: Dict[str, Any] = {
            "Length": get_int(layers["usb_usb_bLength"][descriptor_index]),
            "DescriptorType": 4,
        }
        for key in table:
            # data can be a string or a list of strings
            if type(layers[key]) is str:
                val = get_int(layers[key])
            else:
                val = get_int(layers[key][self.interface_index])

            if key not in layers:
                continue

            if key == "usb_usb_bInterfaceNumber" and val == 0:
                continue

            interface[table[key]] = val
            if key == "usb_usb_bNumEndpoints":
                interface["UsbEndpoints"] = []

        return interface

    def _get_endpoint_descriptor(
        self, layers: Dict[str, Any], index: int
    ) -> Dict[str, int]:
        table = {
            "usb_usb_bEndpointAddress": "EndpointAddress",
            "usb_usb_bInterval": "Interval",
            "usb_usb_wMaxPacketSize": "MaxPacketSize",
        }

        endpoint = {
            "DescriptorType": 5,
        }
        for key in table:
            val = get_int(layers[key][index])
            if val != 0:
                endpoint[table[key]] = val
        return endpoint

    def _save_event(self, event: Dict[str, str]) -> None:
        if not self.device:
            return

        self.device["UsbEvents"].append(event)

    def parse_file(self, file: str) -> None:
        bus_id, addrs = self._get_usb_addrs(file)
        if len(addrs) == 0:
            print("Device(s) not found in pcap file")
            return

        # Filter the device related packets and the C_PORT_CONNECTION clear
        # feature packets to allow detection of the re-plug/re-enumerate events
        tshark_filter = f"usb.bus_id == {bus_id}"
        tshark_filter += " and (usbhub.setup.PortFeatureSelector == 16"
        for addr in addrs:
            tshark_filter += f" or usb.device_address == {addr}"
        tshark_filter += ")"

        p = self._run_tshark(file, tshark_filter)
        for line in p.stdout:
            pcap_data = json.loads(line)
            if "layers" in pcap_data:
                layers = pcap_data["layers"]
                usb_port = None

                if (
                    layers["frame"]["frame_frame_cap_len"]
                    != layers["frame"]["frame_frame_len"]
                ):
                    print(
                        "* Incomplete frame {}: {} bytes captured < {}".format(
                            layers["frame"]["frame_frame_number"],
                            layers["frame"]["frame_frame_cap_len"],
                            layers["frame"]["frame_frame_len"],
                        )
                    )

                # Store the USB port of C_PORT_CONNECTION clear feature packet
                # Trigger an enumeration requirement if it's the same port that
                # was used for the previous device description
                if "usbhub_usbhub_setup_Port" in layers:
                    usb_port = layers["usbhub_usbhub_setup_Port"]
                    if usb_port == self.usb_port:
                        self.enumerate = True

                if get_int(layers["usb"]["usb_usb_transfer_type"]) == URB_INTERRUPT:
                    event = self._get_interrupt_event(layers)
                    if len(event) > 0:
                        self._save_event(event)

                elif get_int(layers["usb"]["usb_usb_transfer_type"]) == URB_CONTROL:
                    if "usb_usb_bDescriptorType" in layers:
                        descriptor_index = -1

                        # usb_usb_bDescriptorType can be a string or a list of strings
                        if type(layers["usb_usb_bDescriptorType"]) is str:
                            layer = [layers["usb_usb_bDescriptorType"]]
                        else:
                            layer = layers["usb_usb_bDescriptorType"]

                        for descriptor_type in layer:
                            descriptor_index += 1
                            descriptor_type = get_int(descriptor_type)

                            if descriptor_type == DESCRIPTOR_DEVICE:
                                # Check this is a reply for the Vid[:Pid] expected
                                if layers["usb"]["usb_usb_src"] == "host":
                                    continue
                                found = False
                                for i in range(len(self.device_ids)):
                                    if get_int(layers["usb_usb_idVendor"]) == int(
                                        self.device_ids[i][0], 16
                                    ):
                                        if len(self.device_ids[i]) == 1 or get_int(
                                            layers["usb_usb_idProduct"]
                                        ) == int(self.device_ids[i][1], 16):
                                            found = True
                                            break
                                if not found:
                                    continue

                                # Save the previous USB device
                                if (
                                    self.device
                                    and len(self.device["UsbInterfaces"]) > 0
                                ):
                                    self._save_phase()

                                # Create a new USB device
                                # using a fake PlatformId based on USB bus id and device address,
                                # this PlatformId should be stable for all recorded devices
                                if not self.platform_id:
                                    self.platform_id = "{:x}-{:x}".format(
                                        get_int(layers["usb"]["usb_usb_bus_id"]),
                                        get_int(
                                            layers["usb"]["usb_usb_device_address"]
                                        ),
                                    )
                                # Device re-enumeration is triggered when 'Created' time differs
                                # from previous phase, this keeps the 'Created' time from previous
                                # phase unless a re-enumeration requirement has been detected
                                if not self.device or self.enumerate:
                                    frame_time = layers["frame"]["frame_frame_time"]
                                    self.usb_port = usb_port
                                    self.enumerate = False
                                else:
                                    frame_time = self.device["Created"]
                                self.device = {
                                    "GType": "FuUsbDevice",
                                    "PlatformId": self.platform_id,
                                    "Created": frame_time,
                                    "IdVendor": get_int(layers["usb_usb_idVendor"]),
                                    "IdProduct": get_int(layers["usb_usb_idProduct"]),
                                    "Device": get_int(layers["usb_usb_bcdDevice"]),
                                    "USB": get_int(layers["usb_usb_bcdUSB"]),
                                    "Manufacturer": get_int(
                                        layers["usb_usb_iManufacturer"]
                                    ),
                                    "Product": get_int(layers["usb_usb_iProduct"]),
                                    "UsbInterfaces": [],
                                    "UsbEvents": [],
                                }

                            elif descriptor_type == DESCRIPTOR_CONFIGURATION:
                                if "usb_usb_iConfiguration" in layers:
                                    # The GetConfigurationIndex USB event is not directly
                                    # related to a specific USB event, but data can be
                                    # retrieved from the DESCRIPTOR CONFIGURATION request
                                    index = (
                                        layers["usb_usb_iConfiguration"]
                                        .encode("utf-8")
                                        .hex()
                                    )
                                    event = {
                                        "Id": "GetConfigurationIndex",
                                        "Data": str(
                                            base64.b64encode(bytes.fromhex(index)),
                                            "utf-8",
                                        ),
                                    }
                                    self._save_event(event)

                            elif descriptor_type == DESCRIPTOR_STRING:
                                if "usb_usb_DescriptorIndex" in layers:
                                    desc_index = get_int(
                                        layers["usb_usb_DescriptorIndex"]
                                    )
                                    if desc_index == 0:
                                        # The list of supported languages are not recorded for the emulation
                                        continue
                                    event_str = {
                                        "Id": "GetStringDescriptor:DescIndex=0x{:02x}".format(
                                            desc_index
                                        )
                                    }
                                    # duplicate the event so it can also be used for GetStringDescriptorBytes
                                    language_id = get_int(layers["usb_usb_LanguageId"])
                                    length = get_int(layers["usb_usb_setup_wLength"])
                                    event_bytes = {
                                        "Id": "GetStringDescriptorBytes:DescIndex=0x{:02x}".format(
                                            desc_index
                                        )
                                    }
                                    event_bytes["Id"] += f",Langid=0x{language_id:04x}"
                                    event_bytes["Id"] += f",Length=0x{length:x}"

                                elif "usb_usb_bString" in layers:
                                    if get_int(layers["usb_usb_bLength"]) != len(
                                        layers["usb_usb_bString"].encode("utf-16")
                                    ):
                                        # Discard frame used to retrieve STRING DESCRIPTOR length
                                        continue

                                    # Found a new STRING DESCRIPTOR response
                                    data = (
                                        layers["usb_usb_bString"].encode("utf-8").hex()
                                    )
                                    if "usb_usb_capdata" in layers:
                                        # Add leftover capture data
                                        data += "00"
                                        data += layers["usb_usb_capdata"].replace(
                                            ":", ""
                                        )
                                    event_str["Data"] = str(
                                        base64.b64encode(bytes.fromhex(data)), "utf-8"
                                    )

                                    # now that the event is completed it can be added to the device events
                                    self._save_event(event_str)
                                    # duplicate the event so it can also be used for GetStringDescriptorBytes
                                    event_bytes["Data"] = event_str["Data"]
                                    self._save_event(event_bytes)

                            elif descriptor_type == DESCRIPTOR_INTERFACE:
                                interface = self._get_interface_descriptor(
                                    layers, descriptor_index
                                )
                                if not interface:
                                    continue

                                # Add the interface to the device
                                self.device["UsbInterfaces"].append(interface)

                                if (
                                    "InterfaceClass" in interface
                                    and "InterfaceSubClass" in interface
                                    and "InterfaceProtocol" in interface
                                ):
                                    # The GetCustomIndex USB event is not directly
                                    # related to a specific USB event, but data can be
                                    # retrieved from the DESCRIPTOR INTERFACE request
                                    index = interface["Interface"].to_bytes(1, "big")
                                    event = {
                                        "Id": "GetCustomIndex:ClassId=0x{:02x},SubclassId=0x{:02x},ProtocolId=0x{:02x}".format(
                                            interface["InterfaceClass"],
                                            interface["InterfaceSubClass"],
                                            interface["InterfaceProtocol"],
                                        ),
                                        "Data": str(
                                            base64.b64encode(index),
                                            "utf-8",
                                        ),
                                    }
                                    self._save_event(event)

                                self.interface_index += 1

                            elif descriptor_type == DESCRIPTOR_ENDPOINT:
                                if (
                                    len(layers["usb_usb_bEndpointAddress"])
                                    > self.endpoint_index
                                ):
                                    endpoint = self._get_endpoint_descriptor(
                                        layers, self.endpoint_index
                                    )

                                    # Add the endpoint to the first interface with missing endpoint
                                    for interface in self.device["UsbInterfaces"]:
                                        if (
                                            "UsbEndpoints" in interface
                                            and len(interface["UsbEndpoints"])
                                            < interface["NumEndpoints"]
                                        ):
                                            interface["UsbEndpoints"].append(endpoint)
                                            break
                                    self.endpoint_index += 1

                            elif descriptor_type == DESCRIPTOR_EXTRA:
                                pass
                            else:
                                sys.stderr.write(
                                    f"Unknown descriptor type: 0x{descriptor_type:02x}"
                                    " — skipping\n"
                                )

                    elif "usb_usb_bmRequestType_type" in layers:
                        # Found vendor CONTROL URB request
                        direction = not (layers["usb_usb_bmRequestType_direction"])
                        s = f"ControlTransfer:Direction=0x{direction:02x}"
                        s += ",RequestType=0x{:02x}".format(
                            get_int(layers["usb_usb_bmRequestType_type"])
                        )
                        s += ",Recipient=0x{:02x}".format(
                            get_int(layers["usb_usb_bmRequestType_recipient"])
                        )
                        if "usbhid_usbhid_setup_bRequest" in layers:
                            s += f",Request=0x{get_int(layers['usbhid_usbhid_setup_bRequest']):02x}"
                        elif "usb_usb_setup_bRequest" in layers:
                            s += f",Request=0x{get_int(layers['usb_usb_setup_bRequest']):02x}"
                        if (
                            "usbhid_usbhid_setup_ReportID" in layers
                            and "usbhid_usbhid_setup_ReportType" in layers
                        ):
                            rep_id = get_int(layers["usbhid_usbhid_setup_ReportID"])
                            typ = get_int(layers["usbhid_usbhid_setup_ReportType"])
                            val = typ << 8 | rep_id
                            s += f",Value=0x{val:04x}"
                        elif "usb_usb_setup_wValue" in layers:
                            s += f",Value=0x{get_int(layers['usb_usb_setup_wValue']):04x}"
                        if "usbhid_usbhid_setup_wIndex" in layers:
                            s += f",Idx=0x{get_int(layers['usbhid_usbhid_setup_wIndex']):04x}"
                        elif "usb_usb_setup_wIndex" in layers:
                            s += f",Idx=0x{get_int(layers['usb_usb_setup_wIndex']):04x}"
                        if "usbhid_usbhid_setup_wLength" in layers:
                            length = get_int(layers["usbhid_usbhid_setup_wLength"])
                        elif "usb_usb_setup_wLength" in layers:
                            length = get_int(layers["usb_usb_setup_wLength"])
                        else:
                            length = 0
                        if "usb_usb_data_fragment" in layers:
                            data = layers["usb_usb_data_fragment"].replace(":", "")
                        else:
                            data = "00" * length
                        s += ",Data={}".format(
                            str(base64.b64encode(bytes.fromhex(data)), "utf-8")
                        )
                        s += f",Length=0x{length:x}"
                        event = {"Id": s}

                        if direction:
                            # Duplicate the outgoing data as response and add the event to the device events
                            event["Data"] = str(
                                base64.b64encode(bytes.fromhex(data)), "utf-8"
                            )
                            self._save_event(event)

                    elif "usb_usb_control_Response" in layers:
                        # Found CONTROL URB response
                        data = layers["usb_usb_control_Response"].replace(":", "")
                        event["Data"] = str(
                            base64.b64encode(bytes.fromhex(data)), "utf-8"
                        )

                        # now that the event is complete it can be added to the device events
                        self._save_event(event)

                elif get_int(layers["usb"]["usb_usb_transfer_type"]) == URB_BULK:
                    # TODO: check it
                    event = self._get_bulk_event(layers)
                    if event:
                        self._save_event(event)

                else:
                    if not self.device:
                        continue

                    print(
                        "Unknown frame type: " + layers["usb"]["usb_usb_transfer_type"]
                    )

        # Save the last USB device
        if "UsbInterfaces" in self.device:
            self._save_phase()


# --- FuHidrawDevice translation -----------------------------------------
#
# pcap2emulation.py records each USB device as a FuUsbDevice with USB-level
# `ControlTransfer:` events. Plugins that talk to their hardware via the
# kernel's hidraw interface (FuHidrawDevice / FuUdevDevice) instead of
# libusb don't see USB control transfers — they see Write:/Ioctl: hidraw
# events, and fwupd's emulation framework only intercepts I/O for devices
# whose GType matches the backend that produced them. So a FuUsbDevice
# fixture loaded against a FuHidrawDevice plugin doesn't intercept; the
# plugin's hidraw I/O falls through to the real device file.
#
# The translation below converts the FuUsbDevice phase data into
# equivalent FuHidrawDevice entries, splitting one USB device into N
# hidraw entries (one per HID interface) and rewriting class control
# transfers to their hidraw-API equivalents:
#
#   SET_REPORT (host -> device, class, interface, bRequest=0x09)
#     -> Write:Data=<base64>,Length=0x..
#   GET_REPORT (device -> host, class, interface, bRequest=0x01)
#     -> Ioctl:Request=0xc0c1480a (HIDIOCGINPUT(193)),
#        DataOut=<base64>
#
# Standard requests (descriptors, SET_CONFIGURATION, …) and non-HID
# interface traffic are dropped, matching what a hidraw consumer would
# never see.
#
# Note: pcap2emulation flips the direction bit when recording, so events
# saved as Direction=0x01 are actually host->device on the wire.

# HIDIOCGINPUT(192) — kernel _IOC encoding for the HID class GET_REPORT
# the dell-monitor-rt plugin uses. dir=READ|WRITE, type='H', nr=0x0A, size=192.
# The leading report-ID byte makes the buffer 193, but the ioctl size field
# encodes the wire size (192 = 0xc0).
HIDRAW_HIDIOCGINPUT_193 = 0xC0C1480A


def _hidraw_event_from_control(usb_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Translate one ControlTransfer event into a hidraw Write/Ioctl event,
    or return None if the event is dropped (non-HID-class, descriptor read,
    etc.)."""
    eid = usb_event.get("Id", "")
    if not eid.startswith("ControlTransfer:"):
        return None

    # Parse the "k=v,k=v,..." tail. ControlTransfer: prefix already consumed.
    body = eid[len("ControlTransfer:") :]
    fields: Dict[str, str] = {}
    for part in body.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        fields[k] = v

    # Only HID class control transfers go to the hidraw layer. Class+Interface
    # recipient = bmRequestType bits (Type=Class=1, Recipient=Interface=1).
    if fields.get("RequestType") != "0x01":
        return None
    if fields.get("Recipient") != "0x01":
        return None

    # Direction is flipped by pcap2emulation when recording — see the
    # `direction = not (...)` line in the parser. So Direction=0x01 here
    # means host->device on the wire (SET_REPORT-style write), and
    # Direction=0x00 means device->host (GET_REPORT-style read).
    direction = fields.get("Direction")
    request = fields.get("Request")
    data_b64 = fields.get("Data", "")
    length_str = fields.get("Length", "0x0")
    try:
        length = int(length_str, 16) if length_str.startswith("0x") else int(length_str)
    except ValueError:
        length = 0

    if direction == "0x01" and request == "0x09":
        # SET_REPORT — host->device write. The captured Data is the wire
        # payload (typically 64 / 192 / 256 bytes depending on the device's
        # output report size). On the hidraw side the same payload is
        # written verbatim by fu_udev_device_write — but the device may or
        # may not have a leading Report ID byte depending on its HID
        # descriptor. Devices that declare *no* report IDs are written
        # as `0x00 + payload`; devices that declare report IDs use the
        # report ID itself. This converter doesn't parse the HID
        # descriptor, so it emits the wire payload as-is and leaves any
        # Report-ID prefix to a downstream specialization layer.
        return {
            "Id": f"Write:Data={data_b64},Length=0x{length:x}",
        }
    if direction == "0x00" and request == "0x01":
        # GET_REPORT — device->host read. Same Report-ID caveat applies.
        # The ioctl request encodes len in its size field and our
        # constant assumes len=192; plugins with different report sizes
        # need their own constant.
        return {
            "Id": f"Ioctl:Request=0x{HIDRAW_HIDIOCGINPUT_193:x}",
            "DataOut": usb_event.get("Data", data_b64),
        }
    return None


def _backend_id_for_hid_interface(
    usb_dev: Dict[str, Any], iface: Dict[str, Any], counter: int
) -> str:
    """Synthesize a plausible Linux sysfs hidraw BackendId.

    The exact PCI host-controller path is machine-specific and won't match
    the user's live device, but that's fine — fwupd's emulation framework
    treats fixture entries with no matching real-device backend_id as
    fresh synthetic devices and tags them FWUPD_DEVICE_FLAG_EMULATED.
    The plugin still attaches via quirk (HIDRAW\\VEN_xxxx&DEV_xxxx) and
    I/O gets intercepted because the synthetic device has the flag.
    """
    bus = usb_dev.get("PlatformId", "0-0").split("-")[0]
    port = usb_dev.get("PlatformId", "0-0").split("-", 1)[1]
    vid = usb_dev.get("IdVendor", 0)
    pid = usb_dev.get("IdProduct", 0)
    intf = iface.get("Interface", 0)
    # 0003 in the HID device tag = HID class. Counter forms the instance
    # suffix (e.g. .0034) and the hidraw node number.
    return (
        f"/sys/devices/pci0000:00/0000:00:14.0/usb{bus}/{bus}-{port}/"
        f"{bus}-{port}:1.{intf}/0003:{vid:04X}:{pid:04X}.{counter:04X}/"
        f"hidraw/hidraw{counter}"
    )


def _structural_events_for_hidraw(
    backend_id: str, vid: int, pid: int
) -> List[Dict[str, Any]]:
    """Stereotyped events that an EMULATED FuHidrawDevice's setup-time probe
    expects to find. Without these, fu_device_get_backend_parent() and the
    HID property reads fall back to live sysfs queries — which fail because
    the synthetic device has no real sysfs entry behind it. With them, the
    EMULATED branch satisfies the queries from the recorded event store.

    The first event records the device's USB parent in the device tree —
    it's the parent of the hidraw node, with the trailing "/hidraw/hidrawN"
    stripped. The remaining events synthesize the standard HID uevent
    properties (HID_ID, HID_NAME) using the VID/PID we already have."""
    parent_backend_id = backend_id.rsplit("/hidraw/", 1)[0]
    return [
        {
            "Id": "GetBackendParent:Subsystem=hid",
            "GType": "FuUdevDevice",
            "BackendId": parent_backend_id,
        },
        {
            "Id": "ReadProp:Key=HID_ID",
            "Data": f"0003:{vid:08X}:{pid:08X}",
        },
        {
            "Id": "ReadProp:Key=HID_NAME",
            "Data": f"USB HID ({vid:04x}:{pid:04x})",
        },
    ]


def convert_phases_to_hidraw(phases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Translate FuUsbDevice phases to FuHidrawDevice phases. One USB device
    in the input becomes one FuHidrawDevice per HID interface in the output.

    Each output device entry leads with the stereotyped probe events fwupd
    needs to satisfy a hidraw setup walk under emulation, then includes the
    translated wire events distributed to the matching interface based on
    the wIndex of the original control transfer.

    Per-device device IDs are kept stable across phases (same BackendId for
    a given USB-interface tuple) so the engine can match an entry across
    setup/install/reload — without that, the install phase's events don't
    attach to the device that completed the setup phase."""
    # Cache per-(usb_platform_id, interface_num) → (counter, BackendId) so
    # the same logical interface in multiple phases gets the same BackendId.
    # The counter seed is arbitrary; we just need uniqueness across entries.
    counter_state = [0x30]
    seen: Dict[Tuple[str, int], Tuple[int, str]] = {}

    def _stable_entry_for(
        usb_dev: Dict[str, Any], iface: Dict[str, Any]
    ) -> Tuple[int, str]:
        key = (usb_dev.get("PlatformId", ""), iface.get("Interface", 0))
        if key not in seen:
            counter_state[0] += 1
            seen[key] = (
                counter_state[0],
                _backend_id_for_hid_interface(usb_dev, iface, counter_state[0]),
            )
        return seen[key]

    new_phases: List[Dict[str, Any]] = []
    for phase in phases:
        new_devices: List[Dict[str, Any]] = []
        for usb_dev in phase.get("UsbDevices", []):
            hid_ifaces = [
                iface
                for iface in usb_dev.get("UsbInterfaces", [])
                if iface.get("InterfaceClass") == INTERFACE_CLASS_HID
            ]
            if not hid_ifaces:
                continue
            # One FuHidrawDevice entry per HID interface
            iface_entries: List[Dict[str, Any]] = []
            for iface in hid_ifaces:
                hidraw_n, backend_id = _stable_entry_for(usb_dev, iface)
                vid = usb_dev.get("IdVendor", 0)
                pid = usb_dev.get("IdProduct", 0)
                entry = {
                    "GType": "FuHidrawDevice",
                    "BackendId": backend_id,
                    "Subsystem": "hidraw",
                    "DeviceFile": f"/dev/hidraw{hidraw_n}",
                    "Created": 0,
                    "IdVendor": vid,
                    "IdProduct": pid,
                    "Events": _structural_events_for_hidraw(backend_id, vid, pid),
                    "_iface_num": iface.get("Interface", 0),
                }
                iface_entries.append(entry)
            # Translate each USB event and route it to the matching interface
            for usb_event in usb_dev.get("UsbEvents", []):
                hidraw_event = _hidraw_event_from_control(usb_event)
                if hidraw_event is None:
                    continue
                # Decode wIndex from the original event Id — class control
                # transfers carry the target interface number there.
                eid = usb_event.get("Id", "")
                target_iface = 0
                for part in eid.split(","):
                    if part.startswith("Idx="):
                        try:
                            target_iface = int(part.split("=", 1)[1], 16) & 0xFF
                        except ValueError:
                            pass
                        break
                # Find the entry for this interface; fall back to first
                for entry in iface_entries:
                    if entry["_iface_num"] == target_iface:
                        entry["Events"].append(hidraw_event)
                        break
                else:
                    iface_entries[0]["Events"].append(hidraw_event)
            # Strip the temporary _iface_num scaffolding before emit
            for entry in iface_entries:
                entry.pop("_iface_num", None)
                new_devices.append(entry)
        new_phases.append({"FwupdVersion": "2.0.0", "UsbDevices": new_devices})
    return new_phases


if __name__ == "__main__":
    options = argparse.ArgumentParser(description="Convert pcap file to emulation file")
    options.add_argument("input_pcap", type=str, help="pcap file to convert")
    options.add_argument("output_archive", type=str, help="Output archive path")
    options.add_argument(
        "device_id",
        metavar=("VendorID[:ProductID]"),
        type=str,
        nargs="+",
        help="Device ID in hexadecimal",
    )
    options.add_argument(
        "--gtype",
        choices=["FuUsbDevice", "FuHidrawDevice"],
        default="FuUsbDevice",
        help=(
            "Output device GType. FuUsbDevice (default) records USB-level "
            "ControlTransfer events; FuHidrawDevice translates HID-class "
            "control transfers into hidraw Write/Ioctl events suitable for "
            "plugins that talk to their device via /dev/hidrawN."
        ),
    )

    args = options.parse_args()

    path = os.path.abspath(os.path.expanduser(os.path.expandvars(args.input_pcap)))
    parser = Pcap2Emulation(args.device_id)
    parser.parse_file(path)
    if args.gtype == "FuHidrawDevice":
        parser.phases = convert_phases_to_hidraw(parser.phases)
    parser.save_archive(args.output_archive)
