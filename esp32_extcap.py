
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import select
import struct
import sys
import threading
import time

import serial
from serial.tools import list_ports


# --------------------------------------------------
# Configuracion
# --------------------------------------------------

MAX_FRAME = 2500
LINKTYPE_IEEE802_11 = 105

# Protocolo serie:
# MAGIC (4 bytes) + longitud uint16 LE + trama + CRC16 LE
MAGIC = b"\xA5\x5A"

STOP = threading.Event()


# --------------------------------------------------
# Puerto serie multiplataforma
# --------------------------------------------------

def default_port():
    """Detecta un puerto serie predeterminado."""

    ports = list(list_ports.comports())

    if sys.platform == "win32":
        preferred = [
            p.device for p in ports
            if p.device.upper().startswith("COM")
        ]
        return preferred[0] if preferred else "COM3"

    if sys.platform == "darwin":
        preferred = [
            p.device for p in ports
            if "usbserial" in p.device.lower()
            or "usbmodem" in p.device.lower()
        ]
        return preferred[0] if preferred else "/dev/cu.usbserial-0001"

    preferred = [
        p.device for p in ports
        if p.device.startswith("/dev/ttyUSB")
        or p.device.startswith("/dev/ttyACM")
    ]

    return preferred[0] if preferred else "/dev/ttyUSB0"


# --------------------------------------------------
# PCAP clasico
# --------------------------------------------------

def pcap_header():
    """Cabecera global PCAP, little-endian."""

    return struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        LINKTYPE_IEEE802_11,
    )


def pcap_packet_header(packet, timestamp=None):
    """Cabecera de un paquete PCAP."""

    if timestamp is None:
        timestamp = time.time()

    sec = int(timestamp)
    usec = int((timestamp - sec) * 1_000_000)

    return struct.pack(
        "<IIII",
        sec,
        usec,
        len(packet),
        len(packet),
    )


# --------------------------------------------------
# Lectura exacta
# --------------------------------------------------

def read_exact(port, size):
    """Lee exactamente size bytes o devuelve None al detenerse."""

    data = bytearray()

    while len(data) < size and not STOP.is_set():
        part = port.read(size - len(data))

        if part:
            data.extend(part)

    if len(data) != size:
        return None

    return bytes(data)


# --------------------------------------------------
# CRC16-CCITT
# Debe coincidir con el firmware Arduino
# --------------------------------------------------

def crc16(data):
    crc = 0xFFFF

    for byte in data:
        crc ^= byte << 8

        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    return crc


# --------------------------------------------------
# Protocolo serie: MAGIC + longitud + trama + CRC
# --------------------------------------------------

def read_magic_frame(port):
    """Lee A5 5A + longitud little-endian + trama Wi-Fi."""
    previous = 0

    while not STOP.is_set():
        current = port.read(1)

        if not current:
            continue

        value = current[0]

        if previous == 0xA5 and value == 0x5A:
            raw_len = read_exact(port, 2)

            if raw_len is None:
                return None

            length = struct.unpack("<H", raw_len)[0]

            if not 10 <= length <= MAX_FRAME:
                previous = 0
                continue

            packet = read_exact(port, length)

            if packet is None:
                return None

            return packet

        previous = value

    return None


# --------------------------------------------------
# Extcap: descubrimiento de interfaz
# --------------------------------------------------

def list_interfaces():
    print("extcap {version=1.0}")
    print(
        "interface {value=esp32}"
        "{display=ESP32 Wi-Fi Monitor}"
        "{control=2}"
    )


def list_dlts():
    print(
        "dlt {number=105}"
        "{name=IEEE802_11}"
        "{display=IEEE 802.11}"
    )


def config():
    print(
        "arg {number=0}{call=--port}"
        "{display=Puerto serie}{type=string}"
        f"{{default={default_port()}}}{{required=true}}"
    )

    print(
        "arg {number=1}{call=--baud}"
        "{display=Velocidad serie}{type=integer}"
        "{default=921600}{required=true}"
    )

    print(
        "arg {number=2}{call=--framing}"
        "{display=Protocolo serie}{type=selector}"
        "{default=magic}{required=true}"
    )

    print(
        "value {arg=2}{value=magic}"
        "{display=Marcador A5 5A (firmware actual)}"
    )


# --------------------------------------------------
# Control extcap
# --------------------------------------------------

def read_control_message(fd):
    """Lee un mensaje extcap: tipo + longitud big-endian."""

    header = bytearray()

    while len(header) < 4 and not STOP.is_set():
        try:
            if os.name != "nt":
                ready, _, _ = select.select([fd], [], [], 0.2)

                if not ready:
                    continue

            part = os.read(fd, 4 - len(header))

        except OSError:
            return None

        if not part:
            if os.name == "nt":
                return None
            continue

        header.extend(part)

    if len(header) != 4:
        return None

    msg_type = bytes(header[:1])
    length = int.from_bytes(header[1:4], "big")
    remaining = length

    while remaining > 0 and not STOP.is_set():
        try:
            if os.name != "nt":
                ready, _, _ = select.select([fd], [], [], 0.2)

                if not ready:
                    continue

            chunk = os.read(fd, min(remaining, 4096))

        except OSError:
            return None

        if not chunk:
            return None

        remaining -= len(chunk)

    return msg_type


def control_reader(path):
    """Espera la orden Q para detener la captura."""

    if not path:
        return

    fd = None

    try:
        if os.name == "nt":
            # Las tuberias con nombre de Windows no admiten select().
            with open(path, "rb", buffering=0) as pipe:
                while not STOP.is_set():
                    header = pipe.read(4)

                    if len(header) != 4:
                        break

                    length = int.from_bytes(header[1:4], "big")
                    remaining = length

                    while remaining > 0 and not STOP.is_set():
                        chunk = pipe.read(min(remaining, 4096))

                        if not chunk:
                            return

                        remaining -= len(chunk)

                    if header[:1] == b"Q":
                        STOP.set()
                        break

        else:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)

            while not STOP.is_set():
                msg = read_control_message(fd)

                if msg == b"Q":
                    STOP.set()
                    break

                if msg is None:
                    time.sleep(0.05)

    except (OSError, ValueError) as exc:
        if not STOP.is_set():
            print(
                f"Control extcap: {exc}",
                file=sys.stderr,
                flush=True,
            )

    finally:
        if fd is not None:
            os.close(fd)


# --------------------------------------------------
# Captura
# --------------------------------------------------

def capture(args):
    if not args.fifo:
        raise ValueError("Wireshark no proporciono --fifo")

    STOP.clear()

    if args.extcap_control_in:
        threading.Thread(
            target=control_reader,
            args=(args.extcap_control_in,),
            daemon=True,
        ).start()

    packets = 0
    bad_packets = 0
    output = None

    try:
        with serial.Serial(
            port=args.port,
            baudrate=args.baud,
            timeout=0.2,
            xonxoff=False,
            rtscts=False,
            dsrdtr=False,
        ) as port:

            # Abrir el FIFO de Wireshark.
            output = open(args.fifo, "wb", buffering=0)
            output.write(pcap_header())

            print(
                f"ESP32: puerto={args.port}, "
                f"baud={args.baud}, protocolo=magic",
                file=sys.stderr,
                flush=True,
            )

            while not STOP.is_set():
                packet = read_magic_frame(port)

                if packet is None:
                    continue

                # No se escriben mensajes de texto en el FIFO PCAP.
                output.write(pcap_packet_header(packet))
                output.write(packet)

                packets += 1

                if packets % 1000 == 0:
                    print(
                        f"Paquetes recibidos: {packets}",
                        file=sys.stderr,
                        flush=True,
                    )

    except (
        BrokenPipeError,
        OSError,
        ValueError,
        serial.SerialException,
    ) as exc:
        if not STOP.is_set():
            print(
                f"Captura finalizada: {exc}",
                file=sys.stderr,
                flush=True,
            )

    finally:
        STOP.set()

        if output is not None:
            output.close()

        print(
            f"Captura detenida. "
            f"Paquetes: {packets}; "
            f"errores de protocolo: {bad_packets}",
            file=sys.stderr,
            flush=True,
        )


# --------------------------------------------------
# Entrada principal
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ESP32 Wi-Fi Monitor para Wireshark"
    )

    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-interface")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--capture", action="store_true")

    parser.add_argument("--fifo")
    parser.add_argument("--port", default=default_port())
    parser.add_argument("--baud", type=int, default=921600)

    parser.add_argument(
        "--framing",
        choices=("magic",),
        default="magic",
    )

    parser.add_argument("--extcap-control-in")
    parser.add_argument("--extcap-control-out")
    parser.add_argument("--extcap-capture-filter")

    args, _ = parser.parse_known_args()

    if args.extcap_interfaces:
        list_interfaces()

    elif args.extcap_dlts:
        list_dlts()

    elif args.extcap_config:
        config()

    elif args.capture:
        try:
            capture(args)

        except (
            OSError,
            ValueError,
            serial.SerialException,
        ) as exc:
            print(
                f"Error extcap: {exc}",
                file=sys.stderr,
                flush=True,
            )
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        STOP.set()
