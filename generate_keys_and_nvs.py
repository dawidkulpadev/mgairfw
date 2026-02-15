# MioGiapicco devices nRF52840 factory data generator script
# Adapted for Raspberry Pi remote SWD flashing
# Copyright (C) 2026  Dawid Kulpa

import sys
import os
import argparse
import base64
import binascii
import re
import struct
import subprocess
import time
from intelhex import IntelHex

# Importy kryptograficzne
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

# --- KONFIGURACJA SSH / RPI ---
RPI_USER = "dkulpa"
RPI_HOST = "192.168.7.2"
RPI_SSH_KEY = os.path.expanduser("~/.ssh/rpi_swd_id_rsa")
OPENOCD_CFG = ["-f", "/home/dkulpa/rpi-swd.cfg", "-f", "target/nordic/nrf52.cfg"]

# Adres w pamięci Flash nRF52840, gdzie zapiszemy dane (np. początek storage_partition)
# Sprawdź w swoim dts/pm_static.yml. Domyślnie często 0xFC000 lub koniec flasha.
TARGET_FLASH_ADDRESS = 0xFC000

def int_to_bytes(val, length=32):
    return val.to_bytes(length, byteorder='big')

def load_pem_private_key(filename):
    try:
        with open(filename, 'rb') as f:
            pem_data = f.read()
            private_key = serialization.load_pem_private_key(pem_data, password=None)
            if not isinstance(private_key.curve, ec.SECP256R1):
                raise ValueError("Key must be on the SECP256R1 (P-256) curve")
            return private_key
    except Exception as e:
        print(f"[Error] Loading PEM key {filename}: {e}")
        sys.exit(1)

def ssh_exec(cmd_str):
    """Uruchamia komendę na RPi przez SSH"""
    ssh_cmd = [
        "ssh",
        "-o", "IdentitiesOnly=yes",
        "-i", RPI_SSH_KEY,
        f"{RPI_USER}@{RPI_HOST}",
        cmd_str
    ]
    try:
        result = subprocess.check_output(ssh_cmd, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"[Error] SSH/OpenOCD failed: {e.output.decode('utf-8')}")
        sys.exit(1)

def get_mac_from_nrf_remote():
    """Odczytuje MAC z rejestrów FICR nRF52840 przez RPi OpenOCD"""
    print(f"[*] Connecting to {RPI_HOST} to read MAC via OpenOCD...")

    # NOWA STRATEGIA:
    # 1. init - inicjalizacja
    # 2. catch {reset halt} - próba resetu. Ignorujemy błędy (HardFault na pustym chipie).
    # 3. mrw - odczytujemy rejestry do zmiennych Tcl (w0, w1).
    # 4. echo - wypisujemy je w sformatowany sposób, łatwy do wyłapania regexem.
    # 5. shutdown

    tcl_cmd = (
        "init; "
        "catch {reset halt}; "
        "set w0 [mrw 0x100000a4]; "
        "set w1 [mrw 0x100000a8]; "
        "echo [format \"MAC_DUMP: 0x%08x 0x%08x\" $w0 $w1]; "
        "shutdown"
    )

    openocd_cmd = f"sudo openocd {' '.join(OPENOCD_CFG)} -c '{tcl_cmd}'"

    output = ssh_exec(openocd_cmd)

    # Szukamy naszej sformatowanej linii: MAC_DUMP: 0x12345678 0x9abcdef0
    match = re.search(r'MAC_DUMP:\s+0x([0-9a-fA-F]{8})\s+0x([0-9a-fA-F]{8})', output)

    if not match:
        print("[Error] Could not find MAC_DUMP in OpenOCD output.")
        print("Possible causes:")
        print("1. Chip is locked (APPROTECT). Run 'nrf52_recover' manually.")
        print("2. Wiring/Power issues.")
        print(f"Raw output:\n{output}")
        sys.exit(1)

    # OpenOCD zwraca: 0x0000HHLL (w1 - High) oraz 0xXXXXXXXX (w0 - Low)
    # Gdzie HH to najwyższy bajt adresu (MSB).

    w1_hex = match.group(2) # np. "0000913e"
    w0_hex = match.group(1) # np. "649e..."

    w1_bytes = binascii.unhexlify(w1_hex) # \x00\x00\x91\x3e
    w0_bytes = binascii.unhexlify(w0_hex) # \x64\x9e...

    # Składamy adres w formacie Big Endian (MSB first):
    # Bierzemy 2 ostatnie bajty z W1 (High part) i całe 4 bajty z W0 (Low part).
    # W1[2] to MSB. W0[3] to LSB.

    mac_byte_list = list(w1_bytes[2:4] + w0_bytes)

    # --- SYMULACJA ZACHOWANIA ZEPHYRA ---
    # Zephyr dla adresu domyślnego wymusza typ "Random Static",
    # ustawiając dwa najstarsze bity MSB na 1 (OR 0xC0).
    # Zobacz: bt_read_static_addr() w drivers/bluetooth/hci/nrf.c

    original_msb = mac_byte_list[0]
    mac_byte_list[0] |= 0xC0  # Wymuszenie bitów Random Static

    if original_msb != mac_byte_list[0]:
        print(f"[*] Adjusted MSB from {hex(original_msb)} to {hex(mac_byte_list[0])} (Zephyr Random Static compliance)")

    mac_bytes = bytes(mac_byte_list)
    hex_mac = binascii.hexlify(mac_bytes).decode('utf-8').upper()

    print(f"    Final MAC Address: {hex_mac}")
    return hex_mac

def flash_remote(hex_file_path):
    """Wysyła plik hex na RPi i flashuje"""
    remote_tmp = "/tmp/factory_data.hex"

    print(f"[*] Uploading {hex_file_path} to RPi...")
    scp_cmd = [
        "scp",
        "-o", "IdentitiesOnly=yes",
        "-i", RPI_SSH_KEY,
        hex_file_path,
        f"{RPI_USER}@{RPI_HOST}:{remote_tmp}"
    ]
    subprocess.check_call(scp_cmd)

    print(f"[*] Flashing via OpenOCD...")
    # program <file> [verify] [reset] [exit]
    # Używamy adresu zapisanego w HEX, więc nie podajemy go w komendzie program
    openocd_cmd = f"sudo openocd {' '.join(OPENOCD_CFG)} -c 'init; reset halt; program {remote_tmp} verify reset exit'"
    ssh_exec(openocd_cmd)
    print("[+] Flashing complete!")

def main():
    parser = argparse.ArgumentParser(description="Key generator for nRF52840 (Remote RPi Flashing)")
    parser.add_argument("--ca_key", required=True, help="Path to ca_key.pem file")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--mac", help="Manual MAC address (AA:BB:CC:DD:EE:FF)")
    group.add_argument("--read_mac", action="store_true", help="Read MAC from nRF52 via RPi OpenOCD")

    parser.add_argument("--out", required=False, help="Optional output filename (without extension)")
    # Adres flash można nadpisać argumentem
    parser.add_argument("--addr", type=lambda x: int(x, 0), default=TARGET_FLASH_ADDRESS,
                        help=f"Flash address offset (default: {hex(TARGET_FLASH_ADDRESS)})")

    args = parser.parse_args()

    # --- 1. Ustalenie MAC ---
    if args.read_mac:
        mac_input = get_mac_from_nrf_remote()
    else:
        mac_input = args.mac

    clean_mac_hex = re.sub(r'[^a-fA-F0-9]', '', mac_input).lower()
    if len(clean_mac_hex) != 12:
        print(f"[Error] Invalid MAC length: {len(clean_mac_hex)}")
        sys.exit(1)

    mac_raw_bytes = binascii.unhexlify(clean_mac_hex)

    if args.out:
        base_name = os.path.splitext(args.out)[0]
    else:
        base_name = clean_mac_hex

    hex_filename = f"{base_name}.hex"

    # --- 2. Generowanie kluczy (identycznie jak w ESP32) ---
    print(f"--- Generating keys for MAC: {clean_mac_hex} ---")

    manu_priv_key = load_pem_private_key(args.ca_key)
    manu_pub_key = manu_priv_key.public_key()
    manu_pub_nums = manu_pub_key.public_numbers()
    manu_pub_bytes = int_to_bytes(manu_pub_nums.x) + int_to_bytes(manu_pub_nums.y)

    dev_priv_key = ec.generate_private_key(ec.SECP256R1())
    dev_pub_key = dev_priv_key.public_key()
    dev_priv_val = dev_priv_key.private_numbers().private_value
    dev_priv_bytes = int_to_bytes(dev_priv_val)
    dev_pub_nums = dev_pub_key.public_numbers()
    dev_pub_bytes = int_to_bytes(dev_pub_nums.x) + int_to_bytes(dev_pub_nums.y)

    # --- 3. Podpis (Logika Legacy z ESP32 - base64 string) ---
    mac_b64 = base64.b64encode(mac_raw_bytes).decode('utf-8')
    dev_pub_b64 = base64.b64encode(dev_pub_bytes).decode('utf-8')

    # Zachowujemy format payloadu taki sam jak w wersji ESP, by backend mógł go zweryfikować
    payload_str = f"2;-1;{mac_b64};{dev_pub_b64}"
    payload_bytes = payload_str.encode('utf-8')
    print(f"[*] Data to sign: {payload_str}")

    signature_der = manu_priv_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature_der)
    signature_raw = int_to_bytes(r) + int_to_bytes(s)

    # --- 4. Pakowanie danych do struktury binarnej (dla nRF C struct) ---
    # Struktura danych (Little Endian dla nagłówków, Big Endian dla kluczy krypto):
    # Magic (4B) | MAC (6B) | Pad (2B) | Manu Pub (64B) | Dev Priv (32B) | Dev Pub (64B) | Signature (64B)

    MAGIC = 0x4D474B50 # "MGKP"

    # struct format: I (uint32), 6s (mac), 2x (pad), 64s, 32s, 64s, 64s
    binary_data = struct.pack(
        '<I6s2x64s32s64s64s',
        MAGIC,
        mac_raw_bytes,
        manu_pub_bytes,
        dev_priv_bytes,
        dev_pub_bytes,
        signature_raw
    )

    # --- 5. Generowanie pliku Intel HEX ---
    ih = IntelHex()
    ih.puts(args.addr, binary_data)
    ih.write_hex_file(hex_filename)

    print(f"[+] Generated HEX file: {hex_filename} at address {hex(args.addr)}")

    # --- 6. Flashowanie (opcjonalne) ---
    # Automatyczne flashowanie, jeśli odczytano MAC (zakładamy, że user chce od razu wgrać)
    # lub jeśli user wyraźnie by o to poprosił (tu: automatycznie dla wygody)

    user_input = input(f"Do you want to flash {hex_filename} to the device now? [Y/n]: ")
    if user_input.lower() not in ['n', 'no']:
        flash_remote(hex_filename)

if __name__ == "__main__":
    main()