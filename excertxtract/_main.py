#!/usr/bin/env python3

# Simple script to extract Nintendo Switch SSL certificate and key from CAL0
# Copyright (C) 2020, 2023 eXhumer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Credits for basically all the help I needed
# - Blake Warner

from argparse import ArgumentParser
from pathlib import Path

from exnut import CAL0, Keys, verify_ssl_rsa_kek


def __program_main():
    parser = ArgumentParser()
    parser.add_argument("cal0_path", help="Path to decrypted NX CAL0 file", type=Path)
    parser.add_argument("keys_path", help="Path to NX keys file", type=Path)
    parser.add_argument("--ssl-path", help="File path to extract SSL certificate to", type=Path)

    args = parser.parse_args()

    if not args.cal0_path.exists():
        raise RuntimeError(f"CAL0 file specified {args.cal0_path} doesn't exist!")

    if not args.keys_path.exists():
        raise RuntimeError(f"Keys file specified {args.keys_path} doesn't exist!")

    with args.keys_path.open(mode="r") as keys_stream:
        keys = Keys.from_stream(keys_stream)

    if "ssl_rsa_kek" not in keys:
        raise RuntimeError(f"ssl_rsa_kek not in {args.keys_path}")

    ssl_rsa_kek = keys["ssl_rsa_kek"]

    if not verify_ssl_rsa_kek(ssl_rsa_kek):
        raise RuntimeError(f"ssl_rsa_kek in {args.keys_path} is invalid!")

    with args.cal0_path.open(mode="rb") as cal0_stream:
        cal0 = CAL0.from_stream(cal0_stream, ssl_rsa_kek)

    print(f'Device ID: {cal0.device_id}')
    print(f'Serial Number: {cal0.serial_number}')
    ssl_path = cal0.extract_ssl_certificate_key_pem(out_path=args.ssl_path)
    print(f"Extracted Nintendo Switch SSL certificate and key successfully to {ssl_path}!")
