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

from binascii import hexlify
from pathlib import Path
from typing import BinaryIO

from Crypto.Cipher import AES
from Crypto.IO import PEM
from Crypto.Util import Counter

from ._utils import get_priv_key_der


class CAL0:
    def __init__(self, serial_number: bytes, ssl_certificate: bytes,
                 rsa_2048_eticket_certificate: bytes, device_id: str, ssl_key: bytes):
        self.__device_id = device_id
        self.__rsa_2048_eticket_certificate = rsa_2048_eticket_certificate
        self.__serial_number = serial_number
        self.__ssl_certificate = ssl_certificate
        self.__ssl_key = ssl_key

    @property
    def device_id(self):
        return self.__device_id

    def extract_ssl_certificate_key_pem(self, out_path: Path | None = None):
        '''Extract the SSL certificate and key in PEM encoded format.

        It write to a file named <DEVICE_ID>.pem, where DEVICE_ID is
        the device ID extracted from the certificate.
        '''

        if not out_path:
            out_path = Path(f'{self.__device_id}.pem')

        with open(out_path, 'w') as ssl_pem_stream:
            ssl_pem_stream.write(PEM.encode(self.__ssl_certificate, 'CERTIFICATE'))
            ssl_pem_stream.write('\n')
            ssl_pem_stream.write(PEM.encode(self.__ssl_key, 'RSA PRIVATE KEY'))

        return out_path

    @classmethod
    def from_stream(cls, stream: BinaryIO, ssl_rsa_kek: bytes):
        '''Read CAL0 information from stream'''

        assert stream.readable()
        cal0 = stream.read()

        if int.from_bytes(cal0[0x0:0x4], byteorder='little', signed=False) != 810303811:
            raise RuntimeError("Stream doesn't contain valid NX CAL0 data!")

        serial_number = cal0[0x250:0x25E].decode('utf-8')
        ssl_certificate_size = int.from_bytes(cal0[0xAD0:0xAD4], byteorder='little', signed=False)
        ssl_certificate = cal0[0xAE0:0xAE0+ssl_certificate_size]
        rsa_2048_eticket_certificate = cal0[0x2A90:0x2CD0]
        device_id = hexlify(cal0[0x35E0:0x35E8]).decode('utf-8')
        ctr = Counter.new(128, initial_value=int(hexlify(cal0[0x3AE0:0x3AF0]), 16))
        dec = AES.new(ssl_rsa_kek, AES.MODE_CTR, counter=ctr).decrypt(cal0[0x3AF0:0x3C10])
        ssl_key = get_priv_key_der(ssl_certificate, dec[:0x100])

        return cls(serial_number, ssl_certificate, rsa_2048_eticket_certificate, device_id,
                   ssl_key)

    @property
    def rsa_2048_eticket_certificate(self):
        return self.__rsa_2048_eticket_certificate

    @property
    def serial_number(self):
        return self.__serial_number

    @property
    def ssl_certificate(self):
        return self.__ssl_certificate

    @property
    def ssl_key(self):
        return self.__ssl_key
