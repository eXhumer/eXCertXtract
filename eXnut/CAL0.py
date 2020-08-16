#!/usr/bin/env python3

# Simple script to extract Nintendo Switch SSL certificate and key from CAL0
# Copyright (C) 2020 eXhumer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from pathlib import Path
from binascii import hexlify
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.IO import PEM
from eXnut.utils import get_priv_key_der
from typing import NoReturn

class CAL0:
	def __init__(self):
		self.serial_number = None
		self.ssl_certificate = None
		self.rsa_2048_eticket_certificate = None
		self.device_id = None
		self.ssl_key = None

	def read_file(self, filePath: Path, ssl_rsa_kek: bytes) -> NoReturn:
		'''Read an external file and load CAL0 information to instance'''
		with open(filePath, 'rb') as cal0_stream:
			cal0 = cal0_stream.read()
			if int.from_bytes(cal0[0x0:0x4], byteorder='little', signed=False) == 810303811:
				self.serial_number = cal0[0x250:0x25E].decode('utf-8')
				ssl_certificate_size = int.from_bytes(cal0[0xAD0:0xAD4], byteorder='little', signed=False)
				self.ssl_certificate = cal0[0xAE0:0xAE0+ssl_certificate_size]
				self.rsa_2048_eticket_certificate = cal0[0x2A90:0x2CD0]
				self.device_id = hexlify(cal0[0x35E0:0x35E8]).decode('utf-8')
				ctr = Counter.new(128, initial_value=int(hexlify(cal0[0x3AE0:0x3AF0]), 16))
				dec = AES.new(ssl_rsa_kek, AES.MODE_CTR, counter=ctr).decrypt(cal0[0x3AF0:0x3C10])
				self.ssl_key = get_priv_key_der(self.ssl_certificate, dec[:0x100])
			else:
				raise RuntimeError(f'{filePath} is not a valid CAL0 file!')

	def extract_ssl_cert_key_pem(self) -> NoReturn:
		'''Extract the SSL certificate and key in PEM encoded format.
		
		It write to a file named <DEVICE_ID>.pem, where DEVICE_ID is
		the device ID extracted from the certificate.
		'''
		out_path = Path(f'./{self.device_id}.pem')
		with open(out_path, 'w') as ssl_pem_stream:
			ssl_pem_stream.write(PEM.encode(self.ssl_certificate, 'CERTIFICATE'))
			ssl_pem_stream.write('\n')
			ssl_pem_stream.write(PEM.encode(self.ssl_key, 'RSA PRIVATE KEY'))
