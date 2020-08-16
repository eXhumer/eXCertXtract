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

# Credits for basically all the help I needed
# - Blake Warner

from eXnut.CAL0 import CAL0
from eXnut.Keys import Keys
from eXnut.utils import verify_ssl_rsa_kek
from pathlib import Path
from sys import argv

def main():
	if len(argv) == 3:
		cal0_path = Path(argv[1])
		keys_path = Path(argv[2])

		if not cal0_path.exists():
			raise RuntimeError(f'CAL0 file specified {cal0_path} doesn\'t exist!')

		if not keys_path.exists():
			raise RuntimeError(f'Keys file specified {keys_path} doesn\'t exist!')

		cal0 = CAL0()
		keys = Keys()

		keys.read_file(keys_path)
		ssl_rsa_kek = keys.get_key('ssl_rsa_kek')

		if verify_ssl_rsa_kek(ssl_rsa_kek):
			cal0.read_file(cal0_path, ssl_rsa_kek)
			
		else:
			raise RuntimeError(f'ssl_rsa_kek in keys file is invalid!')

		print(f'Device ID: {cal0.device_id}')
		print(f'Serial Number: {cal0.serial_number}')
		cal0.extract_ssl_cert_key_pem()
		print(f'Extracted Nintendo Switch SSL certificate and key successfully to {cal0.device_id}.pem!')

	else:
		raise RuntimeError(f'Usage: python {__file__} CAL0_FILE_PATH KEYS_FILE_PATH')

if __name__ == '__main__':
	main()
