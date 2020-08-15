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
		cal0Path = Path(argv[1])
		keysPath = Path(argv[2])

		if not cal0Path.exists():
			raise RuntimeError(f'CAL0 file specified {cal0Path} doesn\'t exist!')

		if not keysPath.exists():
			raise RuntimeError(f'Keys file specified {keysPath} doesn\'t exist!')

		cal0 = CAL0()
		keys = Keys()

		keys.readFile(keysPath)
		ssl_rsa_kek = keys.getKey('ssl_rsa_kek')

		if verify_ssl_rsa_kek(ssl_rsa_kek):
			cal0.readFile(cal0Path, ssl_rsa_kek)
			
		else:
			raise RuntimeError(f'ssl_rsa_kek in keys file is invalid!')

		print(f'Device ID: {cal0.deviceId}')
		print(f'Serial Number: {cal0.serialNumber}')
		cal0.getPEMCertificate()
		print('Extracted Nintendo Switch SSL certificate and key successfully!')

	else:
		raise RuntimeError('Usage: python ssl_extract.py CAL0_FILE_PATH KEYS_FILE_PATH')

if __name__ == '__main__':
	main()
