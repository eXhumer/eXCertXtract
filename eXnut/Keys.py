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
from binascii import unhexlify
from typing import NoReturn

class Keys:
	def __init__(self):
		pass

	def read_file(self, keys_file_path: Path) -> NoReturn:
		'''Read an external file and load keys from the file'''
		keys = {}
		with open(keys_file_path, 'r') as keys_stream:
			raw_key_lines = keys_stream.readlines()
			for raw_key_line in raw_key_lines:
				[key_name, key_value] = raw_key_line.replace('\n', '').replace(' ', '').split('=')
				keys.update({key_name: unhexlify(key_value)})
		self.__dict__.update(keys)

	def get_key(self, key_name: str) -> bytes:
		'''Attempt to get a key from keyname'''
		if key_name in self.__dict__.keys():
			return self.__dict__[key_name]
		else:
			return b''
