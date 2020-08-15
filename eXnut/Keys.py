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

class Keys:
	def __init__(self):
		pass

	def readFile(self, keysFilePath: Path):
		'''Read an external file and load keys from the file'''
		keys = {}
		with open(keysFilePath, 'r') as keysStream:
			rawKeyLines = keysStream.readlines()
			for rawKeyLine in rawKeyLines:
				[keyname, keyvalue] = rawKeyLine.replace('\n', '').replace(' ', '').split('=')
				keys.update({keyname: unhexlify(keyvalue)})
		self.__dict__.update(keys)

	def getKey(self, keyname: str) -> bytes:
		'''Attempt to get a key from keyname'''
		if keyname in self.__dict__.keys():
			return self.__dict__[keyname]
		else:
			return b''
