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

from binascii import unhexlify
from typing import TextIO


class Keys:
    def __init__(self, **keys: bytes):
        self.__keys = keys

    def __contain__(self, key: str):
        return key in self.__keys

    def __getitem__(self, key: str):
        return self.__keys[key]

    @classmethod
    def from_stream(cls, keys_stream: TextIO):
        '''Read an external file and load keys from the file'''

        assert keys_stream.readable()

        keys = {}

        for raw_key_line in keys_stream.readlines():
            [key_name, key_value] = raw_key_line.replace('\n', '').replace(' ', '').split('=')
            keys |= {key_name: unhexlify(key_value)}

        return cls(keys)
