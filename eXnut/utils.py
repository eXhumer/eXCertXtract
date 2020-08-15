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

# Credits for extended_gcd, modinv, get_primes, get_pubk, get_priv_key_der
# - SimonMKWii
# - SciresM
# - SocraticBliss

from fractions import gcd
from hashlib import sha256
from random import randint
from binascii import hexlify
from asn1 import Decoder as ASN1Decoder, Encoder as ASN1Encoder

def extended_gcd(aa, bb):
	'''Extended Euclidean algorithm'''
	lastremainder, remainder = abs(aa), abs(bb)
	x, lastx, y, lasty = 0, 1, 1, 0
	while remainder:
		lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
		x, lastx = lastx - quotient*x, x
		y, lasty = lasty - quotient*y, y
	return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
	'''Function to perform modular multiplicative inversion'''
	g, x, _ = extended_gcd(a, m)
	if g != 1:
		raise ValueError
	return x % m

def get_primes(D, N, E = 0x10001):
	'''Computes P, Q given E,D where pow(pow(X, D, N), E, N) == X'''
	assert(pow(pow(0xCAFEBABE, D, N), E, N) == 0xCAFEBABE) # Check privk validity
	# code taken from https://stackoverflow.com/a/28299742
	k = E*D - 1
	if k & 1:
		raise ValueError('Could not compute factors. Is private exponent incorrect?')
	t = 0
	while not k & 1:
		k >>= 1
		t += 1
	r = k
	while True:
		g = randint(0, N)
		y = pow(g, r, N)
		if y == 1 or y == N - 1:
			continue
		for _ in range(1, t):
			x = pow(y, 2, N)
			if x == 1 or x == N - 1:
				break
			y = x
		if x == 1:
			break
		elif x == N - 1:
			continue
		x = pow(y, 2, N)
		if x == 1:
			break
	p = gcd(y - 1, N)
	q = N // p
	assert N % p == 0
	if p < q:
		p, q = q, p
	return (p, q)

def get_pubk(clcert):
	'''Function to get the RSA public key and modulus from Nintendo Switch SSL certificate'''
	clcert_decoder = ASN1Decoder()
	clcert_decoder.start(clcert)
	clcert_decoder.enter() # Seq, 3 elem
	clcert_decoder.enter() # Seq, 8 elem
	clcert_decoder.read() 
	clcert_decoder.read()
	clcert_decoder.read()
	clcert_decoder.read()
	clcert_decoder.read()
	clcert_decoder.read()
	clcert_decoder.enter()
	clcert_decoder.enter()
	_, v = clcert_decoder.read()
	assert(v == '1.2.840.113549.1.1.1') # rsaEncryption(PKCS #1)
	clcert_decoder.leave()
	_, v = clcert_decoder.read()
	rsa_decoder = ASN1Decoder()
	rsa_decoder.start(v[1:])
	rsa_decoder.enter()
	_, N = rsa_decoder.read()
	_, E = rsa_decoder.read()
	return (E, N)

def get_priv_key_der(clcert, privk):
	'''Function to generate the private key in DER format from Nintendo Switch SSL Certificate and raw private exponent.'''

	if len(privk) != 0x100:
		print('Error: Private key is not 0x100 bytes...')
		sys.exit(1)

	E, N = get_pubk(clcert)
	D = int(hexlify(privk), 0x10)

	if pow(pow(0xDEADCAFE, E, N), D, N) != 0xDEADCAFE:
		print('Error: privk does not appear to be inverse of pubk!')
		sys.exit(1)

	P, Q = get_primes(D, N, E)
	dP = D % (P - 1)
	dQ = D % (Q - 1)
	Q_inv = modinv(Q, P)

	enc = ASN1Encoder()
	enc.start()
	enc.enter(0x10)
	enc.write(0)
	enc.write(N)
	enc.write(E)
	enc.write(D)
	enc.write(P)
	enc.write(Q)
	enc.write(dP)
	enc.write(dQ)
	enc.write(Q_inv)
	enc.leave()
	return enc.output()

def verify_ssl_rsa_kek(ssl_rsa_kek: bytes) -> bool:
	'''Function to verify the SSL RSA Kek via SHA256 hash'''
	return sha256(ssl_rsa_kek).digest().hex() == '02a3ccf14a9572947b40afa87ad8cdd3d3a39dccf5d7911cdaf78f369e788840'
