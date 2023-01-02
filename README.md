# eXCertXtract

Python package to extract SSL Certificate from Nintendo Switch CAL0 partition (decrypted PRODINFO).

## Usage Reguirements
* [Python 3.11+](https://www.python.org/downloads/) (May work in previous versions, but only tested 3.11+)
* pip package manager
* Backup of CAL0 partition from a Nintendo Switch you wish to extract SSL certificate from
* Keys from Nintendo Switch containing the `ssl_rsa_kek` key

## To install
`pip install -e git+https://github.com/eXhumer/eXCertXtract.git@dev#egg=excertxtract`

## Usage
```
usage: eXCertXtract [-h] [--ssl-path SSL_PATH] cal0_path keys_path

positional arguments:
  cal0_path            Path to decrypted NX CAL0 file
  keys_path            Path to NX keys file

options:
  -h, --help           show this help message and exit
  --ssl-path SSL_PATH  File path to extract SSL certificate to
```
