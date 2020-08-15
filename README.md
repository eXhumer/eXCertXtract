# NX-CertXtract

A simple Python 3 script to extract SSL Certificate from Nintendo Switch CAL0 partition (decrypted PRODINFO).

## Usage Reguirements
* [Python 3.8.0+](https://www.python.org/downloads/) (May work in previous versions, but only tested 3.8.0+)
* PIP module requirements from `requirements.txt`
* Backup of CAL0 partition from a Nintendo Switch you wish to extract SSL certificate from
* Keys from Nintendo Switch containing the `ssl_rsa_kek` key

### To install the PIP requirements
`pip install -r requirements.txt`

## Usage
`python ssl_extract.py CAL0_FILE_PATH KEYS_FILE_PATH`
