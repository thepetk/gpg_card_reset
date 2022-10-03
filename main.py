#!/usr/bin/env python3
#
# This script aims to reset and re-configure a plugged in
# Yubikey card. To do so it uses the GnuPG module which is
# a free implementation of the OpenPGP standard as defined
# by the RFC4880 (also known as PGP). 
#
# More info can be found here: https://gnupg.org/
#
# The flow of the script is very simple. It is designed with
# the following steps:
#
# User input: 
# The user gives all the required information. First/Last
# name, email and PIN/Admin PIN are required.
#
# Env setup:
# The script creates all the temporary directories and exports
# the GNUPGHOME environment variable in order to avoid creating
# issues to the operating system which is hosting the process.
# It also updates the ownership and mode of these directories
# in order to be able to clean them afterwards
#
# Master-key/Sub-keys generation:
# Following the environment setup the script will try to
# create the pubring.kbx file and with this the master key
# of the user. After the master key generation inside the custom homedir
# we are going to create three (3) sub keys for the newly
# created key. Those keys have specific usage and this is
# sign (signing) | encr (encryption) | auth (authentication)
#
# Card (YubiKey Reset & Re-configure)
# With --card-edit command and the usage of pexpect we are reseting
# and reconfiguring the card with the created master and sub keys.
# Moreover, the script applies a factory-reset command and then
# It imports the keys and the given input to the card
#
# Revocation certificate/ssh key/public key export:
# As a last step it generates the revocation certificate,
# and exportd the ssh_key and public key for the user
import argparse
import getpass
import logging
import os
import random
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

import pexpect

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--key-length", help="Master-Key length", type=int)
parser.add_argument("-t", "--key-type", help="Master-Key type", type=int)
parser.add_argument("-e", "--key-expiry", help="Master-Key expiry", type=str)
parser.add_argument("--log-level", help="Logging level", type=str)
args = parser.parse_args()
random.seed = os.urandom(1024)

# Default loggers settings include time of the log
# name of process, the logging level of the message
# the module which has pushed this message to the logger
# and the message itself. Format below:

# <time> - <process> - <level> - <module>:: <msg>
logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)

# Global variables include the master key configuration,
# the sub-keys configuration, the logging level mapping
# (str -> logging.LEVEL) and access permissions for tmp
# directories
DEFAULT_KEY_LENGTH: int = args.key_length if args.key_length else 4096
DEFAULT_KEY_TYPE: int = args.key_type if args.key_type else 1
DEFAULT_KEY_EXPIRY: str = args.key_expiry if args.key_expiry else "5y"
DEFAULT_KEY_FILE_TMPL: str = (
    "Key-Type: {ktype}\nKey-Length: {klength}\nName-Real: {name}\nName-Email: {email}\nName-Comment: {comment}\nExpire-Date: {expiry}\nPassphrase: {passphrase}"
)
GPG_HOME: str = "ram/gpgtmp"
MAX_RETRIES: int = 3
LOG_LEVEL_MAPPING = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR
}
LOGLEVEL: int = (
    LOG_LEVEL_MAPPING.get(args.log_level)
    if args.log_level and LOG_LEVEL_MAPPING.get(args.log_level)
    else logging.INFO
)
INPUT_DATA_NAME: str = "input_data"
PASS_LENGTH = 16
PASS_CHARS = string.ascii_letters + string.digits + "!@#$%^&*()"
PEXPECT_TIMEOUT = 900
PEXPECT_ENCODING = "utf-8"
SUBKEY_FILE_TMPL: str = "Subkey-Type: {ktype}\nSubkey-Length: {klength}\nSubkey-Usage: {kusage}"
SUBKEYS_LIST: List[Dict[str, str]] = [
    {
        "key_type": "rsa",
        "key_length": "4096",
        "key_usage": "sign",
        "key_expiry": "5y"
    },
    {
        "key_type": "rsa",
        "key_length": "4096",
        "key_usage": "encr",
        "key_expiry": "5y"
    },
    {
        "key_type": "rsa",
        "key_length": "4096",
        "key_usage": "auth",
        "key_expiry": "5y"
    },
]
TEMP_DIRS: List[Tuple[str, int]] = [
    ("ram/*", 775), (GPG_HOME, 700), ("tmp/", 777)
]
