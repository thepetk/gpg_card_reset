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


class GenericBashError(Exception):
    pass


class MountFSFailedError(GenericBashError):
    pass


class ChangeOwnershipFailedError(GenericBashError):
    pass


class ChangeModeFailedError(GenericBashError):
    pass


class GPGKeyIDNotFoundError(GenericBashError):
    pass


class YubiKeyIDNotFoundError(GenericBashError):
    pass


class BashMixin:
    """
    BashMixin includes all bash commands operations
    done by this script. It always calls a command
    through command method.

    It facilitates the cmod, chown, mkdir and mount
    commands.

    :raises: MountFSFailedError (unable to mount ram/)
    :raises: ChangeOwnershipFailedError (unable to
             update ownership of directory)
    :raises: ChangeModeFailedError (unable to update
             mode of directory)
    """
    def __init__(self, gnupghome: str = GPG_HOME) -> None:
        self.gnupghome = self.full_path(gnupghome)

        self._set_env()

    def __str__(self) -> str:
        return "<Bash Executor>"

    @property
    def _env(self) -> Dict[str, str]:
        os.environ["GNUPGHOME"] = self.gnupghome
        _current_env = os.environ.copy()
        return _current_env

    def full_path(self, path: str = "") -> str:
        return "{}/{}".format(str(Path.home()), path)

    def command(
        self,
        args_list: List[str],
        ignore_stderr: bool = False
    ) -> str:
        """Handles all bash commands ran by this script"""
        ret = subprocess.Popen(
            args_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env
        )

        out, err = ret.communicate()
        if err:
            if ignore_stderr is True:
                logger.debug(
                    "{}: Command '{}' output [below]".format(
                        self.__str__(), " ".join(args_list)
                    )
                )
                for _err in err.decode("utf8").split("\n"):
                    if _err:
                        logger.debug("{}: {}".format(
                            self.__str__(), _err
                        ))
            else:
                raise GenericBashError(
                    "Command {} failed with error: {}".format(
                        " ".join(args_list), err.decode("utf8")
                    )
                )
        return out.decode("utf8")

    def _set_env(self) -> bool:
        """Exports GNUPGHOME as env var and configures dirs"""
        # Mount RAM directory on ram
        _ = self.mkdir(self.full_path("ram"))
        _ = self.mount(
            "ramfs",
            self.full_path("ram"),
            [
                "-t", "ramfs", "-o", "size=1M"
            ]
        )
        # Create directories
        for path, perms in TEMP_DIRS:
            _ = self.mkdir(self.full_path(path))

        # Configure perms and own for new dirs
        _ = self.chown(
            os.getuid(), self.full_path(GPG_HOME), recursive=True
        )
        for path, perms in TEMP_DIRS:
            _ = self.chmod(self.full_path(path), perms)

        logger.info("{}: Generate Master/Sub keys:: Pubring file generated".format(
            self.__str__()
        ))
        return True

    def mkdir(self, path: str) -> None:
        if os.path.exists(path) is False:
            _ = self.command(["sudo", "mkdir", path])
        logger.debug("{}: Dir created: {}, already_exists: {}".format(
            self.__str__(), path, str(os.path.exists(path))
        ))

    def mount(
        self, src: str, tar: str, options: List[str] = None
    ) -> None:
        try:

            if options is not None:
                _ = self.command(["sudo", "mount"] + options + [src, tar])
            else:
                _ = self.command(["sudo", "mount", src, tar])

            logger.debug("{}: Dir mounted:: {} to target:: {}".format(
                self.__str__(), src, tar
            ))
        except GenericBashError as e:
            logger.error("{}: Error mounting filesystem {}:: {}".format(
                    self.__str__(), src, str(e)
                )
            )
            raise MountFSFailedError(str(e))

    def chown(self, uid: int, path: str, **kwargs) -> None:
        try:
            c_list = ["sudo", "chown", "-R", str(uid), path]
            if kwargs.get("recursive") is True:
                _ = c_list.remove("-R")
            _ = self.command(c_list)
        except GenericBashError as e:
            logger.error(
                "{}: Error changing ownership dir:: {} :: {}".format(
                    self.__str__(), path, str(e)
                )
            )
            raise ChangeOwnershipFailedError(str(e))

    def chmod(self, path: str, perms: int, **kwargs) -> None:
        try:
            c_list = ["sudo", "chmod", "-R", str(perms), path]
            if kwargs.get("recursive") is True:
                _ = c_list.remove("-R")
            _ = self.command(c_list)
        except GenericBashError as e:
            logger.error(
                "{}: Error changing mode dir:: {} :: {}".format(
                    self.__str__(), path, str(e)
                )
            )
            raise ChangeModeFailedError(str(e))


class UserInput:
    """
    Basic input class which gathers all required data
    field for this script. Those fields are:

    :param first_name: User's first name (not null)
    :type first_name: str

    :param last_name: User's last name (not null)
    :type last_name: str

    :param mail: User's email (not null, must include @ and .)
    :type mail: str

    :param pin: Yubikey's PIN (must be longer than 6 chars)
    :type pin: str

    :param admin_pin: Yubikey's Admin PIN (must be longer that 8 chars)
    :type admin_pin: str
    
    :property name: Full name of user
    :type name: str
    """
    def __init__(self) -> None:
        self.first_name = self._get_str("What is your First Name: ")
        self.last_name = self._get_str("What is your Last Name: ")
        self.mail = self._get_email("What is your Email: ")
        self.pin = self._get_pin(
            "Please, choose a 6-digit PIN (don't be obvious like birthday date): ", 6
        )
        self.admin_pin = self._get_pin(
            "Please, choose an 8 digits adminPIN, it will allows you to unblock your yubikey after 3 PIN fails):\n", 8
        )

    def __str__(self) -> str:
        return "<UserInput>"

    def _get_str(self, msg: str, valid: bool = False) -> str:
        while not valid:
            _field = input("{}: {}".format(self.__str__(), msg))
            if _field:
                return _field
            logger.info(
                "{}: Input not correct. Try again".format(self.__str__())
            )

    def _get_pin(self, msg: str, length: int, valid: bool = False) -> str:
        while not valid:
            _field = getpass.getpass("{}: {}".format(self.__str__(), msg))
            if len(_field) >= length:
                return _field
            logger.info(
                "{}: Input not correct. Try again".format(self.__str__())
            )

    def _get_email(self, msg: str, valid = False) -> str:
        while not valid:
            _field = input("{}: {}".format(self.__str__(), msg))
            if _field and "." in str(_field) and "@" in str(_field):
                return _field
            logger.info(
                "{}: Input not correct. Try again".format(self.__str__())
            )

    @property
    def name(self) -> str:
        return "{} {}".format(self.first_name, self.last_name)
