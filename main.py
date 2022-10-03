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

class GPGInputData:
    """
    Contents for GPG master/sub keys generation. This is required
    for --batch mode creation of master key and sub keys. Batch is
    used from gpg2 for unattended key generation. More information

    https://gnupg.org/documentation/manuals/gnupg-2.0/Unattended-GPG-key-generation.html

    Inside the gpg input data we are defining:
    :param name: Name of the user
    :type name: str

    :param email: Email of the user
    :type email: str

    :param comment: Comment of the user
    :type comment: str (default "None")

    :param ktype: One of 1 - ('RSA'), 2 - ('DSA'), 3 - ('ELG-E')
    :type ktype: str (default: RSA)

    :param klength: Length of key
    :type klength: int (default: 4096)

    :param expiry: Expiry date of key
    :type expiry: str (default: 5y)

    :param passphrase: Key's passhprase
    :type passphrase: str
    """
    def __init__(
        self,
        name: str = "",
        email: str = "",
        comment: str = "",
        ktype: Optional[int] = None,
        klength: Optional[int] = None,
        expiry: Optional[str] = None,
        passphrase: Optional[str] = None,
    ) -> None:

        self.name = name
        self.email = email
        self.comment = comment
        self.passphrase = passphrase
        self.ktype = ktype if ktype is not None else DEFAULT_KEY_TYPE
        self.klength = klength if klength is not None else DEFAULT_KEY_LENGTH
        self.expiry = expiry if expiry is not None else DEFAULT_KEY_EXPIRY

    def __str__(self) -> str:
        return "<GPGInputdata>"

    @property
    def template(self) -> str:
        return DEFAULT_KEY_FILE_TMPL.format(
            ktype=self.ktype,
            klength=self.klength,
            name=self.name,
            email=self.email,
            comment=self.comment,
            expiry=self.expiry,
            passphrase=self.passphrase
        )

    def to_file(self, path: str) -> None:
        """
        Creates a temporary file to the filesystem
        After script's execution it cleans this file
        """
        logger.debug("{}: Creating temporary file:: {}".format(
                self.__str__(), path
            )
        )
        f = open(path, "w")
        f.write(self.template)
        f.close()
        logger.debug("{}: Created temporary file:: {}".format(
            self.__str__(), self.template
        ))


@dataclass
class GPGCardCommand:
    expect: Optional[Union[List[str], str]] = None
    response: Optional[str] = None
    mode: Literal["admin", "pass", "normal"] = "normal"
    passphrase: bool = False
    sleep: int = 0
    log: Optional[str] = None


class GPGCardManager:
    """
    The GPGCardManager is responsible for the update and reset
    of the card (Yubikey for example). It accepts a list of
    GPGCardCommand instances in order to interact with the card

    The interact method spawns a pexpect child in order to automate
    the interactive dialog that --card-edit of gpg2 command has.
    It separates the GPGCommand in three methods:

    - _set_deafult_passphrase: Sets default passphrase for the given key
                               mostly used to import keys inside the card

    - _access_admin: Handles the interactive dialog for accessing the
                     admin mode of gpg2 --card-edit command

    - _normal: All other commands are handled through _normal method
    """
    def __init__(self) -> None:
        self._process = None
        self._DEFAULT_PASS = "12345678"
        self._MODEMAP: Dict[Literal["admin", "pass", "normal"], Callable] = {
            "admin": self._access_admin,
            "pass": self._set_default_passphrase,
            "normal": self._normal
        }
    def __str__(self) -> str:
        return "<GPGCardManager>"

    def _spawn(self, command: str, timeout: int) -> Any:
        return pexpect.spawn(
            command, timeout=timeout, encoding=PEXPECT_ENCODING
        )

    def _set_default_passphrase(
        self, expect: Optional[Union[List[str], str]] = None, response: Optional[str] = None
    ) -> None:
        assert expect is None and response is None

        _exc = self._process.expect(["gpg/card>", "passphrase"])
        if not _exc:
            _ = self._process.sendline(self._DEFAULT_PASS)
            _ = self._process.expect("gpg/card>")

    def _access_admin(self, expect: Optional[Union[List[str], str]], response: str) -> None:
        _ = self._process.expect(expect)
        _ = self._process.sendline(response)
        _ret = self._process.expect(
            ["Admin commands are allowed", "Admin commands are not allowed"]
        )
        if not _ret == 0:
            _ = self._process.sendline(response)
            _ = self._process.expect(expect)

    def _normal(self, expect: Optional[Union[List[str], str]], response: Optional[str]) -> None:
        if not response is None and self._process:
            _ = (
                self._process.expect(expect)
                if expect is not None else None
            )
            _ = (
                self._process.sendline(response)
                if response is not None else None
            )

    def _handle_mode(self, gpgcc: GPGCardCommand) -> None:
        return self._MODEMAP[gpgcc.mode](gpgcc.expect, gpgcc.response)

    def interact(
        self,
        command: str,
        gpgccs: List[GPGCardCommand],
        timeout: int = PEXPECT_TIMEOUT
    ) -> None:
        self._process = self._spawn(command, timeout)
        try:
            for gpgcc in gpgccs:
                _ = self._handle_mode(gpgcc)

                if gpgcc.log:
                    logger.info("{}: {}".format(self.__str__(), gpgcc.log))

                if gpgcc.sleep:
                    time.sleep(gpgcc.sleep)
        except pexpect.exceptions.TIMEOUT:
            logger.warning("{}: pexpect timeout reached".format(self.__str__()))


class GPGManager(BashMixin):
    """
    The GPGManager is an abstraction over BashMixin and GPGCardManager.
    It includes its own functionality regarding the master and sub keys
    generation.

    On its initialization, initializes BashMixin, so it sets the environment
    of the script (by creating all the necessary directorys etc). Then,
    it kills all the pre-existing agents of gpg2. Finally it creates
    a GPGCardManager instance to handle all card-edit commands
    """
    def __init__(self):
        super().__init__()
        _ = self._kill_agents()

        self.card = GPGCardManager()

    def _kill_agents(self) -> None:
        logger.info("{}: Generate Master/Sub keys:: Killing all active previous gpg-agents".format(
            self.__str__()
        ))
        _ = self.command(["gpgconf", "--kill", "gpg-agent"])

    def _clean(self, path: str) -> None:
        logger.debug("{}: Cleaning temporary file:: {}".format(
            self.__str__(), path
        ))
        _ = self.command(["rm", path])

    def create_master_key(
        self,
        name: str,
        email: str,
        comment: str,
        passphrase: str,
        path: str = "",
        ktype: Optional[str] = None,
        klength: Optional[str] = None,
        expiry: Optional[str] = None,
    ) -> None:
        """
        Temporary creates a file called input_data
        containing all information for the gpg key.
        Then it creates a gpg key with the given data
        and cleans the temp created file.
        """
        _ = GPGInputData(
            name=name,
            email=email,
            comment=comment,
            ktype=ktype,
            klength=klength,
            expiry=expiry,
            passphrase=passphrase
        ).to_file(path)

        _ = self.command(
            [
                "gpg2",
                "--full-gen-key",
                "--pinentry-mode=loopback",
                "--expert",
                "--batch",
                path
            ], ignore_stderr=True
        ) 

        self._clean(path)

    def create_sub_key(
        self,
        uid: str,
        passphrase: str,
        homedir: str,
        ktype: Optional[str] = None,
        klength: Optional[str] = None,
        kusage: Optional[str] = None,
        expiry: Optional[str] = None,
    ) -> None:

        _ = self.command(
            [
                "gpg2",
                "--homedir", homedir,
                "--pinentry-mode=loopback",
                "--batch",
                "--passphrase", passphrase,
                "--quick-add-key", uid,
                "{}{}".format(ktype, klength),
                kusage,
                expiry
            ],
            ignore_stderr=True,
        )

    def get_master_key_id(self) -> str:
        _kid: List[str] = []
        args_list: List[str] = [
            "gpg2", "-k", "--homedir", self.full_path(GPG_HOME)
        ]

        logger.debug("{}: Getting master key_id".format(self.__str__()))        
        _key_info = self.command(args_list, ignore_stderr=True)

        if _key_info:
            _lines = [line.strip(" ") for line in _key_info.split("\n")]
            _kid = [
                _lines[i+1] for i in range(0, len(_lines))
                if _lines[i].startswith("pub")
            ]

        if not _kid:
            raise GPGKeyIDNotFoundError(
                "{}: Command {}: KeyID not found".format(
                    self.__str__(), " ".join(args_list)
                )
            )

        return _kid[0]

    def factory_reset(self) -> None:
        logger.info(
            "{}: Reseting Yubikey:: Fetching Card".format(self.__str__())
        )
        _ = self.card.interact(
            " ".join(["gpg2", "--pinentry-mode=loopback", "--card-edit"]),
            [
                # Factory-reset apply
                GPGCardCommand(
                    expect="gpg/card>",
                    response="admin",
                    mode="admin",
                ),
                GPGCardCommand(expect=None, response="factory-reset"),
                GPGCardCommand(expect="Continue?", response="y"),
                GPGCardCommand(
                    expect="reset?",
                    response="yes",
                    log="Reseting Yubikey:: Applying factory-reset",
                    sleep=3
                ),
                GPGCardCommand(expect="gpg/card>", response=None),
            ],
            timeout=900
        )

    def reconfigure_card(
        self,
        pin: str,
        admin_pin: str,
        first_name: str,
        last_name: str
    ) -> None:
        logger.info(
            "{}: Reseting Yubikey:: Configure Card".format(self.__str__())
        )
        _ = self.card.interact(
            " ".join(["gpg2", "--pinentry-mode=loopback", "--card-edit"]),
            [
                # Reset card interactive configuration
                GPGCardCommand(
                    expect="gpg/card>",
                    response="admin",
                    mode="admin",
                ),
                # Update cardholder's name
                GPGCardCommand(expect=None, response="name"),
                GPGCardCommand(expect="Cardholder's surname:", response=last_name),
                GPGCardCommand(
                    expect="Cardholder's given name:", response=first_name, sleep=1
                ),
                GPGCardCommand(expect=None, response="12345678"),
                GPGCardCommand(expect="gpg/card>", response="passwd", sleep=2),
                # Update pin
                GPGCardCommand(expect="Your selection?", response="1", sleep=2),
                GPGCardCommand(expect=None, response="123456"),
                GPGCardCommand(expect=None, response=pin),
                GPGCardCommand(expect=None, response=pin),
                # Update admin pin
                GPGCardCommand(expect="Your selection?", response="3", sleep=2),
                GPGCardCommand(expect=None, response="12345678"),
                GPGCardCommand(expect=None, response=admin_pin),
                GPGCardCommand(expect=None, response=admin_pin),
                # Exit
                GPGCardCommand(expect="Your selection?", response="Q", sleep=2),
                GPGCardCommand(expect=None, response="Q"),
                GPGCardCommand(
                    expect=["gpg/card>", pexpect.EOF, pexpect.TIMEOUT],
                    response=None,
                    sleep=2,
                    log="Reseting Yubikey:: [OK] Admin PIN and PIN set"
                )
            ],
            timeout=900
        ),

    def set_keys(self, key_id: str, passphrase: str, admin_pin: str) -> None:
        logger.info(
            "{}: Reseting Yubikey:: Importing keys to Yubikey".format(
                self.__str__()
            )
        )
        _ = self.card.interact(
            " ".join(["gpg2", "--pinentry-mode=loopback", "--edit-key", key_id]),
            [
                # Signing Key Import
                GPGCardCommand(expect="gpg>", response="key 1"),
                GPGCardCommand(expect="gpg>", response="keytocard"),
                GPGCardCommand(expect="Your selection?", response="1"),
                GPGCardCommand(expect="Enter passphrase:", response=passphrase),
                GPGCardCommand(expect="Enter passphrase:", response=admin_pin),
                GPGCardCommand(expect="Enter passphrase:", response=admin_pin),
                # Encryption Key Import
                GPGCardCommand(expect="gpg>", response="key 1"),
                GPGCardCommand(expect="gpg>", response="key 2"),
                GPGCardCommand(expect="gpg>", response="keytocard"),
                GPGCardCommand(expect="Your selection?", response="2"),
                GPGCardCommand(expect="passphrase", response=passphrase),
                GPGCardCommand(expect="passphrase", response=admin_pin),
                # Authentication Key Import
                GPGCardCommand(expect="gpg>", response="key 2"),
                GPGCardCommand(expect="gpg>", response="key 3"),
                GPGCardCommand(expect="gpg>", response="keytocard"),
                GPGCardCommand(expect="Your selection?", response="3"),
                GPGCardCommand(expect="passphrase", response=passphrase),
                GPGCardCommand(expect="passphrase", response=admin_pin),
                # Save
                GPGCardCommand(
                    expect="gpg>",
                    response="save",
                    log="Reseting Yubikey:: [OK] GPG keys imported to Yubikey"
                ),
            ],
            timeout=15
        ),

    def check_status(self, name: str) -> bool:
        logger.info(
            "{}: Reseting Yubikey:: Checking status".format(
                self.__str__()
            )
        )
        _ret = self.command(["gpg2", "--card-status"])
        for _line in _ret.splitlines():
            for _k in ["signature key", "authentication key", "encryption key"]:
                # all keys must be imported
                if (
                    _line
                    and _k in _line.casefold()
                    and "[none]" in _line.casefold()
                ):
                    return False
            # Correct naming
            if (
                _line
                and "name of cardholder" in _line
                and not name in _line
            ):
                return False
            # Correct pin retries counters
            if (
                _line
                and "pin retry counter" in _line
                and not("3 0 3" in _line or "3 3 3" in _line)
            ):
                return False

        return True

    def generate_revocation(self, last_name: str, passphrase: str, key_id: str) -> str:
        logger.info(
            "{}: Reseting Yubikey:: Generate revocation certificate".format(
                self.__str__()
            )
        )
        _ = self.card.interact(
            " ".join(
                [
                    "gpg2",
                    "--pinentry-mode=loopback",
                    "--output",
                    self.full_path(f"tmp/{last_name}_revoc.asc"),
                    "--generate-revocation",
                    key_id
                ]
            ),
            [
                GPGCardCommand(expect="this key?", response="y"),
                # Revocation cert for Signing key
                GPGCardCommand(expect="Your decision?", response="1"),
                GPGCardCommand(expect="empty line:", response=" "),
                GPGCardCommand(expect="this okay?", response="y"),
                GPGCardCommand(
                    expect="passphrase:",
                    response=passphrase,
                    sleep=1,
                    log="Reseting Yubikey:: [OK] Revocation certificate generated"
                ),
            ]
        )
        _ret = self.command(["cat", self.full_path(f"tmp/{last_name}_revoc.asc")])
        logger.debug(
            "{}: Reseting Yubikey:: Revocation certificate - {}".format(
                self.__str__(), _ret
            )
        )
        return _ret

    def export_pub_key(self, mail: str) -> str:
        logger.info(
            "{}: Reseting Yubikey:: Generate public key".format(
                self.__str__()
            )
        )
        p_key = self.command(["gpg2", "--armor", "--export", mail])
        logger.debug(
            "{}: Reseting Yubikey:: Public key - {}".format(
                self.__str__(), p_key
            )
        )
        logger.info(
            "{}: Reseting Yubikey:: [OK] Public key exported".format(
                self.__str__()
            )
        )
        return p_key

    def generate_ssh_key(self, key_id: str) -> str:
        logger.info(
            "{}: Reseting Yubikey:: Generate ssh key".format(
                self.__str__()
            )
        )
        s_key = self.command(["gpg2", "--export-ssh-key", key_id])
        logger.debug(
            "{}: Reseting Yubikey:: SSH key - {}".format(
                self.__str__(), s_key
            )
        )
        return s_key

    def clean(self) -> str:
        logger.info("{}: Cleaning temporary files".format(self.__str__()))
        logger.debug("{}: Unmounting:: {}".format(self.__str__(), self.full_path("ram")))
        _ = self.command(["sudo", "unmount", self.full_path("ram")])
        
        for _path in ["*.csv", "*.asc", "ram", "tmp"]:
            logger.debug("{}: Removing:: {}".format(self.__str__(), self.full_path(_path)))
            _ = self._clean(self.full_path(_path))
        
        logger.debug("{}: Killing gpg agent".format(self.__str__()))
        _ = self.command(["gpgconf", "--kill", "gpg-agent"])
        logger.info("{}: [OK] Cleaned all temporary files")




class YubiHandler:
    """
    YubiHandler is the main class of YubiResetor script.
    It handles the GPGManager class functionalitties in order
    to make the script more verbose and easily understandable.
    Available methods/properties:

    :property yubi_id: The plugged in yubikey's id
    :type yubi_id: str

    :property master_key_id: The fingerprint of the master key
    :type master_key_id: str

    :method gen_master_key: Generates a master key
    :returns: None

    :method gen_sub_key: Generates 3 sub keys for the master
    :returns: None

    :method get_pub_key: Gets the exported public key for user
    :returns: str

    :method reset: Resets the given card
    :returns: None

    :method config: Reconfigures the given card after reset
    :returns: None
    """
    def __init__(self) -> None:
        self.gpg = GPGManager()

    def __str__(self) -> str:
        return "<YubikeyInfoHandler>"

    @property
    def yubi_id(self) -> str:
        _yid: List[str] = []
        args_list: list[str] = ["ykman", "info"]

        logger.debug(
            "{}: Fetching yubikey id with:: [ykman info]".format(self.__str__())
        )
        _yinfo = self.gpg.command(args_list, ignore_stderr=True)

        if _yinfo:
            _lines = [line.strip(" ") for line in _yinfo.split("\n")]
            _yid = [
                line.replace(" ", "").replace("Serialnumber:", "")
                for line in _lines
                if line.replace(" ", "").startswith("Serialnumber:")
            ]

        if not _yid:
            raise YubiKeyIDNotFoundError("{}: Command {}: Yubikey ID not found".format(
                    self.__str__(), " ".join(args_list)
                )
            )
        return _yid[0]

    @property
    def master_key_id(self) -> str:
        return self.gpg.get_master_key_id()

    def gen_master_key(
        self, name: str, email: str, comment: str, passphrase: str
    ) -> None:
        """Generates master key for yubikey"""
        logger.debug("{}: Genereting Master key with gpg2 --full-gen-key!".format(
            self.__str__()
        ))
        _ = self.gpg.create_master_key(
            name, email, comment, passphrase, self.gpg.full_path(INPUT_DATA_NAME)
        )
        logger.info("{}: [OK] Master key generated!".format(self.__str__()))

    def gen_sub_key(
        self,
        passphrase: str,
        fingerprint: str,
        key_type: str,
        key_length: str,
        key_usage: str,
        key_expiry: str
    ) -> None:
        """Generates subkey for given key ID"""
        logger.debug("{}: Genereting subkey {} for fingerprint: {}".format(
            self.__str__(), key_usage, fingerprint
        ))
        _ = self.gpg.create_sub_key(
            fingerprint,
            passphrase,
            self.gpg.full_path(GPG_HOME),
            key_type,
            key_length,
            key_usage,
            key_expiry
        )
        logger.info("{}: [OK] Subkey key {} generated!".format(
            self.__str__(), key_usage
        ))

    def get_pub_key(self, mail: str) -> str:
        return self.gpg.export_pub_key(mail)

    def reset(self) -> None:
        _ = self.gpg.factory_reset()

    def config(
        self,
        key_id:str,
        passphrase: str,
        pin: str,
        admin_pin: str,
        first_name: str,
        last_name: str
    ) -> str:
        _ = self.gpg.reconfigure_card(pin, admin_pin, first_name, last_name)
        _ = self.gpg.set_keys(key_id, passphrase, admin_pin)
        return self.gpg.generate_ssh_key(key_id)

    def is_valid(self, name: str) -> bool:
        return self.gpg.check_status(name)


def gen_passphrase() -> str:
    """
    Creates a random password which will be used as
    passphrase to the new master key and as an input to create
    the subkeys required.
    """
    logger.debug("<YubikeyScript>: Generating random passphrase")
    return str(
        "".join(random.choice(PASS_CHARS) for i in range(PASS_LENGTH))
    )

def welcome() -> None:
    print("\n\n{}\n\n".format("=" * 100))
    print("Welcome to the YubiKey Resetor script\n")
    print("* sudo password may be required")
    print("\n\n{}\n\n".format("=" * 100))

def main():
    logger.setLevel(LOGLEVEL)
    handler.setLevel(LOGLEVEL)
    logger.addHandler(handler)

    # Welcome message to indicate user input
    # and usage of sudo passsword
    _ = welcome()

    user = UserInput()
    passphrase = gen_passphrase()

    # Master key generation
    yubi_handler = YubiHandler()
    _ = yubi_handler.gen_master_key(user.name, user.mail, "None", passphrase)

    # Sub keys generation
    fingerprint = yubi_handler.master_key_id
    _ = yubi_handler.yubi_id
    for k in SUBKEYS_LIST:
        _ = yubi_handler.gen_sub_key(
            passphrase,
            fingerprint,
            k["key_type"],
            k["key_length"],
            k["key_usage"],
            k["key_expiry"]
        )

    # Card reset and re-configuration
    for attempt in range(1, MAX_RETRIES + 1):
        if attempt > 1:
            logger.warning(
                "<YubikeyScript>: Card not properly reset. Attempt [{}/{}]".format(
                    attempt, MAX_RETRIES
                )
            )
        _ = yubi_handler.reset()
        _ = yubi_handler.config(
            fingerprint,
            passphrase,
            user.pin,
            user.admin_pin,
            user.first_name,
            user.last_name
        )

        if yubi_handler.is_valid(user.name):
            break

    if yubi_handler.is_valid(user.name):
        # Public key export
        pub_key = yubi_handler.get_pub_key(user.mail)
        logger.info("<YubikeyScript>: GPG Keys generated, Yubikey set!")
        logger.info("<YubikeyScript>: Your public key is::\n{}".format(pub_key))
    else:
        logger.error("<YubikeyScript>: Yubikey reset failed")


if __name__ == "__main__":
    main()
