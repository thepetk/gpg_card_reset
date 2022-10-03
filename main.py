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
