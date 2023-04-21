# GPGCard Reset
A simple stand alone GPG card reset python script to avoid unnecessary interactions

## Introduction
This script is usefull if you try to reset your Yubico 4 or another version. It tries to avoid unnecessary communications with the ```gpg/card``` or ```gpg``` shell script. The main idea and flow behind this is to ```generate master key``` and ```authentication```, ```encryption``` and ```synchronization``` certificates according to your needs (RSA, EC etc and your preffered length)

## Supported Platforms
Its only dependency outside of python core modules, ```pexpect``` and is supposed to be fine for ```Linux/Mac``` platforms. TBI: An addition has to be made for ```windows``` as it is not tested thoroughly (most probably a module like ```wexpect``` would do the trick).

## Installation
The simple ```makefile``` of the project indicates the ```install``` command with a simple installation of ```pexpect``` and the ```virtual environment``` needed by python to execute the script.

```bash
make install
```

The above command is your solution and will do the trick!

## Run the script
The script uses a set of ```gpg2``` package commands in order to set everything up:
1. ```gpg2 --full-gen-key --pinentry-mode=loopback --expert --batch``` to generate the master key
2. ```gpg2 --pinentry-mode=loopback --batch --passphrase <passphrase> --quick-add-key <uid>``` for the 3 sub keys
3. ```gpg2 --pinentry-mode=loopback --card-edit``` in order to update the card.
4. ```gpg2 --edit-key``` for importing the keys inside the card.
5. ```factory-reset```, ```name```, ```passwd```, ```keytocard``` inside the ```gpg2 gpg2/card/``` shell.
6. ```gpg2 --pinentry-mode=loopback --output <path> --generate-revocation certificate``` to generate the cert revocation.

The command to run the script is (remember to have plugged in your device)
```
make reset
```

# Contribution
Feel free to create an issue for everything that you have experienced or everything that you think that will make this script better
