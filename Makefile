KEY_LENGTH ?= 4096
KEY_TYPE ?= 1
KEY_EXPIRY ?= 5y
LOG_LEVEL ?= info

help: ## List makefile information
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

install-venv: ## Create temporary virtual python environment
	python3 -m venv _venv

install: install-venv ## Install pexpect dependencies
	echo "Installing dependencies"
	_venv/bin/pip3 install pexpect

reset: install ## Reset inserted yubikey [LOG_LEVEL='debug,info,warning,error' | KEY_LENGTH=4096 | KEY_EXPIRY=5y | KEY_TYPE=1]
	_venv/bin/python3 -m main --log-level ${LOG_LEVEL} --key-length ${KEY_LENGTH} --key-type ${KEY_TYPE} --key-expiry ${KEY_EXPIRY}
	rm -r _venv