# name of your application
APPLICATION ?= $(notdir $(patsubst %/,%,$(CURDIR)))

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# tinycrypt works for 32-bit architectures only. The nrf52dk is chosen as a
# placeholder for all Cortex-M4 boards.
BOARD_WHITELIST += native nrf52dk

USEPKG += tinycrypt
USEMODULE += fmt
USEMODULE += xtimer
USEMODULE += random
USEMODULE += prng_minstd


include $(RIOTBASE)/Makefile.include
