APPLICATION ?= $(notdir $(patsubst %/,%,$(CURDIR)))


BOARD ?= native
RIOTBASE ?= $(CURDIR)/../RIOT
QUIET ?= 1


BOARD_INSUFFICIENT_MEMORY := arduino-duemilanove arduino-nano arduino-uno

# micro-ecc is not 16 bit compatible
BOARD_BLACKLIST = chronos msb-430 msb-430h telosb wsn430-v1_3b wsn430-v1_4 z1

USEPKG += micro-ecc

TEST_ON_CI_WHITELIST += all

include $(RIOTBASE)/Makefile.include
