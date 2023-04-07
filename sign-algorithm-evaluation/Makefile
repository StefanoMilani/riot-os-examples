APPLICATION ?= ecc_key_gen_$(notdir $(patsubst %/,%,$(CURDIR)))



BOARD ?= native
RIOTBASE ?= $(CURDIR)/../../RIOT
QUIET ?= 1



# FEATURES_REQUIRED = periph_hwrng
USEMODULE += random

USEPKG += micro-ecc

TEST_ON_CI_WHITELIST += all

include $(RIOTBASE)/Makefile.include
