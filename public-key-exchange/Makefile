# name of your application
APPLICATION ?= $(notdir $(patsubst %/,%,$(CURDIR))) 

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

BOARD_INSUFFICIENT_MEMORY := airfy-beacon arduino-duemilanove arduino-mega2560 \
                             arduino-nano arduino-uno chronos mega-xplained \
                             msb-430 msb-430h nrf51dk nrf51dongle nrf6310 \
                             nucleo-f031k6 nucleo-f042k6 nucleo-l031k6 \
                             nucleo-f030r8 nucleo-f070rb nucleo-f072rb \
                             nucleo-f334r8 nucleo-f303k8 nucleo-l053r8 \
                             stm32f0discovery telosb wsn430-v1_3b wsn430-v1_4 \
                             yunjia-nrf51822 waspmote-pro z1

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for socket communication via UDP
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_udp
USEMODULE += gnrc_sock_udp
USEMODULE += posix_sockets
# USEMODULE += posix_time
# Add routing protocol
USEMODULE += gnrc_rpl
USEMODULE += auto_init_gnrc_rpl

# Specify the minimum networking modules for IPv6
USEMODULE += gnrc_ipv6
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo
# Use minimal standard PRNG
USEMODULE += prng_minstd


# Add also the shell, some shell commands (can I remove it?)
USEMODULE += shell
USEMODULE += ps

# AES module
USEMODULE += crypto
USEMODULE += cipher_modes
# micro ecc support
USEPKG += micro-ecc

CFLAGS += -DGNRC_PKTBUF_SIZE=512 -DGNRC_NETIF_IPV6_ADDRS_NUMOF=2 \
          -DGNRC_NETIF_IPV6_GROUPS_NUMOF=2 -DGNRC_IPV6_NIB_NUMOF=1 \
          -DGNRC_IPV6_NIB_OFFL_NUMOF=1 # be able to configure at least one route


# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

# Set a custom channel if needed
ifneq (,$(filter cc110x,$(USEMODULE)))          # radio is cc110x sub-GHz
  DEFAULT_CHANNEL ?= 0
  CFLAGS += -DCC110X_DEFAULT_CHANNEL=$(DEFAULT_CHANNEL)
else
  ifneq (,$(filter at86rf212b,$(USEMODULE)))    # radio is IEEE 802.15.4 sub-GHz
    DEFAULT_CHANNEL ?= 5
    CFLAGS += -DIEEE802154_DEFAULT_SUBGHZ_CHANNEL=$(DEFAULT_CHANNEL)
  else                                          # radio is IEEE 802.15.4 2.4 GHz
    DEFAULT_CHANNEL ?= 26
    CFLAGS += -DIEEE802154_DEFAULT_CHANNEL=$(DEFAULT_CHANNEL)
  endif
endif

