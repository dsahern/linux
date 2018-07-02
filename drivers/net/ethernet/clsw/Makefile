#
# Makefile for the Common Switchdev Driver
#

ccflags-y += -I$(src)/sai -I$(src)

obj-$(CONFIG_NET_CLSW) := clsw.o
clsw-y := clsw_main.o switchdev.o router.o link.o \
	  vlan.o bridge.o sdhal_be_sai.o clsw_sai.o ethtool.o
