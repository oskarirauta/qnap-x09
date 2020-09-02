#
# Makefile for the qnap driver
#
#

ifeq ($(ARCH),arm)
  obj-y += qfunc.o pic-arm.o
else
  obj-$(CONFIG_QNAP_PICD)	+= pic.o gpio.o power.o
endif

