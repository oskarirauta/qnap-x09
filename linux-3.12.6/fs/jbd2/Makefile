#
# Makefile for the linux journaling routines.
#

obj-$(CONFIG_JBD2) += jbd2.o

jbd2-objs := transaction.o commit.o recovery.o checkpoint.o revoke.o journal.o

ifeq ($(QNAP_SHARE_JOURNAL),yes)
jbd2-objs	+= shared_journal.o
endif
