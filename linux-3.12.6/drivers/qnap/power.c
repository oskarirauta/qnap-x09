/*
	Copyright (c) 2009  QNAP Systems, Inc.  All Rights Reserved.
	FILE:
		power.c
	Abstract:
		Interface function to set power recovery function by Power Mamagement of ICH9 LPC Interface Bridge
*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>

static struct pci_dev *g_pdev;

void ich_power_on_recovery()
{
	u16 pmcon_3;
	if(!g_pdev){
		printk("Unable to find power function in LPC Interface Bridge Unit\n");
		return;
	}
	pci_read_config_word(g_pdev, 0xa4, &pmcon_3);
	pci_write_config_word(g_pdev,0xa4, pmcon_3 & 0xfffe);
}

void ich_power_off_recovery()
{
	u16 pmcon_3;
	if(!g_pdev){
		printk("Unable to find power function in LPC Interface Bridge Unit\n");
		return;
	}
	pci_read_config_word(g_pdev, 0xa4, &pmcon_3);
	pci_write_config_word(g_pdev,0xa4, pmcon_3 | 0x1);
}

static int __init lpc_bridge_power_init(void)
{
	struct pci_bus *bus;
	
	bus = pci_find_bus(0,0);
	if(!bus){
		printk("Unable to find pci bus 0\n");
		return -1;
	}
	g_pdev = pci_get_slot(bus,PCI_DEVFN(31,0)); //LPC Interface Bridge Unit
	if(!g_pdev){
		printk("Unable to find power function in LPC Interface Bridge Unit\n");
		return -1;
	}
	return 0;
}

static void __exit lpc_bridge_power_exit(void)
{
}

MODULE_AUTHOR("Wokes Wang<wokeswang@qnap.com");
MODULE_DESCRIPTION("Set Power recovery setting from PM of ICH9 LPC Interface Bridge");
MODULE_LICENSE("GPL");

module_init(lpc_bridge_power_init);
module_exit(lpc_bridge_power_exit);
