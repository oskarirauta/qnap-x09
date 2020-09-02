/*
	Copyright (c) 2009  QNAP Systems, Inc.  All Rights Reserved.
	FILE:
		gpio.c
	Abstract:
		Interface function to get H/W version from GPIO of ICH LPC Interface Bridge
*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define BIT_8 8
#define BIT_9 9
#define BIT_12 12
#define BIT_14 14

#define BIT_28 28
#define BIT_32 32
#define BIT_33 33
#define BIT_34 34

#define BIT_69 69
#define BIT_70 70
#define BIT_71 71

#define MAX_GPIO_SEL1_PIN 32
#define MAX_GPIO_SEL2_PIN 64

#define QNAP_PROC_HW_VERSION "tsinfo/hw_version"

static int g_hw_version_prefix;
static int g_hw_version_postfix;
// ------------------------------------------------------------------------------------------------
//Patch by QNAP: add x59 derivative model
//Patch by QNAP: add x69 derivative model 
//Patch by QNAP: add x79 derivative model
//g_hw_version_postfix: 
//TS-x59
//                      0-> D510/K510,DDR2,USB2.0,3G SATA
//                      1-> reserved
//                      2-> same as 0,reserved for Cisco sample.
//                      3-> reserved
//                      4-> D525,DDR3,USB3.0,6G SATA(9125),PROII,V3.0
//                      5-> D525,DDR2,USB2.0,3G SATA,Pro+(Use original x59 model ,but change CPU)
//                      8-> D525,DDR2,USB2.0,3G SATA,Pro+(Use x59ProII model,but downgrade)
// ------------------------------------------------------------------------------------------------
//TS-x69
//		     	Bit1:1->Etron 188, 0->Etron 168
//		     	Bit2:1-> 3G SATA, 0 -> 6G SATA
// ------------------------------------------------------------------------------------------------
//TS-x79
//		     	Bit0: 1->SAS interface, 0->SATA interface
//		     	Bit1: 1->New PCB, 0->Old PCB
// ------------------------------------------------------------------------------------------------
int Get_Model_Revision(void)
{
#if defined(X86_PINEVIEW)
    return g_hw_version_postfix;
#else    
    return 0;
#endif
}

int is_x59_proII_model(void)
{
#if defined(X86_PINEVIEW)
    if(g_hw_version_postfix == 4)
        return 1;
#endif        
    return 0;
}

int is_x69_USB3_EJ188(void)
{
#if defined(X86_CEDAVIEW)
    if(g_hw_version_postfix & 0x2)
        return 1;
#endif
    return 0;
}

int is_x69_pro_model(void)
{
#if defined(X86_CEDAVIEW)
    if(!(g_hw_version_postfix & 0x4))
        return 1; 	// TS-x69 Pro
#endif
    return 0;		// TS-x69
}

int is_x79_new_PCB(void)
{
    if(g_hw_version_postfix & 0x2)
        return 1; 	
    return 0;
}
EXPORT_SYMBOL(is_x59_proII_model);
EXPORT_SYMBOL(is_x69_pro_model);
EXPORT_SYMBOL(is_x69_USB3_EJ188);
EXPORT_SYMBOL(Get_Model_Revision);
EXPORT_SYMBOL(is_x79_new_PCB);

/////////////////////////////////

static void gpio_enable_bit(unsigned int gpio_addr,int pin)
{
	unsigned int gpio_select;
    if(pin >= MAX_GPIO_SEL2_PIN)
    {
        gpio_addr += 0x40; //GPIO Use Select 3
        pin -= MAX_GPIO_SEL2_PIN;
    }	
    else if(pin >= MAX_GPIO_SEL1_PIN)
    {
        gpio_addr += 0x30; //GPIO Use Select 2
        pin -= MAX_GPIO_SEL1_PIN;
    }
	gpio_select = inl(gpio_addr);
	outl(gpio_select | (1 << pin) ,gpio_addr);
}

static void	gpio_input_bit(unsigned int gpio_addr,int pin)
{
	unsigned int gpio_io_select;
    if(pin >= MAX_GPIO_SEL2_PIN)
    {
        gpio_addr += 0x44; //GPIO Input/Output Select 3
        pin -= MAX_GPIO_SEL2_PIN;
    }	
    else if(pin >= MAX_GPIO_SEL1_PIN)
    {
        gpio_addr += 0x34; //GPIO Input/Output Select 2
        pin -= MAX_GPIO_SEL1_PIN;
    }
	else
	{
        gpio_addr += 0x4; //GPIO Input/Output Select
	}
	gpio_io_select = inl(gpio_addr);
	outl(gpio_io_select | (1 << pin) ,gpio_addr);
}

static int gpio_read_bit(unsigned int gpio_addr,int pin)
{
	unsigned int gpio_read;
    if(pin >= MAX_GPIO_SEL2_PIN)
    {
        gpio_addr += 0x48; ////GPIO Level for Input or Output 3
        pin -= MAX_GPIO_SEL2_PIN;
    }	
    else if(pin >= MAX_GPIO_SEL1_PIN)
    {
        gpio_addr += 0x38; ////GPIO Level for Input or Outputt 2
        pin -= MAX_GPIO_SEL1_PIN;
    }
	else
    {
        gpio_addr += 0xc; //GPIO Level for Input or Output
	}
	gpio_read = inl(gpio_addr);
	return !!(gpio_read & (1 << pin)) ;
}

static int hw_version_proc_show(struct seq_file *m, void *v) {
	seq_printf(m, "%d %d", g_hw_version_prefix, g_hw_version_postfix);
	return 0;
}

static int hw_version_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, hw_version_proc_show, NULL);
}

static struct file_operations hw_version_proc_fops = {
	.open		= hw_version_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init lpc_bridge_init(void)
{
    struct pci_bus *bus;
    struct pci_dev *pdev;
    int hw_version_auxiliary = 0;

    u32 gpio_base;
    u8  gpio_control;

    bus = pci_find_bus(0,0);
    if(!bus){
        printk("Unable to find pci bus 0\n");
        return -1;
    }
    pdev = pci_get_slot(bus,PCI_DEVFN(31,0)); //LPC Interface Bridge Unit
    if(!pdev){
        printk("Unable to find GPIO in LPC Interface Bridge Unit\n");
        return -1;
    }

    pci_read_config_dword(pdev, 0x48, &gpio_base); //GPIO Base Address
    gpio_base &= 0xfffe;            			   //bit 0 : I/O Space

    pci_read_config_byte(pdev, 0x4c, &gpio_control);//GPIO control
    pci_write_config_byte(pdev,0x4c,gpio_control | 0x10);//set GPIO Enable bit

#if defined(X86_PINEVIEW) || defined(X86_CEDAVIEW)
    gpio_enable_bit(gpio_base,BIT_28);
    gpio_enable_bit(gpio_base,BIT_32);
    gpio_enable_bit(gpio_base,BIT_33);
    gpio_enable_bit(gpio_base,BIT_34);

    gpio_input_bit(gpio_base,BIT_28);
    gpio_input_bit(gpio_base,BIT_32);
    gpio_input_bit(gpio_base,BIT_33);
    gpio_input_bit(gpio_base,BIT_34);

    gpio_enable_bit(gpio_base,BIT_8);
    gpio_enable_bit(gpio_base,BIT_9);
    gpio_enable_bit(gpio_base,BIT_12);
    gpio_enable_bit(gpio_base,BIT_14);

    gpio_input_bit(gpio_base,BIT_8);
    gpio_input_bit(gpio_base,BIT_9);
    gpio_input_bit(gpio_base,BIT_12);
    gpio_input_bit(gpio_base,BIT_14);
#elif defined(X86_SANDYBRIDGE)
    gpio_enable_bit(gpio_base,BIT_69);
    gpio_enable_bit(gpio_base,BIT_70);
    gpio_enable_bit(gpio_base,BIT_71);

    gpio_input_bit(gpio_base,BIT_69);
    gpio_input_bit(gpio_base,BIT_70);
    gpio_input_bit(gpio_base,BIT_71);

#endif

#if defined(X86_PINEVIEW)
    //	printk("gpio_base = 0x%x,gpio_control = 0x%x\n",gpio_base,gpio_control);
    g_hw_version_prefix = gpio_read_bit(gpio_base,BIT_28) << 1 |
    gpio_read_bit(gpio_base,BIT_32) << 0;
    g_hw_version_postfix = gpio_read_bit(gpio_base,BIT_33) << 1 |
    gpio_read_bit(gpio_base,BIT_34) << 0;
    		
    hw_version_auxiliary = !gpio_read_bit(gpio_base,BIT_14) << 3 |	
                           !gpio_read_bit(gpio_base,BIT_12) << 2 |	
                           !gpio_read_bit(gpio_base,BIT_9) << 1 |	
                           !gpio_read_bit(gpio_base,BIT_8) << 0;
#elif defined(X86_CEDAVIEW)
    //	printk("gpio_base = 0x%x,gpio_control = 0x%x\n",gpio_base,gpio_control);
    g_hw_version_prefix =  gpio_read_bit(gpio_base,BIT_14) << 1 |
                           gpio_read_bit(gpio_base,BIT_12) << 0;
    g_hw_version_postfix = gpio_read_bit(gpio_base,BIT_9) << 1 |
                           gpio_read_bit(gpio_base,BIT_8) << 0;
    hw_version_auxiliary = gpio_read_bit(gpio_base,BIT_28) << 3 |
                           gpio_read_bit(gpio_base,BIT_32) << 2 |
                           gpio_read_bit(gpio_base,BIT_33) << 1 |
                           gpio_read_bit(gpio_base,BIT_34) << 0;
#elif defined(X86_SANDYBRIDGE)
    g_hw_version_prefix = 0;
#if defined(TS470) || defined(TS670) || defined(TS870)
    {
        struct cpuinfo_x86 *c = &cpu_data(0);
        int pro_type = 0;
        if(strstr(c->x86_model_id,"i3") != NULL || strstr(c->x86_model_id,"i5") != NULL || strstr(c->x86_model_id,"i7") != NULL)
            pro_type = 1;
        g_hw_version_postfix = !gpio_read_bit(gpio_base,BIT_71) << 3 |
                           !gpio_read_bit(gpio_base,BIT_70) << 2 |
                           !gpio_read_bit(gpio_base,BIT_69) << 1 |
                           pro_type ;
    }
#else
    g_hw_version_postfix = gpio_read_bit(gpio_base,BIT_71) << 2 |
                           gpio_read_bit(gpio_base,BIT_70) << 1 |
                           gpio_read_bit(gpio_base,BIT_69) << 0;
#endif
    hw_version_auxiliary = 0;
#endif
    g_hw_version_postfix += hw_version_auxiliary * 4;
    //For TS-x59Plus
#if defined(X86_PINEVIEW)
    if(g_hw_version_postfix == 0 || g_hw_version_postfix == 2){
        struct cpuinfo_x86 *c = &cpu_data(0);
        if(strstr(c->x86_model_id,"D525"))
            g_hw_version_postfix = 5;
    }
#endif
    //
    //	printk("BIT28:BIT32:BIT33:BIT34 = %d:%d:%d:%d\n",	gpio_read_bit(gpio_base,BIT_28),gpio_read_bit(gpio_base,BIT_32),gpio_read_bit(gpio_base,BIT_33),gpio_read_bit(gpio_base,BIT_34));

    struct proc_dir_entry *entry;
    entry = proc_create(QNAP_PROC_HW_VERSION, 0, NULL, &hw_version_proc_fops);
    return 0;
}

static void __exit lpc_bridge_exit(void)
{
    remove_proc_entry(QNAP_PROC_HW_VERSION, NULL);
}

MODULE_AUTHOR("Wokes Wang<wokeswang@qnap.com");
MODULE_DESCRIPTION("Get H/W version from GPIO of ICH9 LPC Interface Bridge");
MODULE_LICENSE("GPL");
module_init(lpc_bridge_init);
module_exit(lpc_bridge_exit);
