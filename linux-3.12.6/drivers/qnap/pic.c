/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>
#include <asm/io.h>

#include <qnap/pic.h>
#include <qnap/qfunc.h>
#include <qnap/sendmessage.h>
#include <linux/proc_fs.h>
#include <qnap/marvell_reg.h>

#include <linux/string.h>
#include <linux/parser.h>

static int usage = 0;
static wait_queue_head_t	pic_wait;
static wait_queue_head_t	queue_empty_wait;
static wait_queue_head_t	chfiles_wait;
static int tx_begin = 0, tx_end = 0, rx_begin = 0, rx_end = 0;
static unsigned char *tx_buf = NULL;
static unsigned short rx_buf[QUEUE_BUFSIZE];
static DEFINE_SPINLOCK(rx_buf_lock);
static struct qnap_pic_event pic_event[QNAP_PIC_TOTAL_EVENT];
DECLARE_QUEUE(recycle_queue);

int begin = 0, end = 0;
unsigned char *r_buf = NULL;

static struct proc_dir_entry *tsinfo_procdir = NULL;
static struct proc_dir_entry *systemp_procdir;
static struct proc_dir_entry *vendor_procdir;
static struct proc_dir_entry *priority_procdir;
static int sys_temperature = 0;
#define VENDOR	"QNAP"
extern void ich_power_on_recovery();
extern void ich_power_off_recovery();
extern int get_power_state();

struct pci_dev *mv6145dev[4];
int mv_dev_cnt = 0;
//wait_queue_head_t        recycle_wait;


/***************************************************************
	Proc related variable and API
****************************************************************/
static struct proc_dir_entry *ata_time_procdir = NULL;
static struct proc_dir_entry *ata_retry_procdir = NULL;
int qnap_ata_reset_to_ms = 0; // unit: ms
int qnap_ata_retry_val = 0;
static int ata_reset_timeout_read(char *page, char **start, off_t off,int count, int *eof, void *data);
static int ata_reset_timeout_write(struct file *file,const char __user *buffer,unsigned long count,void *data);
static int ata_retry_read(char *page, char **start, off_t off,int count, int *eof, void *data);
static int ata_retry_write(struct file *file,const char __user *buffer,unsigned long count,void *data);



#if defined (TS809) || defined (TS809U) || defined (TS509)
#define x86_LAKEPORT
#elif defined (TS439) || defined (TS639) || defined(TS239) || defined (TS439U) || defined(SS439) || defined(TS839) || defined(SS839)
#define x86_ATOM
#endif

#if defined(TS509) || defined(TS559) || defined(TS569)
#define SUPPORT_5_DISKS
#elif defined(TS639) || defined(TS659) || defined(TS669)
#define SUPPORT_5_DISKS
#define SUPPORT_6_DISKS
#elif defined(TS809) || defined(TS809U) || defined(TS839) || defined(SS839) || defined(TS859) || defined(TS859U) || defined(TS869) || defined(TS869U)
#define SUPPORT_5_DISKS
#define SUPPORT_6_DISKS
#define SUPPORT_8_DISKS
#elif defined(TS1259U) || defined(TS1269U)
#define SUPPORT_5_DISKS
#define SUPPORT_6_DISKS
#define SUPPORT_8_DISKS
#define SUPPORT_12_DISKS
#endif


#if defined(x86_LAKEPORT) || defined(x86_ATOM) || defined(X86_PINEVIEW) || defined(X86_CEDAVIEW) || defined(X86_SANDYBRIDGE)
static int ReadFromCmos(int addr);
static void WriteToCmos(int addr, int value);
static int set_power_lost_mode(int mode);
#define outportb(a,b) outb(b,a)
#define inportb(a) inb(a)
#if defined(x86_LAKEPORT) || defined(X86_PINEVIEW) || defined(X86_CEDAVIEW) || defined(X86_SANDYBRIDGE)
#define  CMOSNDXPORT    0x70
#define  CMOSDATAPORT   0x71
#define	 POWERSTATE     0x61
#elif defined(x86_ATOM)
#define  CMOSNDXPORT    0x72
#define  CMOSDATAPORT   0x73
#define  POWERSTATE	0xAE
#endif
#endif
//Patch by QNAP: add x59 derivative model
extern int Get_Model_Revision(void);
//
void EnPCIGP(struct pci_dev *pdev, MV_U32 gp)
{
	MV_U32  tmp;
//printk("Set : [0x%X] [0x%X] [0x%X]\n", gp, MV_BIT(8), MV_BIT(8+0));
	pci_read_config_dword(pdev, VENDOR_UNI_REG_2, &tmp);
	printk("Vendor Unique 2 = [0x%4X] - Before\n", tmp);
	pci_write_config_dword(pdev, VENDOR_UNI_REG_2, (tmp|gp));
	pci_read_config_dword(pdev, VENDOR_UNI_REG_2, &tmp);
	printk("Vendor Unique 2 = [0x%4X] - After\n", tmp);
}

void DisPCIGP(struct pci_dev *pdev, MV_U32 gp)
{
	MV_U32  tmp;
	pci_read_config_dword(pdev, VENDOR_UNI_REG_2,&tmp);
	printk("Vendor Unique 2 = [0x%4X] - Before\n", tmp);
	pci_write_config_dword(pdev, VENDOR_UNI_REG_2, (tmp&(~gp)));
	pci_read_config_dword(pdev, VENDOR_UNI_REG_2, &tmp);
	printk("Vendor Unique 2 = [0x%4X] - After\n", tmp);

}

void SetGPACT(int enable)
{
	int i=0;
	for(i=0;i<mv_dev_cnt;i++){
		if(enable)
			EnPCIGP(mv6145dev[i], ACTGP_OUT_EN); 
		else
			DisPCIGP(mv6145dev[i], ACTGP_OUT_EN);
	}
		
}

void SetHDErr(int hd, int en_err)
{
	int host=hd/5;
	int gpno =0;
printk("hd = %d, en = %d\n", hd, en_err);

	if(host == 0)
		gpno = hd-1;
	else
		gpno = hd-5;

	if(en_err){
		EnPCIGP(mv6145dev[host], GP_OUT_EN(gpno));
		EnPCIGP(mv6145dev[host], GP_OUT_SET(gpno));
	}
	else{
//		DisPCIGP(mv6145dev[host], GP_OUT_EN(gpno));
		DisPCIGP(mv6145dev[host], GP_OUT_SET(gpno));
	}
}

int send_message_to_app(unsigned short message)
{
	if (((rx_end + 1) % QUEUE_BUFSIZE) != rx_begin) {
		rx_buf[rx_end] = message;
//printk("qnap pic: get byte 0x%x\n", rx_buf[rx_end]);
		rx_end = ((rx_end + 1) % QUEUE_BUFSIZE);
	}

	if (waitqueue_active(&pic_wait))
		wake_up_interruptible(&pic_wait);

	return 0;
}

EXPORT_SYMBOL(send_message_to_app);

int send_message_to_app_qraid1(unsigned char message)
{
        unsigned long flags;
        static DEFINE_SPINLOCK(lock);
        if(r_buf == NULL)
                return -1;
        spin_lock_irqsave(&lock, flags);
        if((begin != end) && (message == r_buf[end -1]))
        {
                //printk("skip msg %d\n", message);
                spin_unlock_irqrestore(&lock, flags);
                return 0;
        }
        if (((end + 1) % QRAID1_QUEUE_BUFSIZE) != begin) {
                r_buf[end] = message;
                //printk("send_msg_to_app: %d\n", r_buf[end]);
                end = ((end + 1) % QRAID1_QUEUE_BUFSIZE);
        }
        spin_unlock_irqrestore(&lock, flags);

        wake_up_interruptible(&chfiles_wait);

        return 0;
}

EXPORT_SYMBOL(send_message_to_app_qraid1);

static int pic_open(struct inode *inode, struct file *fp)
{
	int result = 0;
	if(!usage){
		tx_buf = (unsigned char*)kmalloc(QUEUE_BUFSIZE, GFP_KERNEL);
		if (tx_buf == NULL) {
			printk("Fail to allocate memory.\n");
			return -ENOMEM;
		}
		//add by Jimmy for qraid1
		r_buf = (unsigned char*)kmalloc(QRAID1_QUEUE_BUFSIZE, GFP_KERNEL);
                if (r_buf == NULL){
			printk("Qraid1 fail to allocate memory.\n");
                        return -ENOMEM;
		}
	}
	usage++;
	return result;
}

static int pic_release(struct inode *inode, struct file *fp)
{
	int result = 0;
	usage--;
	if(usage==0){
		while (tx_begin != tx_end)
			interruptible_sleep_on(&queue_empty_wait);
		if (tx_buf)
            kfree(tx_buf);
		if (r_buf)
                        kfree(r_buf);
	}
	return result;
}
#if defined(X86_SANDYBRIDGE)
static int ReadFromCmos(int addr)
{
        outportb(CMOSNDXPORT, addr);
        return inportb(CMOSDATAPORT);
}

static void WriteToCmos(int addr, int value)
{
        outportb(CMOSNDXPORT, addr);
        outportb(CMOSDATAPORT, value);
}

static int check_CMOS_initialized_by_BIOS(void)
{    
    int state;
    state = ReadFromCmos(POWERSTATE) & 0x1f;
    if (state == 0x01)
        return 1;
    else 
        return 0;
}

static int set_power_lost_mode(int mode)
{    
    int state;
    state = ReadFromCmos(POWERSTATE);
    state &= 0x3f;
    if (check_CMOS_initialized_by_BIOS() == 1)
    {
        switch(mode)
        {
            case QNAP_PIC_POWER_LOSS_POWER_ON:
                state |= (0x2 << 6);
                break;
            case QNAP_PIC_POWER_LOSS_POWER_OFF:
                state |= (0x3 << 6);
                break;
            case QNAP_PIC_POWER_LOSS_LAST_STATE:
                state |= (0x0 << 6);
                break;            
        }
    }
    else
    {
        switch(mode)
        {
            case QNAP_PIC_POWER_LOSS_POWER_ON:
                state |= (0x1 << 6);
                break;
            case QNAP_PIC_POWER_LOSS_POWER_OFF:
                state |= (0x0 << 6);
                break;
            case QNAP_PIC_POWER_LOSS_LAST_STATE:
                state |= (0x2 << 6);
                break;            
        }
    }
    WriteToCmos(POWERSTATE, state);   
    return set_power_lost_mode_to_gpio(mode);
}


#elif defined(x86_LAKEPORT) || defined(x86_ATOM) || defined(X86_PINEVIEW) || defined(X86_CEDAVIEW)
static int ReadFromCmos(int addr)
{
        outportb(CMOSNDXPORT, addr);
        return inportb(CMOSDATAPORT);
}

static void WriteToCmos(int addr, int value)
{
        outportb(CMOSNDXPORT, addr);
        outportb(CMOSDATAPORT, value);
}

int get_current_power_lost_mode()
{
    int state;
    int mode=0;
    state = ReadFromCmos(POWERSTATE);
    if(!(state & 0x80) && (state & 0x40))
        mode = QNAP_PIC_POWER_LOSS_POWER_ON;
    else if(!(state & 0x80) && !(state & 0x40))
        mode = QNAP_PIC_POWER_LOSS_POWER_OFF;
    else if((state & 0x80) && !(state & 0x40))
        mode = QNAP_PIC_POWER_LOSS_LAST_STATE;
    return mode;
}
static int set_power_lost_mode(int mode)
{
    int state;
    state = ReadFromCmos(POWERSTATE);
    switch(mode){
        case QNAP_PIC_POWER_LOSS_POWER_ON:
            WriteToCmos(POWERSTATE, (state & 0x7f) | 0x40);//set BIT7 to 0 & set BIT6 to 1
//Patch by QNAP: add x59 derivative model
#if defined(X86_PINEVIEW)
            if(Get_Model_Revision() == 4 || Get_Model_Revision() == 8)
                set_power_lost_mode_to_gpio(mode);
            else
                ich_power_on_recovery();
#else						
            set_power_lost_mode_to_gpio(mode);
#endif						
        break;
        case QNAP_PIC_POWER_LOSS_POWER_OFF:
            WriteToCmos(POWERSTATE, state & 0x3f);//set BIT7 and BIT6 to 0
//Patch by QNAP: add x59 derivative model
#if defined(X86_PINEVIEW)
            if(Get_Model_Revision() == 4 || Get_Model_Revision() == 8)
                set_power_lost_mode_to_gpio(mode);
            else
                ich_power_off_recovery();
#else						
            set_power_lost_mode_to_gpio(mode);
#endif					
        break;
        case QNAP_PIC_POWER_LOSS_LAST_STATE:
            if(get_current_power_lost_mode() != QNAP_PIC_POWER_LOSS_LAST_STATE){
                WriteToCmos(POWERSTATE, (state & 0xbf) | 0x80);//set BIT7 to 1 & BIT6 to 0
//Patch by QNAP: add x59 derivative model
#if defined(X86_PINEVIEW)
                if(Get_Model_Revision() == 4 || Get_Model_Revision() == 8)
                    set_power_lost_mode_to_gpio(QNAP_PIC_POWER_LOSS_POWER_ON);
                else
                    ich_power_on_recovery();
#elif defined(X86_CEDAVIEW)
                set_power_lost_mode_to_gpio(QNAP_PIC_POWER_LOSS_POWER_ON);
#else
                set_power_lost_mode_to_gpio(mode);
#endif
            }
            else
            //Patch by QNAP: add x59 derivative model
#if defined(X86_PINEVIEW)
                if(Get_Model_Revision() == 4 || Get_Model_Revision() == 8)
                    set_power_lost_mode_to_gpio(QNAP_PIC_POWER_LOSS_POWER_OFF);
                else
                    ich_power_off_recovery();
#elif defined(X86_CEDAVIEW)
                set_power_lost_mode_to_gpio(QNAP_PIC_POWER_LOSS_POWER_OFF);
#endif
        break;
    }
    return 0;
}
#endif

int qnap_pic_send_command(unsigned short *data, int count)
{
	int i;

	if (data == NULL || count <= 0)
		return -EINVAL;
	for (i = 0; i < count; i++){
//mvUartPutcEx(1, data[i]);
//		printk("RAW COMMAND = [0x%2X]\n", data[i]);
		switch(data[i]){
			case QNAP_PIC_STATUS_RED_BLINK:
           	case QNAP_PIC_STATUS_GREEN_BLINK:
           	case QNAP_PIC_STATUS_GREEN_ON:
           	case QNAP_PIC_STATUS_RED_ON:
           	case QNAP_PIC_STATUS_OFF:
           	case QNAP_PIC_USB_LED_ON:
           	case QNAP_PIC_USB_LED_BLINK:
           	case QNAP_PIC_USB_LED_OFF:
#if defined(x86_ATOM) || defined(X86_PINEVIEW) || defined(X86_CEDAVIEW) || defined(X86_SANDYBRIDGE)
			case QNAP_PIC_POWER_LED_ON:
			case QNAP_PIC_POWER_LED_BLINK:
			case QNAP_PIC_POWER_LED_OFF:
#endif
#if defined(X86_SANDYBRIDGE)
            case QNAP_PIC_STATUS_BOTH_BLINK:
            case QNAP_PIC_10G_LED_ON:
            case QNAP_PIC_10G_LED_OFF:
#endif
				set_led_status((unsigned char)data[i]);
				break;
#if defined(x86_LAKEPORT) || defined(x86_ATOM) || defined(X86_PINEVIEW) || defined(X86_CEDAVIEW)
            case QNAP_PIC_POWER_LOSS_POWER_ON:
                 set_power_lost_mode((unsigned char)data[i]);
                 break;
            case QNAP_PIC_POWER_LOSS_POWER_OFF:
                 set_power_lost_mode((unsigned char)data[i]);
                 break;
            case QNAP_PIC_POWER_LOSS_LAST_STATE:
                 set_power_lost_mode((unsigned char)data[i]);
                 break;
            case QNAP_PIC_EUP_ENABLE:
#if defined(X86_PINEVIEW)
                 if(Get_Model_Revision() == 4 || Get_Model_Revision() == 8){
#elif defined(X86_CEDAVIEW)
                if(1){
#else
                if(0){
#endif                
                     int state;
                     state = ReadFromCmos(POWERSTATE);
                     WriteToCmos(POWERSTATE,state | 0x20);
                     set_EUP_state(1);
                 }
                 break;
            case QNAP_PIC_EUP_DISABLE:
#if defined(X86_PINEVIEW)
                 if(Get_Model_Revision() == 4 || Get_Model_Revision() == 8){
#elif defined(X86_CEDAVIEW)
                if(1){
#else
                if(0){
#endif                
                     int state;
                     state = ReadFromCmos(POWERSTATE);
                     WriteToCmos(POWERSTATE,state & ~0x20);
                     set_EUP_state(0);
                 }
                 break;
#elif defined(X86_SANDYBRIDGE)
            case QNAP_PIC_POWER_LOSS_POWER_ON:
            case QNAP_PIC_POWER_LOSS_POWER_OFF:
            case QNAP_PIC_POWER_LOSS_LAST_STATE:
                 set_power_lost_mode((unsigned char)data[i]);
                 break;
            case QNAP_PIC_EUP_ENABLE:
                 {
                     int state;
                     state = ReadFromCmos(POWERSTATE);
                     WriteToCmos(POWERSTATE,state | 0x20);
                 }
                 set_EUP_state(1);
                 break;
            case QNAP_PIC_EUP_DISABLE:
                 {
                     int state;
                     state = ReadFromCmos(POWERSTATE);
                     WriteToCmos(POWERSTATE,state & ~0x20);
                 }
                 set_EUP_state(0);
                 break;
#if defined(TS270) || defined(TS470) || defined(TS470U) || defined(TS670) || defined(TS870)                 
            case QNAP_HDERR_ON(1):
            case QNAP_HDERR_ON(2):
            case QNAP_HDERR_ON(3):
            case QNAP_HDERR_ON(4):
            case QNAP_HDERR_ON(5):
            case QNAP_HDERR_ON(6):
            case QNAP_HDERR_ON(7):
            case QNAP_HDERR_ON(8):
                set_hd_error_led_on((((unsigned char)data[i]-QNAP_HDERR_ON(1))/2)+1, 1);
                break;
            case QNAP_HDERR_OFF(1):
            case QNAP_HDERR_OFF(2):
            case QNAP_HDERR_OFF(3):
            case QNAP_HDERR_OFF(4):
            case QNAP_HDERR_OFF(5):
            case QNAP_HDERR_OFF(6):
            case QNAP_HDERR_OFF(7):
            case QNAP_HDERR_OFF(8):
                set_hd_error_led_on((((unsigned char)data[i]-QNAP_HDERR_OFF(1))/2)+1, 0);
                break;
#if defined(TS470U)
	    case QNAP_SIO_OUTPUT_ON(0):
	    case QNAP_SIO_OUTPUT_ON(1):
		set_sio_output((data[i]-QNAP_SIO_OUTPUT_ON(0))/2, 1);
		break;
	    case QNAP_SIO_OUTPUT_OFF(0):
	    case QNAP_SIO_OUTPUT_OFF(1):
		set_sio_output((data[i]-QNAP_SIO_OUTPUT_OFF(0))/2, 0);
		break;
#endif

#endif                 
#endif                 
//
/*
		case QNAP_GPACT_ON:
			SetGPACT(1);
			break;
		case QNAP_GPACT_OFF:
			SetGPACT(0);
			break;
*/
#if defined(x86_LAKEPORT) || defined(x86_ATOM) || defined(X86_PINEVIEW) || defined(X86_CEDAVIEW)
		case QNAP_HDERR_ON(1):
		case QNAP_HDERR_ON(2):
		case QNAP_HDERR_ON(3):
		case QNAP_HDERR_ON(4):
#endif
#ifdef SUPPORT_5_DISKS
		case QNAP_HDERR_ON(5):
#endif
#ifdef SUPPORT_6_DISKS
		case QNAP_HDERR_ON(6):
#endif
#ifdef SUPPORT_8_DISKS
		case QNAP_HDERR_ON(7):
		case QNAP_HDERR_ON(8):
#endif
#ifdef SUPPORT_12_DISKS
		case QNAP_HDERR_ON(9):
		case QNAP_HDERR_ON(10):
		case QNAP_HDERR_ON(11):
		case QNAP_HDERR_ON(12):			
#endif
			//printk("command on = %d, hd = %d\n", data[i], ((data[i]-QNAP_HDERR_ON(1))/2)+1);
			set_hd_error_led_on((((unsigned char)data[i]-QNAP_HDERR_ON(1))/2)+1, 1);
			break;
#if defined(x86_LAKEPORT) || defined(x86_ATOM) || defined(X86_PINEVIEW) || defined(X86_CEDAVIEW)
		case QNAP_HDERR_OFF(1):
		case QNAP_HDERR_OFF(2):
		case QNAP_HDERR_OFF(3):
		case QNAP_HDERR_OFF(4):
#endif
#ifdef SUPPORT_5_DISKS
		case QNAP_HDERR_OFF(5):
#endif
#ifdef SUPPORT_6_DISKS
		case QNAP_HDERR_OFF(6):
#endif
#ifdef SUPPORT_8_DISKS
		case QNAP_HDERR_OFF(7):
		case QNAP_HDERR_OFF(8):
#endif
#ifdef SUPPORT_12_DISKS
		case QNAP_HDERR_OFF(9):
		case QNAP_HDERR_OFF(10):
		case QNAP_HDERR_OFF(11):
		case QNAP_HDERR_OFF(12):			
#endif
			//printk("command off = %d, hd = %d\n", data[i], ((data[i]-QNAP_HDERR_ON(1))/2)+1);
                        set_hd_error_led_on((((unsigned char)data[i]-QNAP_HDERR_OFF(1))/2)+1, 0);
			break;
		default:
			break;
		}
	}
	return count;
}

EXPORT_SYMBOL(qnap_pic_send_command);

static long pic_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int i, bytes;
	unsigned long flags;
	struct qnap_pic_ioctl qpi;
	int result=-EINVAL;
//	Reg_State s;

	memset(&qpi, 0, sizeof(struct qnap_pic_ioctl));

	switch (cmd) {
	case IOCTL_MSG_GET_MESSAGE:
		while (rx_begin == rx_end) {
			interruptible_sleep_on(&pic_wait);
			if (signal_pending(current)){
printk("pic_ioctl: signal_pending current failed\n");
				return -ERESTARTSYS;
			}
		}
		spin_lock_irqsave(&rx_buf_lock, flags);
		// calculate how many bytes available
		bytes = ((rx_end + QUEUE_BUFSIZE) - rx_begin) % QUEUE_BUFSIZE;
		// read data as many as possible
		for (i = 0 ; i < bytes ; i++) {
			qpi.pic_data[i] = rx_buf[rx_begin];
			qpi.count++;
			rx_begin = (rx_begin + 1) % QUEUE_BUFSIZE;
			
			// Add for save system temperature
                	if((qpi.pic_data[i] >= QNAP_PIC_SYS_TEMP_LOW) && (qpi.pic_data[i] <= QNAP_PIC_SYS_TEMP_HIGH))
                	{
				sys_temperature = qpi.pic_data[i] - 0x80;
                	}

		}

		spin_unlock_irqrestore(&rx_buf_lock, flags);
		result = copy_to_user((void *)arg, &qpi, sizeof(struct qnap_pic_ioctl));
		break;
	case IOCTL_MSG_SEND_MESSAGE:
		if (copy_from_user(&qpi, (struct qnap_pic_ioctl *)arg, sizeof(struct qnap_pic_ioctl)))
			break;
		for (i = 0; i < QUEUE_BUFSIZE && i < qpi.count; i += 2) {
			if (qpi.pic_data[i] >= QNAP_PIC_TOTAL_EVENT || qpi.pic_data[i + 1] >= PIC_EVENT_COMMAND_TYPE)
				continue;
			switch(qpi.pic_data[i]) {
				/* Something should be here. */
			}
			//We should add our action here for TS-509
//			qnap_pic_send_command(pic_event[qpi.pic_data[i]].command[qpi.pic_data[i + 1]], pic_event[qpi.pic_data[i]].count[qpi.pic_data[i + 1]]); 
		}
		result = 0;
		break;
	//JimmyChang add for reset button
	case IOCTL_GPIO_GET_MESSAGE:
	{
		int state = 0;
#if defined (TS809) || defined (TS809U) || defined(TS439) || defined (TS439U) || defined(SS439)
		int button_state = 0;
		int power_state = 0;

		button_state = get_button_status();
		power_state = get_redundant_power_status();
#if defined(TS809) || defined(TS809U)
		state |= (power_state >> 2);
		state |= button_state;
#elif defined(TS439) || defined (TS439U) || defined(SS439)
		state |= power_state;
		state |= (button_state & 0xc0);
#endif
#elif defined(TS459U) || defined(TS859U) || defined(TS1259U) || defined(TS469U) || defined(TS869U) || defined(TS1269U)
		state = get_button_status() & 0xcf;
		state |= get_redundant_power_status();
#else
		state = get_button_status();
#endif	

		if(copy_to_user((void __user *)arg, &state, sizeof(state))){
			return -EFAULT;
                }
	}
	break;
	//JimmyChang add for recycle_bin
	case IOCTL_RECYCLE_SEND_MESSAGE:
	{
		struct recycle_pic_ioctl s;
		if (copy_from_user(&s, (struct recycle_pic_ioctl *)arg, sizeof(struct recycle_pic_ioctl)))
                        break;
		recycle_enable = s.recycle_stat;
	}
	break;

	case IOCTL_RECYCLE_GET_MESSAGE:
	{
		//DECLARE_QUEUE(queue);
		File_Name stat;
		stat.file_name[0] = 0;

                //if no file in the recycle_queue

		while( get_from_queue(&recycle_queue, &stat) == 0){
			interruptible_sleep_on(&recycle_queue.recycle_wait);
			if (signal_pending(current))
                        {
                                printk("recycle_ioctl: signal_pending current failed\n");
                                return -ERESTARTSYS;
                        }
                        //return -EINVAL;
		}

                if(copy_to_user((void __user *)arg, &stat, sizeof(File_Name)))
                {	
                        return -EFAULT;
                }
	}
	break;
	case IOCTL_GET_QUEUE_NUM:
	{
		Queue Q;
		Q.total_file = recycle_queue.total_file;
//		printk("queue num = %d\n", queue.total_file);
	}
	break;
	//JimmyChang add for qraid1
/*
	case IOCTL_QRAID1_GET_MESSAGE:
	{
		int i, bytes;
        	unsigned long flags;
	        struct chfiles_ioctl chfiles_msg;

                memset(&chfiles_msg, 0, sizeof(struct chfiles_ioctl));
                while (begin == end) {
                        printk("PIC without any event\n");
                        interruptible_sleep_on(&chfiles_wait);
                        if (signal_pending(current))
                        {
                                printk("changedfiles_ioctl: signal_pending current failed\n");
                                return -ERESTARTSYS;
                        }
                }
                spin_lock_irqsave(&lock, flags);
                // calculate how many bytes available
                bytes = ((end + QRAID1_QUEUE_BUFSIZE) - begin) % QRAID1_QUEUE_BUFSIZE;
                // read data as many as possible
                for (i = 0 ; i < bytes ; i++) {
                        chfiles_msg.path_id[i] = r_buf[begin];
                        chfiles_msg.count++;
                        begin = (begin + 1) % QRAID1_QUEUE_BUFSIZE;
                }
                spin_unlock_irqrestore(&lock, flags);
                return copy_to_user((void *)arg, &chfiles_msg, sizeof(struct chfiles_ioctl));
        }
	break;

	case IOCTL_QRAID1_SEND_MESSAGE:
	{
		struct qraid1_ioctl s;
		if (copy_from_user(&s, (struct qraid1_ioctl *)arg, sizeof(struct qraid1_ioctl)))
                        break;
                qraid1_enable = s.qraid1_stat;
	}
	break;*/
	case IOCTL_HD_ERROR_LED_SEND_MESSAGE:
	{
		struct hd_error_led hd;

		copy_from_user(&hd, (struct hd_error_led *)arg, sizeof(struct hd_error_led));
		set_hd_error_led_on(hd.hd_num, hd.status);
	}
	break;      //end

	case IOCTL_MSG_SEND_RAW_COMMAND:
		if (copy_from_user(&qpi, (struct qnap_pic_ioctl *)arg, sizeof(struct qnap_pic_ioctl)))
			break;
		//Modify RAW command action for yourself.
		qnap_pic_send_command(qpi.pic_data, qpi.count);
		result = 0;

	default:
		break;
	}
	return result;
}

#ifdef CONFIG_COMPAT
static long pic_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	long ret;
 
	inode = file->f_dentry->d_inode;
 
    ret = pic_ioctl(file, cmd, arg);
    
	return ret;
}
#endif

static void __init qnap_pic_event_init(void)
{
	//Initialize pic event.
	memset(pic_event, 0, sizeof(pic_event));

	pic_event[QNAP_PIC_BOOT_COMPLETE].command[QNAP_PIC_EVENT_ON][0] = QNAP_PIC_STATUS_GREEN_ON;
	pic_event[QNAP_PIC_BOOT_COMPLETE].command[QNAP_PIC_EVENT_ON][1] = QNAP_PIC_BUZZER_LONG;
	pic_event[QNAP_PIC_BOOT_COMPLETE].count[QNAP_PIC_EVENT_ON] = 2;
	pic_event[QNAP_PIC_WRONG_HD_FORMAT].command[QNAP_PIC_EVENT_ON][0] = QNAP_PIC_STATUS_RED_ON;
	pic_event[QNAP_PIC_WRONG_HD_FORMAT].count[QNAP_PIC_EVENT_ON] = 1;
	pic_event[QNAP_PIC_WRONG_HD_FORMAT].command[QNAP_PIC_EVENT_OFF][0] = QNAP_PIC_STATUS_GREEN_ON;
	pic_event[QNAP_PIC_WRONG_HD_FORMAT].count[QNAP_PIC_EVENT_OFF] = 1;
	pic_event[QNAP_PIC_POWER_OFF].command[QNAP_PIC_EVENT_ON][0] = QNAP_PIC_STATUS_OFF;
	pic_event[QNAP_PIC_POWER_OFF].command[QNAP_PIC_EVENT_ON][1] = QNAP_PIC_POWER_LED_BLINK;
	pic_event[QNAP_PIC_POWER_OFF].count[QNAP_PIC_EVENT_ON] = 2;
	pic_event[QNAP_PIC_HD_STANDBY].command[QNAP_PIC_EVENT_ON][0] = QNAP_PIC_STATUS_GREEN_ON;
	pic_event[QNAP_PIC_HD_STANDBY].command[QNAP_PIC_EVENT_ON][1] = QNAP_PIC_POWER_LED_BLINK;
	pic_event[QNAP_PIC_HD_STANDBY].count[QNAP_PIC_EVENT_ON] = 2;
	pic_event[QNAP_PIC_HD_STANDBY].command[QNAP_PIC_EVENT_OFF][0] = QNAP_PIC_STATUS_GREEN_ON;
	pic_event[QNAP_PIC_HD_STANDBY].command[QNAP_PIC_EVENT_OFF][1] = QNAP_PIC_POWER_LED_ON;
	pic_event[QNAP_PIC_HD_STANDBY].count[QNAP_PIC_EVENT_OFF] = 2;
	pic_event[QNAP_PIC_USB_COPY].command[QNAP_PIC_EVENT_ON][0] = QNAP_PIC_USB_LED_BLINK;
	pic_event[QNAP_PIC_USB_COPY].count[QNAP_PIC_EVENT_ON] = 1;
	pic_event[QNAP_PIC_USB_COPY].command[QNAP_PIC_EVENT_OFF][0] = QNAP_PIC_USB_LED_OFF;
	pic_event[QNAP_PIC_USB_COPY].count[QNAP_PIC_EVENT_OFF] = 1;
	pic_event[QNAP_PIC_SET_DEFAULT].command[QNAP_PIC_EVENT_ON][0] = QNAP_PIC_BUZZER_SHORT;
	pic_event[QNAP_PIC_SET_DEFAULT].count[QNAP_PIC_EVENT_ON] = 1;
	pic_event[QNAP_PIC_POWER_RECOVERY].command[QNAP_PIC_EVENT_ON][0] = QNAP_PIC_ENABLE_POWER_RECOVERY;
	pic_event[QNAP_PIC_POWER_RECOVERY].count[QNAP_PIC_EVENT_ON] = 1;
	pic_event[QNAP_PIC_POWER_RECOVERY].command[QNAP_PIC_EVENT_OFF][0] = QNAP_PIC_DISABLE_POWER_RECOVERY;
	pic_event[QNAP_PIC_POWER_RECOVERY].count[QNAP_PIC_EVENT_OFF] = 1;

}

static struct file_operations pic_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = pic_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= pic_compat_ioctl,
#endif
	.open = pic_open,
	.release = pic_release,
};

static struct miscdevice pic_device = {
    PIC_MINOR, "pic", &pic_fops
};

static int systemp_read(char *page, char **start, off_t off,
                   int count, int *eof, void *data)
{
	int     len;

        len=sprintf(page, "%d\n", sys_temperature);
        return len;	
}

static int vendor_read(char *page, char **start, off_t off,
                   int count, int *eof, void *data)
{
	int     len;

        len=sprintf(page, "vendor\t\t: %s\n", VENDOR);
        return len;
}

/* It is because renice value is in range between (-)20~(+)20.
 * Thus, we define 21 as IGNORE value */
#if defined(TS509)
static int rd5ext4_priority_smb = -15;
static int rd5ext3_priority_smb = -15;
static int rd6ext4_priority_smb = -15;
static int rd6ext3_priority_smb = -10;
static int rd1ext4_priority_smb = -15;
static int rd1ext3_priority_smb = -5;
static int rd0ext4_priority_smb = -15;
static int rd0ext3_priority_smb = -15;
static int sglext4_priority_smb = -15;
static int sglext3_priority_smb = -10;
static int lnrext4_priority_smb = -5;
static int lnrext3_priority_smb = -15;
#elif defined(x86_LAKEPORT)
static int rd5ext4_priority_smb = -10;
static int rd5ext3_priority_smb = -5;
static int rd6ext4_priority_smb = 0;
static int rd6ext3_priority_smb = -10;
static int rd1ext4_priority_smb = -10;
static int rd1ext3_priority_smb = -10;
static int rd0ext4_priority_smb = -10;
static int rd0ext3_priority_smb = -5;
static int sglext4_priority_smb = -5;
static int sglext3_priority_smb = -15;
static int lnrext4_priority_smb = -5;
static int lnrext3_priority_smb = -10;
#else /* Atom CPU */
static int rd5ext4_priority_smb = -15;
static int rd5ext3_priority_smb = 0;
static int rd6ext4_priority_smb = -10;
static int rd6ext3_priority_smb = 0;
static int rd1ext4_priority_smb = -5;
static int rd1ext3_priority_smb = -5;
static int rd0ext4_priority_smb = -20;
static int rd0ext3_priority_smb = -5;
static int sglext4_priority_smb = 0;
static int sglext3_priority_smb = 0;
static int lnrext4_priority_smb = -15;
static int lnrext3_priority_smb = 0;
#endif

static int priority_read(char *page, char **start, off_t off,
                   int count, int *eof, void *data)
{
	int len = 0;
    len = sprintf(page,	       "r5e4_pri_smb=%d\n", rd5ext4_priority_smb);
    len += sprintf(page + len, "r5e3_pri_smb=%d\n", rd5ext3_priority_smb);

    len += sprintf(page + len, "r6e4_pri_smb=%d\n", rd6ext4_priority_smb);
    len += sprintf(page + len, "r6e3_pri_smb=%d\n", rd6ext3_priority_smb);

    len += sprintf(page + len, "r1e4_pri_smb=%d\n", rd1ext4_priority_smb);
    len += sprintf(page + len, "r1e3_pri_smb=%d\n", rd1ext3_priority_smb);

    len += sprintf(page + len, "r0e4_pri_smb=%d\n", rd0ext4_priority_smb);
    len += sprintf(page + len, "r0e3_pri_smb=%d\n", rd0ext3_priority_smb);

    len += sprintf(page + len, "r-1e4_pri_smb=%d\n", lnrext4_priority_smb);
    len += sprintf(page + len, "r-1e3_pri_smb=%d\n", lnrext3_priority_smb);
	
    len += sprintf(page + len, "r-2e4_pri_smb=%d\n", sglext4_priority_smb);
    len += sprintf(page + len, "r-2e3_pri_smb=%d\n", sglext3_priority_smb);

	return len;
}

enum {
	RD5EXT4_SMB, RD5EXT3_SMB, RD6EXT4_SMB, RD6EXT3_SMB, RD1EXT4_SMB, RD1EXT3_SMB, 
	LNREXT4_SMB, LNREXT3_SMB, SGLEXT4_SMB, SGLEXT3_SMB,
	RD0EXT4_SMB, RD0EXT3_SMB, NO_OPT
};

static const match_table_t tokens = {
	{ RD5EXT4_SMB, "r5e4_pri_smb=%d" },
	{ RD5EXT3_SMB, "r5e3_pri_smb=%d" },
	{ RD6EXT4_SMB, "r6e4_pri_smb=%d" },
	{ RD6EXT3_SMB, "r6e3_pri_smb=%d" },
	{ RD1EXT4_SMB, "r1e4_pri_smb=%d" },
	{ RD1EXT3_SMB, "r1e3_pri_smb=%d" },
	{ RD0EXT4_SMB, "r0e4_pri_smb=%d" },
	{ RD0EXT3_SMB, "r0e3_pri_smb=%d" },
	{ LNREXT4_SMB, "r-1e4_pri_smb=%d" },
	{ LNREXT3_SMB, "r-1e3_pri_smb=%d" },
	{ SGLEXT4_SMB, "r-2e4_pri_smb=%d" },
	{ SGLEXT3_SMB, "r-2e3_pri_smb=%d" },
	{ NO_OPT, NULL},
};

static int priority_parse(char *buf)
{
	substring_t args[MAX_OPT_ARGS];
	char *p = NULL;

	if(!buf || !*buf)
		return 1;

	while ((p = strsep(&buf, ",")) != NULL) {
		int token;
		if(!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case RD5EXT4_SMB:
			if(match_int(args, &rd5ext4_priority_smb)) 
				return 0;
			break;
		case RD5EXT3_SMB:
			if(match_int(args, &rd5ext3_priority_smb)) 
				return 0;
			break;
		case RD6EXT4_SMB:
			if(match_int(args, &rd6ext4_priority_smb)) 
				return 0;
			break;
		case RD6EXT3_SMB:
			if(match_int(args, &rd6ext3_priority_smb)) 
				return 0;
			break;
		case RD1EXT4_SMB:
			if(match_int(args, &rd1ext4_priority_smb)) 
				return 0;
			break;
		case RD1EXT3_SMB:
			if(match_int(args, &rd1ext3_priority_smb)) 
				return 0;
			break;
		case RD0EXT4_SMB:
			if(match_int(args, &rd0ext4_priority_smb)) 
				return 0;
			break;
		case RD0EXT3_SMB:
			if(match_int(args, &rd0ext3_priority_smb)) 
				return 0;
			break;
		case LNREXT4_SMB:
			if(match_int(args, &lnrext4_priority_smb)) 
				return 0;
			break;
		case LNREXT3_SMB:
			if(match_int(args, &lnrext3_priority_smb)) 
				return 0;
			break;
		case SGLEXT4_SMB:
			if(match_int(args, &sglext4_priority_smb)) 
				return 0;
			break;
		case SGLEXT3_SMB:
			if(match_int(args, &sglext3_priority_smb)) 
				return 0;
			break;
		default:
			goto leave_unknown;
		}
	}
	return 1;

leave_unknown:
	return 0;
}

static int priority_write(struct file *file, const char __user *buffer,
			   unsigned long count, void *data)
{
	int size = count;
	char *pricmd = NULL;

	pricmd = kmalloc(1024, GFP_KERNEL);

	if(!pricmd)
		return -ENOMEM;

	memset(pricmd, 0, 1024);

	if(count > 1024)
		size = 1024;

	if(copy_from_user(pricmd, buffer, size)) {
		count = -EFAULT;
		goto leave;
	}

	if(!pricmd[0]) 
		goto leave;	
	
	pricmd[strlen(pricmd)-1] = 0;

	if(!priority_parse(pricmd)) { 
		printk("Parse command (%s) error ...\n", pricmd);
		count =  -EINVAL;
		goto leave;
	}

leave:

	if(pricmd)
		kfree(pricmd);	

	return count;
}


// adjust ata retry parameters START
static int ata_reset_timeout_read(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	int len;
	len=sprintf(page, "%d\n", qnap_ata_reset_to_ms);
	return len;
}

static int ata_reset_timeout_write(struct file *file,const char __user *buffer,unsigned long count,void *data)
{		
        char data_buf[16] = {'\0'};
        if(copy_from_user(data_buf,buffer,count))
                return -EFAULT;
        data_buf[count] = 0;
        qnap_ata_reset_to_ms = simple_strtoul(data_buf,NULL,0);
        return count;
}


static int ata_retry_read(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	int len;	
	len=sprintf(page, "%d\n", qnap_ata_retry_val);
	return len;
}

static int ata_retry_write(struct file *file,const char __user *buffer,unsigned long count,void *data)
{
        char data_buf[16] = {'\0'};
        if(copy_from_user(data_buf,buffer,count))
                return -EFAULT;
        data_buf[count] = 0;
        qnap_ata_retry_val = simple_strtoul(data_buf,NULL,0);
        return count;
}
// End of adjust ata retry parameters END


static void tsinfo_create_proc(void)
{
	tsinfo_procdir = proc_mkdir("tsinfo", NULL);
	systemp_procdir = create_proc_entry("tsinfo/systemp", 0644, NULL );
	vendor_procdir = create_proc_entry("tsinfo/vendor", 0644, NULL );
	priority_procdir = create_proc_entry("tsinfo/priority", 0644, NULL );

	ata_time_procdir = create_proc_entry("tsinfo/ata_reset_to_ms", 0644, NULL );
	ata_retry_procdir = create_proc_entry("tsinfo/ata_retry", 0644, NULL );


	if(ata_time_procdir == NULL)
		printk("tsinfo: Couldn't create proc ata_time\n");
	else{
		ata_time_procdir->read_proc = ata_reset_timeout_read;
		ata_time_procdir->write_proc = ata_reset_timeout_write;
		printk("tsinfo: create proc ata_time successfully\n");
	}

	if(ata_retry_procdir == NULL)
		printk("tsinfo: Couldn't create proc ata_retry\n");
	else{
		ata_retry_procdir->read_proc = ata_retry_read;
		ata_retry_procdir->write_proc = ata_retry_write;
		printk("tsinfo: create proc ata_retry successfully\n");
	}



	if(systemp_procdir == NULL)
		printk("tsinfo: Couldn't create proc systemp\n");
	else{
		systemp_procdir->read_proc = systemp_read;
		printk("tsinfo: create proc systemp successfully\n");
	}
	if(vendor_procdir == NULL)
		printk("tsinfo: Couldn't create proc verder\n");
	else{
		vendor_procdir->read_proc = vendor_read;
		printk("tsinfo: create proc systemp successfully\n");
	}
	if(priority_procdir == NULL)
		printk("tsinfo: Couldn't create proc priority\n");
	else {
		priority_procdir->read_proc = priority_read;
		priority_procdir->write_proc = priority_write;
		printk("tsinfo: create proc priority successfully\n");
	}
}
static int power_read(char *page,
		       char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int size = 0;
    unsigned int state;;
    if (off != 0)
        goto end;

    state = get_power_state();

    p += sprintf(p,"%x\n",state);

end:
    size = (p - page);
    if (size <= off + count)
    	*eof = 1;
    *start = page + off;
    size -= off;
    if (size > count)
    	size = count;
    if (size < 0)
    	size = 0;
    return size;
}

/*
static const struct pci_device_id mv_pci_ids[] = {
        {PCI_DEVICE(VENDOR_ID, DEVICE_ID_THORLITE_0S1P)},
        {PCI_DEVICE(VENDOR_ID, DEVICE_ID_THORLITE_2S1P)},
        {PCI_DEVICE(VENDOR_ID, DEVICE_ID_THOR_4S1P)},
        {PCI_DEVICE(VENDOR_ID, DEVICE_ID_THOR_4S1P_NEW)},
        {PCI_DEVICE(VENDOR_ID, DEVICE_ID_THORLITE_2S1P_WITH_FLASH)},
        {0}
};

static int mv_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	mv6145dev[mv_dev_cnt] = dev;
        printk("Vendor = [0x%4X]\n", mv6145dev[mv_dev_cnt]->vendor);
        printk("Device = [0x%4X]\n", mv6145dev[mv_dev_cnt]->device);
	mv_dev_cnt++;
        return 0;
}

static void mv_remove(struct pci_dev *dev)
{
}
static struct pci_driver mv_pci_driver = {
        .name     = "qnap_mv",
        .id_table = mv_pci_ids,
        .probe    = mv_probe,
        .remove   = mv_remove,
};
*/
//add a proc interface to active which ports can modify socket receive buffer dynamically.
#include <linux/ctype.h>
#define MAX_ACTIVE_PORT_NUM 30
int active_port[MAX_ACTIVE_PORT_NUM];
int active_port_num=0;
static int
sk_rcv_port_read(char *page,
		       char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int size = 0;
    unsigned int i;
    if (off != 0)
        goto end;

    p += sprintf(p, "active port:");


    for(i=0;i<active_port_num;i++){
        p += sprintf(p,"%d ",active_port[i]);
    }
    p += sprintf(p,"\n");

end:
    size = (p - page);
    if (size <= off + count)
    	*eof = 1;
    *start = page + off;
    size -= off;
    if (size > count)
    	size = count;
    if (size < 0)
    	size = 0;
    return size;
}

static int
sk_rcv_port_write(struct file *file,
			const char __user * buffer,
			unsigned long count, void *data)
{
    char data_buf[256] = {'\0'};
    char *buffer_ptr[MAX_ACTIVE_PORT_NUM+1];
    int i=0,index=0;
    //count include last character
    if (count > sizeof(data_buf) - 1)
        return -EINVAL;

    if (copy_from_user(data_buf, buffer, count))
        return -EFAULT;

    
    data_buf[count] = 0;
    memset(buffer_ptr,0,sizeof(char *) * (MAX_ACTIVE_PORT_NUM + 1));
    while(i < count){
        while(!isalnum(data_buf[i]) && i < count){
            i++;
        }
        if(i == count)
            break;
        buffer_ptr[index] = &data_buf[i];
        while(isalnum(data_buf[i]) && i < count){
            i++;
        }
        data_buf[i++]=0;
        index++;
        if(index >= (MAX_ACTIVE_PORT_NUM + 1))
            break;
    }
    if(index == 0)
    	return count;
	
    if(!strcmp(buffer_ptr[0],"set")){
	memset(active_port,0,sizeof(int) * MAX_ACTIVE_PORT_NUM);
	active_port_num = 0;
        for(i=0;i<index-1;i++){
            active_port[active_port_num] = simple_strtoul(buffer_ptr[i+1],NULL,0);
            if(active_port[active_port_num] != 0 && 
		active_port[active_port_num] < 65535)
                active_port_num++;
	}
    }
    else if(!strcmp(buffer_ptr[0],"add")){
        for(i=0;i<index-1;i++){
	    int port_add;
            port_add = simple_strtoul(buffer_ptr[i+1],NULL,0);
	    if(port_add != 0 && port_add < 65535){
		int j,abort=0;
		for(j=0;j<active_port_num;j++){
        	    if(port_add == active_port[j]){
		    	abort = 1;
			break;
	 	    }
		}
		if(abort == 0 && active_port_num < MAX_ACTIVE_PORT_NUM)
			active_port[active_port_num++] = port_add;
	    }
	}
    }
    else if(!strcmp(buffer_ptr[0],"del")){
	int tmp_active_port[MAX_ACTIVE_PORT_NUM];
	int tmp_active_port_num;
	memcpy(tmp_active_port,active_port,sizeof(int) * MAX_ACTIVE_PORT_NUM);
	tmp_active_port_num = active_port_num;
        for(i=0;i<index-1;i++){
	    int port_del;
            port_del = simple_strtoul(buffer_ptr[i+1],NULL,0);
	    if(port_del != 0 && port_del < 65535){
		int j;
		for(j=0;j<tmp_active_port_num;j++){
        	    if(port_del == tmp_active_port[j]){
			tmp_active_port[j] = 0;
	 	    }
		}
	    }
	}
	memset(active_port,0,sizeof(int) * MAX_ACTIVE_PORT_NUM);
	active_port_num = 0;
	for(i=0;i<tmp_active_port_num;i++){
	    if(tmp_active_port[i] != 0){
		active_port[active_port_num++] = tmp_active_port[i];
	    }
	}
    }
//    for(i=0;i<active_port_num;i++)
//             printk("active port %d :%d\n",i,active_port[i]);
       
    return count;
}

int sk_rcv_port_proc_init()
{
	struct proc_dir_entry *entry=NULL;
	entry=create_proc_read_entry("tsinfo/sk_rcv_port", 0,NULL, sk_rcv_port_read,(void *)0);
	if (entry)
		entry->write_proc = sk_rcv_port_write;
	return 0;
}

int sk_rcv_port_proc_exit()
{
	remove_proc_entry("tsinfo/sk_rcv_port",NULL);
	return 0;
}

int power_proc_init()
{
	struct proc_dir_entry *entry=NULL;
	entry=create_proc_read_entry("tsinfo/power", 0,NULL, power_read,(void *)0);
	return 0;
}

int power_proc_exit()
{
	remove_proc_entry("tsinfo/power",NULL);
	return 0;
}

static __init int qnap_init(void)
{
	int result;
	result = misc_register(&pic_device);
	if (result < 0)
		printk("%s: Fail to register misc device\n", __FUNCTION__);
	else {
		struct pci_dev *pcidev=NULL;
		printk("%s: succeed to register misc device\n", __FUNCTION__);
		init_waitqueue_head(&pic_wait);
		init_waitqueue_head(&queue_empty_wait);
		init_waitqueue_head(&chfiles_wait);
		init_waitqueue_head(&recycle_queue.recycle_wait);
		
		qnap_pic_event_init();
		//Add for system temperature and system vendor
		tsinfo_create_proc();
		sk_rcv_port_proc_init();
        power_proc_init();
		// Get mv6145 pci device
		for_each_pci_dev(pcidev){
			pci_read_config_word(pcidev, PCI_VENDOR_ID, &pcidev->vendor);
			if(pcidev->vendor == MV_VENDOR_ID){
				if(pcidev->device == DEVICE_ID_THOR_4S1P_NEW){
					mv6145dev[mv_dev_cnt] = pcidev;
					pci_read_config_word(pcidev, PCI_DEVICE_ID, &pcidev->device);
					pci_read_config_byte(pcidev, PCI_REVISION_ID, &pcidev->revision);
					printk("MV PCI device: SATA controller [0x%4X], revision: [0x%02X]\n", mv6145dev[mv_dev_cnt]->device, mv6145dev[mv_dev_cnt]->revision);
					mv_dev_cnt++;
				}
			}
		}
		// End
	}
	return result;
}

static void __exit qnap_exit(void)
{
	if (tx_buf)
		kfree(tx_buf);
	if (r_buf)
		kfree(r_buf);
	sk_rcv_port_proc_exit();
    power_proc_exit();
//	pci_unregister_driver(&mv_pci_driver);
}

MODULE_AUTHOR("Ricky Cheng <rickycheng@qnap.com.tw>");
MODULE_DESCRIPTION("QNAP Kernel-User interface");
MODULE_LICENSE("GPL");

module_init(qnap_init);
module_exit(qnap_exit);

