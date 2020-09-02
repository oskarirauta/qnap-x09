//PATCH: PIC and GPIO
//PATCH: support sys debug
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#if defined(QNAP_HAL)
#include <linux/kernel.h>
#include <linux/module.h>
char cpu_model[50];
EXPORT_SYMBOL(cpu_model);
unsigned int FlashDevId;
EXPORT_SYMBOL(FlashDevId);
unsigned int FlashVendorId;
EXPORT_SYMBOL(FlashVendorId);
#else
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <qnap/pic.h>
#include <qnap/qfunc.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>

// QNAP Patch
#include <linux/version.h>
#include <linux/spinlock_types.h>
///////////////////////////////

//PATCH:suuport  ehci/otg into test mode
#include <asm/io.h>
///////////////////////////////
#define VENDOR  "QNAP"

char cpu_model[50];
EXPORT_SYMBOL(cpu_model);

// QNAP Patch: Flash Info.
unsigned int FlashDevId;
EXPORT_SYMBOL(FlashDevId);
unsigned int FlashVendorId;
EXPORT_SYMBOL(FlashVendorId);

/***************************************************************
	Functions which export by other modules 
****************************************************************/
extern void serial8250_PIC_init(u32 baudRate);
extern void serial8250_PIC_transmit_char(const unsigned char c);
extern int serial8250_PIC_eeprom_read(unsigned char addr, unsigned char *data, unsigned char count);
extern int serial8250_PIC_eeprom_write(unsigned char addr, unsigned char *data, unsigned char count);
//extern void QNAP_adequate_rcv_init(void); // roylin mask
extern u32 mvGpioRegWrite(u32 offset, u32 val);
extern u32 mvGppOut(u32 group, u32 mask, u32 value);

extern u32 mvGppValueSet (u32 group, u32 mask, u32 value);
extern u32 QNAP_model_type(void);
extern u32 QNAP_hw_model(void);
/**************************************************************
	PIC related variable and API
	rx_buf receive from PIC or from Kernel API
****************************************************************/
static int rx_begin = 0, rx_end = 0;
static wait_queue_head_t	pic_wait;
static unsigned short rx_buf[QUEUE_BUFSIZE];
static DEFINE_SPINLOCK(rx_buf_lock);
static DEFINE_SPINLOCK(lock);
static struct qnap_pic_event pic_event[QNAP_PIC_TOTAL_EVENT];
static int pic_open(struct inode *inode, struct file *fp);
static int pic_release(struct inode *inode, struct file *fp);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,6)		
static int pic_ioctl(struct file *filp, u_int cmd, u_long arg);
#else
static int pic_ioctl(struct inode * inode, struct file *filp, u_int cmd, u_long arg);
#endif


static void qnap_pic_event_init(void);
static struct file_operations pic_fops = {
	.owner = THIS_MODULE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,6)
	.unlocked_ioctl = pic_ioctl,
#else
	.ioctl = pic_ioctl,
#endif	
	.open = pic_open,
	.release = pic_release,
};

static struct miscdevice pic_device = {
    PIC_MINOR, "pic", &pic_fops
};

/***************************************************************
	QRAID1 related variable and API
	qraid1_rx_buf receive from  Kernel API
****************************************************************/
int qraid1_enable = 0; //used in namei.c & read_write.c
static int qraid1_begin = 0, qraid1_end = 0;
static wait_queue_head_t chfiles_wait;
static unsigned char qraid1_rx_buf[QRAID1_QUEUE_BUFSIZE];

/***************************************************************
	RECYCLE related variable and API
****************************************************************/
extern int recycle_enable; //use namei.c
DECLARE_QUEUE(recycle_queue);//export to namei.c

/***************************************************************
	Socket receive buffer related variable and API
****************************************************************/
#define MAX_ACTIVE_PORT_NUM 30
int active_port[MAX_ACTIVE_PORT_NUM];
int active_port_num=0;

/***************************************************************
	Proc related variable and API
****************************************************************/
int qnap_ata_reset_to_ms = 0; // unit: ms
int qnap_ata_retry_val = 0;
static int ata_reset_timeout_read(char *page, char **start, off_t off,int count, int *eof, void *data);
static int ata_reset_timeout_write(struct file *file,const char __user *buffer,unsigned long count,void *data);
static int ata_retry_read(char *page, char **start, off_t off,int count, int *eof, void *data);
static int ata_retry_write(struct file *file,const char __user *buffer,unsigned long count,void *data);


static int flash_vendorID_read(char *page, char **start, off_t off,int count, int *eof, void *data);
static int flash_deviceID_read(char *page, char **start, off_t off,int count, int *eof, void *data);

static int systemp_read(char *page, char **start, off_t off,int count, int *eof, void *data);
static int vendor_read(char *page, char **start, off_t off,int count, int *eof, void *data);
static void tsinfo_create_proc(void);
static int model_type_read(char *page,char **start, off_t off, int count, int *eof, void *data);
static int model_type_proc_init(void);
static int sk_rcv_port_read(char *page,char **start, off_t off, int count, int *eof, void *data);
static int sk_rcv_port_write(struct file *file,const char __user * buffer,unsigned long count, void *data);
//int sk_rcv_port_proc_init(void);


/***************************************************************
	Misc related variable and API
****************************************************************/
static int sys_temperature = 0;
static __init int qnap_pic_init(void);

/***************************************************************
	PIC DEBUG  related variable and API
****************************************************************/
static int sys_debug; //for interrupt
static int sys_debug_read(char *page,char **start,off_t off,int count,int *eof,void *data);
static int sys_debug_write(struct file *file,const char __user *buffer,unsigned long count,void *data);
static int sys_msg_proc_init(void);


int set_hd_error_led_on(int disk_num, int enable)
{
	//printk("===============disk num : %x, enable: %x\n", disk_num,enable);
#if defined(TS419)
	if (!strncmp(cpu_model,"88F6282",7)){
		switch(disk_num){
			case HDD1:	// sda
				gpio_out(GPP49, enable ? 0 : 1);
				break;
			case HDD2: // sdb
				gpio_out(GPP48, enable ? 0 : 1);
				break;
			case HDD3: // sdc
				gpio_out(GPP47, enable ? 0 : 1);
				break;
			case HDD4: // sdd
				gpio_out(GPP46, enable ? 0 : 1);
				break;
			default:
				break;
		}
	}else if (!strncmp(cpu_model,"88F6281",7)){
		if (gpio_in(GPP44)){ //TS419 TS410
			switch(disk_num){
				case HDD1:	// sda
					gpio_out(GPP49, enable ? 0 : 1);
					break;
				case HDD2: // sdb
					gpio_out(GPP48, enable ? 0 : 1);
					break;
				case HDD3: // sdc
					gpio_out(GPP47, enable ? 0 : 1);
					break;
				case HDD4: // sdd
					gpio_out(GPP46, enable ? 0 : 1);
					break;
				default:
					break;
			}
		}else { //TS419U TS410U
			switch(disk_num){
				case HDD1:	// sda
					gpio_out(GPP46, enable ? 0 : 1);
					break;
				case HDD2: // sdb
					gpio_out(GPP47, enable ? 0 : 1);
					break;
				case HDD3: // sdc
					gpio_out(GPP48, enable ? 0 : 1);
					break;
				case HDD4: // sdd
					gpio_out(GPP49, enable ? 0 : 1);
					break;
				default:
					break;
			}
		}
	}
#elif defined(TS219) || defined(TS119) || defined(TS218) || defined(TS118)
	if (!strncmp(cpu_model,"88F6282",7)){
		switch(disk_num){
	                case HDD1: // sda
	                        gpio_out(GPP46, enable ? 0 : 1);
	                        break;
	                case HDD2: // sdb
	                        gpio_out(GPP47, enable ? 0 : 1);
	                        break;
			default:
				break;
		}
	}else if (!strncmp(cpu_model,"88F6281",7)){
		switch(disk_num){
	                case HDD1: // sda
					if(QNAP_model_type() == QNAP_MODEL_STANDARD)
						gpio_out(GPP34, enable ? 0 : 1);
					else
						gpio_out(GPP35, enable ? 0 : 1);	
	                        break;
	                case HDD2: // sdb
	                        	if(QNAP_model_type() == QNAP_MODEL_STANDARD)
						gpio_out(GPP35, enable ? 0 : 1);
					else
						gpio_out(GPP34, enable ? 0 : 1);	
	                        break;
			default:
				break;
		}		
	}
#endif
	return 0;
}


/***************************************************************
	Internal API definition
****************************************************************/

static void qnap_pic_event_init(void)
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

static int pic_open(struct inode *inode, struct file *fp)
{
    return 0;
}

static int pic_release(struct inode *inode, struct file *fp)
{
	return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,6)		
static int pic_ioctl(struct file *filp, u_int cmd, u_long arg)
#else
static int pic_ioctl(struct inode * inode, struct file *filp, u_int cmd, u_long arg)
#endif
{
	int i, bytes;
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,6)		
//	DEFINE_SPINLOCK(lock);
//	//spinlock_t lock = __SPIN_LOCK_UNLOCKED(lock);
//#else
//	spinlock_t lock = SPIN_LOCK_UNLOCKED;
//#endif	
	unsigned long flags;
	struct qnap_pic_ioctl qpi;
	struct eeprom_pic_ioctl epi;
	struct recycle_pic_ioctl rpi;
	File_Name recycle_msg;
	struct chfiles_ioctl qraid1_msg;
	struct qraid1_ioctl qraid1_send_msg;
	struct hd_error_led hd_msg;
	int result=-EINVAL;
	int retval=0;//GPIO43:USB COPY BUTTON,GPIO37:RESET BUTTON
	
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
			rx_buf[rx_begin] = 0;
			qpi.count++;
			rx_begin = (rx_begin + 1) % QUEUE_BUFSIZE;		
			// Add for save system temperature
#if 0
			if((qpi.pic_data[i] >= QNAP_PIC_SYS_TEMP_LOW) && (qpi.pic_data[i] <= QNAP_PIC_SYS_TEMP_HIGH))
				sys_temperature = qpi.pic_data[i] - 0x80;
#else
			if( (qpi.pic_data[i] & QNAP_IOCTL_SYS_TEMPERATURE) == QNAP_IOCTL_SYS_TEMPERATURE){
				unsigned char temp_sys_temp = (qpi.pic_data[i]&0xFF);
				if( (temp_sys_temp >= QNAP_PIC_SYS_TEMP_LOW) && (temp_sys_temp <= QNAP_PIC_SYS_TEMP_HIGH) ){
					sys_temperature = temp_sys_temp - 0x80;
					//printk("=== check: sys_temperature is %d, raw is 0x%x\n",sys_temperature,qpi.pic_data[i]); // debug msg
				}
			}
#endif
		}
		spin_unlock_irqrestore(&rx_buf_lock, flags);
		result = copy_to_user((void *)arg, &qpi, sizeof(struct qnap_pic_ioctl));
		break;
	case IOCTL_MSG_SEND_MESSAGE:
		if (copy_from_user(&qpi, (struct qnap_pic_ioctl *)arg, sizeof(struct qnap_pic_ioctl)))
			break;
		for (i = 0; i < QUEUE_BUFSIZE && i < qpi.count; i += 2) {
			int event,type;
			event = qpi.pic_data[i];
			type = qpi.pic_data[i + 1];
			if (event >= QNAP_PIC_TOTAL_EVENT || type >= PIC_EVENT_COMMAND_TYPE)
				continue;
			switch(event) {
				/* Something should be here. */
			}
			qnap_pic_send_command(pic_event[event].command[type], pic_event[event].count[type]); 
		}
		result = 0;
		break;
	case IOCTL_GPIO_GET_MESSAGE:
		{
			//Patch by QNAP: PIC and GPIO
			if (!strncmp(cpu_model,"88F6282",7)){
				//GPIO43:USB COPY BUTTON, GPIO37:RESET BUTTON
				retval |= gpio_in(GPP37)? (1<<16) : 0;
				retval |= gpio_in(GPP43)? (1<<15) : 0;
				/////////////////////////////////////////////			
			}else if (!strncmp(cpu_model,"88F6281",7)){
#if defined(TS119) || defined(TS219) || defined(TS118) || defined(TS218)
				//GPIO15:USB COPY BUTTON, GPIO16:RESET BUTTON
				retval |= gpio_in(GPP15)? (1<<15) : 0;
				retval |= gpio_in(GPP16)? (1<<16) : 0;
#elif defined(TS419)
				//GPIO43:USB COPY BUTTON, GPIO37:RESET BUTTON
				retval |= gpio_in(GPP37)? (1<<16) : 0;
				retval |= gpio_in(GPP43)? (1<<15) : 0;
#endif
			}
			if(copy_to_user((void __user *)arg, &retval, sizeof(retval))){
				return -EFAULT;
			}
			//////////////////////////////////////////////////  
		}
		break;
	case IOCTL_RECYCLE_SEND_MESSAGE:
		if (copy_from_user(&rpi, (struct recycle_pic_ioctl *)arg, sizeof(struct recycle_pic_ioctl)))
	        	break;
		recycle_enable = rpi.recycle_stat;
		break;
	case IOCTL_RECYCLE_GET_MESSAGE:
		recycle_msg.file_name[0] = 0;
                //if no file in the recycle_queue
		while( get_from_queue(&recycle_queue, &recycle_msg) == 0){
			interruptible_sleep_on(&recycle_queue.recycle_wait);
			if (signal_pending(current)){
	                	printk("recycle_ioctl: signal_pending current failed\n");
                    		return -ERESTARTSYS;
            		}
			//return -EINVAL;
		}
        	if(copy_to_user((void __user *)arg, &recycle_msg, sizeof(File_Name)))
                	return -EFAULT;
		break;
	case IOCTL_GET_QUEUE_NUM:
		printk("recycle_queue num = %d\n", recycle_queue.total_file);
		break;
	//JimmyChang add for qraid1
	case IOCTL_QRAID1_GET_MESSAGE:
	        memset(&qraid1_msg, 0, sizeof(struct chfiles_ioctl));
        	while (qraid1_begin == qraid1_end) {
//              	printk("PIC without any event\n");
	                interruptible_sleep_on(&chfiles_wait);
        	        if (signal_pending(current)){
                	        printk("changedfiles_ioctl: signal_pending current failed\n");
                        	return -ERESTARTSYS;
	                }
        	}
	        spin_lock_irqsave(&lock, flags);
        	// calculate how many bytes available
	        bytes = ((qraid1_end + QRAID1_QUEUE_BUFSIZE) - qraid1_begin) % QRAID1_QUEUE_BUFSIZE;
        	// read data as many as possible
	        for (i = 0 ; i < bytes ; i++) {
        	        qraid1_msg.path_id[i] = qraid1_rx_buf[qraid1_begin];
                	qraid1_msg.count++;
	                qraid1_begin = (qraid1_begin + 1) % QRAID1_QUEUE_BUFSIZE;
        	}
	        spin_unlock_irqrestore(&lock, flags);
        	return copy_to_user((void *)arg, &qraid1_msg, sizeof(struct chfiles_ioctl));
		break;
	case IOCTL_QRAID1_SEND_MESSAGE:
		if (copy_from_user(&qraid1_send_msg, (struct qraid1_ioctl *)arg, sizeof(struct qraid1_ioctl)))
                        break;
		qraid1_enable = qraid1_send_msg.qraid1_stat;
		break;
	case IOCTL_HD_ERROR_LED_SEND_MESSAGE:
		copy_from_user(&hd_msg, (struct hd_error_led *)arg, sizeof(struct hd_error_led));
		//printk("hd.hd_num = %d, hd.status = %d\n", hd.hd_num, hd.status);
		if(hd_msg.status == READ_WRITE_ERROR)
			set_hd_error_led_on(hd_msg.hd_num,1);
		else if(hd_msg.status == HD_OK)
			set_hd_error_led_on(hd_msg.hd_num,0);
		break;
	case IOCTL_MSG_SEND_RAW_COMMAND:
		if (copy_from_user(&qpi, (struct qnap_pic_ioctl *)arg, sizeof(struct qnap_pic_ioctl)))
			break;
		qnap_pic_send_command(qpi.pic_data, qpi.count);
		result = 0;
		break;
// roylin add by pic eeprom read/write =====================
	case IOCTL_SEND_EEPROM_READ:
		memset(&epi, 0, sizeof(struct eeprom_pic_ioctl));
		if (copy_from_user(&epi, (struct eeprom_pic_ioctl *)arg, sizeof(struct eeprom_pic_ioctl)))
                      break;
		result = qnap_pic_eeprom_read(epi.addr, epi.data, epi.count);
		copy_to_user((void *)arg, &epi, sizeof(struct eeprom_pic_ioctl));
		break;
        case IOCTL_SEND_EEPROM_WRITE:
		memset(&epi, 0, sizeof(struct eeprom_pic_ioctl));
		if (copy_from_user(&epi, (struct eeprom_pic_ioctl *)arg, sizeof(struct eeprom_pic_ioctl)))
                      break;
                result = qnap_pic_eeprom_write(epi.addr, epi.data, epi.count);
                break;
/////////////////////////////////////////////////////////////
	default:
		break;
	}
	return result;
}

static int systemp_read(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	int len;
	len=sprintf(page, "%d\n", sys_temperature);
	return len;	
}

static int vendor_read(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	int len;
	len=sprintf(page, "vendor\t\t: %s\n", VENDOR);
	return len;
}

static int flash_vendorID_read(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	int len;
	len=sprintf(page, "0x%x", FlashVendorId);
	return len;
}

static int flash_deviceID_read(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	int len;
	len=sprintf(page, "0x%x", FlashDevId);
	return len;
}

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




static void tsinfo_create_proc(void)
{
	struct proc_dir_entry *systemp_procdir;
	struct proc_dir_entry *vendor_procdir;
	struct proc_dir_entry *flash_vendorID_procdir;
	struct proc_dir_entry *flash_deviceID_procdir;

	struct proc_dir_entry *ata_time_procdir;
	struct proc_dir_entry *ata_retry_procdir;

	proc_mkdir("tsinfo", NULL);
	systemp_procdir = create_proc_entry("tsinfo/systemp", 0644, NULL );
	vendor_procdir = create_proc_entry("tsinfo/vendor", 0644, NULL );
	flash_vendorID_procdir = create_proc_entry("tsinfo/flash_vendorID", 0644, NULL );
	flash_deviceID_procdir = create_proc_entry("tsinfo/flash_deviceID", 0644, NULL );

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
    if(flash_vendorID_procdir == NULL)
		printk("tsinfo: Couldn't create proc flash verderID\n");
	else{
		flash_vendorID_procdir->read_proc = flash_vendorID_read;
		printk("tsinfo: create proc systemp successfully\n");
    }
    if(flash_deviceID_procdir == NULL)
		printk("tsinfo: Couldn't create proc flash deviceID\n");
	else{
		flash_deviceID_procdir->read_proc = flash_deviceID_read;
		printk("tsinfo: create proc systemp successfully\n");
    }
    
}

static int model_type_read(char *page,char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int size = 0;
    if (off != 0)
        goto end;

    p += sprintf(p, "%d",QNAP_model_type());
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

static int get_cpu_model(char *page,char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int size = 0;
    if (off != 0)
        goto end;

    p += sprintf(p, "%s",cpu_model);
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

static int get_hw_model(char *page,char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int size = 0;
    if (off != 0)
        goto end;

    p += sprintf(p, "%d %d", 0, QNAP_hw_model());
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

static int model_type_proc_init()
{
	struct proc_dir_entry *entry=NULL;
	entry=create_proc_read_entry("tsinfo/model_type", 0,NULL, model_type_read,(void *)0);
	entry=create_proc_read_entry("tsinfo/cpu_model", 0,NULL, get_cpu_model,(void *)0);
	entry=create_proc_read_entry("tsinfo/hw_version", 0,NULL, get_hw_model,(void *)0);
	return 0;
}

//add a proc interface to active which ports can modify socket receive buffer dynamically.
static int sk_rcv_port_read(char *page,char **start, off_t off, int count, int *eof, void *data)
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

static int sk_rcv_port_write(struct file *file,const char __user * buffer,unsigned long count, void *data)
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
    for(i=0;i<active_port_num;i++)
             printk("active port %d :%d\n",i,active_port[i]);
       
    return count;
}


int sk_rcv_port_proc_init(void)
{
	struct proc_dir_entry *entry=NULL;
	entry=create_proc_read_entry("tsinfo/sk_rcv_port", 0,NULL, sk_rcv_port_read,(void *)0);
	if (entry)
		entry->write_proc = sk_rcv_port_write;
	return 0;
}

//PATCH: support sys debug

static int sys_debug_read(char *page,char **start,off_t off,int count,int *eof,void *data)
{
	char *p = page;
	int size=0;
//	p += sprintf(p,"sys debug level:%d",sys_debug);
	p += sprintf(p,"pic debug level:%d",sys_debug);
	p += sprintf(p,"\n");
	size = p - page;
	if(size <= off + count)
		*eof = 1;
	*start = page + off;
	size -= off;
	if(size > count)
		size = count;
	if(size < 0)
		size = 0;
	return size;
}

static int sys_debug_write(struct file *file,const char __user *buffer,unsigned long count,void *data)
{
        char data_buf[256] = {'\0'};
        if(copy_from_user(data_buf,buffer,count))
                return -EFAULT;
        data_buf[count] = 0;
        sys_debug = simple_strtoul(data_buf,NULL,0);
        return count;
}

static int sys_msg_proc_init(void)
{
	struct proc_dir_entry *entry=NULL;
	entry = create_proc_read_entry("tsinfo/sys_debug",0,NULL,sys_debug_read,(void*)0);
        //entry = create_proc_nit_waitqueue_headread_entry("tsinfo/pic_debug",0,NULL,sys_debug_read,(void*)0);
	if(entry)
		entry->write_proc = sys_debug_write;
	return 0;
}



static __init int qnap_pic_init(void)
{
	int result=0;
	printk("%s: succeed to register misc device\n", __FUNCTION__);
	init_waitqueue_head(&pic_wait);
	init_waitqueue_head(&chfiles_wait);
	init_waitqueue_head(&recycle_queue.recycle_wait);
	qnap_pic_event_init();
	//Add for system temperature and system vendor
	tsinfo_create_proc();
	sk_rcv_port_proc_init();
	model_type_proc_init();
	sys_msg_proc_init();

	serial8250_PIC_init(19200);
	serial8250_PIC_transmit_char(QNAP_PIC_BUZZER_SHORT);
	result = misc_register(&pic_device);

	return result;
}
/////////////////////////////////////////////////////////////////////////////////////////////
int send_message_to_app(unsigned short message)
{
    if (((rx_end + 1) % QUEUE_BUFSIZE) != rx_begin) {
            rx_buf[rx_end] = message;
//printk("qnap pic: get byte 0x%x\n", rx_buf[rx_end]);
            rx_end = ((rx_end + 1) % QUEUE_BUFSIZE);
    }
//== roylin test ==========================
#if 0
	{
	int i;
	printk("\n=== QUEUE => ");
	for(i=0;i<QUEUE_BUFSIZE;i++){
		printk("0x%02X ",rx_buf[i]);
	}
	printk("\n");
	}
#endif
//=========================================
	if (waitqueue_active(&pic_wait))
                wake_up_interruptible(&pic_wait);
	return 0;
}

int qnap_pic_eeprom_write(unsigned char addr, unsigned char *data, unsigned char count)
{
	if (data == NULL || count <= 0)
                return -EINVAL;
        return serial8250_PIC_eeprom_write(addr, data, count);
}

int qnap_pic_eeprom_read(unsigned char addr, unsigned char *data, unsigned char count)
{
	return serial8250_PIC_eeprom_read(addr, data, count);
}

static unsigned logo_led_sts = 0;
int qnap_pic_send_command(unsigned short *data, int count)
{
	int i;

	if (data == NULL || count <= 0)
		return -EINVAL;

	for (i = 0; i < count; i++){
		switch(data[i]){
			case QNAP_HDERR_ON(1):
			case QNAP_HDERR_ON(2):
			case QNAP_HDERR_ON(3):
			case QNAP_HDERR_ON(4):
				set_hd_error_led_on((((unsigned char)data[i] - QNAP_HDERR_ON(1)) / 2) + 1,1);
				break;
			case QNAP_HDERR_OFF(1):
			case QNAP_HDERR_OFF(2):
			case QNAP_HDERR_OFF(3):
			case QNAP_HDERR_OFF(4):
				set_hd_error_led_on((((unsigned char)data[i] - QNAP_HDERR_ON(1)) / 2) + 1,0);
				break;
			case QNAP_LOGO_LED_ON:
                                GPIO_Set_Logo_LED(1);
                                logo_led_sts = 0;
                                break;
                        case QNAP_LOGO_LED_OFF:
                                GPIO_Set_Logo_LED(0);
                                logo_led_sts = 0;
                                break;
                        case QNAP_LOGO_LED_HD:
                                logo_led_sts = 1;
                                break;
			case QNAP_PIC_POWER_LOSS_POWER_ON:
				break;
			case QNAP_PIC_POWER_LOSS_POWER_OFF:
				serial8250_PIC_transmit_char(QNAP_PIC_DISABLE_POWER_RECOVERY);
				break;
			case QNAP_PIC_POWER_LOSS_LAST_STATE:
				serial8250_PIC_transmit_char(QNAP_PIC_ENABLE_POWER_RECOVERY);
				break;
			default:
				serial8250_PIC_transmit_char((unsigned char)data[i]);
				if(logo_led_sts == 1){
                                        if((unsigned char)data[i] == QNAP_PIC_STATUS_OFF)
                                                GPIO_Set_Logo_LED(0);
                                        else if((unsigned char)data[i] == QNAP_PIC_STATUS_GREEN_ON)
                                                GPIO_Set_Logo_LED(1);
                                }
				break;
		}
	}
	return count;
}



int send_message_to_app_qraid1(unsigned char message)
{
	unsigned long flags;
	//static DEFINE_SPINLOCK(lock);

	spin_lock_irqsave(&lock, flags);
	if((qraid1_begin != qraid1_end) && (message == qraid1_rx_buf[qraid1_end -1]))
	{
		//printk("skip msg %d\n", message);
		spin_unlock_irqrestore(&lock, flags);
		return 0;
	}
	if (((qraid1_end + 1) % QRAID1_QUEUE_BUFSIZE) != qraid1_begin) {
		qraid1_rx_buf[qraid1_end] = message;
		//printk("send_msg_to_app: %d\n", r_buf[end]);
		qraid1_end = ((qraid1_end + 1) % QRAID1_QUEUE_BUFSIZE);
	}
	spin_unlock_irqrestore(&lock, flags);
	wake_up_interruptible(&chfiles_wait);
	return 0;
}

int qnap_check_skport(__be16 s_port)
{
	int result = -1;
	if(active_port_num > 0){
		int i=0;
		while(i < active_port_num){
			if(s_port == htons(active_port[i])){
				result = 0;
				break;
			}
			i++;
		}
	}
	return result;
}

int qnap_get_pic_debug_level(void)
{
	return sys_debug;
}
///////////////////////////////////////////////////////////////////////////////////
EXPORT_SYMBOL(send_message_to_app);
EXPORT_SYMBOL(send_message_to_app_qraid1);
EXPORT_SYMBOL(qnap_get_pic_debug_level);

__initcall(qnap_pic_init);
#endif
