#ifndef __PIC_H__
#define __PIC_H__

#define QUEUE_BUFSIZE 	128
#define QRAID1_QUEUE_BUFSIZE	512
#define PIC_MINOR       80
#define PIC_DEV         "/dev/pic"

#define QNAP_PIC_TOTAL_EVENT    11
#define PIC_EVENT_COMMAND_SIZE  8
#define PIC_EVENT_COMMAND_TYPE  2
struct qnap_pic_ioctl {
	unsigned short pic_data[QUEUE_BUFSIZE];
	int count;
};

struct qnap_pic_event {
	unsigned short command[PIC_EVENT_COMMAND_TYPE][PIC_EVENT_COMMAND_SIZE];
	int count[PIC_EVENT_COMMAND_TYPE];
};

#ifdef CONFIG_ARM
// roylin add by eeprom
struct eeprom_pic_ioctl {
	unsigned char addr;
	unsigned char count;
	unsigned char data[256];
};
#endif // CONFIG_ARM

typedef struct tagReg_State{
        int reset_stat;
}Reg_State;

struct recycle_pic_ioctl{
        int recycle_stat;
};

extern struct objQueue queue;

typedef struct tagFile_Name {
        char file_name[256];
        int stat;
} File_Name;

struct hd_error_led{
        int hd_num;
        int status;
};

#ifdef CONFIG_ARM
enum{
//        READ_WRITE_ERROR = 0,
        HD_OK = 0,
	READ_WRITE_ERROR,
};
#else
enum{
        READ_WRITE_ERROR = 0,
        HD_OK
};
#endif // CONFIG_ARM



enum{
	HDD1 = 1,
	HDD2,
	HDD3,
	HDD4,
	HDD5,
	HDD6,
	HDD7,
	HDD8,
	HDD9,
	HDD10,
	HDD11,
	HDD12
};

#ifndef USB_DRV_DEFINED
typedef enum
{
    USB_DRV_UNKNOWN_HCD = 0,
    USB_DRV_UHCI_HCD,
    USB_DRV_EHCI_HCD,
    USB_DRV_XHCI_HCD,
    USB_DRV_ETXHCI_HCD,
} USB_DRV_TYPE;
#define USB_DRV_DEFINED
#endif

#define IOCTL_MSG_MAGIC                 'Q'
#define IOCTL_MSG_GET_MESSAGE           _IOR(IOCTL_MSG_MAGIC, 1000, struct qnap_pic_ioctl)
#define IOCTL_MSG_SEND_MESSAGE          _IOW(IOCTL_MSG_MAGIC, 1001, struct qnap_pic_ioctl)
#define IOCTL_MSG_SEND_RAW_COMMAND      _IOW(IOCTL_MSG_MAGIC, 1002, struct qnap_pic_ioctl)
#define IOCTL_GPIO_GET_MESSAGE		_IOR(IOCTL_MSG_MAGIC, 1003, int)
#define IOCTL_RECYCLE_SEND_MESSAGE      _IOW(IOCTL_MSG_MAGIC, 1004, struct recycle_pic_ioctl)
#define IOCTL_RECYCLE_GET_MESSAGE       _IOR(IOCTL_MSG_MAGIC, 1005, int)
#define IOCTL_QRAID1_GET_MESSAGE       	_IOR(IOCTL_MSG_MAGIC, 1006, struct chfiles_ioctl)
#define IOCTL_QRAID1_SEND_MESSAGE       _IOW(IOCTL_MSG_MAGIC, 1007, struct qraid1_ioctl)
#define IOCTL_HD_ERROR_LED_SEND_MESSAGE _IOW(IOCTL_MSG_MAGIC, 1008, int)
#define IOCTL_GET_QUEUE_NUM		_IOR(IOCTL_MSG_MAGIC, 1009, int)
#ifdef CONFIG_ARM
#define IOCTL_SEND_EEPROM_WRITE		_IOW(IOCTL_MSG_MAGIC, 1010, struct eeprom_pic_ioctl)
#define IOCTL_SEND_EEPROM_READ          _IOW(IOCTL_MSG_MAGIC, 1011, struct eeprom_pic_ioctl)
#endif // CONFIG_ARM
/***************************************************
 New Ioctl format to support eSATA support port multiplier feature.
 Definition for  unsigned short pic_data in struct qnap_pic_ioctl
 0x00xx -- reserved for old format
 0x01xx -- SATA Up
 0x02xx -- SATA Down
 0x03xx -- ESATA Up
 0x04xx -- ESATA Down
 0x05xx -- SATA Err
****************************************************/
#define QNAP_IOCTL_SATA_UP      0x0100
#define QNAP_IOCTL_SATA_DOWN    0x0200
#define QNAP_IOCTL_ESATA_UP     0x0300
#define QNAP_IOCTL_ESATA_DOWN   0x0400
#define QNAP_IOCTL_SATA_ERR     0x0500
#define QNAP_IOCTL_ETH_UP       0x0600
#define QNAP_IOCTL_ETH_DOWN     0x0700
#define QNAP_IOCTL_BOND_UP      0x0800
#define QNAP_IOCTL_BOND_DOWN    0x0900
#define QNAP_IOCTL_USB_DRV_RELOAD 0x0a00
#define QNAP_IOCTL_USB_SET_POLL_INTV 0x0b00
#define QNAP_IOCTL_SYS_TEMPERATURE (0x0c00)
/////////////////////////////////////////////////////

/* Old command defined in NasPPC, Not final in NasARM 01/11 - Ricky */
#define QNAP_PIC_BOOT_COMPLETE			0
#define QNAP_PIC_NO_HD				1
#define QNAP_PIC_WRONG_HD_FORMAT		2
#define QNAP_PIC_HD_BAD_BLOCK			3
#define QNAP_PIC_HD_FULL			4
#define QNAP_PIC_FIRMWARE_UPDATE		5
#define QNAP_PIC_POWER_OFF			6
#define QNAP_PIC_HD_STANDBY			7
#define QNAP_PIC_USB_COPY			8
#define QNAP_PIC_SET_DEFAULT			9
#define QNAP_PIC_POWER_RECOVERY			10
#define QNAP_PIC_TOTAL_EVENT			11
#define QNAP_PIC_EVENT_OFF			0
#define QNAP_PIC_EVENT_ON			1

#define QNAP_ISCSI_UP				0x0E
#define QNAP_ISCSI_DOWN                     	0x0F
#define QNAP_USB_PRINTER_UP			0x10
#define QNAP_USB_PRINTER_DOWN			0x11
#define QNAP_USB_PRINTER2_UP			0x12
#define QNAP_USB_PRINTER2_DOWN			0x13
#define QNAP_USB_PRINTER3_UP			0x14
#define QNAP_USB_PRINTER3_DOWN			0x15
#define QNAP_USB_PRINTER4_UP			0x16
#define QNAP_USB_PRINTER4_DOWN			0x17
#define QNAP_USB_PRINTER5_UP			0x18
#define QNAP_USB_PRINTER5_DOWN			0x19

#define MD_RESYNCING				0x20
#define MD_RESYNCING_DONE			0x21
#define MD_RESYNCING_SKIP			0x22
#define MD1_REBUILDING				0x23
#define MD1_REBUILDING_DONE			0x24
#define MD1_REBUILDING_SKIP			0x25
#define MD1_RESYNCING				0x26
#define MD1_RESYNCING_DONE			0x27
#define MD1_RESYNCING_SKIP			0x28
#define MD_DEGRAGE				0x29
#define MD2_REBUILDING				0x2A
#define MD2_REBUILDING_DONE			0x2B
#define MD2_REBUILDING_SKIP			0x2C
#define MD2_RESYNCING				0x2D
#define MD2_RESYNCING_DONE			0x2E
#define MD2_RESYNCING_SKIP			0x2F
#define MD3_REBUILDING				0xFA
#define MD3_REBUILDING_DONE			0xFB
#define MD3_REBUILDING_SKIP			0xFC
#define MD3_RESYNCING				0xFD
#define MD3_RESYNCING_DONE			0xFE
#define MD3_RESYNCING_SKIP			0xFF

#define QNAP_PIC_FAN_STOP			0x30
#define QNAP_PIC_FAN_SILENCE			0x31
#define QNAP_PIC_FAN_LOW			0x32
#define QNAP_PIC_FAN_MED			0x33
#define QNAP_PIC_FAN_HIGH			0x34
#define QNAP_PIC_FAN_FULL_SPEED			0x35
#define QNAP_PIC_TEMP_WARM_TO_HOT		0x3A
#define QNAP_PIC_TEMP_HOT_TO_WARM		0x3B
#define QNAP_PIC_TEMP_COLD_TO_WARM		0x3C
#define QNAP_PIC_TEMP_WARM_TO_COLD		0x3D

#define QNAP_PIC_SYS_TEMP_71_79                 0X38
#define QNAP_PIC_SYS_TEMP_80                    0x39
#define QNAP_PIC_POWER_BUTTON			0x40
#define QNAP_PIC_SOFTWARE_SHUTDOWN		0x41
#define QNAP_PIC_POWER_LOSS_POWER_ON            0x42
#define QNAP_PIC_POWER_LOSS_POWER_OFF           0x43
#define QNAP_PIC_POWER_LOSS_LAST_STATE          0x44
#define QNAP_PIC_POWER_RECOVERY_STATUS		0x46
#define QNAP_PIC_ENABLE_POWER_RECOVERY		0x48
#define QNAP_PIC_DISABLE_POWER_RECOVERY		0x49
#define QNAP_PIC_BUZZER_SHORT			0x50
#define QNAP_PIC_POWER_LED_OFF			0x4B
#define QNAP_PIC_POWER_LED_BLINK		0x4C
#define QNAP_PIC_POWER_LED_ON			0x4D
#define QNAP_PIC_EUP_ENABLE 			0x4E
#define QNAP_PIC_EUP_DISABLE 			0x4F

#define QNAP_PIC_BUZZER_LONG			0x51
#define QNAP_PIC_STATUS_RED_BLINK_LONG		0x52
#define QNAP_PIC_STATUS_GREEN_BLINK_LONG	0x53
#define QNAP_PIC_STATUS_RED_BLINK		0x54
#define QNAP_PIC_STATUS_GREEN_BLINK		0x55
#define QNAP_PIC_STATUS_GREEN_ON		0x56
#define QNAP_PIC_STATUS_RED_ON			0x57
#define QNAP_PIC_STATUS_BOTH_BLINK		0x58
#define QNAP_PIC_STATUS_OFF			0x59
#define QNAP_PIC_STATUS_GREEN_BLINK_1HZ		0x5A
#define QNAP_PIC_STATUS_RED_BLINK_1HZ		0x5B
#define QNAP_PIC_STATUS_BOTH_BLINK_1HZ		0x5C

#define QNAP_PIC_USB_LED_ON			0x60
#define QNAP_PIC_USB_LED_BLINK			0x61
#define QNAP_PIC_USB_LED_OFF			0x62
#define QNAP_PIC_10G_LED_ON			    0x63
#define QNAP_PIC_10G_LED_OFF		    0x64
#define QNAP_PIC_POWER_RECOVERY_ON		0x65
#define QNAP_PIC_POWER_RECOVERY_OFF		0x66
#define QNAP_PIC_USB_COPY_BUTTON		0x68
#define QNAP_PIC_SET_DEFAULT_BUTTON		0x6A

#define QNAP_PIC_FAN_ENABLE			0x71
#define QNAP_PIC_FAN_DISABLE			0x72
#define QNAP_PIC_FAN1_ERROR			0x73
#define QNAP_PIC_FAN1_NORMAL			0x74
#define QNAP_PIC_FAN2_ERROR                     0x75
#define QNAP_PIC_FAN2_NORMAL                    0x76
#define QNAP_PIC_FAN3_ERROR                     0x77
#define QNAP_PIC_FAN3_NORMAL                    0x78
#define QNAP_PIC_FAN4_ERROR                     0x79
#define QNAP_PIC_FAN4_NORMAL                    0x7A
#define QNAP_PIC_SYS_TEMP_LOW                   0x80

#define QNAP_GPACT_ON                           0xA0
#define QNAP_GPACT_OFF                          0xA1
#define QNAP_HDERR_ON(nr)                       (0xA0+(nr)*2)
#define QNAP_HDERR_OFF(nr)                      (0xA1+(nr)*2)
#ifdef CONFIG_ARM
// roylin add TS-119P+ LOGO LED
#define QNAP_LOGO_LED_ON                        0xC0
#define QNAP_LOGO_LED_OFF                       0xC1
#define QNAP_LOGO_LED_HD                        0xC2
// roylin add PIC new function
#define QNAP_PIC_RTC_ENABLE			0xF0
#define QNAP_PIC_RTC_DISABLE			0xF1
#define QNAP_PIC_WOL_ENABLE			0xF2
#define QNAP_PIC_WOL_DISABLE			0xF3
#define QNAP_PIC_EUP_DISABLE			0xF4
#define QNAP_PIC_EUP_ENABLE			0xF5
#endif // CONFIG_ARM
/////////////////////////////////////////////////////
// QNAP Patch: fix bug#38643: System temperature up to 70 degree C displayed, no 75 degree C, modify it from 0xC6 to 0xE4
// QNAP_PIC_SYS_TEMP_HIGH belown to QNAP_IOCTL_SYS_TEMPERATURE group
#define QNAP_PIC_SYS_TEMP_HIGH      (0xE4)
#define QNAP_USBDEV_IN				0xC9

#define QNAP_ESATA2_UP				0xC7
#define QNAP_ESATA2_DOWN			0xC8
#define QNAP_NET_UP				0xCD
#define QNAP_NET_DOWN				0xCE
#define QNAP_NET_NIC2_UP			0xCF
#define QNAP_NET_NIC2_DOWN			0xD0
#define QNAP_NET_NIC_UP				0xD1
#define QNAP_NET_NIC_DOWN			0xD2

#define QNAP_NET_BOND1_UP                     0x109E
#define QNAP_NET_BOND1_DOWN                   0x109F
#define QNAP_NET_NIC3_UP                      0x109A
#define QNAP_NET_NIC3_DOWN                    0x109B
#define QNAP_NET_NIC4_UP                      0x109C
#define QNAP_NET_NIC4_DOWN                    0x109D


//Ricky added some hotswap command
#define QNAP_ESATA_UP				0xD3
#define QNAP_ESATA_DOWN				0xD4
#define QNAP_USB_FRONT_UP			0xD5
#define QNAP_USB_FRONT_DOWN			0xD6
#define QNAP_USB_BACK1_UP			0xD7
#define QNAP_USB_BACK1_DOWN			0xD8
#define QNAP_USB_BACK2_UP			0xD9
#define QNAP_USB_BACK2_DOWN			0xDA
#define QNAP_USB_BACK3_UP			0xDB
#define QNAP_USB_BACK3_DOWN			0xDC
#define QNAP_SATA_UP				0xDD
#define QNAP_SATA_DOWN				0xDE
// Hugo add for IP filter
#define QNAP_BLOCK_IP_EVENT                   	0xDF
//End
//Patch by QNAP: add x59 derivative model
#define QNAP_USB_BACK5_UP			0x30
#define QNAP_USB_BACK5_DOWN			0x31
#define QNAP_USB_BACK6_UP			0x32
#define QNAP_USB_BACK6_DOWN			0x33
#define QNAP_USB_PRINTER6_UP		0x34
#define QNAP_USB_PRINTER6_DOWN		0x35
#define QNAP_USB_PRINTER7_UP		0x36
#define QNAP_USB_PRINTER7_DOWN		0x37
///////////////////////////////////////////////////////
#define QNAP_USB_OVER_LIMIT			0xE0
#define MD_REBUILDING				0xE1
#define MD_REBUILDING_DONE			0xE2
#define MD_REBUILDING_SKIP			0xE3

#define QNAP_USB_BACK4_UP			0xE4
#define QNAP_USB_BACK4_DOWN			0xE5

#define QNAP_SATA4_UP                           0xE6
#define QNAP_SATA4_DOWN				0xE7
#define QNAP_SATA5_UP				0xE8
#define QNAP_SATA5_DOWN				0xE9
#define QNAP_SATA2_UP				0xEA
#define QNAP_SATA2_DOWN				0xEB
#define QNAP_SATA3_UP				0xEC
#define QNAP_SATA3_DOWN				0xED
#define QNAP_SATA6				0xEE
#define QNAP_SATA7				0xEF
#define QNAP_SATA8_UP			0xCA
#define QNAP_SATA8_DOWN			0xCB

#define QNAP_USB_WIRELESS_UP		0xCC
#define QNAP_USB_WIRELESS_DOWN	0xC5

//MD ERROR Section start 0xAx
#define MD_ERR_DEGRADE_RAID5			0xF0
#define MD_ERR_DEGRADE_RAID6			0xF1
#define MD_ERR_RECOVERY_ACTDEV0			0xF2
#define MD_ERR_RECOVERY_ACTDEV1			0xF3
#define MD_ERR_RECOVERY_ACTDEV2			0xF4
#define MD_ERR_RECOVERY_ACTDEV3			0xF5
#define MD_ERR_RECOVERY_ACTDEV4			0xF6
#define MD_ERR_RECOVERY_ACTDEV5			0xF7
#define MD_ERR_RECOVERY_ACTDEV6			0xF8
#define MD_ERR_RECOVERY_ACTDEV7			0xF9
//MD ERROR Section end

// SIO
#define QNAP_SIO_OUTPUT_OFF(nr)                 (0x1A0+(nr)*2)
#define QNAP_SIO_OUTPUT_ON(nr)                  (0x1A1+(nr)*2)

// The following definition just for user mode application
#define ERROR_NO_ERROR				0x0000
#define ERROR_NO_HD				0x0001
#define ERROR_HD_WRONG_FORMAT			0x0002
#define ERROR_HD_ALMOST_FULL			0x0010
#define REBUILDING				0x0020
#define	IMG_UPDATE				0x0040				
#define FORMATTING				0x0080
#define ERROR_HD_BAD_BLOCK			0x0100
#define ERROR_NIC_DOWN				0x0200
#define DEGRADE					0x0400
#define ERROR_HD_FULL				0x1000
#define HD_STANDBY				0x10000
#define FAN_ERROR				0x4000

//End of command definition

#ifdef CONFIG_ARM
#define    GPP0  0
#define    GPP1  1
#define    GPP2  2
#define    GPP3  3
#define    GPP4  4
#define    GPP5  5
#define    GPP6  6
#define    GPP7  7
#define    GPP8  8
#define    GPP9  9
#define    GPP10 10
#define    GPP11 11
#define    GPP12 12
#define    GPP13 13
#define    GPP14 14
#define    GPP15 15
#define    GPP16 16
#define    GPP17 17
#define    GPP18 18
#define    GPP19 19
#define    GPP20 20
#define    GPP21 21
#define    GPP22 22
#define    GPP23 23
#define    GPP24 24
#define    GPP25 25
#define    GPP26 26
#define    GPP27 27
#define    GPP28 28
#define    GPP29 29
#define    GPP30 30
#define    GPP31 31
#define    GPP32 32
#define    GPP33 33
#define    GPP34 34
#define    GPP35 35
#define    GPP36 36
#define    GPP37 37
#define    GPP38 38
#define    GPP39 39
#define    GPP40 40
#define    GPP41 41
#define    GPP42 42
#define    GPP43 43
#define    GPP44 44
#define    GPP45 45
#define    GPP46 46
#define    GPP47 47
#define    GPP48 48
#define    GPP49 49
#define    GPP50 50


//Define TS219/TS219P
#define QNAP_MODEL_PRO 0
#define QNAP_MODEL_STANDARD 1
#define QNAP_MODEL_ECONOMIC 2
////////////////
//Patch by QNAP: PIC and GPIO
//#define MV_GPP_IRQ_CAUSE_REG          0x10110
//#define MV_GPP_IRQ_HIGH_CAUSE_REG     0x10150
//#define MV_GPP_IRQ_CAUSE_REG            0x10114
//#define MV_GPP_IRQ_HIGH_CAUSE_REG       0x10154

#define MV_GPP_DATA_IN_REG              0x10	//0x10110
#define MV_GPP_DATA_IN_HIGH_REG 	0x50	//0x10150

unsigned int gpio_out(unsigned int gpio, unsigned int val);
unsigned int gpio_in(unsigned int gpio);
#endif // CONFIG_ARM
int set_led_status(u_int);
int send_message_to_app(unsigned short message);
int qnap_pic_send_command(unsigned short *, int);
#ifdef CONFIG_ARM
int qnap_pic_eeprom_read (unsigned char, unsigned char *, unsigned char);
int qnap_pic_eeprom_write(unsigned char, unsigned char *, unsigned char);
#endif // CONFIG_ARM
void qnap_pic_reset(void);
int get_button_status(void);
int set_hd_error_led_on(int disk_num, int enable);
int get_redundant_power_status(void);
int sk_rcv_port_proc_init(void);
int sk_rcv_port_proc_exit(void);
int set_power_lost_mode_to_gpio(int mode);
void set_EUP_state(int enable);
int set_sio_output(int io_num, int enable);
#ifdef CONFIG_ARM
unsigned int QNAP_model_type(void);
unsigned int QNAP_hw_model(void);
void GPIO_Set_Logo_LED(int on);
#endif // CONFIG_ARM
extern int recycle_enable;

#endif	/*End of __PIC_H__*/
