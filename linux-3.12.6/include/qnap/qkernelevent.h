#ifndef _QKERNELEVENT_H_
#define _QKERNELEVENT_H_

#define u32 	unsigned int

#define QKV_MINOR	81
#define QKV_DEV			"/dev/qkernelevent"
#define IOCTL_QWD_MSG_MAGIC		'Q'
#define IOCTL_QWD_SET_TIMER		_IOW(IOCTL_QWD_MSG_MAGIC, 2000, u32) //Set watchdog timer
#define IOCTL_QWD_SET_OUTn		_IO(IOCTL_QWD_MSG_MAGIC, 2001) //Set watchdog timer
#define IOCTL_ENABLE_WD			_IOW(IOCTL_QWD_MSG_MAGIC, 2002, int)	//Enable/Disable watchdog


#endif /* _QKERNELEVENT_H_ */
