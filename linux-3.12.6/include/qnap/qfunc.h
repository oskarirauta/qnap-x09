#ifndef __QFUNC_H__
#define __QFUNC_H__
#include "pic.h"
#define MAX_ENTRY       512
#define MAX_PATH        256
#define STAT_DIR        1
#define STAT_FILE       2

#define CHANGEDFILE_RMDIR 		1
#define CHANGEDFILE_MKDIR 		2
#define CHANGEDFILE_SYMLINK 		3
#define CHANGEDFILE_LINK 		4
#define CHANGEDFILE_UNLINK 		5
#define CHANGEDFILE_RENAME 		6 
#define CHANGEDFILE_CHOWN 		7
#define CHANGEDFILE_CHMOD 		8
#define CHANGEDFILE_WRITE 		9


#define RSYNC_PATH_CONFIG		101
#define RSYNC_PATH_SHARE		102
#define RSYNC_PATH_LOG			103

#define path_in_share(path)				\
({							\
	int ret;					\
	if( path && ( !strncmp("/share/", path, 7) ||	\
  		!strncmp("/home/httpd/cgi-bin/filemanager/share/", path, 38)) )\
		ret = 1;				\
	else						\
		ret = 0;				\
	ret;						\
})

#define path_in_config(path)					\
({								\
	int ret;						\
	if( path && ( !strncmp("/etc/config/", path, 12) ||	\
		!strncmp("/mnt/HDA_ROOT/.config/", path, 22)) ) \
		ret = 1;					\
	else							\
		ret = 0;					\
	ret;							\
})

#define path_in_log(path)					\
({								\
	int ret;						\
	if( path && ( !strncmp("/etc/logs/", path, 10) ||	\
		!strncmp("/mnt/HDA_ROOT/.logs/", path, 20)) ) \
		ret = 1;					\
	else							\
		ret = 0;					\
	ret;							\
})

//#define MAX_ENTRY       512

typedef struct objQueue {
        int queue_start;
        int queue_end;
        char *data[MAX_ENTRY];
        int stat[MAX_ENTRY];
	int total_file;
        spinlock_t lock;
        wait_queue_head_t recycle_wait;
} Queue;

struct chfiles_ioctl {
        unsigned char path_id[QRAID1_QUEUE_BUFSIZE];
        int count;
};

struct qraid1_ioctl {
        int qraid1_stat;
};

#define INIT_QUEUE(q)                           \
{                                               \
        .queue_start    = 0,                    \
        .queue_end      = 0,                    \
        .lock           = __SPIN_LOCK_UNLOCKED(q.lock),   \
	.total_file	= 0,			\
}
#define DECLARE_QUEUE(n)                                   \
        struct objQueue n = INIT_QUEUE(n);

//#define MAX_PATH        		512
//DECLARE_QUEUE(queue);

extern char* full_d_path(struct dentry* d, struct vfsmount* mnt, char* buf, int len);

char *qstrdup(char *str);
//int IsEmpty(struct objQueue q);
int IsFull(struct objQueue *q);
void show_queue_obj(struct objQueue q);
int put_to_queue( struct objQueue *q, const char *str, int state);
int get_from_queue(struct objQueue *q, File_Name *s);
int IsEmpty(struct objQueue *q);
int getcwd(char *buf, unsigned long size);
int my_strlen ( const char * mstr) ;
void changedfiles_log_filename( const char * oldname, const char * newname, const int operation) ;
int is_word_temp(char *pathname);
char * get_full_name( const char * oldname );
int is_in_share_folder(char *pathname);
int is_in_trash(char *pathname);
int is_in_eSATA(char *pahtname);
int is_in_usb(char *pahtname);

#endif /* __QFUNC_H__ */
