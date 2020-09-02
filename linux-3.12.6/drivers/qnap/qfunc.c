// PATCH: Review QRAID1
//PATCH: Add for recycle_bin feature, Review recycle_bin

/*
	These functions are used by recycle_bin and qraid1.
*/
#if !defined(QNAP_HAL)
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <qnap/qfunc.h>
#include <linux/file.h>
#include <asm/unistd.h>
#include <linux/mount.h>
#include <linux/miscdevice.h>
#include <linux/wait.h>
#include <qnap/sendmessage.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

// QNAP Patch
#include <linux/slab.h>

/////////////////////////////////////////////
void msleep(unsigned int msecs);
extern int recycle_enable;
extern int qraid1_enable;

char *qstrdup(char *str)
{
        int n = strlen(str)+1;
        char *s = kmalloc(n, GFP_ATOMIC);
        if (!s) return NULL;
        return strcpy(s, str);
}


int IsFull(struct objQueue *q)
{
        if(q->queue_start == ((q->queue_end + 1) % MAX_ENTRY))
                return 1;
        else
                return 0;
}

void show_queue_obj(struct objQueue q)
{
        int i;
        for(i = q.queue_start; i!=q.queue_end; i=(i+1)%MAX_ENTRY)
        {
                printk("[%d] = %s\n", i, q.data[i]);
        }
}

int put_to_queue( struct objQueue *q, const char *str, int state)
{
    unsigned long flag;

    if(IsFull(q)){
	//wait for more space
	while(q->total_file > (MAX_ENTRY - 10))
	{
//printk("the queue is full = %d\n", q->total_file);
		msleep(10);
	}
    }
    spin_lock_irqsave(&q->lock, flag);

// put the filename to queue
    q->data[q->queue_end] = qstrdup((char *)str);
// put the filename's state to queue
    q->stat[q->queue_end] = state;
    q->queue_end = (q->queue_end + 1) % MAX_ENTRY;


    spin_unlock_irqrestore(&q->lock, flag);

	wake_up_interruptible(&q->recycle_wait);

	q->total_file++;
	//printk("put_to_queue = %d\n", q->total_file);

    return 0;
}

int IsEmpty(struct objQueue *q){
        if(q->queue_start == q->queue_end){
		q->total_file = 0;
                return 1;
	}
        else
                return 0;
}

int get_from_queue(struct objQueue *q, File_Name *s){
        unsigned long flag;

        if(IsEmpty(q))
                goto error;

        spin_lock_irqsave(&q->lock, flag);

        // get the filename from queue
        strcpy(s->file_name, q->data[q->queue_start]);
//printk("get from gueue: [%s]\n", s->file_name);
        kfree(q->data[q->queue_start]);

        // get the filename's state from queue
        s->stat = q->stat[q->queue_start];
        q->queue_start = (q->queue_start + 1) % MAX_ENTRY;

        spin_unlock_irqrestore(&q->lock, flag);

	q->total_file--;
	//printk("get_from_queue = %d\n", q->total_file);

        return 1;
error:
        return 0;
}


/* PATCH: Review QRAID1, 
	Since we have sys_getcwd(), 
	why reinvent the wheel? */ 
#if 1
int getcwd(char *buff, unsigned long size)
{
	mm_segment_t old_fs;
	int ret;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	ret = sys_getcwd(buff, size);

	set_fs(old_fs);

	return ret;
}

#else

int getcwd(char *buf, unsigned long size)
{
	unsigned long lock_flags;
	int error;
	struct path pwd,root;
	char *page = __getname();

	spinlock_t dcache_lock = SPIN_LOCK_UNLOCKED;	

	if (!page)
		return -ENOMEM;

	read_lock(&current->fs->lock);
	pwd = current->fs->pwd;
	path_get(&current->fs->pwd);
	root = current->fs->root;
	path_get(&current->fs->root);
	read_unlock(&current->fs->lock);

	error = -ENOENT;
	/* Has the current directory has been unlinked? */
	spin_lock_irqsave(&dcache_lock, lock_flags);

		
	if (IS_ROOT(pwd.dentry) || !d_unhashed(pwd.dentry)) {
	    unsigned long s;
	    char * cwd;

		cwd = __d_path(pwd.dentry, pwd.mnt, &root, page, PAGE_SIZE);
	    spin_unlock_irqrestore(&dcache_lock, lock_flags);
	    error = -ERANGE;
	    len = PAGE_SIZE + page - cwd;
	    if (len <= size) {
            error = len;
            strncat(buf, cwd, size);
	    }
    } else
        spin_unlock_irqrestore(&dcache_lock, lock_flags);
leave:
	path_put(&pwd);
	path_put(&root);
	__putname(page);
    return error;
}
#endif

int my_strlen ( const char * mstr) 
{ 
  char * c; 
  int i=0; 
  c = (char *)mstr; 
  while ( *c != '\0' ) 
	{ 
	  c++; 
	  i++; 
	}
  return i; 
}

int is_word_temp(char *pathname)
{
        char *tmp1, *tmp2 = 0 , tmp3[256] = "/";
        tmp1 = pathname;
        if(*pathname != '/'){
                tmp2 = strcat(tmp3, pathname);
                goto result;
        }else
                while(*tmp1 != '\0')
                {
                        tmp1 = tmp1 + 1;
                        while(*pathname != '/')
                        {
                                pathname = pathname + 1;
                                if(*pathname == '\0')
                                        goto result;
                        }
                        tmp2 = pathname;
                        pathname = pathname + 1;
                }

        result:
                //It is word temp
                if(*(tmp2+1) == '~' && *(tmp2+2) == '$')
                        return 0;
                else
                        return 1;
}

// PATCH: Review QRAID1
char * get_full_name( const char * oldname )
{
	char *fullname;
	char *error = NULL;
	long len = 0;

	if ( !oldname )
		return error;
	// filter .lck extension file
	//if(!strcmp((char*)(oldname+(strlen(oldname)-4)), ".lck"))
	//      return;
	fullname = __getname();
	
	if(!fullname) 
		return ERR_PTR(-ENOMEM);
	
	fullname[0] = '\0';

	/* basename file names, fill path if neccessary */
	if ( *oldname == '/' ) {
		if ( !strncmp(oldname, "/HDA_DATA/", 10) ) {    // For ftp
			strncpy(fullname, "/share", 6);
			strncpy(&fullname[6], oldname, (MAX_PATH-6)-1);
		} else
			strncpy(fullname, oldname, MAX_PATH - 1);
	} else {
		int left = 0;
		len = getcwd(fullname, MAX_PATH);
		if ( len < 0 ) {
			printk("changedfiles: getcwd returned an error (%ld)", len);
			__putname(fullname);
			return ERR_PTR(len);
		}
		/* 	String length over MAX_PATH will be 
		* 	useless although we have a page size buffer */
 		snprintf(fullname + len, 
				(left = (MAX_PATH - len)) >= 0 ? left : 0,
				"/%s", oldname);
	}

	return fullname;
}

/* Check the file is in the /share */
int is_in_share_folder(char *pathname)
{
	char *tmp = pathname+4;
	char *tmp1 = pathname+10;

	if(!strncmp("_DATA/", tmp1, 6))
		return 1;
	else if(!strncmp("/home/httpd/cgi-bin/filemanager/share", pathname, 37))
		return 1;
	else if(!strncmp("_DATA/", tmp, 6))
		return 2;
	else if(!strncmp("/share/Qmultimedia", pathname, 18))
		return 1;
	else
		return 0;
}

int is_in_trash(char *pathname)
{
	char *tmp = pathname+4;
	char *tmp1 = pathname+41;
	char *tmp2 = pathname+10;

	if(!strncmp("/share/HDA_DATA/Network Recycle Bin", pathname, 35))
		return 1;
	else if(!strncmp("/share/MD0_DATA/Network Recycle Bin", pathname, 35))
		return 1;
	else if(!strncmp("/share/HDB_DATA/Network Recycle Bin", pathname, 35))
		return 1;
	else if(!strncmp("_DATA/Network Recycle Bin", tmp1, 25))
		return 1;
	else if(!strncmp("_DATA/Network Recycle Bin", tmp, 25))
		return 2;
	else if(!strncmp("_DATA/Network Recycle Bin", tmp2, 25))//for volume number more than 2
		return 1;
	else
		return 0;
}

int is_in_eSATA(char *pathname)
{
	if(!strncmp("/share/external/sdy", pathname, 19) || !strncmp("/share/external/sdz", pathname, 19))
		return 1;
	else
		return 0;
}

int is_in_usb(char *pathname)
{
	if(!strncmp("/share/external", pathname, 15))
		return 1;
	else
		return 0;
}

// PATCH: Review QRAID1
void changedfiles_log_filename( const char * oldname, const char * newname, const int operation) 
{ 
	char fulloldname[MAX_PATH]; 
	char fullnewname[MAX_PATH]; 
	long len=0;
	char *fullname=NULL;
	int rsync_path_id = RSYNC_PATH_SHARE;
	
	if ( !oldname )
		return;
	// filter .lck extension file
	//if(!strcmp((char*)(oldname+(strlen(oldname)-4)), ".lck"))
	//	return;
#ifdef DEBUG
	//printk("oldname=%s, newname=%s\n", oldname, newname?newname:"NULL");
#endif
	fulloldname[0]='\0'; 
	fullnewname[0]='\0'; 

	/* basename file names, fill path if neccessary */
	if ( *oldname == '/' ) { 
		if ( !strncmp(oldname, "/HDA_DATA/", 10) ) {	// For ftp
			strncpy(fulloldname, "/share", 6);
			strncpy(&fulloldname[6], oldname, (MAX_PATH-6)-1); 
		} else
			strncpy(fulloldname, oldname, MAX_PATH - 1); 
	} else { 
		len = getcwd(fulloldname, MAX_PATH); 
		if ( len <  0 ) { 
			printk("changedfiles: getcwd returned an error (%ld)", len); 
			return;
		}

		/* +2 means '/' + '\0' */
		if ( ( my_strlen( fulloldname ) + my_strlen( oldname ) + 2) >= MAX_PATH ) {
#if 0 
			len = (my_strlen(fulloldname) + my_strlen(oldname));
			printk("changedfiles: oldfilename too long! %d bytes.  Max: %d", (int)len, MAX_PATH); 
			printk("fulloldname: %s\n", fulloldname);
			printk("oldname: %s\n", oldname);
			return;
#else
/* Richard Chen 20090707, 
 * If the length is too long, we don't need to do things here.
 * Passing the path is enough since we don't use whole path. */
#ifdef DEBUG
			len = strlen(fulloldname);
#endif /* DEBUG */

#endif
		} else {
			strcat(fulloldname, "/"); 
			strcat(fulloldname, oldname);
		} 
#ifdef DEBUG
		if ( len > 0 ) 
			printk("changedfiles: (2) full oldpath is '%s'\n", fulloldname); 
#endif
	}

	if ( newname != NULL ) {
		if ( *newname == '/' ) { 
			if ( !strncmp(newname, "/HDA_DATA/", 10) ) {	// For ftp
				strncpy(fullnewname, "/share", 6);
				strncpy(&fullnewname[6], newname, (MAX_PATH-6)); 
			} else
				strncpy( fullnewname, newname, MAX_PATH ); 
#ifdef DEBUG
			printk("changedfiles: (1) full newpath is '%s'\n", fullnewname); 
#endif
		} else { 
			len = getcwd(fullnewname, MAX_PATH);
			if ( len < 0 ) { 
				printk("changedfiles: getcwd return an error (%ld)", len); 
				return; 
			}
	 		/* +2 means '/' + '\0' */ 
			if ( (my_strlen(fullnewname) + my_strlen(newname) + 2) >= MAX_PATH ) { 
/* Richard Chen 20090707, 
 * If the length is too long, we don't need to do things here.
 * Passing the path is enough since we don't use whole path. */
#ifdef DEBUG
				len = strlen(fullnewname);
#endif
			} else {
				strcat(fullnewname, "/"); 
				strcat(fullnewname, newname); 
			}
		}
#ifdef DEBUG
		if ( len > 0 ) 
			printk("changedfiles: full newpath is '%s'\n", fullnewname); 
#endif
	}

	if ( path_in_share(fulloldname) ) {
		if ( path_in_share(fullnewname) )
  			fullname=fullnewname;
		else
  			fullname=fulloldname;
	} else if( path_in_share(fullnewname) ) {
  		fullname=fullnewname;
	} else if ( path_in_config(fulloldname) ) {
  		fullname=fulloldname;
		rsync_path_id = RSYNC_PATH_CONFIG;
	} else if ( path_in_log(fulloldname) ) {
  		fullname=fulloldname;
		rsync_path_id = RSYNC_PATH_LOG;
 	} else
  		return;

#ifdef DEBUG
	switch (operation){
		case	CHANGEDFILE_RMDIR:
			printk("operation = RMDIR\n");
			break;
		case	CHANGEDFILE_MKDIR:
			printk("operation = MKDIR\n");
			break;
		case	CHANGEDFILE_SYMLINK:
			printk("operation = SYMLINK\n");
			break;
		case	CHANGEDFILE_LINK:
			printk("operation = LINK\n");
			break;
		case	CHANGEDFILE_UNLINK:
			printk("operation = UNLINK\n");
			break;
		case	CHANGEDFILE_WRITE:
			printk("operation = WRITE\n");
			break;
		case	CHANGEDFILE_RENAME:
			printk("operation = RENAME\n");
			break;
		case	CHANGEDFILE_CHOWN:
			printk("operation = CHOWN\n");
			break;
		case	CHANGEDFILE_CHMOD:
			printk("operation = CHMOD\n");
			break;
		default:
			printk("operation=%d, unknown operation\n", operation);
	}	
	switch(rsync_path_id) {
	case RSYNC_PATH_CONFIG:	
		printk("RSYNC_PATH_CONFIG: %s\n", fullname); break;
	case RSYNC_PATH_LOG:	
		printk("RSYNC_PATH_LOG: %s\n", fullname); break;
	case RSYNC_PATH_SHARE:	
		printk("RSYNC_PATH_SHARE: %s\n", fullname); break;
	}
#endif
	send_message_to_app_qraid1(rsync_path_id);

}

int qnap_check_recycle(void)
{
	return recycle_enable;
}

int qnap_check_qraid1(void)
{
	return qraid1_enable;
}
#endif
