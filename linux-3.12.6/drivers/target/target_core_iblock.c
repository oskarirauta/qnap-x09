/*******************************************************************************
 * Filename:  target_core_iblock.c
 *
 * This file contains the Storage Engine  <-> Linux BlockIO transport
 * specific functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2010 Rising Tide Systems
 * Copyright (c) 2008-2010 Linux-iSCSI.org
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ******************************************************************************/

#include <linux/string.h>
#include <linux/parser.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/file.h>
#include <linux/module.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

#if defined(CONFIG_MACH_QNAPTS) 
/* 2014/06/14, adamhsu, redmine 8530 (start) */
#include <asm/unaligned.h>
#include <target/target_core_fabric.h>
/* 2014/06/14, adamhsu, redmine 8530 (end) */
#endif

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include "target_core_iblock.h"

#if defined(CONFIG_MACH_QNAPTS) 
#include "vaai_target_struc.h"
#include "target_general.h"


#if defined(SUPPORT_FAST_BLOCK_CLONE)
#include "target_fast_clone.h"
#endif

#if defined(SUPPORT_TP)
/* 2014/06/14, adamhsu, redmine 8530 (start) */
#include "linux/fiemap.h"
#include "tp_def.h"
/* 2014/06/14, adamhsu, redmine 8530 (end) */

#include "fbdisk.h"  // for threhold notification usage

#if defined(QNAP_HAL)
#include <qnap/hal_event.h>
extern int send_hal_netlink(NETLINK_EVT *event);
#endif
#endif
#endif /* defined(CONFIG_MACH_QNAPTS) */

#define IBLOCK_MAX_BIO_PER_TASK	 32	/* max # of bios to submit at a time */
#define IBLOCK_BIO_POOL_SIZE	128

#ifdef QNAP_SHARE_JOURNAL
extern int init_blkdev_journal(char *blkdev_name, char *lun_uuid);
extern int release_blkdev_journal(char *blkdev_name);
extern int blkdev_set_aops(struct block_device *bdev, unsigned long enable);
#endif

static struct se_subsystem_api iblock_template;

static void iblock_bio_done(struct bio *, int);

/*	iblock_attach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
static int iblock_attach_hba(struct se_hba *hba, u32 host_id)
{
	pr_debug("CORE_HBA[%d] - TCM iBlock HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		IBLOCK_VERSION, TARGET_CORE_MOD_VERSION);
	return 0;
}

static void iblock_detach_hba(struct se_hba *hba)
{
}

static void *iblock_allocate_virtdevice(struct se_hba *hba, const char *name)
{
	struct iblock_dev *ib_dev = NULL;

	ib_dev = kzalloc(sizeof(struct iblock_dev), GFP_KERNEL);
	if (!ib_dev) {
		pr_err("Unable to allocate struct iblock_dev\n");
		return NULL;
	}

	pr_debug( "IBLOCK: Allocated ib_dev for %s\n", name);

	return ib_dev;
}

static struct se_device *iblock_create_virtdevice(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	void *p)
{
	struct iblock_dev *ib_dev = p;
	struct se_device *dev;
	struct se_dev_limits dev_limits;
	struct block_device *bd = NULL;
	struct request_queue *q;
	struct queue_limits *limits;
	u32 dev_flags = 0;
	int ret = -EINVAL;
#ifdef CONFIG_MACH_QNAPTS   //Benjamin 20120822 for BUG 26582: snapshot lun cannot map into iSCSI target.      
    fmode_t mode, mode_all = FMODE_WRITE|FMODE_READ|FMODE_EXCL;
#endif

	if (!ib_dev) {
		pr_err("Unable to locate struct iblock_dev parameter\n");
		return ERR_PTR(ret);
	}
	memset(&dev_limits, 0, sizeof(struct se_dev_limits));

	ib_dev->ibd_bio_set = bioset_create(IBLOCK_BIO_POOL_SIZE, 0);
	if (!ib_dev->ibd_bio_set) {
		pr_err("IBLOCK: Unable to create bioset()\n");
		return ERR_PTR(-ENOMEM);
	}
	pr_debug("IBLOCK: Created bio_set()\n");
	/*
	 * iblock_check_configfs_dev_params() ensures that ib_dev->ibd_udev_path
	 * must already have been set in order for echo 1 > $HBA/$DEV/enable to run.
	 */
	pr_debug( "IBLOCK: Claiming struct block_device: %s\n",
			ib_dev->ibd_udev_path);

#ifdef CONFIG_MACH_QNAPTS   //Benjamin 20120822 for BUG 26582: snapshot lun cannot map into iSCSI target.      
	bd = lookup_bdev(ib_dev->ibd_udev_path);
	if (IS_ERR(bd)) {
		ret = PTR_ERR(bd);
		pr_err("IBLOCK: Fail to lookup block device by %s, PTR_ERR=%d.\n", 
		        ib_dev->ibd_udev_path, ret);
		goto failed;
    }

  	ret = blkdev_get(bd, mode_all, ib_dev);
	if (ret) {
		pr_err("IBLOCK: Fail to get block device, PTR_ERR=%d.\n", ret);
		goto failed;            
    }

    mode = (bdev_read_only(bd) ? 0 : FMODE_WRITE) | FMODE_READ | FMODE_EXCL;
    
	pr_debug("IBLOCK: Succeed to lookup block device by %s with mode 0x%x.\n", 
	         ib_dev->ibd_udev_path, mode);
    //Must call blkdev_put() after bdev_read_only().
    blkdev_put(bd, mode_all);  

	bd = blkdev_get_by_path(ib_dev->ibd_udev_path, mode, ib_dev);
#else
	bd = blkdev_get_by_path(ib_dev->ibd_udev_path,
				FMODE_WRITE|FMODE_READ|FMODE_EXCL, ib_dev);
#endif
    
	if (IS_ERR(bd)) {
		ret = PTR_ERR(bd);
#ifdef CONFIG_MACH_QNAPTS   //Benjamin 20120821 for debug.      
		pr_err("IBLOCK: Fail to get block device by %s, PTR_ERR=%d.\n", 
		        ib_dev->ibd_udev_path, ret);
#endif        
		goto failed;
	}
	/*
	 * Setup the local scope queue_limits from struct request_queue->limits
	 * to pass into transport_add_device_to_core_hba() as struct se_dev_limits.
	 */
	q = bdev_get_queue(bd);
	limits = &dev_limits.limits;

#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_LOGICAL_BLOCK_4KB_FROM_NAS_GUI)
    /* adamhsu 2013/06/07 - Support to set the logical block size from NAS GUI. */
    if ((se_dev->su_dev_flags & SDF_USING_QLBS) && se_dev->se_dev_qlbs)
        limits->logical_block_size = (unsigned short)se_dev->se_dev_qlbs;
    else
#endif
        limits->logical_block_size = bdev_logical_block_size(bd);

	limits->max_hw_sectors = queue_max_hw_sectors(bdev_get_queue(bd));
	limits->max_sectors = queue_max_sectors(bdev_get_queue(bd));
	dev_limits.hw_queue_depth = q->nr_requests;
	dev_limits.queue_depth = q->nr_requests;

	ib_dev->ibd_bd = bd;

#ifdef CONFIG_MACH_QNAPTS   // "IBLOCK" --> "iSCSI Storage" 
	dev = transport_add_device_to_core_hba(hba,
			&iblock_template, se_dev, dev_flags, ib_dev,
			&dev_limits, "iSCSI Storage", IBLOCK_VERSION);
#else
	dev = transport_add_device_to_core_hba(hba,
			&iblock_template, se_dev, dev_flags, ib_dev,
			&dev_limits, "IBLOCK", IBLOCK_VERSION);
#endif 
    
	if (!dev)
		goto failed;

	/*
	 * Check if the underlying struct block_device request_queue supports
	 * the QUEUE_FLAG_DISCARD bit for UNMAP/WRITE_SAME in SCSI + TRIM
	 * in ATA and we need to set TPE=1
	 */
#if defined(CONFIG_MACH_QNAPTS)
#if defined(SUPPORT_TP)
	if(!strcmp(dev->se_sub_dev->se_dev_provision, "thin"))
		dev->se_sub_dev->se_dev_attrib.emulate_tpu = 1;

	if (blk_queue_discard(q)) {
		dev->se_sub_dev->se_dev_attrib.max_unmap_lba_count =
				q->limits.max_discard_sectors;

		dev->se_sub_dev->se_dev_attrib.max_unmap_block_desc_count = MAX_UNMAP_DESC_COUNT;
		dev->se_sub_dev->se_dev_attrib.unmap_granularity =
				q->limits.discard_granularity >> 9;
		dev->se_sub_dev->se_dev_attrib.unmap_granularity_alignment =
				q->limits.discard_alignment;

		pr_debug("IBLOCK: BLOCK Discard support available,"
				" disabled by default\n");
	}


#endif
#endif

	if (blk_queue_nonrot(q))
		dev->se_sub_dev->se_dev_attrib.is_nonrot = 1;

	return dev;

failed:
	if (ib_dev->ibd_bio_set) {
		bioset_free(ib_dev->ibd_bio_set);
		ib_dev->ibd_bio_set = NULL;
	}
	ib_dev->ibd_bd = NULL;
	return ERR_PTR(ret);
}

static void iblock_free_device(void *p)
{
	struct iblock_dev *ib_dev = p;
#ifdef QNAP_SHARE_JOURNAL
	struct block_device *bdev = ib_dev->ibd_bd;
	struct file *file = container_of(bdev->bd_inode->i_mapping, struct file,
					 f_mapping);
	int err = 0;

	if (file->f_mode & FMODE_JOURNAL_SUPPORT) {
		pr_info("[BLKJBD] disable journal support when release.\n");
		err = release_blkdev_journal(ib_dev->ibd_udev_path);
		if (err) {
			pr_info("[BLKJBD] %s: release_blkdev_journal failed.\n",
				__func__);
			file->f_mode |= FMODE_JOURNAL_SUPPORT;
		}
	}
#endif
	if (ib_dev->ibd_bd != NULL)
		blkdev_put(ib_dev->ibd_bd, FMODE_WRITE|FMODE_READ|FMODE_EXCL);
	if (ib_dev->ibd_bio_set != NULL)
		bioset_free(ib_dev->ibd_bio_set);
	kfree(ib_dev);
}

static inline struct iblock_req *IBLOCK_REQ(struct se_task *task)
{
	return container_of(task, struct iblock_req, ib_task);
}

static struct se_task *
iblock_alloc_task(unsigned char *cdb)
{
	struct iblock_req *ib_req;

	ib_req = kzalloc(sizeof(struct iblock_req), GFP_KERNEL);
	if (!ib_req) {
		pr_err("Unable to allocate memory for struct iblock_req\n");
		return NULL;
	}

	atomic_set(&ib_req->pending, 1);
	return &ib_req->ib_task;
}

static unsigned long long iblock_emulate_read_cap_with_block_size(
	struct se_device *dev,
	struct block_device *bd,
	struct request_queue *q)
{

#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_LOGICAL_BLOCK_4KB_FROM_NAS_GUI)
    /* adamhsu 2013/06/07 - Support to set the logical block size from NAS GUI. */
	unsigned long long blocks_long = 0;
	u32 block_size = 0;

    if ((dev->se_sub_dev->su_dev_flags & SDF_USING_QLBS) && dev->se_sub_dev->se_dev_qlbs){
        blocks_long = (div_u64(i_size_read(bd->bd_inode), dev->se_sub_dev->se_dev_qlbs) - 1);
        block_size = dev->se_sub_dev->se_dev_qlbs;
    }else{
        blocks_long = (div_u64(i_size_read(bd->bd_inode), bdev_logical_block_size(bd)) - 1);
        block_size = bdev_logical_block_size(bd);
    }
#else
	unsigned long long blocks_long = (div_u64(i_size_read(bd->bd_inode),
					bdev_logical_block_size(bd)) - 1);
	u32 block_size = bdev_logical_block_size(bd);
#endif

	if (block_size == dev->se_sub_dev->se_dev_attrib.block_size)
		return blocks_long;

	switch (block_size) {
	case 4096:
		switch (dev->se_sub_dev->se_dev_attrib.block_size) {
		case 2048:
			blocks_long <<= 1;
			break;
		case 1024:
			blocks_long <<= 2;
			break;
		case 512:
			blocks_long <<= 3;
		default:
			break;
		}
		break;
	case 2048:
		switch (dev->se_sub_dev->se_dev_attrib.block_size) {
		case 4096:
			blocks_long >>= 1;
			break;
		case 1024:
			blocks_long <<= 1;
			break;
		case 512:
			blocks_long <<= 2;
			break;
		default:
			break;
		}
		break;
	case 1024:
		switch (dev->se_sub_dev->se_dev_attrib.block_size) {
		case 4096:
			blocks_long >>= 2;
			break;
		case 2048:
			blocks_long >>= 1;
			break;
		case 512:
			blocks_long <<= 1;
			break;
		default:
			break;
		}
		break;
	case 512:
		switch (dev->se_sub_dev->se_dev_attrib.block_size) {
		case 4096:
			blocks_long >>= 3;
			break;
		case 2048:
			blocks_long >>= 2;
			break;
		case 1024:
			blocks_long >>= 1;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return blocks_long;
}

static void iblock_end_io_flush(struct bio *bio, int err)
{
	struct se_cmd *cmd = bio->bi_private;

	if (err)
		pr_err("IBLOCK: cache flush failed: %d\n", err);

	if (cmd)
		transport_complete_sync_cache(cmd, err == 0);
	bio_put(bio);
}

/*
 * Implement SYCHRONIZE CACHE.  Note that we can't handle lba ranges and must
 * always flush the whole cache.
 */
static void iblock_emulate_sync_cache(struct se_task *task)
{
	struct se_cmd *cmd = task->task_se_cmd;
	struct iblock_dev *ib_dev = cmd->se_dev->dev_ptr;
	int immed = (cmd->t_task_cdb[1] & 0x2);
	struct bio *bio;

	/*
	 * If the Immediate bit is set, queue up the GOOD response
	 * for this SYNCHRONIZE_CACHE op.
	 */
	if (immed)
		transport_complete_sync_cache(cmd, 1);

	bio = bio_alloc(GFP_KERNEL, 0);
	bio->bi_end_io = iblock_end_io_flush;
	bio->bi_bdev = ib_dev->ibd_bd;
	if (!immed)
		bio->bi_private = cmd;
	submit_bio(WRITE_FLUSH, bio);
}

#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_TP)
struct fbdisk_file* _fbdisk_get_fbdisk_file(
	struct fbdisk_device *pfbd, 
	sector_t startlba, 
	u32 *pu32backingfileindex
	)
{
	u32 u32index = 0;
	struct fbdisk_file *pfbf = NULL;

	if ((pfbd == NULL) ||(pu32backingfileindex == NULL))
		BUG_ON(1);

	for (u32index = 0; u32index < (pfbd->fb_file_num); u32index++){
		pfbf = &pfbd->fb_backing_files_ary[u32index];

		if (((startlba >= pfbf->fb_start_sector) && (startlba < pfbf->fb_end_sector))
		|| ((startlba >  pfbf->fb_start_sector) && (startlba <= pfbf->fb_end_sector) ) ){
			pfbf = &pfbd->fb_backing_files_ary[u32index];
			break;
		}
	}

	if (pfbf){
		*pu32backingfileindex = u32index;
	}

	return pfbf;
}

struct fbdisk_file* _fbdisk_get_fbdisk_file2(
	struct fbdisk_device *pfbd, 
	u32 pu32backingfileindex
	)
{
	struct fbdisk_file *pfbf = NULL;

	if ( pfbd == NULL )
		BUG_ON(1);

	pfbf = &pfbd->fb_backing_files_ary[pu32backingfileindex];

	return pfbf;
}

/* 2014/06/14, adamhsu, redmine 8530 (start) */
int __iblock_get_lba_map_status(
	struct se_cmd *se_cmd,
	sector_t start_lba,
	u32 desc_count,
	u8 *param,
	int *err
	)
{
#define SIZE_ORDER	20

	LIO_SE_DEVICE *se_dev = se_cmd->se_dev;
	LIO_IBLOCK_DEV *ib_dev = NULL;
	struct block_device *bd = NULL;
	struct fbdisk_device *fb_dev = NULL;
	struct fbdisk_file *fb_file = NULL;
	u32 idx, count = desc_count;
	int ret;
	LBA_STATUS_DESC *desc = NULL;

	/**/
	desc = kzalloc((count * sizeof(LBA_STATUS_DESC)), GFP_KERNEL);
	if (!desc){
		*err = (int)ERR_OUT_OF_RESOURCES;
		ret = -ENOMEM;
		goto _EXIT_;
	}

	ib_dev = (LIO_IBLOCK_DEV *)(se_dev->dev_ptr);
	bd = ib_dev->ibd_bd;

	/* we only handle fbdisk device for blk i/o ... */
	if (strncmp(bd->bd_disk->disk_name, "fbdisk", 6)){
		*err = (int)ERR_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		ret = -ENODEV;
		goto _EXIT_;
	}		

	fb_dev = (struct fbdisk_device *)bd->bd_disk->private_data;
	fb_file = _fbdisk_get_fbdisk_file(fb_dev, start_lba, &idx);
	if (!fb_file){
		*err = (int)ERR_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		ret = -ENODEV;
		goto _EXIT_;
	}		

	ret = __get_file_lba_map_status(se_dev, bd, 
			fb_file->fb_backing_file->f_mapping->host,
			start_lba, &count, (u8 *)desc);

	if (ret != 0){
		pr_err("%s - ret:%d, after exec "
			"__get_file_lba_map_status()\n", __FUNCTION__, ret);

		*err = (int)ERR_UNKNOWN_SAM_OPCODE;
	} else {
		/* update the lba status descriptor */
		memcpy(&param[8], (u8 *)desc,
			(count* sizeof(LBA_STATUS_DESC)));

		/* to update PARAMETER DATA LENGTH finally */
		count = ((count << 4) + 4);
		put_unaligned_be32(count, &param[0]);
	}

_EXIT_:
	if (desc)
		kfree(desc);

	return ret;

}
#endif

#if defined(CONFIG_MACH_QNAPTS)
/* 20140626, adamhsu, redmine 8745,8777,8778 */
static int iblock_do_discard(struct se_cmd *se_cmd, sector_t lba, u32 range)
{
	struct se_device *se_dev = se_cmd->se_dev;
	struct iblock_dev *ibd = se_dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	int barrier = 0, bs_order, ret;

	bs_order = ilog2(se_dev->se_sub_dev->se_dev_attrib.block_size);

#if defined(SUPPORT_LOGICAL_BLOCK_4KB_FROM_NAS_GUI)
	/* here needs to depend on the logical blick size to convert value */
	ret = __blkio_transfer_task_lba_to_block_lba((1 << bs_order), &lba);
	if (ret != 0){
		__set_err_reason(ERR_LOGICAL_UNIT_COMMUNICATION_FAILURE, 
			&se_cmd->scsi_sense_reason);
		return -EINVAL;
	}    
	range *= ((1 << bs_order) >> 9);
#endif

	ret = blkdev_issue_discard(bd, lba, range, GFP_KERNEL, barrier);
	if (ret != 0){
		if (ret == -ENOSPC)
			__set_err_reason(ERR_NO_SPACE_WRITE_PROTECT, 
				&se_cmd->scsi_sense_reason);
		else if (ret == -ENOMEM)
			__set_err_reason(ERR_OUT_OF_RESOURCES, 
				&se_cmd->scsi_sense_reason);
		else
			__set_err_reason(ERR_LOGICAL_UNIT_COMMUNICATION_FAILURE, 
				&se_cmd->scsi_sense_reason);
	}
	return ret;
}

#else /* !defined(CONFIG_MACH_QNAPTS) */
static int iblock_do_discard(struct se_device *dev, sector_t lba, u32 range)
{
	struct iblock_dev *ibd = dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	int barrier = 0;

	return blkdev_issue_discard(bd, lba, range, GFP_KERNEL, barrier);
}
#endif

static void iblock_free_task(struct se_task *task)
{
	kfree(IBLOCK_REQ(task));
}

enum {
	Opt_udev_path, Opt_force, Opt_err
};

static match_table_t tokens = {
	{Opt_udev_path, "udev_path=%s"},
	{Opt_force, "force=%d"},
	{Opt_err, NULL}
};

static ssize_t iblock_set_configfs_dev_params(struct se_hba *hba,
					       struct se_subsystem_dev *se_dev,
					       const char *page, ssize_t count)
{
	struct iblock_dev *ib_dev = se_dev->se_dev_su_ptr;
	char *orig, *ptr, *opts;
	substring_t args[MAX_OPT_ARGS];
	int ret = 0, token;

	opts = kstrdup(page, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;

	orig = opts;

	while ((ptr = strsep(&opts, ",\n")) != NULL) {
		if (!*ptr)
			continue;

		token = match_token(ptr, tokens, args);
		switch (token) {
		case Opt_udev_path:
			if (ib_dev->ibd_bd) {
				pr_err("Unable to set udev_path= while"
					" ib_dev->ibd_bd exists\n");
				ret = -EEXIST;
				goto out;
			}
			if (match_strlcpy(ib_dev->ibd_udev_path, &args[0],
				SE_UDEV_PATH_LEN) == 0) {
				ret = -EINVAL;
				break;
			}                                
			pr_debug("IBLOCK: Referencing UDEV path: %s\n",
					ib_dev->ibd_udev_path);
			ib_dev->ibd_flags |= IBDF_HAS_UDEV_PATH;
			break;
		case Opt_force:
			break;
		default:
			break;
		}
	}

out:
	kfree(orig);
	return (!ret) ? count : ret;
}

static ssize_t iblock_check_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev)
{
	struct iblock_dev *ibd = se_dev->se_dev_su_ptr;

	if (!(ibd->ibd_flags & IBDF_HAS_UDEV_PATH)) {
		pr_err("Missing udev_path= parameters for IBLOCK\n");
		return -EINVAL;
	}

	return 0;
}

static ssize_t iblock_show_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	char *b)
{
	struct iblock_dev *ibd = se_dev->se_dev_su_ptr;
	struct block_device *bd = ibd->ibd_bd;
	char buf[BDEVNAME_SIZE];
	ssize_t bl = 0;

	if (bd)
		bl += sprintf(b + bl, "iBlock device: %s",
				bdevname(bd, buf));
	if (ibd->ibd_flags & IBDF_HAS_UDEV_PATH) {
		bl += sprintf(b + bl, "  UDEV PATH: %s\n",
				ibd->ibd_udev_path);
	} else
		bl += sprintf(b + bl, "\n");

	bl += sprintf(b + bl, "        ");
	if (bd) {
		bl += sprintf(b + bl, "Major: %d Minor: %d  %s\n",
			MAJOR(bd->bd_dev), MINOR(bd->bd_dev), (!bd->bd_contains) ?
			"" : (bd->bd_holder == ibd) ?
			"CLAIMED: IBLOCK" : "CLAIMED: OS");
	} else {
		bl += sprintf(b + bl, "Major: 0 Minor: 0\n");
	}

	return bl;
}

#if (LINUX_VERSION_CODE == KERNEL_VERSION(3,2,26)) || (LINUX_VERSION_CODE == KERNEL_VERSION(3,4,6))
static void iblock_bio_destructor(struct bio *bio)
{
	struct se_task *task = bio->bi_private;
	struct iblock_dev *ib_dev = task->task_se_cmd->se_dev->dev_ptr;

	bio_free(bio, ib_dev->ibd_bio_set);
}
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,10,20)) || (LINUX_VERSION_CODE == KERNEL_VERSION(3,12,6))
#else
#error "Ooo.. what kernel version do you compile ??"
#endif

static struct bio *
iblock_get_bio(struct se_task *task, sector_t lba, u32 sg_num)
{
	struct iblock_dev *ib_dev = task->task_se_cmd->se_dev->dev_ptr;
	struct iblock_req *ib_req = IBLOCK_REQ(task);
	struct bio *bio;

	/*
	 * Only allocate as many vector entries as the bio code allows us to,
	 * we'll loop later on until we have handled the whole request.
	 */
	if (sg_num > BIO_MAX_PAGES)
		sg_num = BIO_MAX_PAGES;

	bio = bio_alloc_bioset(GFP_NOIO, sg_num, ib_dev->ibd_bio_set);
	if (!bio) {
		pr_err("Unable to allocate memory for bio\n");
		return NULL;
	}

	pr_debug("Allocated bio: %p task_sg_nents: %u using ibd_bio_set:"
		" %p\n", bio, task->task_sg_nents, ib_dev->ibd_bio_set);
	pr_debug("Allocated bio: %p task_size: %u\n", bio, task->task_size);

	bio->bi_bdev = ib_dev->ibd_bd;
	bio->bi_private = task;

#if (LINUX_VERSION_CODE == KERNEL_VERSION(3,2,26)) || (LINUX_VERSION_CODE == KERNEL_VERSION(3,4,6))
	bio->bi_destructor = iblock_bio_destructor;
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,10,20)) || (LINUX_VERSION_CODE == KERNEL_VERSION(3,12,6))
#else
#error "Ooo.. what kernel version do you compile ??"
#endif

	bio->bi_end_io = &iblock_bio_done;
	bio->bi_sector = lba;
	atomic_inc(&ib_req->pending);

	pr_debug("Set bio->bi_sector: %llu\n", (unsigned long long)bio->bi_sector);
	pr_debug("Set ib_req->pending: %d\n", atomic_read(&ib_req->pending));
	return bio;
}

static void iblock_submit_bios(struct bio_list *list, int rw)
{
	struct blk_plug plug;
	struct bio *bio;

	blk_start_plug(&plug);
	while ((bio = bio_list_pop(list)))
		submit_bio(rw, bio);
	blk_finish_plug(&plug);
}

static int iblock_do_task(struct se_task *task)
{
	struct se_cmd *cmd = task->task_se_cmd;
	struct se_device *dev = cmd->se_dev;
	struct iblock_req *ibr = IBLOCK_REQ(task);
	struct bio *bio;
	struct bio_list list;
	struct scatterlist *sg;
	u32 i, sg_num = task->task_sg_nents;
	sector_t block_lba;
	unsigned bio_cnt;
	int rw;

	/* for threshold notification usage */
#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_TP)
	struct iblock_dev *ibd = dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	struct fbdisk_device *pfbdev = NULL;
	struct fbdisk_file *pfbfile = NULL;
	struct inode *pInode = NULL;
	/* Jonathan Ho, 20141124, use threshold_max to avoid inaccuracy */
	unsigned long threshold_max;
	loff_t total = 0, used = 0;

#if defined(QNAP_HAL)
	NETLINK_EVT hal_event;
#endif
	
#endif	

#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_TP)
	unsigned long long blocks = dev->transport->get_blocks(dev);

	/* For run-time capacity change warning */
	if(!strcmp(dev->se_sub_dev->se_dev_provision, "thin")){ // only checking when thin-lun
		if ( dev->se_sub_dev->se_dev_attrib.lun_blocks != blocks ){
			dev->se_sub_dev->se_dev_attrib.lun_blocks = blocks;
			cmd->scsi_sense_reason = TCM_CAPACITY_DATA_HAS_CHANGED;
			return -ENOSYS;
		}
	}
#endif

	if (task->task_data_direction == DMA_TO_DEVICE) {
		/*
		 * Force data to disk if we pretend to not have a volatile
		 * write cache, or the initiator set the Force Unit Access bit.
		 */
		if (dev->se_sub_dev->se_dev_attrib.emulate_write_cache == 0 ||
		    (dev->se_sub_dev->se_dev_attrib.emulate_fua_write > 0 &&
		     (cmd->se_cmd_flags & SCF_FUA)))
			rw = WRITE_FUA;
		else
			rw = WRITE;
	} else {
		rw = READ;
	}

	/*
	 * Do starting conversion up from non 512-byte blocksize with
	 * struct se_task SCSI blocksize into Linux/Block 512 units for BIO.
	 */
	if (dev->se_sub_dev->se_dev_attrib.block_size == 4096)
		block_lba = (task->task_lba << 3);
	else if (dev->se_sub_dev->se_dev_attrib.block_size == 2048)
		block_lba = (task->task_lba << 2);
	else if (dev->se_sub_dev->se_dev_attrib.block_size == 1024)
		block_lba = (task->task_lba << 1);
	else if (dev->se_sub_dev->se_dev_attrib.block_size == 512)
		block_lba = task->task_lba;
	else {
		pr_err("Unsupported SCSI -> BLOCK LBA conversion:"
				" %u\n", dev->se_sub_dev->se_dev_attrib.block_size);
		cmd->scsi_sense_reason = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		return -ENOSYS;
	}

#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_TP)

	/* Calculate the total and allocated capacity */
	if (rw){
			pfbdev = bd->bd_disk->private_data;
			for ( i = 0; i < pfbdev->fb_file_num; i++ ){ // link all fbdisk files
				pfbfile = _fbdisk_get_fbdisk_file2(pfbdev, i);
				pInode = pfbfile->fb_backing_file->f_mapping->host;
				
				total += pInode->i_size;
				used += pInode->i_blocks;
			}

	}

	/* check capacity threshold reached or not */
    	if(!strcmp(dev->se_sub_dev->se_dev_provision, "thin")){ // only checking when thin-lun

#if defined(QNAP_HAL)
		memset(&hal_event, 0, sizeof(NETLINK_EVT));
		hal_event.type = HAL_EVENT_ISCSI;
#endif			

		if (rw){
			/* Here to use div_u64() to make 64 bit division to 
			 * avoid this code will be fail to build with 32bit
			 * compiler environment
			 */
			/* Jonathan Ho, 20141124, use "threshold_max" to avoid inaccuracy */
			threshold_max = \
				div_u64((total * dev->se_sub_dev->se_dev_attrib.tp_threshold_percent), 
				100);

			threshold_max += \
				(((1 << dev->se_sub_dev->se_dev_attrib.tp_threshold_set_size) >> 1) * 512);

#if 0			/* move to function of iblock_update_allocated() */
			/* calculate used and available resource count */
			dev->se_sub_dev->se_dev_attrib.allocated = used * 512;
#endif
			dev->se_sub_dev->se_dev_attrib.used = \
				(u32)div_u64((u64)(used * 512), 
				((1 << (dev->se_sub_dev->se_dev_attrib.tp_threshold_set_size)) *512));

			dev->se_sub_dev->se_dev_attrib.avail = \
				(u32)div_u64((u64)((total - (used * 512))), 
				((1 << (dev->se_sub_dev->se_dev_attrib.tp_threshold_set_size)) * 512));

			/* Jonathan Ho, 20141124, use "threshold_max" to avoid inaccuracy */
			if ( (used * 512) > threshold_max){
				if ( !dev->se_sub_dev->se_dev_attrib.tp_threshold_hit ){

					dev->se_sub_dev->se_dev_attrib.tp_threshold_hit++;
					cmd->scsi_sense_reason = TCM_THIN_PROVISIONING_SOFT_THRESHOLD_REACHED;

#if defined(QNAP_HAL)
					hal_event.arg.action = HIT_LUN_THRESHOLD;
					hal_event.arg.param.iscsi_lun.lun_index = dev->se_sub_dev->se_dev_attrib.lun_index;
					hal_event.arg.param.iscsi_lun.tp_threshold = dev->se_sub_dev->se_dev_attrib.tp_threshold_percent;
					hal_event.arg.param.iscsi_lun.tp_avail = (total - used * 512) >> 30; //unit: GB
					send_hal_netlink(&hal_event);
#endif
					return -ENOSYS;
				}
			}
			else{
				dev->se_sub_dev->se_dev_attrib.tp_threshold_hit = 0;
			}
			
		}
   	}
#if 0	/* move to function of iblock_update_allocated() */
	else{ // thick LUN
		if (rw){
	          dev->se_sub_dev->se_dev_attrib.allocated = used * 512;
		}
			
	}
#endif
#endif /*(CONFIG_MACH_QNAPTS) && defined(SUPPORT_TP)*/

#ifdef QNAP_SHARE_JOURNAL
	if (is_journal_support(dev))
		rw |= REQ_QNAP_JOURNAL;
#endif

	bio = iblock_get_bio(task, block_lba, sg_num);
	if (!bio) {
		cmd->scsi_sense_reason = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		return -ENOMEM;
	}

	bio_list_init(&list);
	bio_list_add(&list, bio);
	bio_cnt = 1;

	for_each_sg(task->task_sg, sg, task->task_sg_nents, i) {
		/*
		 * XXX: if the length the device accepts is shorter than the
		 *	length of the S/G list entry this will cause and
		 *	endless loop.  Better hope no driver uses huge pages.
		 */
		while (bio_add_page(bio, sg_page(sg), sg->length, sg->offset)
				!= sg->length) {
			if (bio_cnt >= IBLOCK_MAX_BIO_PER_TASK) {
				iblock_submit_bios(&list, rw);
				bio_cnt = 0;
			}

			bio = iblock_get_bio(task, block_lba, sg_num);
			if (!bio)
				goto fail;
			bio_list_add(&list, bio);
			bio_cnt++;
		}

		/* Always in 512 byte units for Linux/Block */
		block_lba += sg->length >> IBLOCK_LBA_SHIFT;
		sg_num--;
	}

	iblock_submit_bios(&list, rw);

	if (atomic_dec_and_test(&ibr->pending)) {
		transport_complete_task(task,
				!atomic_read(&ibr->ib_bio_err_cnt));
	}
	return 0;

fail:
	while ((bio = bio_list_pop(&list)))
		bio_put(bio);
	cmd->scsi_sense_reason = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	return -ENOMEM;
}

static u32 iblock_get_device_rev(struct se_device *dev)
{
	return SCSI_SPC_2; /* Returns SPC-3 in Initiator Data */
}

static u32 iblock_get_device_type(struct se_device *dev)
{
	return TYPE_DISK;
}

static sector_t iblock_get_blocks(struct se_device *dev)
{
	struct iblock_dev *ibd = dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	struct request_queue *q = bdev_get_queue(bd);

	return iblock_emulate_read_cap_with_block_size(dev, bd, q);
}

static void iblock_bio_done(struct bio *bio, int err)
{
	struct se_task *task = bio->bi_private;
	struct iblock_req *ibr = IBLOCK_REQ(task);

	/*
	 * Set -EIO if !BIO_UPTODATE and the passed is still err=0
	 */
	if (!test_bit(BIO_UPTODATE, &bio->bi_flags) && !err)
		err = -EIO;

	if (err != 0) {
		pr_err("test_bit(BIO_UPTODATE) failed for bio: %p,"
			" err: %d\n", bio, err);
		/*
		 * Bump the ib_bio_err_cnt and release bio.
		 */
		atomic_inc(&ibr->ib_bio_err_cnt);
		smp_mb__after_atomic_inc();
		/* To check no space */
		if ( err == -ENOSPC )
			task->task_se_cmd->transport_state = CMD_T_NO_SPACE_IO_FAILED;		
	}

	bio_put(bio);

	if (!atomic_dec_and_test(&ibr->pending))
		return;

	pr_debug("done[%p] bio: %p task_lba: %llu bio_lba: %llu err=%d\n",
		 task, bio, task->task_lba,
		 (unsigned long long)bio->bi_sector, err);

	transport_complete_task(task, !atomic_read(&ibr->ib_bio_err_cnt));
}

#ifdef CONFIG_MACH_QNAPTS // 2010/12/13 Nike Chen, support online lun expansion
int iblock_change_dev_size(struct se_device *dev)
{
    int ret = 0;
    struct iblock_dev *ib_dev = dev->dev_ptr;
    struct block_device *bd = ib_dev->ibd_bd;

#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_LOGICAL_BLOCK_4KB_FROM_NAS_GUI)
    /* adamhsu 2013/06/07 - Support to set the logical block size from NAS GUI. */
	unsigned long long blocks_long = 0;
	u32 block_size = 0;

    if ((dev->se_sub_dev->su_dev_flags & SDF_USING_QLBS) && dev->se_sub_dev->se_dev_qlbs){
        blocks_long = (div_u64(i_size_read(bd->bd_inode), dev->se_sub_dev->se_dev_qlbs) - 1);
        block_size = dev->se_sub_dev->se_dev_qlbs;
    }else{
        blocks_long = (div_u64(i_size_read(bd->bd_inode), bdev_logical_block_size(bd)) - 1);
        block_size = bdev_logical_block_size(bd);
    }
#else
    unsigned long long blocks_long = (div_u64(i_size_read(bd->bd_inode),
                                      bdev_logical_block_size(bd)) - 1);
    u32 block_size = bdev_logical_block_size(bd);
#endif

    /*
        * Determine the number of bytes from i_size_read() minus
        * one (1) logical sector from underlying struct block_device
        */
//        fd_dev->fd_dev_size = (i_size_read(file->f_mapping->host) -
//                                bdev_logical_block_size(bd));
    /*
        * Benjamin 20120601: There is no dev->dev_sectors_total anymore.     
        * That's why I do not update the sector count (dev->dev_sectors_total) via READ_CAPACITY
        * As you can see, this function becomes dummy, I keep this function for symmetry only.
        */
    pr_debug("iBlock: Using size: %llu bytes from struct"
            " block_device blocks: %llu logical_block_size: %d\n",
            blocks_long * block_size, blocks_long,
            block_size);

        return ret;
}
#endif
#ifdef QNAP_SHARE_JOURNAL
static int iblock_set_journal_support(struct se_subsystem_dev *se_sub_dev,
				      unsigned long enable)
{
	struct iblock_dev *ibd = se_sub_dev->se_dev_su_ptr;
	struct block_device *bd = ibd->ibd_bd;
	struct file *file;
	char buf[BDEVNAME_SIZE];
	int err = 0;

	file = container_of(bd->bd_inode->i_mapping, struct file, f_mapping);

	if (enable) {
		pr_info("[BLKJBD] enable journal for file-based LUN\n");
		err = init_blkdev_journal(ibd->ibd_udev_path,
					  se_sub_dev->t10_wwn.unit_serial);
		if (err) {
			pr_info("[BLKJBD] %s: init_blkdev_journal failed\n",
				__func__);
		} else {
			file->f_mode |= FMODE_JOURNAL_SUPPORT;
			blkdev_set_aops(bd, 1);
		}
	} else {
		pr_info("[BLKJBD] disable journal support\n");
		blkdev_set_aops(bd, 0);
		file->f_mode &= ~FMODE_JOURNAL_SUPPORT;
		err = release_blkdev_journal(ibd->ibd_udev_path);
		if (err) {
			pr_info("[BLKJBD] %s: release_blkdev_journal failed\n",
				__func__);
			file->f_mode |= FMODE_JOURNAL_SUPPORT;
		}
	}

	return err;
}
#endif

static struct se_subsystem_api iblock_template = {
	.name			= "iblock",
	.owner			= THIS_MODULE,
	.transport_type		= TRANSPORT_PLUGIN_VHBA_PDEV,
	.write_cache_emulated	= 1,
	.fua_write_emulated	= 1,
	.attach_hba		= iblock_attach_hba,
	.detach_hba		= iblock_detach_hba,
	.allocate_virtdevice	= iblock_allocate_virtdevice,
	.create_virtdevice	= iblock_create_virtdevice,
	.free_device		= iblock_free_device,
	.alloc_task		= iblock_alloc_task,
	.do_task		= iblock_do_task,
	.do_discard		= iblock_do_discard,
	.do_sync_cache		= iblock_emulate_sync_cache,
	.free_task		= iblock_free_task,
	.check_configfs_dev_params = iblock_check_configfs_dev_params,
	.set_configfs_dev_params = iblock_set_configfs_dev_params,
	.show_configfs_dev_params = iblock_show_configfs_dev_params,
	.get_device_rev		= iblock_get_device_rev,
	.get_device_type	= iblock_get_device_type,
	.get_blocks		= iblock_get_blocks,
#ifdef CONFIG_MACH_QNAPTS // 2010/12/13 Nike Chen, support online lun expansion
    .change_dev_size    = iblock_change_dev_size,
#endif	

#if defined(CONFIG_MACH_QNAPTS)
#if defined(SUPPORT_VAAI)
	/* api for write same function */
	.do_prepare_ws_buffer       = do_prepare_ws_buffer,
	.do_check_before_ws         = do_check_before_ws,
	.do_check_ws_zero_buffer    = do_check_ws_zero_buffer,
	.do_ws_wo_unmap             = iblock_do_ws_wo_unmap,
	.do_ws_w_anchor             = iblock_do_ws_w_anchor,
	.do_ws_w_unmap              = iblock_do_ws_w_unmap,

	/* api for atomic test and set (ATS) function */
	.do_check_before_ats        = do_check_before_ats,
	.do_ats                     = iblock_do_ats,
#endif

#if defined(SUPPORT_TP)
/* 2014/06/14, adamhsu, redmine 8530 (start) */
	.do_get_lba_map_status = __iblock_get_lba_map_status,
/* 2014/06/14, adamhsu, redmine 8530 (end) */
#endif

#if defined(SUPPORT_TPC_CMD)
	/* api for 3rd-party ROD function */    
	.do_pt                  = iblock_do_populate_token,
	.do_chk_before_pt       = iblock_before_populate_token,
	.do_wrt                 = iblock_do_write_by_token,
	.do_wzrt                = iblock_do_write_by_zero_rod_token,
	.do_chk_before_wrt      = iblock_before_write_by_token,
	.do_receive_rt          = iblock_receive_rod_token,
#endif
#endif /* defined(CONFIG_MACH_QNAPTS) */
#ifdef QNAP_SHARE_JOURNAL
	.set_journal_support	= iblock_set_journal_support,
#endif
};

static int __init iblock_module_init(void)
{
	return transport_subsystem_register(&iblock_template);
}

static void iblock_module_exit(void)
{
	transport_subsystem_release(&iblock_template);
}

MODULE_DESCRIPTION("TCM IBLOCK subsystem plugin");
MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

module_init(iblock_module_init);
module_exit(iblock_module_exit);
