/*
 *  linux/fs/block_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2001  Andrea Arcangeli <andrea@suse.de> SuSE
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/device_cgroup.h>
#include <linux/highmem.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/blkpg.h>
#include <linux/magic.h>
#include <linux/buffer_head.h>
#include <linux/swap.h>
#include <linux/pagevec.h>
#include <linux/writeback.h>
#include <linux/mpage.h>
#include <linux/mount.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/log2.h>
#include <linux/cleancache.h>
#include <linux/aio.h>
#include <asm/uaccess.h>
#include "internal.h"

#ifdef QNAP_SHARE_JOURNAL
#include "blkdev_jbd2.h"
#include <linux/delay.h>
#endif

struct bdev_inode {
	struct block_device bdev;
	struct inode vfs_inode;
};

static const struct address_space_operations def_blk_aops;

#ifdef QNAP_SHARE_JOURNAL
static const struct address_space_operations def_blk_double_write_aops;
static DEFINE_MUTEX(g_blkdev_journal_init_mutex);
#endif

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
	return container_of(inode, struct bdev_inode, vfs_inode);
}

inline struct block_device *I_BDEV(struct inode *inode)
{
	return &BDEV_I(inode)->bdev;
}
EXPORT_SYMBOL(I_BDEV);

/*
 * Move the inode from its current bdi to a new bdi. If the inode is dirty we
 * need to move it onto the dirty list of @dst so that the inode is always on
 * the right list.
 */
static void bdev_inode_switch_bdi(struct inode *inode,
			struct backing_dev_info *dst)
{
	struct backing_dev_info *old = inode->i_data.backing_dev_info;
	bool wakeup_bdi = false;

	if (unlikely(dst == old))		/* deadlock avoidance */
		return;
	bdi_lock_two(&old->wb, &dst->wb);
	spin_lock(&inode->i_lock);
	inode->i_data.backing_dev_info = dst;
	if (inode->i_state & I_DIRTY) {
		if (bdi_cap_writeback_dirty(dst) && !wb_has_dirty_io(&dst->wb))
			wakeup_bdi = true;
		list_move(&inode->i_wb_list, &dst->wb.b_dirty);
	}
	spin_unlock(&inode->i_lock);
	spin_unlock(&old->wb.list_lock);
	spin_unlock(&dst->wb.list_lock);

	if (wakeup_bdi)
		bdi_wakeup_thread_delayed(dst);
}

/* Kill _all_ buffers and pagecache , dirty or not.. */
void kill_bdev(struct block_device *bdev)
{
	struct address_space *mapping = bdev->bd_inode->i_mapping;

	if (mapping->nrpages == 0)
		return;

	invalidate_bh_lrus();
	truncate_inode_pages(mapping, 0);
}	
EXPORT_SYMBOL(kill_bdev);

/* Invalidate clean unused buffers and pagecache. */
void invalidate_bdev(struct block_device *bdev)
{
	struct address_space *mapping = bdev->bd_inode->i_mapping;

	if (mapping->nrpages == 0)
		return;

	invalidate_bh_lrus();
	lru_add_drain_all();	/* make sure all lru add caches are flushed */
	invalidate_mapping_pages(mapping, 0, -1);
	/* 99% of the time, we don't need to flush the cleancache on the bdev.
	 * But, for the strange corners, lets be cautious
	 */
	cleancache_invalidate_inode(mapping);
}
EXPORT_SYMBOL(invalidate_bdev);

int set_blocksize(struct block_device *bdev, int size)
{
	/* Size must be a power of two, and between 512 and PAGE_SIZE */
	if (size > PAGE_SIZE || size < 512 || !is_power_of_2(size))
		return -EINVAL;

	/* Size cannot be smaller than the size supported by the device */
	if (size < bdev_logical_block_size(bdev))
		return -EINVAL;

	/* Don't change the size if it is same as current */
	if (bdev->bd_block_size != size) {
		sync_blockdev(bdev);
		bdev->bd_block_size = size;
		bdev->bd_inode->i_blkbits = blksize_bits(size);
		kill_bdev(bdev);
	}
	return 0;
}

EXPORT_SYMBOL(set_blocksize);

int sb_set_blocksize(struct super_block *sb, int size)
{
	if (set_blocksize(sb->s_bdev, size))
		return 0;
	/* If we get here, we know size is power of two
	 * and it's value is between 512 and PAGE_SIZE */
	sb->s_blocksize = size;
	sb->s_blocksize_bits = blksize_bits(size);
	return sb->s_blocksize;
}

EXPORT_SYMBOL(sb_set_blocksize);

int sb_min_blocksize(struct super_block *sb, int size)
{
	int minsize = bdev_logical_block_size(sb->s_bdev);
	if (size < minsize)
		size = minsize;
	return sb_set_blocksize(sb, size);
}
EXPORT_SYMBOL(sb_min_blocksize);

static int
blkdev_get_block(struct inode *inode, sector_t iblock,
		struct buffer_head *bh, int create)
{
	bh->b_bdev = I_BDEV(inode);
	bh->b_blocknr = iblock;
	set_buffer_mapped(bh);
	return 0;
}

static ssize_t
blkdev_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
			loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;

	return __blockdev_direct_IO(rw, iocb, inode, I_BDEV(inode), iov, offset,
				    nr_segs, blkdev_get_block, NULL, NULL, 0);
}

int __sync_blockdev(struct block_device *bdev, int wait)
{
	if (!bdev)
		return 0;
	if (!wait)
		return filemap_flush(bdev->bd_inode->i_mapping);
	return filemap_write_and_wait(bdev->bd_inode->i_mapping);
}

/*
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
	return __sync_blockdev(bdev, 1);
}
EXPORT_SYMBOL(sync_blockdev);

/*
 * Write out and wait upon all dirty data associated with this
 * device.   Filesystem data as well as the underlying block
 * device.  Takes the superblock lock.
 */
int fsync_bdev(struct block_device *bdev)
{
	struct super_block *sb = get_super(bdev);
	if (sb) {
		int res = sync_filesystem(sb);
		drop_super(sb);
		return res;
	}
	return sync_blockdev(bdev);
}
EXPORT_SYMBOL(fsync_bdev);

/**
 * freeze_bdev  --  lock a filesystem and force it into a consistent state
 * @bdev:	blockdevice to lock
 *
 * If a superblock is found on this device, we take the s_umount semaphore
 * on it to make sure nobody unmounts until the snapshot creation is done.
 * The reference counter (bd_fsfreeze_count) guarantees that only the last
 * unfreeze process can unfreeze the frozen filesystem actually when multiple
 * freeze requests arrive simultaneously. It counts up in freeze_bdev() and
 * count down in thaw_bdev(). When it becomes 0, thaw_bdev() will unfreeze
 * actually.
 */
struct super_block *freeze_bdev(struct block_device *bdev)
{
	struct super_block *sb;
	int error = 0;

	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (++bdev->bd_fsfreeze_count > 1) {
		/*
		 * We don't even need to grab a reference - the first call
		 * to freeze_bdev grab an active reference and only the last
		 * thaw_bdev drops it.
		 */
		sb = get_super(bdev);
		drop_super(sb);
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		return sb;
	}

	sb = get_active_super(bdev);
	if (!sb)
		goto out;
	error = freeze_super(sb);
	if (error) {
		deactivate_super(sb);
		bdev->bd_fsfreeze_count--;
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		return ERR_PTR(error);
	}
	deactivate_super(sb);
 out:
	sync_blockdev(bdev);
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	return sb;	/* thaw_bdev releases s->s_umount */
}
EXPORT_SYMBOL(freeze_bdev);

/**
 * thaw_bdev  -- unlock filesystem
 * @bdev:	blockdevice to unlock
 * @sb:		associated superblock
 *
 * Unlocks the filesystem and marks it writeable again after freeze_bdev().
 */
int thaw_bdev(struct block_device *bdev, struct super_block *sb)
{
	int error = -EINVAL;

	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (!bdev->bd_fsfreeze_count)
		goto out;

	error = 0;
	if (--bdev->bd_fsfreeze_count > 0)
		goto out;

	if (!sb)
		goto out;

	error = thaw_super(sb);
	if (error) {
		bdev->bd_fsfreeze_count++;
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		return error;
	}
out:
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	return 0;
}
EXPORT_SYMBOL(thaw_bdev);

static int blkdev_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, blkdev_get_block, wbc);
}

static int blkdev_readpage(struct file * file, struct page * page)
{
	return block_read_full_page(page, blkdev_get_block);
}

//George Wu, 20130629, blkdev_readpages
#ifdef CONFIG_MACH_QNAPTS
#ifdef USE_BLKDEV_READPAGES
static int blkdev_readpages(struct file *file, struct address_space *mapping,
                        struct list_head *pages, unsigned nr_pages)
{
        return mpage_readpages(mapping, pages, nr_pages, blkdev_get_block);
}
#endif
#endif

//George Wu, 20130721, blkdev_writepages
#ifdef CONFIG_MACH_QNAPTS
#ifdef USE_BLKDEV_WRITEPAGES
int blkdev_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
        return mpage_writepages(mapping, wbc, blkdev_get_block);
}
#endif
#endif

static int blkdev_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	return block_write_begin(mapping, pos, len, flags, pagep,
				 blkdev_get_block);
}

static int blkdev_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	int ret;
	ret = block_write_end(file, mapping, pos, len, copied, page, fsdata);

	unlock_page(page);
	page_cache_release(page);

	return ret;
}

/*
 * private llseek:
 * for a block special file file_inode(file)->i_size is zero
 * so we compute the size by hand (just as in block_read/write above)
 */
static loff_t block_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *bd_inode = file->f_mapping->host;
	loff_t retval;

	mutex_lock(&bd_inode->i_mutex);
	retval = fixed_size_llseek(file, offset, whence, i_size_read(bd_inode));
	mutex_unlock(&bd_inode->i_mutex);
	return retval;
}
	
int blkdev_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	struct inode *bd_inode = filp->f_mapping->host;
	struct block_device *bdev = I_BDEV(bd_inode);
	int error;
	
	error = filemap_write_and_wait_range(filp->f_mapping, start, end);
	if (error)
		return error;

	/*
	 * There is no need to serialise calls to blkdev_issue_flush with
	 * i_mutex and doing so causes performance issues with concurrent
	 * O_SYNC writers to a block device.
	 */
	error = blkdev_issue_flush(bdev, GFP_KERNEL, NULL);
	if (error == -EOPNOTSUPP)
		error = 0;

	return error;
}
EXPORT_SYMBOL(blkdev_fsync);

/*
 * pseudo-fs
 */

static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(bdev_lock);
static struct kmem_cache * bdev_cachep __read_mostly;

static struct inode *bdev_alloc_inode(struct super_block *sb)
{
	struct bdev_inode *ei = kmem_cache_alloc(bdev_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void bdev_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct bdev_inode *bdi = BDEV_I(inode);

	kmem_cache_free(bdev_cachep, bdi);
}

static void bdev_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, bdev_i_callback);
}

static void init_once(void *foo)
{
	struct bdev_inode *ei = (struct bdev_inode *) foo;
	struct block_device *bdev = &ei->bdev;

	memset(bdev, 0, sizeof(*bdev));
	mutex_init(&bdev->bd_mutex);
	INIT_LIST_HEAD(&bdev->bd_inodes);
	INIT_LIST_HEAD(&bdev->bd_list);
#ifdef CONFIG_SYSFS
	INIT_LIST_HEAD(&bdev->bd_holder_disks);
#endif
	inode_init_once(&ei->vfs_inode);
	/* Initialize mutex for freeze. */
	mutex_init(&bdev->bd_fsfreeze_mutex);
}

static inline void __bd_forget(struct inode *inode)
{
	list_del_init(&inode->i_devices);
	inode->i_bdev = NULL;
	inode->i_mapping = &inode->i_data;
}

static void bdev_evict_inode(struct inode *inode)
{
	struct block_device *bdev = &BDEV_I(inode)->bdev;
	struct list_head *p;
	truncate_inode_pages(&inode->i_data, 0);
	invalidate_inode_buffers(inode); /* is it needed here? */
	clear_inode(inode);
	spin_lock(&bdev_lock);
	while ( (p = bdev->bd_inodes.next) != &bdev->bd_inodes ) {
		__bd_forget(list_entry(p, struct inode, i_devices));
	}
	list_del_init(&bdev->bd_list);
	spin_unlock(&bdev_lock);
}

static const struct super_operations bdev_sops = {
	.statfs = simple_statfs,
	.alloc_inode = bdev_alloc_inode,
	.destroy_inode = bdev_destroy_inode,
	.drop_inode = generic_delete_inode,
	.evict_inode = bdev_evict_inode,
};

static struct dentry *bd_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_pseudo(fs_type, "bdev:", &bdev_sops, NULL, BDEVFS_MAGIC);
}

static struct file_system_type bd_type = {
	.name		= "bdev",
	.mount		= bd_mount,
	.kill_sb	= kill_anon_super,
};

static struct super_block *blockdev_superblock __read_mostly;

#ifdef QNAP_SHARE_JOURNAL
static void record_work_start(struct record *r)
{
	if (!r->record_applied) {
		r->start_jiffies = jiffies;
		r->record_applied = true;
	}
}

static void record_work_complete(struct record *r)
{
	unsigned long elapsed_jiffies;

	if (!r->record_applied)
		return;

	elapsed_jiffies = jiffies - r->start_jiffies;

	if (r->last_elapsed &&
	    elapsed_jiffies > r->last_elapsed * BLKDEV_RECORD_THRESHOLD) {
		r->nsec_to_delay += BLKDEV_RECORD_DELAY_INTERVAL;
		if (r->nsec_to_delay > BLKDEV_RECORD_DELAY_MAX_VALUE) {
			r->nsec_to_delay = BLKDEV_RECORD_DELAY_MAX_VALUE;
			pr_info("[BLKJBD] max %dns delay\n",
				BLKDEV_RECORD_DELAY_MAX_VALUE);
		}
		r->stable_count = 0;
		pr_info("[BLKJBD] add delay: %uns\n", r->nsec_to_delay);
	} else {
		r->stable_count++;
		if (r->stable_count > BLKDEV_RECORD_STABLE_COUNT &&
		    r->nsec_to_delay > 0) {
			r->nsec_to_delay -= BLKDEV_RECORD_DELAY_INTERVAL;
			pr_info("[BLKJBD] shorten delay: %uns\n",
				r->nsec_to_delay);
			r->stable_count = 0;
		}
	}
	r->last_elapsed = elapsed_jiffies;
	r->record_applied = false;
}

void blkdev_journal_do_checkpoint(journal_t *journal, tid_t seq,
				  unsigned long push_to_blocknr)
{
	struct j_lun_dev_s *j_lun_dev, *tmp;
	int err = 0;

	mutex_lock(&journal->j_checkpoint_mutex);
	mutex_lock(&journal->j_list_mutex);
	list_for_each_entry_safe(j_lun_dev, tmp,
				 &journal->j_lun_dev_list, list) {
		mutex_unlock(&journal->j_list_mutex);
		err = sync_blockdev(j_lun_dev->lun_blkdev);
		if (err)
			pr_err("[BLKJBD] %s: got sync_blockdev error.\n",
			       __func__);
		mutex_lock(&journal->j_list_mutex);
	}


	list_for_each_entry_safe(j_lun_dev, tmp,
				 &journal->j_lun_dev_list, list) {
		mutex_unlock(&journal->j_list_mutex);
		blkdev_issue_flush(j_lun_dev->lun_blkdev, GFP_KERNEL, NULL);
		if (err)
			pr_err("[BLKJBD] %s: got blkdev_issue_flush error.\n",
			       __func__);
		mutex_lock(&journal->j_list_mutex);
	}
	mutex_unlock(&journal->j_list_mutex);


	__jbd2_update_log_tail(journal, seq, push_to_blocknr);
	mutex_unlock(&journal->j_checkpoint_mutex);
}
EXPORT_SYMBOL(blkdev_journal_do_checkpoint);

static void blkdev_journal_flush_specific_block_device(journal_t *journal,
						       int index)
{
	struct j_lun_dev_s *j_lun_dev;

	mutex_lock(&journal->j_list_mutex);
	list_for_each_entry(j_lun_dev, &journal->j_lun_dev_list, list) {
		if (index == j_lun_dev->des_index) {
			mutex_unlock(&journal->j_list_mutex);
			sync_blockdev(j_lun_dev->lun_blkdev);
			blkdev_issue_flush(j_lun_dev->lun_blkdev,
					   GFP_KERNEL,
					   NULL);
			mutex_lock(&journal->j_list_mutex);
			break;
		}
	}
	mutex_unlock(&journal->j_list_mutex);
}

static int blkdev_journal_verify_next_log_blocknr(journal_t *journal,
						  int index)
{
	int i, checked_cnt = 0;
	int is_des_valid = 1;
	unsigned int next_blocknr = journal->j_head + 1;

	if (next_blocknr == journal->j_last)
		next_blocknr = journal->j_first;

	for (i=0; i<BLKDEV_MAX_JOURNAL_USER_NUM; i++) {
		unsigned int des_j_blocknr = journal->j_des_blocknr[i];

		if (!des_j_blocknr)
			continue;
		if (next_blocknr == des_j_blocknr) {
			if (i != index)
				spin_lock(&journal->j_des_lock[i]);
			blkdev_journal_flush_specific_block_device(journal, i);
			if (!journal->j_descriptor[i]) {
				brelse(journal->j_descriptor[i]);
				journal->j_descriptor[i] = NULL;
				journal->j_des_used_space[i] = 0;
				journal->j_des_blocknr[i] = 0;
			}
			if (i != index)
				spin_unlock(&journal->j_des_lock[i]);
			if (i == index)
				is_des_valid = 0;
			break;
		}
		if (++checked_cnt == journal->j_used_lun_nr)
			break;
	}

	return is_des_valid;
}

static int blkdev_journal_get_log_blocknr(journal_t *journal,
					  unsigned long long *p_blocknr,
					  int index)
{
	int is_valid;

retry_journal:
	write_lock(&journal->j_state_lock);
	if (journal->j_free < 1) {
		WARN_ONCE(1, "[BLKJBD] journal->j_free < 1\n");
		write_unlock(&journal->j_state_lock);
		wake_up(&journal->j_wait_commit);
		wait_event(journal->j_wait_done_commit,
			   (journal->j_free > 0));
		goto retry_journal;
	}
	*p_blocknr = journal->j_head;

	/* If the blocknr-to-be is used by other lun as a descriptor(partial),
	 * we need to hold the lun's descriptor lock, flush the block device
	 * and release his descritpor. */
	is_valid = blkdev_journal_verify_next_log_blocknr(journal, index);

	if (!is_valid)
		goto reallocate_des;

	journal->j_head += 1;
	if (journal->j_head == journal->j_last) {
		journal->j_head = journal->j_first;
	}

	journal->j_free -= 1;
	if (journal->j_head%journal->j_checkpoint_threshold == 0) {
		wake_up(&journal->j_wait_commit);
		record_work_complete(&journal->j_record);
	}

reallocate_des:
	write_unlock(&journal->j_state_lock);

	return is_valid;
}

static int blkdev_journal_find_descriptor_index(journal_t *journal,
			struct buffer_head *obh, unsigned char *uuid)
{
	int index = -1;
	struct j_lun_dev_s *j_lun_dev;

	dev_t target_dev = obh->b_bdev->bd_dev;
	mutex_lock(&journal->j_list_mutex);
	list_for_each_entry(j_lun_dev, &journal->j_lun_dev_list, list) {
		dev_t dev = j_lun_dev->lun_blkdev->bd_dev;
		if (dev == target_dev) {
			index = j_lun_dev->des_index;
			memcpy(uuid, j_lun_dev->lun_uuid, JBD2_UUID_LEN);
			break;
		}
	}
	mutex_unlock(&journal->j_list_mutex);

	return index;
}

static int blkdev_journal_get_descriptor_buffer(journal_t *journal, int index,
						unsigned char *uuid)
{
	struct buffer_head *des_bh;
	unsigned long long blocknr;
	journal_header_t *header;
	int used_space;

	des_bh = journal->j_descriptor[index];
	used_space = journal->j_des_used_space[index];
	if (des_bh) {
		if (used_space + BLKDEV_JOURNAL_TAG_SIZE64 <
		    journal->j_blocksize - BLKDEV_JOURNAL_DES_TAIL_SIZE) {
			get_bh(des_bh);
			return 0;
		} else {
			brelse(des_bh);
			des_bh = NULL;
		}
	}
	blkdev_journal_get_log_blocknr(journal, &blocknr, index);
	des_bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
	if (!des_bh) {
		pr_err("[BLKJBD] OOM in %s\n", __func__);
		journal->j_descriptor[index] = des_bh;
		return -ENOMEM;
	}
	lock_buffer(des_bh);
	get_bh(des_bh);
	used_space = 0;
	memset(des_bh->b_data, 0, journal->j_blocksize);
	/* a new descriptor needs header */
	header = (journal_header_t *)des_bh->b_data;
	header->h_magic = cpu_to_be32(JBD2_MAGIC_NUMBER);
	header->h_blocktype = cpu_to_be32(JBD2_DESCRIPTOR_BLOCK);
	write_lock(&journal->j_state_lock);
	header->h_sequence = cpu_to_be32(journal->j_transaction_sequence++);
	/* avoid overflow sequence */
	if (journal->j_transaction_sequence == (UINT_MAX-1))
		journal->j_transaction_sequence = 1;
	journal->j_des_blocknr[index] = blocknr;
	write_unlock(&journal->j_state_lock);
	used_space += sizeof(journal_header_t);
	/* copy uuid */
	memcpy(&des_bh->b_data[used_space], uuid, JBD2_UUID_LEN);
	used_space += JBD2_UUID_LEN;
	set_buffer_uptodate(des_bh);
	unlock_buffer(des_bh);
	journal->j_descriptor[index] = des_bh;
	journal->j_des_used_space[index] = used_space;

	return 0;
}

static int blkdev_journal_allocate_buffer(journal_t *journal,
					  struct buffer_head *ori_bh,
					  struct buffer_head **out_bh,
					  sector_t blocknr)
{
	int is_escape = 0;
	struct buffer_head *new_bh;
	struct page *new_page;
	char *mapped_data;
	unsigned int new_offset;

retry_alloc:
	new_bh = alloc_buffer_head(GFP_NOFS);
	if (!new_bh) {
		congestion_wait(BLK_RW_ASYNC, HZ/50);
		goto retry_alloc;
	}
	atomic_set(&new_bh->b_count, 1);

	new_page = ori_bh->b_page;
	new_offset = offset_in_page(ori_bh->b_data);

	mapped_data = kmap_atomic(new_page);
	if (*((__be32 *)(mapped_data + new_offset)) ==
	    cpu_to_be32(JBD2_MAGIC_NUMBER))
		is_escape = 1;
	kunmap_atomic(mapped_data);

	if (is_escape) {
		/* JBD2_MAGIC_NUMBER is found! We need to allocate a new
		 * page, copy data from original page to the new one, and 
		 * replace the begining 4 bytes of the page with zero. */
		char *tmp;

		tmp = jbd2_alloc(ori_bh->b_size, GFP_NOFS);
		if (!tmp) {
			brelse(new_bh);
			return -ENOMEM;
		}
		mapped_data = kmap_atomic(new_page);
		memcpy(tmp, mapped_data + new_offset, ori_bh->b_size);
		kunmap_atomic(mapped_data);
		new_page = virt_to_page(tmp);
		new_offset = offset_in_page(tmp);
		/* modify the newly-allocate page */
		mapped_data = kmap_atomic(new_page);
		*((unsigned int *)(mapped_data + new_offset)) = 0;
		kunmap_atomic(mapped_data);
	}
	set_bh_page(new_bh, new_page, new_offset);
	new_bh->b_size = ori_bh->b_size;
	new_bh->b_bdev = journal->j_dev;
	new_bh->b_blocknr = blocknr;
	new_bh->b_private = ori_bh;
	set_buffer_mapped(new_bh);
	set_buffer_dirty(new_bh);

	*out_bh = new_bh;

	return is_escape;
}

static void write_tag_block(blkdev_journal_block_tag_t *tag,
			    unsigned long long j_block,
			    unsigned long long lun_block)
{
	tag->t_j_blocknr = cpu_to_be32(j_block & (u32)~0);
	tag->t_blocknr = cpu_to_be32(lun_block & (u32)~0);
	tag->t_blocknr_high = cpu_to_be32((lun_block >> 31) >> 1);
}

static void blkdev_journal_block_tag_csum_set(journal_t *j,
					      blkdev_journal_block_tag_t *tag,
					      struct buffer_head *bh,
					      __u32 sequence)
{
	struct page *page = bh->b_page;
	__u8 *addr;
	__u32 csum32;
	__be32 seq;

	if (!jbd2_journal_has_csum_v2or3(j))
		return;

	seq = cpu_to_be32(sequence);
	addr = kmap_atomic(page);
	csum32 = jbd2_chksum(j, j->j_csum_seed, (__u8 *)&seq, sizeof(seq));
	csum32 = jbd2_chksum(j, csum32, addr + offset_in_page(bh->b_data),
			     bh->b_size);
	kunmap_atomic(addr);

	tag->t_checksum = cpu_to_be32(csum32);
}

static void blkdev_journal_descr_block_csum_set(journal_t *j,
						struct buffer_head *bh)
{
	struct jbd2_journal_block_tail *tail;
	__u32 csum;

	if (!jbd2_journal_has_csum_v2or3(j))
		return;

	tail = (struct jbd2_journal_block_tail *)(bh->b_data + j->j_blocksize -
			sizeof(struct jbd2_journal_block_tail));
	tail->t_checksum = 0;
	csum = jbd2_chksum(j, j->j_csum_seed, bh->b_data, j->j_blocksize);
	tail->t_checksum = cpu_to_be32(csum);
}

void blkdev_force_write_to_journal(struct page *page,
				   unsigned from, unsigned to)
{
	struct buffer_head *new_bh, *ori_bh, *des_bh, *head, *wbuf[2];
	unsigned block_start, block_end;
	unsigned blocksize;
	journal_t *journal = BLKDEV_SB(blockdev_superblock)->s_journal;
	int des_index;
	unsigned char lun_uuid[JBD2_UUID_LEN];
	int used_space;
	unsigned long long blocknr;
	struct blk_plug plug;
	char *tagp = NULL;
	int flags;
	int is_des_valid;
	int tag_flag;
	blkdev_journal_block_tag_t *tag = NULL;
	int tag_bytes = BLKDEV_JOURNAL_TAG_SIZE64;
	journal_header_t *header;
	int i, err = 0;

	ori_bh = head = page_buffers(page);
	blocksize = ori_bh->b_size;

	block_start = 0;
	blk_start_plug(&plug);
	do {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			pr_info("[BLKJBD] %s: Access out-of-boundary page\n",
				__func__);
			break;
		}
		/* find the right descriptor, and modify it */
		des_index = blkdev_journal_find_descriptor_index(journal,
								 ori_bh,
								 lun_uuid);
		if (des_index < 0) {
			pr_info("[BLKJBD] %s: The target lun doens't join"
				" journal support. No valid des_index found.\n",
				__func__);
			break;
		}
		spin_lock(&journal->j_des_lock[des_index]);
realloc_des_bh:
		err = blkdev_journal_get_descriptor_buffer(journal,
							   des_index,
							   lun_uuid);
		if (err) {
			spin_unlock(&journal->j_des_lock[des_index]);
			pr_info("[BLKJBD] %s: Get descriptor buffer failed.\n",
				__func__);
			break;
		}
		des_bh = journal->j_descriptor[des_index];
		header = (journal_header_t *)des_bh->b_data;
		used_space = journal->j_des_used_space[des_index];

		tagp = &des_bh->b_data[used_space];
		set_buffer_dirty(des_bh);
		wbuf[0] = des_bh;

		/* allocate a new block on journal */
		is_des_valid = blkdev_journal_get_log_blocknr(journal,
							      &blocknr,
							      des_index);
		if (!is_des_valid)
			goto realloc_des_bh;

		flags = blkdev_journal_allocate_buffer(journal, ori_bh,
						       &new_bh, blocknr);
		tag_flag = JBD2_FLAG_VALID_TAG;
		if (flags & 1)
			tag_flag |= JBD2_FLAG_ESCAPE;
		tag = (blkdev_journal_block_tag_t *)tagp;
		write_tag_block(tag, blocknr, ori_bh->b_blocknr);
		tag->t_flags = cpu_to_be16(tag_flag);
		blkdev_journal_block_tag_csum_set(journal, tag, new_bh,
					be32_to_cpu(header->h_sequence));
		blkdev_journal_descr_block_csum_set(journal, des_bh);

		/* update descriptor pointer position */
		used_space += tag_bytes;
		wbuf[1] = new_bh;
		/* write descriptor and data block */
		for (i=0; i<2; i++) {
			lock_buffer(wbuf[i]);
			clear_buffer_dirty(wbuf[i]);
			set_buffer_uptodate(wbuf[i]);
			wbuf[i]->b_end_io = end_buffer_write_sync;
			submit_bh(WRITE_FLUSH_FUA, wbuf[i]);
		}
		/* wait descriptor and data block */
		for (i=0; i<2; i++)
			wait_on_buffer(wbuf[i]);

		free_buffer_head(new_bh);

		block_start = block_end;
		ori_bh = ori_bh->b_this_page;
		journal->j_des_used_space[des_index] = used_space;
		spin_unlock(&journal->j_des_lock[des_index]);
	} while(ori_bh != head);
	blk_finish_plug(&plug);
}
EXPORT_SYMBOL(blkdev_force_write_to_journal);

static void blkdev_journal_check_log_left_space(journal_t *journal)
{
	int cur_user_nr;
retry_journal:
	write_lock(&journal->j_state_lock);
	cur_user_nr = journal->j_used_lun_nr;
	if (!journal->j_record.nsec_to_delay)
		ndelay(journal->j_record.nsec_to_delay);
	record_work_start(&journal->j_record);
	if (journal->j_free <= cur_user_nr * BLKDEV_MAX_SPLICE_WRITE_NUM) {
		/* there's few space left in the journal */
		write_unlock(&journal->j_state_lock);
		/* wake up checkpoint thread */
		wake_up(&journal->j_wait_commit);
		wait_event(journal->j_wait_done_commit,
			   (journal->j_free >
			    cur_user_nr * BLKDEV_MAX_SPLICE_WRITE_NUM));
		goto retry_journal;
	}
	write_unlock(&journal->j_state_lock);
}

static void blkdev_journal_check_barrier(journal_t *journal)
{
	read_lock(&journal->j_state_lock);
	if (journal->j_barrier_count) {
		pr_info("[BLKJBD] %s start, j_barrier_count: %d\n",
			__func__, journal->j_barrier_count);
		read_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_transaction_locked,
			   journal->j_barrier_count == 0);
		pr_info("[BLKJBD] %s end\n", __func__);
		goto out;
	}
	read_unlock(&journal->j_state_lock);
out:
	return;
}

void blkdev_journal_preliminary_check(void)
{
	journal_t *journal = BLKDEV_SB(blockdev_superblock)->s_journal;

	blkdev_journal_check_barrier(journal);
	/* We must check whether there's space left in the journal */
	blkdev_journal_check_log_left_space(journal);

}
EXPORT_SYMBOL(blkdev_journal_preliminary_check);

static int blkdev_double_write_begin(struct file *file,
				     struct address_space *mapping,
				     loff_t pos, unsigned len, unsigned flags,
				     struct page **pagep, void **fsdata)
{

	blkdev_journal_preliminary_check();
	return block_write_begin(mapping, pos, len, flags, pagep,
				blkdev_get_block);
}

static int blkdev_double_write_end(struct file *file,
				   struct address_space *mapping,
				   loff_t pos, unsigned len, unsigned copied,
				   struct page *page, void *fsdata)
{
	int ret;
	unsigned start;

	ret = block_write_end(file, mapping, pos, len, copied, page, fsdata);
	/* force write to another block device */
	start = pos & (PAGE_CACHE_SIZE - 1);
	blkdev_force_write_to_journal(page, start, start+ret);
	unlock_page(page);
	page_cache_release(page);
	return ret;
}

static void parse_lun_uuid_in_binary(unsigned char *dst, char *src)
{
	u32 time_low;
	u16 time_mid;
	u16 time_hi_and_version;
	u16 clock_seq;
	u8 node[6];
	char *cp;
	char buf[3];
	int i;
	u32 tmp;

	time_low = simple_strtoul(src, NULL, 16);
	time_mid = simple_strtoul(src+9, NULL, 16);
	time_hi_and_version = simple_strtoul(src+14, NULL, 16);
	clock_seq = simple_strtoul(src+19, NULL, 16);
	cp = src + 24;
	buf[2] = 0;

	for (i=0; i<6; i++) {
		buf[0] = *cp++;
		buf[1] = *cp++;
		node[i] = simple_strtoul(buf, NULL, 16);
	}
	tmp = time_low;

	dst[3] = (unsigned char) tmp;
	tmp >>= 8;
	dst[2] = (unsigned char) tmp;
	tmp >>= 8;
	dst[1] = (unsigned char) tmp;
	tmp >>= 8;
	dst[0] = (unsigned char) tmp;
	tmp = time_mid;

	dst[5] = (unsigned char) tmp;
	tmp >>= 8;
	dst[4] = (unsigned char) tmp;
	tmp = time_hi_and_version;

	dst[7] = (unsigned char) tmp;
	tmp >>= 8;
	dst[6] = (unsigned char) tmp;
	tmp = clock_seq;

	dst[9] = (unsigned char) tmp;
	tmp >>= 8;
	dst[8] = (unsigned char) tmp;

	memcpy(dst+10, node, 6);
}

int init_blkdev_journal(char *blkdev_name, char *lun_uuid_str)
{
	journal_t *journal;
	struct block_device *blk_bdev;
	struct block_device *journal_bdev;
	struct blkdev_sb_info *sbi;
	int journal_nr_blocks;
	struct buffer_head *bh;
	unsigned char uuid[JBD2_UUID_LEN];
	struct j_lun_dev_s *j_lun_dev;
	int err = 0;

	blk_bdev = blkdev_get_by_path(blkdev_name, FMODE_READ|FMODE_WRITE,
				      blockdev_superblock);
	if (IS_ERR(blk_bdev)) {
		pr_err("[BLKJBD] get lun blkdev failed\n");
		return -1;
	}

	mutex_lock(&g_blkdev_journal_init_mutex);
	if (BLKDEV_SB(blockdev_superblock)) {
		/* a journal has been initialized by previous block devices */
		journal = BLKDEV_SB(blockdev_superblock)->s_journal;
		goto found_journal;
	}

	/* FIXME: journal name should be passed from user space */
	journal_bdev = blkdev_get_by_path(BLKDEV_JOURNAL_PATH,
					  FMODE_READ|FMODE_WRITE|FMODE_EXCL,
					  blockdev_superblock);
	if (IS_ERR(journal_bdev)) {
		pr_err("[BLKJBD] get journal blkdev failed\n");
		goto out_jbdev;
	}

	bh = __bread(journal_bdev, 1, 4096);
	if (!bh) {
		pr_err("[BLKJBD] couldn't read superblock of "
		  "external journal\n");
		goto out_bdev;
	}
	/* initialize additional superblock info for a block device */
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		goto out_bdev;

	blockdev_superblock->s_fs_info = sbi;
	sbi->s_sb = blockdev_superblock;
	sbi->s_commit_interval = BLKDEV_DEF_MAX_CHECKPOINT_AGE * HZ;
	sbi->s_min_batch_time = BLKDEV_DEF_MIN_BATCH_TIME;
	sbi->s_max_batch_time = BLKDEV_DEF_MAX_BATCH_TIME;
	/* [BLKJBD] FIXME: journal length and start position */
	journal_nr_blocks = get_capacity(journal_bdev->bd_disk) / 8;
	journal = blkdev_journal_init_dev(journal_bdev, blk_bdev, 1,
					  journal_nr_blocks,
					  journal_bdev->bd_block_size);
	if (!journal) {
		pr_err("[BLKJBD] failed to create device journal\n");
		goto out_bdev;
	}
	journal->j_private = blockdev_superblock;
	ll_rw_block(READ | REQ_META | REQ_PRIO, 1, &journal->j_sb_buffer);
	wait_on_buffer(journal->j_sb_buffer);
	if (!buffer_uptodate(journal->j_sb_buffer)) {
		pr_err("[BLKJBD] failed to read journal superblock\n");
		goto out_journal;
	}
	BLKDEV_SB(blockdev_superblock)->journal_bdev = journal_bdev;
	BLKDEV_SB(blockdev_superblock)->blk_bdev = blk_bdev;
	/* re-initialize journal parameters */
	journal->j_commit_interval = sbi->s_commit_interval;
	journal->j_min_batch_time = sbi->s_min_batch_time;
	journal->j_max_batch_time = sbi->s_max_batch_time;
	journal->j_checkpoint_threshold =
		journal_nr_blocks * BLKDEV_CHECKPOINT_JOURNAL_SPACE;
	journal->j_flags |= JBD2_BARRIER;

found_journal:
	journal->j_fs_dev = blk_bdev;
	parse_lun_uuid_in_binary(uuid, lun_uuid_str);

	err = blkdev_journal_load(journal, uuid);
	if (err) {
		pr_err("[BLKJBD] blkdev_journal_load failed\n");
		goto out_journal;
	}
	if (!jbd2_journal_set_features(journal, 0, 0,
				       JBD2_FEATURE_INCOMPAT_CSUM_V3)) {
		pr_err("[BLKJBD] failed to set journal cksum feature\n");
		goto out_journal;
	}
	BLKDEV_SB(blockdev_superblock)->s_journal = journal;
	/* add infos of a block device that has journal support */
	j_lun_dev = kzalloc(sizeof(struct j_lun_dev_s), GFP_KERNEL);
	if (!j_lun_dev) {
		pr_err("[BLKJBD] failed to allocate j_lun_dev\n");
		goto out_journal;
	}
	INIT_LIST_HEAD(&j_lun_dev->list);
	j_lun_dev->lun_devname = blkdev_name;
	j_lun_dev->lun_blkdev = blk_bdev;
	memcpy(j_lun_dev->lun_uuid, uuid, JBD2_UUID_LEN);

	mutex_lock(&journal->j_list_mutex);
	j_lun_dev->des_index = find_next_zero_bit(journal->j_des_usage_bitmap,
						  BLKDEV_MAX_JOURNAL_USER_NUM,
						  0);
	if (j_lun_dev->des_index == BLKDEV_MAX_JOURNAL_USER_NUM) {
		pr_err("[BLKJBD] Only %d numbers of lun could enable journal"
		       " support\n", BLKDEV_MAX_JOURNAL_USER_NUM);
		goto exceeds_journal;
	}
	bitmap_set(journal->j_des_usage_bitmap, j_lun_dev->des_index, 1);
	list_add(&j_lun_dev->list, &journal->j_lun_dev_list);
	mutex_unlock(&journal->j_list_mutex);

	write_lock(&journal->j_state_lock);
	journal->j_used_lun_nr++;
	write_unlock(&journal->j_state_lock);
	blkdev_journal_update_user_nr(journal, j_lun_dev->lun_uuid);

	mutex_unlock(&g_blkdev_journal_init_mutex);

	pr_info("[BLKJBD] finish journal init\n");
	pr_info("[BLKJBD] current journal user:\n");
	list_for_each_entry(j_lun_dev, &journal->j_lun_dev_list, list) {
		pr_info("[BLKJBD] %s\n", j_lun_dev->lun_devname);
	}

	return 0;

exceeds_journal:
	kfree(j_lun_dev);
out_journal:
	pr_err("[BLKJBD] journal init failed\n");
	if (!journal->j_used_lun_nr) {
		blkdev_journal_destroy(journal);
		kfree(sbi);
		blockdev_superblock->s_fs_info = NULL;
	}

out_bdev:
	if (!journal->j_used_lun_nr)
		blkdev_put(journal_bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

out_jbdev:
	blkdev_put(blk_bdev, FMODE_READ|FMODE_WRITE);
	mutex_unlock(&g_blkdev_journal_init_mutex);

	return -1;
}
EXPORT_SYMBOL(init_blkdev_journal);

int release_blkdev_journal(char *blkdev_name) {
	struct blkdev_sb_info *sbi = BLKDEV_SB(blockdev_superblock);
	journal_t *journal = sbi->s_journal;
	int err = 0;
	int user_nr;
	struct j_lun_dev_s *j_lun_dev, *tmp;

	mutex_lock(&journal->j_checkpoint_mutex);
	mutex_lock(&journal->j_list_mutex);
	list_for_each_entry_safe(j_lun_dev, tmp,
				 &journal->j_lun_dev_list, list) {
		if (strcmp(blkdev_name, j_lun_dev->lun_devname) == 0) {
			/* a right lun is found, delete it */
			unsigned long index = j_lun_dev->des_index;
			spin_lock(&journal->j_des_lock[index]);
			if (!journal->j_descriptor[index]) {
				brelse(journal->j_descriptor[index]);
				journal->j_descriptor[index] = NULL;
				journal->j_des_used_space[index] = 0;
				journal->j_des_blocknr[index] = 0;
			}
			spin_unlock(&journal->j_des_lock[index]);
			bitmap_clear(journal->j_des_usage_bitmap, index, 1);
			//pr_info("[BLKJBD] clear bitmap at index %lu\n", index);
			pr_info("[BLKJBD] kick out %s from journal support\n", blkdev_name);
			blkdev_put(j_lun_dev->lun_blkdev,
				   FMODE_READ|FMODE_WRITE);
			list_del(&j_lun_dev->list);
			kfree(j_lun_dev);
		}
	}
	mutex_unlock(&journal->j_list_mutex);
	mutex_unlock(&journal->j_checkpoint_mutex);

	write_lock(&journal->j_state_lock);
	journal->j_used_lun_nr--;
	journal->j_superblock->s_nr_users = cpu_to_be32(journal->j_used_lun_nr);
	user_nr = journal->j_used_lun_nr;
	write_unlock(&journal->j_state_lock);

	blkdev_journal_update_user_nr(journal, NULL);

	if (sbi->s_journal && user_nr == 0) {
		pr_info("[BLKJBD] destory journal\n");
		err = blkdev_journal_destroy(sbi->s_journal);
		blkdev_put(sbi->journal_bdev,
			   FMODE_READ|FMODE_WRITE|FMODE_EXCL);
		sbi->s_journal = NULL;
		if (err < 0)
			pr_err("[BLKJBD] failed to clean up the journal\n");
		kfree(sbi);
		blockdev_superblock->s_fs_info = NULL;
	}

	return err;
}
EXPORT_SYMBOL(release_blkdev_journal);

void blkdev_set_aops(struct block_device *bdev, unsigned long enable)
{
	if (enable)
		bdev->bd_inode->i_data.a_ops = &def_blk_double_write_aops;
	else
		bdev->bd_inode->i_data.a_ops = &def_blk_aops;
}
EXPORT_SYMBOL(blkdev_set_aops);

#endif

void __init bdev_cache_init(void)
{
	int err;
	static struct vfsmount *bd_mnt;

	bdev_cachep = kmem_cache_create("bdev_cache", sizeof(struct bdev_inode),
			0, (SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|
				SLAB_MEM_SPREAD|SLAB_PANIC),
			init_once);
	err = register_filesystem(&bd_type);
	if (err)
		panic("Cannot register bdev pseudo-fs");
	bd_mnt = kern_mount(&bd_type);
	if (IS_ERR(bd_mnt))
		panic("Cannot create bdev pseudo-fs");
	blockdev_superblock = bd_mnt->mnt_sb;   /* For writeback */
}

/*
 * Most likely _very_ bad one - but then it's hardly critical for small
 * /dev and can be fixed when somebody will need really large one.
 * Keep in mind that it will be fed through icache hash function too.
 */
static inline unsigned long hash(dev_t dev)
{
	return MAJOR(dev)+MINOR(dev);
}

static int bdev_test(struct inode *inode, void *data)
{
	return BDEV_I(inode)->bdev.bd_dev == *(dev_t *)data;
}

static int bdev_set(struct inode *inode, void *data)
{
	BDEV_I(inode)->bdev.bd_dev = *(dev_t *)data;
	return 0;
}

static LIST_HEAD(all_bdevs);

struct block_device *bdget(dev_t dev)
{
	struct block_device *bdev;
	struct inode *inode;

	inode = iget5_locked(blockdev_superblock, hash(dev),
			bdev_test, bdev_set, &dev);

	if (!inode)
		return NULL;

	bdev = &BDEV_I(inode)->bdev;

	if (inode->i_state & I_NEW) {
		bdev->bd_contains = NULL;
		bdev->bd_super = NULL;
		bdev->bd_inode = inode;
		bdev->bd_block_size = (1 << inode->i_blkbits);
		bdev->bd_part_count = 0;
		bdev->bd_invalidated = 0;
		inode->i_mode = S_IFBLK;
		inode->i_rdev = dev;
		inode->i_bdev = bdev;
		inode->i_data.a_ops = &def_blk_aops;
		mapping_set_gfp_mask(&inode->i_data, GFP_USER);
		inode->i_data.backing_dev_info = &default_backing_dev_info;
		spin_lock(&bdev_lock);
		list_add(&bdev->bd_list, &all_bdevs);
		spin_unlock(&bdev_lock);
		unlock_new_inode(inode);
	}
	return bdev;
}

EXPORT_SYMBOL(bdget);

/**
 * bdgrab -- Grab a reference to an already referenced block device
 * @bdev:	Block device to grab a reference to.
 */
struct block_device *bdgrab(struct block_device *bdev)
{
	ihold(bdev->bd_inode);
	return bdev;
}
EXPORT_SYMBOL(bdgrab);

long nr_blockdev_pages(void)
{
	struct block_device *bdev;
	long ret = 0;
	spin_lock(&bdev_lock);
	list_for_each_entry(bdev, &all_bdevs, bd_list) {
		ret += bdev->bd_inode->i_mapping->nrpages;
	}
	spin_unlock(&bdev_lock);
	return ret;
}

void bdput(struct block_device *bdev)
{
	iput(bdev->bd_inode);
}

EXPORT_SYMBOL(bdput);
 
static struct block_device *bd_acquire(struct inode *inode)
{
	struct block_device *bdev;

	spin_lock(&bdev_lock);
	bdev = inode->i_bdev;
	if (bdev) {
		ihold(bdev->bd_inode);
		spin_unlock(&bdev_lock);
		return bdev;
	}
	spin_unlock(&bdev_lock);

	bdev = bdget(inode->i_rdev);
	if (bdev) {
		spin_lock(&bdev_lock);
		if (!inode->i_bdev) {
			/*
			 * We take an additional reference to bd_inode,
			 * and it's released in clear_inode() of inode.
			 * So, we can access it via ->i_mapping always
			 * without igrab().
			 */
			ihold(bdev->bd_inode);
			inode->i_bdev = bdev;
			inode->i_mapping = bdev->bd_inode->i_mapping;
			list_add(&inode->i_devices, &bdev->bd_inodes);
		}
		spin_unlock(&bdev_lock);
	}
	return bdev;
}

int sb_is_blkdev_sb(struct super_block *sb)
{
	return sb == blockdev_superblock;
}

/* Call when you free inode */

void bd_forget(struct inode *inode)
{
	struct block_device *bdev = NULL;

	spin_lock(&bdev_lock);
	if (!sb_is_blkdev_sb(inode->i_sb))
		bdev = inode->i_bdev;
	__bd_forget(inode);
	spin_unlock(&bdev_lock);

	if (bdev)
		iput(bdev->bd_inode);
}

/**
 * bd_may_claim - test whether a block device can be claimed
 * @bdev: block device of interest
 * @whole: whole block device containing @bdev, may equal @bdev
 * @holder: holder trying to claim @bdev
 *
 * Test whether @bdev can be claimed by @holder.
 *
 * CONTEXT:
 * spin_lock(&bdev_lock).
 *
 * RETURNS:
 * %true if @bdev can be claimed, %false otherwise.
 */
static bool bd_may_claim(struct block_device *bdev, struct block_device *whole,
			 void *holder)
{
	if (bdev->bd_holder == holder)
		return true;	 /* already a holder */
	else if (bdev->bd_holder != NULL)
		return false; 	 /* held by someone else */
	else if (bdev->bd_contains == bdev)
		return true;  	 /* is a whole device which isn't held */

	else if (whole->bd_holder == bd_may_claim)
		return true; 	 /* is a partition of a device that is being partitioned */
	else if (whole->bd_holder != NULL)
		return false;	 /* is a partition of a held device */
	else
		return true;	 /* is a partition of an un-held device */
}

/**
 * bd_prepare_to_claim - prepare to claim a block device
 * @bdev: block device of interest
 * @whole: the whole device containing @bdev, may equal @bdev
 * @holder: holder trying to claim @bdev
 *
 * Prepare to claim @bdev.  This function fails if @bdev is already
 * claimed by another holder and waits if another claiming is in
 * progress.  This function doesn't actually claim.  On successful
 * return, the caller has ownership of bd_claiming and bd_holder[s].
 *
 * CONTEXT:
 * spin_lock(&bdev_lock).  Might release bdev_lock, sleep and regrab
 * it multiple times.
 *
 * RETURNS:
 * 0 if @bdev can be claimed, -EBUSY otherwise.
 */
static int bd_prepare_to_claim(struct block_device *bdev,
			       struct block_device *whole, void *holder)
{
retry:
	/* if someone else claimed, fail */
	if (!bd_may_claim(bdev, whole, holder))
		return -EBUSY;

	/* if claiming is already in progress, wait for it to finish */
	if (whole->bd_claiming) {
		wait_queue_head_t *wq = bit_waitqueue(&whole->bd_claiming, 0);
		DEFINE_WAIT(wait);

		prepare_to_wait(wq, &wait, TASK_UNINTERRUPTIBLE);
		spin_unlock(&bdev_lock);
		schedule();
		finish_wait(wq, &wait);
		spin_lock(&bdev_lock);
		goto retry;
	}

	/* yay, all mine */
	return 0;
}

/**
 * bd_start_claiming - start claiming a block device
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 *
 * @bdev is about to be opened exclusively.  Check @bdev can be opened
 * exclusively and mark that an exclusive open is in progress.  Each
 * successful call to this function must be matched with a call to
 * either bd_finish_claiming() or bd_abort_claiming() (which do not
 * fail).
 *
 * This function is used to gain exclusive access to the block device
 * without actually causing other exclusive open attempts to fail. It
 * should be used when the open sequence itself requires exclusive
 * access but may subsequently fail.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Pointer to the block device containing @bdev on success, ERR_PTR()
 * value on failure.
 */
static struct block_device *bd_start_claiming(struct block_device *bdev,
					      void *holder)
{
	struct gendisk *disk;
	struct block_device *whole;
	int partno, err;

	might_sleep();

	/*
	 * @bdev might not have been initialized properly yet, look up
	 * and grab the outer block device the hard way.
	 */
	disk = get_gendisk(bdev->bd_dev, &partno);
	if (!disk)
		return ERR_PTR(-ENXIO);

	/*
	 * Normally, @bdev should equal what's returned from bdget_disk()
	 * if partno is 0; however, some drivers (floppy) use multiple
	 * bdev's for the same physical device and @bdev may be one of the
	 * aliases.  Keep @bdev if partno is 0.  This means claimer
	 * tracking is broken for those devices but it has always been that
	 * way.
	 */
	if (partno)
		whole = bdget_disk(disk, 0);
	else
		whole = bdgrab(bdev);

	module_put(disk->fops->owner);
	put_disk(disk);
	if (!whole)
		return ERR_PTR(-ENOMEM);

	/* prepare to claim, if successful, mark claiming in progress */
	spin_lock(&bdev_lock);

	err = bd_prepare_to_claim(bdev, whole, holder);
	if (err == 0) {
		whole->bd_claiming = holder;
		spin_unlock(&bdev_lock);
		return whole;
	} else {
		spin_unlock(&bdev_lock);
		bdput(whole);
		return ERR_PTR(err);
	}
}

#ifdef CONFIG_SYSFS
struct bd_holder_disk {
	struct list_head	list;
	struct gendisk		*disk;
	int			refcnt;
};

static struct bd_holder_disk *bd_find_holder_disk(struct block_device *bdev,
						  struct gendisk *disk)
{
	struct bd_holder_disk *holder;

	list_for_each_entry(holder, &bdev->bd_holder_disks, list)
		if (holder->disk == disk)
			return holder;
	return NULL;
}

static int add_symlink(struct kobject *from, struct kobject *to)
{
	return sysfs_create_link(from, to, kobject_name(to));
}

static void del_symlink(struct kobject *from, struct kobject *to)
{
	sysfs_remove_link(from, kobject_name(to));
}

/**
 * bd_link_disk_holder - create symlinks between holding disk and slave bdev
 * @bdev: the claimed slave bdev
 * @disk: the holding disk
 *
 * DON'T USE THIS UNLESS YOU'RE ALREADY USING IT.
 *
 * This functions creates the following sysfs symlinks.
 *
 * - from "slaves" directory of the holder @disk to the claimed @bdev
 * - from "holders" directory of the @bdev to the holder @disk
 *
 * For example, if /dev/dm-0 maps to /dev/sda and disk for dm-0 is
 * passed to bd_link_disk_holder(), then:
 *
 *   /sys/block/dm-0/slaves/sda --> /sys/block/sda
 *   /sys/block/sda/holders/dm-0 --> /sys/block/dm-0
 *
 * The caller must have claimed @bdev before calling this function and
 * ensure that both @bdev and @disk are valid during the creation and
 * lifetime of these symlinks.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int bd_link_disk_holder(struct block_device *bdev, struct gendisk *disk)
{
	struct bd_holder_disk *holder;
	int ret = 0;

	mutex_lock(&bdev->bd_mutex);

	WARN_ON_ONCE(!bdev->bd_holder);

	/* FIXME: remove the following once add_disk() handles errors */
	if (WARN_ON(!disk->slave_dir || !bdev->bd_part->holder_dir))
		goto out_unlock;

	holder = bd_find_holder_disk(bdev, disk);
	if (holder) {
		holder->refcnt++;
		goto out_unlock;
	}

	holder = kzalloc(sizeof(*holder), GFP_KERNEL);
	if (!holder) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	INIT_LIST_HEAD(&holder->list);
	holder->disk = disk;
	holder->refcnt = 1;

	ret = add_symlink(disk->slave_dir, &part_to_dev(bdev->bd_part)->kobj);
	if (ret)
		goto out_free;

	ret = add_symlink(bdev->bd_part->holder_dir, &disk_to_dev(disk)->kobj);
	if (ret)
		goto out_del;
	/*
	 * bdev could be deleted beneath us which would implicitly destroy
	 * the holder directory.  Hold on to it.
	 */
	kobject_get(bdev->bd_part->holder_dir);

	list_add(&holder->list, &bdev->bd_holder_disks);
	goto out_unlock;

out_del:
	del_symlink(disk->slave_dir, &part_to_dev(bdev->bd_part)->kobj);
out_free:
	kfree(holder);
out_unlock:
	mutex_unlock(&bdev->bd_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(bd_link_disk_holder);

/**
 * bd_unlink_disk_holder - destroy symlinks created by bd_link_disk_holder()
 * @bdev: the calimed slave bdev
 * @disk: the holding disk
 *
 * DON'T USE THIS UNLESS YOU'RE ALREADY USING IT.
 *
 * CONTEXT:
 * Might sleep.
 */
void bd_unlink_disk_holder(struct block_device *bdev, struct gendisk *disk)
{
	struct bd_holder_disk *holder;

	mutex_lock(&bdev->bd_mutex);

	holder = bd_find_holder_disk(bdev, disk);

	if (!WARN_ON_ONCE(holder == NULL) && !--holder->refcnt) {
		del_symlink(disk->slave_dir, &part_to_dev(bdev->bd_part)->kobj);
		del_symlink(bdev->bd_part->holder_dir,
			    &disk_to_dev(disk)->kobj);
		kobject_put(bdev->bd_part->holder_dir);
		list_del_init(&holder->list);
		kfree(holder);
	}

	mutex_unlock(&bdev->bd_mutex);
}
EXPORT_SYMBOL_GPL(bd_unlink_disk_holder);
#endif

/**
 * flush_disk - invalidates all buffer-cache entries on a disk
 *
 * @bdev:      struct block device to be flushed
 * @kill_dirty: flag to guide handling of dirty inodes
 *
 * Invalidates all buffer-cache entries on a disk. It should be called
 * when a disk has been changed -- either by a media change or online
 * resize.
 */
static void flush_disk(struct block_device *bdev, bool kill_dirty)
{
	if (__invalidate_device(bdev, kill_dirty)) {
		char name[BDEVNAME_SIZE] = "";

		if (bdev->bd_disk)
			disk_name(bdev->bd_disk, 0, name);
		printk(KERN_WARNING "VFS: busy inodes on changed media or "
		       "resized disk %s\n", name);
	}

	if (!bdev->bd_disk)
		return;
	if (disk_part_scan_enabled(bdev->bd_disk))
		bdev->bd_invalidated = 1;
}

/**
 * check_disk_size_change - checks for disk size change and adjusts bdev size.
 * @disk: struct gendisk to check
 * @bdev: struct bdev to adjust.
 *
 * This routine checks to see if the bdev size does not match the disk size
 * and adjusts it if it differs.
 */
void check_disk_size_change(struct gendisk *disk, struct block_device *bdev)
{
	loff_t disk_size, bdev_size;

	disk_size = (loff_t)get_capacity(disk) << 9;
	bdev_size = i_size_read(bdev->bd_inode);
	if (disk_size != bdev_size) {
		char name[BDEVNAME_SIZE];

		disk_name(disk, 0, name);
		printk(KERN_INFO
		       "%s: detected capacity change from %lld to %lld\n",
		       name, bdev_size, disk_size);
		i_size_write(bdev->bd_inode, disk_size);
		flush_disk(bdev, false);
	}
}
EXPORT_SYMBOL(check_disk_size_change);

/**
 * revalidate_disk - wrapper for lower-level driver's revalidate_disk call-back
 * @disk: struct gendisk to be revalidated
 *
 * This routine is a wrapper for lower-level driver's revalidate_disk
 * call-backs.  It is used to do common pre and post operations needed
 * for all revalidate_disk operations.
 */
int revalidate_disk(struct gendisk *disk)
{
	struct block_device *bdev;
	int ret = 0;

	if (disk->fops->revalidate_disk)
		ret = disk->fops->revalidate_disk(disk);

	bdev = bdget_disk(disk, 0);
	if (!bdev)
		return ret;

	mutex_lock(&bdev->bd_mutex);
	check_disk_size_change(disk, bdev);
	bdev->bd_invalidated = 0;
	mutex_unlock(&bdev->bd_mutex);
	bdput(bdev);
	return ret;
}
EXPORT_SYMBOL(revalidate_disk);

/*
 * This routine checks whether a removable media has been changed,
 * and invalidates all buffer-cache-entries in that case. This
 * is a relatively slow routine, so we have to try to minimize using
 * it. Thus it is called only upon a 'mount' or 'open'. This
 * is the best way of combining speed and utility, I think.
 * People changing diskettes in the middle of an operation deserve
 * to lose :-)
 */
int check_disk_change(struct block_device *bdev)
{
	struct gendisk *disk = bdev->bd_disk;
	const struct block_device_operations *bdops = disk->fops;
	unsigned int events;

	events = disk_clear_events(disk, DISK_EVENT_MEDIA_CHANGE |
				   DISK_EVENT_EJECT_REQUEST);
	if (!(events & DISK_EVENT_MEDIA_CHANGE))
		return 0;

	flush_disk(bdev, true);
	if (bdops->revalidate_disk)
		bdops->revalidate_disk(bdev->bd_disk);
	return 1;
}

EXPORT_SYMBOL(check_disk_change);

void bd_set_size(struct block_device *bdev, loff_t size)
{
	unsigned bsize = bdev_logical_block_size(bdev);

	mutex_lock(&bdev->bd_inode->i_mutex);
	i_size_write(bdev->bd_inode, size);
	mutex_unlock(&bdev->bd_inode->i_mutex);
	while (bsize < PAGE_CACHE_SIZE) {
		if (size & bsize)
			break;
		bsize <<= 1;
	}
	bdev->bd_block_size = bsize;
	bdev->bd_inode->i_blkbits = blksize_bits(bsize);
}
EXPORT_SYMBOL(bd_set_size);

static void __blkdev_put(struct block_device *bdev, fmode_t mode, int for_part);

/*
 * bd_mutex locking:
 *
 *  mutex_lock(part->bd_mutex)
 *    mutex_lock_nested(whole->bd_mutex, 1)
 */

static int __blkdev_get(struct block_device *bdev, fmode_t mode, int for_part)
{
	struct gendisk *disk;
	struct module *owner;
	int ret;
	int partno;
	int perm = 0;

	if (mode & FMODE_READ)
		perm |= MAY_READ;
	if (mode & FMODE_WRITE)
		perm |= MAY_WRITE;
	/*
	 * hooks: /n/, see "layering violations".
	 */
	if (!for_part) {
		ret = devcgroup_inode_permission(bdev->bd_inode, perm);
		if (ret != 0) {
			bdput(bdev);
			return ret;
		}
	}

 restart:

	ret = -ENXIO;
	disk = get_gendisk(bdev->bd_dev, &partno);
	if (!disk)
		goto out;
	owner = disk->fops->owner;

	disk_block_events(disk);
	mutex_lock_nested(&bdev->bd_mutex, for_part);
	if (!bdev->bd_openers) {
		bdev->bd_disk = disk;
		bdev->bd_queue = disk->queue;
		bdev->bd_contains = bdev;
		if (!partno) {
			struct backing_dev_info *bdi;

			ret = -ENXIO;
			bdev->bd_part = disk_get_part(disk, partno);
			if (!bdev->bd_part)
				goto out_clear;

			ret = 0;
			if (disk->fops->open) {
				ret = disk->fops->open(bdev, mode);
				if (ret == -ERESTARTSYS) {
					/* Lost a race with 'disk' being
					 * deleted, try again.
					 * See md.c
					 */
					disk_put_part(bdev->bd_part);
					bdev->bd_part = NULL;
					bdev->bd_disk = NULL;
					bdev->bd_queue = NULL;
					mutex_unlock(&bdev->bd_mutex);
					disk_unblock_events(disk);
					put_disk(disk);
					module_put(owner);
					goto restart;
				}
			}

			if (!ret) {
				bd_set_size(bdev,(loff_t)get_capacity(disk)<<9);
				bdi = blk_get_backing_dev_info(bdev);
				if (bdi == NULL)
					bdi = &default_backing_dev_info;
				bdev_inode_switch_bdi(bdev->bd_inode, bdi);
			}

			/*
			 * If the device is invalidated, rescan partition
			 * if open succeeded or failed with -ENOMEDIUM.
			 * The latter is necessary to prevent ghost
			 * partitions on a removed medium.
			 */
			if (bdev->bd_invalidated) {
				if (!ret)
					rescan_partitions(disk, bdev);
				else if (ret == -ENOMEDIUM)
					invalidate_partitions(disk, bdev);
			}
			if (ret)
				goto out_clear;
		} else {
			struct block_device *whole;
			whole = bdget_disk(disk, 0);
			ret = -ENOMEM;
			if (!whole)
				goto out_clear;
			BUG_ON(for_part);
			ret = __blkdev_get(whole, mode, 1);
			if (ret)
				goto out_clear;
			bdev->bd_contains = whole;
			bdev_inode_switch_bdi(bdev->bd_inode,
				whole->bd_inode->i_data.backing_dev_info);
			bdev->bd_part = disk_get_part(disk, partno);
			if (!(disk->flags & GENHD_FL_UP) ||
			    !bdev->bd_part || !bdev->bd_part->nr_sects) {
				ret = -ENXIO;
				goto out_clear;
			}
			bd_set_size(bdev, (loff_t)bdev->bd_part->nr_sects << 9);
		}
	} else {
		if (bdev->bd_contains == bdev) {
			ret = 0;
			if (bdev->bd_disk->fops->open)
				ret = bdev->bd_disk->fops->open(bdev, mode);
			/* the same as first opener case, read comment there */
			if (bdev->bd_invalidated) {
				if (!ret)
					rescan_partitions(bdev->bd_disk, bdev);
				else if (ret == -ENOMEDIUM)
					invalidate_partitions(bdev->bd_disk, bdev);
			}
			if (ret)
				goto out_unlock_bdev;
		}
		/* only one opener holds refs to the module and disk */
		put_disk(disk);
		module_put(owner);
	}
	bdev->bd_openers++;
	if (for_part)
		bdev->bd_part_count++;
	mutex_unlock(&bdev->bd_mutex);
	disk_unblock_events(disk);
	return 0;

 out_clear:
	disk_put_part(bdev->bd_part);
	bdev->bd_disk = NULL;
	bdev->bd_part = NULL;
	bdev->bd_queue = NULL;
	bdev_inode_switch_bdi(bdev->bd_inode, &default_backing_dev_info);
	if (bdev != bdev->bd_contains)
		__blkdev_put(bdev->bd_contains, mode, 1);
	bdev->bd_contains = NULL;
 out_unlock_bdev:
	mutex_unlock(&bdev->bd_mutex);
	disk_unblock_events(disk);
	put_disk(disk);
	module_put(owner);
 out:
	bdput(bdev);

	return ret;
}

/**
 * blkdev_get - open a block device
 * @bdev: block_device to open
 * @mode: FMODE_* mask
 * @holder: exclusive holder identifier
 *
 * Open @bdev with @mode.  If @mode includes %FMODE_EXCL, @bdev is
 * open with exclusive access.  Specifying %FMODE_EXCL with %NULL
 * @holder is invalid.  Exclusive opens may nest for the same @holder.
 *
 * On success, the reference count of @bdev is unchanged.  On failure,
 * @bdev is put.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int blkdev_get(struct block_device *bdev, fmode_t mode, void *holder)
{
	struct block_device *whole = NULL;
	int res;

	WARN_ON_ONCE((mode & FMODE_EXCL) && !holder);

	if ((mode & FMODE_EXCL) && holder) {
		whole = bd_start_claiming(bdev, holder);
		if (IS_ERR(whole)) {
			bdput(bdev);
			return PTR_ERR(whole);
		}
	}

	res = __blkdev_get(bdev, mode, 0);

	if (whole) {
		struct gendisk *disk = whole->bd_disk;

		/* finish claiming */
		mutex_lock(&bdev->bd_mutex);
		spin_lock(&bdev_lock);

		if (!res) {
			BUG_ON(!bd_may_claim(bdev, whole, holder));
			/*
			 * Note that for a whole device bd_holders
			 * will be incremented twice, and bd_holder
			 * will be set to bd_may_claim before being
			 * set to holder
			 */
			whole->bd_holders++;
			whole->bd_holder = bd_may_claim;
			bdev->bd_holders++;
			bdev->bd_holder = holder;
		}

		/* tell others that we're done */
		BUG_ON(whole->bd_claiming != holder);
		whole->bd_claiming = NULL;
		wake_up_bit(&whole->bd_claiming, 0);

		spin_unlock(&bdev_lock);

		/*
		 * Block event polling for write claims if requested.  Any
		 * write holder makes the write_holder state stick until
		 * all are released.  This is good enough and tracking
		 * individual writeable reference is too fragile given the
		 * way @mode is used in blkdev_get/put().
		 */
		if (!res && (mode & FMODE_WRITE) && !bdev->bd_write_holder &&
		    (disk->flags & GENHD_FL_BLOCK_EVENTS_ON_EXCL_WRITE)) {
			bdev->bd_write_holder = true;
			disk_block_events(disk);
		}

		mutex_unlock(&bdev->bd_mutex);
		bdput(whole);
	}

	return res;
}
EXPORT_SYMBOL(blkdev_get);

/**
 * blkdev_get_by_path - open a block device by name
 * @path: path to the block device to open
 * @mode: FMODE_* mask
 * @holder: exclusive holder identifier
 *
 * Open the blockdevice described by the device file at @path.  @mode
 * and @holder are identical to blkdev_get().
 *
 * On success, the returned block_device has reference count of one.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Pointer to block_device on success, ERR_PTR(-errno) on failure.
 */
struct block_device *blkdev_get_by_path(const char *path, fmode_t mode,
					void *holder)
{
	struct block_device *bdev;
	int err;

	bdev = lookup_bdev(path);
	if (IS_ERR(bdev))
		return bdev;

	err = blkdev_get(bdev, mode, holder);
	if (err)
		return ERR_PTR(err);

	if ((mode & FMODE_WRITE) && bdev_read_only(bdev)) {
		blkdev_put(bdev, mode);
		return ERR_PTR(-EACCES);
	}

	return bdev;
}
EXPORT_SYMBOL(blkdev_get_by_path);

/**
 * blkdev_get_by_dev - open a block device by device number
 * @dev: device number of block device to open
 * @mode: FMODE_* mask
 * @holder: exclusive holder identifier
 *
 * Open the blockdevice described by device number @dev.  @mode and
 * @holder are identical to blkdev_get().
 *
 * Use it ONLY if you really do not have anything better - i.e. when
 * you are behind a truly sucky interface and all you are given is a
 * device number.  _Never_ to be used for internal purposes.  If you
 * ever need it - reconsider your API.
 *
 * On success, the returned block_device has reference count of one.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Pointer to block_device on success, ERR_PTR(-errno) on failure.
 */
struct block_device *blkdev_get_by_dev(dev_t dev, fmode_t mode, void *holder)
{
	struct block_device *bdev;
	int err;

	bdev = bdget(dev);
	if (!bdev)
		return ERR_PTR(-ENOMEM);

	err = blkdev_get(bdev, mode, holder);
	if (err)
		return ERR_PTR(err);

	return bdev;
}
EXPORT_SYMBOL(blkdev_get_by_dev);

static int blkdev_open(struct inode * inode, struct file * filp)
{
	struct block_device *bdev;

	/*
	 * Preserve backwards compatibility and allow large file access
	 * even if userspace doesn't ask for it explicitly. Some mkfs
	 * binary needs it. We might want to drop this workaround
	 * during an unstable branch.
	 */
	filp->f_flags |= O_LARGEFILE;

	if (filp->f_flags & O_NDELAY)
		filp->f_mode |= FMODE_NDELAY;
	if (filp->f_flags & O_EXCL)
		filp->f_mode |= FMODE_EXCL;
	if ((filp->f_flags & O_ACCMODE) == 3)
		filp->f_mode |= FMODE_WRITE_IOCTL;

	bdev = bd_acquire(inode);
	if (bdev == NULL)
		return -ENOMEM;

	filp->f_mapping = bdev->bd_inode->i_mapping;

	return blkdev_get(bdev, filp->f_mode, filp);
}

static void __blkdev_put(struct block_device *bdev, fmode_t mode, int for_part)
{
	struct gendisk *disk = bdev->bd_disk;
	struct block_device *victim = NULL;

	mutex_lock_nested(&bdev->bd_mutex, for_part);
	if (for_part)
		bdev->bd_part_count--;

	if (!--bdev->bd_openers) {
		WARN_ON_ONCE(bdev->bd_holders);
		sync_blockdev(bdev);
		kill_bdev(bdev);
		/* ->release can cause the old bdi to disappear,
		 * so must switch it out first
		 */
		bdev_inode_switch_bdi(bdev->bd_inode,
					&default_backing_dev_info);
	}
	if (bdev->bd_contains == bdev) {
		if (disk->fops->release)
			disk->fops->release(disk, mode);
	}
	if (!bdev->bd_openers) {
		struct module *owner = disk->fops->owner;

		disk_put_part(bdev->bd_part);
		bdev->bd_part = NULL;
		bdev->bd_disk = NULL;
		if (bdev != bdev->bd_contains)
			victim = bdev->bd_contains;
		bdev->bd_contains = NULL;

		put_disk(disk);
		module_put(owner);
	}
	mutex_unlock(&bdev->bd_mutex);
	bdput(bdev);
	if (victim)
		__blkdev_put(victim, mode, 1);
}

void blkdev_put(struct block_device *bdev, fmode_t mode)
{
	mutex_lock(&bdev->bd_mutex);

	if (mode & FMODE_EXCL) {
		bool bdev_free;

		/*
		 * Release a claim on the device.  The holder fields
		 * are protected with bdev_lock.  bd_mutex is to
		 * synchronize disk_holder unlinking.
		 */
		spin_lock(&bdev_lock);

		WARN_ON_ONCE(--bdev->bd_holders < 0);
		WARN_ON_ONCE(--bdev->bd_contains->bd_holders < 0);

		/* bd_contains might point to self, check in a separate step */
		if ((bdev_free = !bdev->bd_holders))
			bdev->bd_holder = NULL;
		if (!bdev->bd_contains->bd_holders)
			bdev->bd_contains->bd_holder = NULL;

		spin_unlock(&bdev_lock);

		/*
		 * If this was the last claim, remove holder link and
		 * unblock evpoll if it was a write holder.
		 */
		if (bdev_free && bdev->bd_write_holder) {
			disk_unblock_events(bdev->bd_disk);
			bdev->bd_write_holder = false;
		}
	}

	/*
	 * Trigger event checking and tell drivers to flush MEDIA_CHANGE
	 * event.  This is to ensure detection of media removal commanded
	 * from userland - e.g. eject(1).
	 */
	disk_flush_events(bdev->bd_disk, DISK_EVENT_MEDIA_CHANGE);

	mutex_unlock(&bdev->bd_mutex);

	__blkdev_put(bdev, mode, 0);
}
EXPORT_SYMBOL(blkdev_put);

static int blkdev_close(struct inode * inode, struct file * filp)
{
	struct block_device *bdev = I_BDEV(filp->f_mapping->host);
	blkdev_put(bdev, filp->f_mode);
	return 0;
}

static long block_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct block_device *bdev = I_BDEV(file->f_mapping->host);
	fmode_t mode = file->f_mode;

	/*
	 * O_NDELAY can be altered using fcntl(.., F_SETFL, ..), so we have
	 * to updated it before every ioctl.
	 */
	if (file->f_flags & O_NDELAY)
		mode |= FMODE_NDELAY;
	else
		mode &= ~FMODE_NDELAY;

	return blkdev_ioctl(bdev, mode, cmd, arg);
}

/*
 * Write data to the block device.  Only intended for the block device itself
 * and the raw driver which basically is a fake block device.
 *
 * Does not take i_mutex for the write and thus is not for general purpose
 * use.
 */
ssize_t blkdev_aio_write(struct kiocb *iocb, const struct iovec *iov,
			 unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct blk_plug plug;
	ssize_t ret;

	BUG_ON(iocb->ki_pos != pos);

	blk_start_plug(&plug);
	ret = __generic_file_aio_write(iocb, iov, nr_segs, &iocb->ki_pos);
	if (ret > 0) {
		ssize_t err;

		err = generic_write_sync(file, pos, ret);
		if (err < 0 && ret > 0)
			ret = err;
	}
	blk_finish_plug(&plug);
	return ret;
}
EXPORT_SYMBOL_GPL(blkdev_aio_write);

static ssize_t blkdev_aio_read(struct kiocb *iocb, const struct iovec *iov,
			 unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *bd_inode = file->f_mapping->host;
	loff_t size = i_size_read(bd_inode);

	if (pos >= size)
		return 0;

	size -= pos;
	if (size < iocb->ki_nbytes)
		nr_segs = iov_shorten((struct iovec *)iov, nr_segs, size);
	return generic_file_aio_read(iocb, iov, nr_segs, pos);
}

/*
 * Try to release a page associated with block device when the system
 * is under memory pressure.
 */
static int blkdev_releasepage(struct page *page, gfp_t wait)
{
	struct super_block *super = BDEV_I(page->mapping->host)->bdev.bd_super;

	if (super && super->s_op->bdev_try_to_free_page)
		return super->s_op->bdev_try_to_free_page(super, page, wait);

	return try_to_free_buffers(page);
}

static const struct address_space_operations def_blk_aops = {
	.readpage	= blkdev_readpage,
	.writepage	= blkdev_writepage,
	.write_begin	= blkdev_write_begin,
	.write_end	= blkdev_write_end,
	//George Wu, 20130629, blkdev_readpages
#ifdef CONFIG_MACH_QNAPTS
#ifdef USE_BLKDEV_READPAGES
	.readpages      = blkdev_readpages,
#endif
#endif
	.writepages	= generic_writepages,
	.releasepage	= blkdev_releasepage,
	.direct_IO	= blkdev_direct_IO,
	.is_dirty_writeback = buffer_check_dirty_writeback,
};

#ifdef QNAP_SHARE_JOURNAL
static const struct address_space_operations def_blk_double_write_aops = {
	.readpage	= blkdev_readpage,
	.writepage	= blkdev_writepage,
	.write_begin	= blkdev_double_write_begin,
	.write_end	= blkdev_double_write_end,
	//George Wu, 20130629, blkdev_readpages
#ifdef CONFIG_MACH_QNAPTS
#ifdef USE_BLKDEV_READPAGES
	.readpages      = blkdev_readpages,
#endif
#endif
	.writepages	= generic_writepages,
	.releasepage	= blkdev_releasepage,
	.direct_IO	= blkdev_direct_IO,
	.is_dirty_writeback = buffer_check_dirty_writeback,
};
#endif

const struct file_operations def_blk_fops = {
	.open		= blkdev_open,
	.release	= blkdev_close,
	.llseek		= block_llseek,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= blkdev_aio_read,
	.aio_write	= blkdev_aio_write,
	.mmap		= generic_file_mmap,
	.fsync		= blkdev_fsync,
	.unlocked_ioctl	= block_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_blkdev_ioctl,
#endif
	.splice_read	= generic_file_splice_read,
	.splice_write	= generic_file_splice_write,
};

int ioctl_by_bdev(struct block_device *bdev, unsigned cmd, unsigned long arg)
{
	int res;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	res = blkdev_ioctl(bdev, 0, cmd, arg);
	set_fs(old_fs);
	return res;
}

EXPORT_SYMBOL(ioctl_by_bdev);

/**
 * lookup_bdev  - lookup a struct block_device by name
 * @pathname:	special file representing the block device
 *
 * Get a reference to the blockdevice at @pathname in the current
 * namespace if possible and return it.  Return ERR_PTR(error)
 * otherwise.
 */
struct block_device *lookup_bdev(const char *pathname)
{
	struct block_device *bdev;
	struct inode *inode;
	struct path path;
	int error;

	if (!pathname || !*pathname)
		return ERR_PTR(-EINVAL);

	error = kern_path(pathname, LOOKUP_FOLLOW, &path);
	if (error)
		return ERR_PTR(error);

	inode = path.dentry->d_inode;
	error = -ENOTBLK;
	if (!S_ISBLK(inode->i_mode))
		goto fail;
	error = -EACCES;
	if (path.mnt->mnt_flags & MNT_NODEV)
		goto fail;
	error = -ENOMEM;
	bdev = bd_acquire(inode);
	if (!bdev)
		goto fail;
out:
	path_put(&path);
	return bdev;
fail:
	bdev = ERR_PTR(error);
	goto out;
}
EXPORT_SYMBOL(lookup_bdev);

int __invalidate_device(struct block_device *bdev, bool kill_dirty)
{
	struct super_block *sb = get_super(bdev);
	int res = 0;

	if (sb) {
		/*
		 * no need to lock the super, get_super holds the
		 * read mutex so the filesystem cannot go away
		 * under us (->put_super runs with the write lock
		 * hold).
		 */
		shrink_dcache_sb(sb);
		res = invalidate_inodes(sb, kill_dirty);
		drop_super(sb);
	}
	invalidate_bdev(bdev);
	return res;
}
EXPORT_SYMBOL(__invalidate_device);

void iterate_bdevs(void (*func)(struct block_device *, void *), void *arg)
{
	struct inode *inode, *old_inode = NULL;

	spin_lock(&inode_sb_list_lock);
	list_for_each_entry(inode, &blockdev_superblock->s_inodes, i_sb_list) {
		struct address_space *mapping = inode->i_mapping;

		spin_lock(&inode->i_lock);
		if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW) ||
		    mapping->nrpages == 0) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		__iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&inode_sb_list_lock);
		/*
		 * We hold a reference to 'inode' so it couldn't have been
		 * removed from s_inodes list while we dropped the
		 * inode_sb_list_lock.  We cannot iput the inode now as we can
		 * be holding the last reference and we cannot iput it under
		 * inode_sb_list_lock. So we keep the reference and iput it
		 * later.
		 */
		iput(old_inode);
		old_inode = inode;

		func(I_BDEV(inode), arg);

		spin_lock(&inode_sb_list_lock);
	}
	spin_unlock(&inode_sb_list_lock);
	iput(old_inode);
}
