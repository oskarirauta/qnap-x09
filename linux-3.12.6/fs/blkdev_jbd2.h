#include <linux/jbd2.h>
/*
 * Default journal batching time
 */
#define BLKDEV_DEF_MAX_CHECKPOINT_AGE   10
#define BLKDEV_DEF_MIN_BATCH_TIME	0
#define BLKDEV_DEF_MAX_BATCH_TIME	15000	/* 15ms */
#define BLKDEV_JOURNAL(inode)	(BLKDEV_SB(inode->i_sb)->s_journal)
/*
 * This value depends on how many "write_begin" will be called
 * in the mdo_splice_from_socket of iSCSI target.
 */
#define BLKDEV_MAX_SPLICE_WRITE_NUM 65
//#define BLKDEV_CHECKPOINT_JOURNAL_SPACE 0.0078125
//#define BLKDEV_CHECKPOINT_JOURNAL_SPACE 0.125
#define BLKDEV_CHECKPOINT_JOURNAL_SPACE 0.05
#define BLKDEV_JOURNAL_PATH		"/dev/mapper/blkdev_journal"

struct blkdev_sb_info {
	struct journal_s *s_journal;
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
	struct block_device *blk_bdev;
	struct super_block *s_sb;
};

static inline struct blkdev_sb_info *BLKDEV_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

