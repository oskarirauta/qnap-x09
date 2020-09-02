/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-thin-metadata.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-disk.h"
#include "persistent-data/dm-transaction-manager.h"

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

/*--------------------------------------------------------------------------
 * As far as the metadata goes, there is:
 *
 * - A superblock in block zero, taking up fewer than 512 bytes for
 *   atomic writes.
 *
 * - A space map managing the metadata blocks.
 *
 * - A space map managing the data blocks.
 *
 * - A btree mapping our internal thin dev ids onto struct disk_device_details.
 *
 * - A hierarchical btree, with 2 levels which effectively maps (thin
 *   dev id, virtual block) -> block_time.  Block time is a 64-bit
 *   field holding the time in the low 24 bits, and block in the top 48
 *   bits.
 *
 * BTrees consist solely of btree_nodes, that fill a block.  Some are
 * internal nodes, as such their values are a __le64 pointing to other
 * nodes.  Leaf nodes can store data of any reasonable size (ie. much
 * smaller than the block size).  The nodes consist of the header,
 * followed by an array of keys, followed by an array of values.  We have
 * to binary search on the keys so they're all held together to help the
 * cpu cache.
 *
 * Space maps have 2 btrees:
 *
 * - One maps a uint64_t onto a struct index_entry.  Which points to a
 *   bitmap block, and has some details about how many free entries there
 *   are etc.
 *
 * - The bitmap blocks have a header (for the checksum).  Then the rest
 *   of the block is pairs of bits.  With the meaning being:
 *
 *   0 - ref count is 0
 *   1 - ref count is 1
 *   2 - ref count is 2
 *   3 - ref count is higher than 2
 *
 * - If the count is higher than 2 then the ref count is entered in a
 *   second btree that directly maps the block_address to a uint32_t ref
 *   count.
 *
 * The space map metadata variant doesn't have a bitmaps btree.  Instead
 * it has one single blocks worth of index_entries.  This avoids
 * recursive issues with the bitmap btree needing to allocate space in
 * order to insert.  With a small data block size such as 64k the
 * metadata support data devices that are hundreds of terrabytes.
 *
 * The space maps allocate space linearly from front to back.  Space that
 * is freed in a transaction is never recycled within that transaction.
 * To try and avoid fragmenting _free_ space the allocator always goes
 * back and fills in gaps.
 *
 * All metadata io is in THIN_METADATA_BLOCK_SIZE sized/aligned chunks
 * from the block manager.
 *--------------------------------------------------------------------------*/

#define DM_MSG_PREFIX   "thin metadata"

#define THIN_SUPERBLOCK_MAGIC 27022010
#define THIN_SUPERBLOCK_LOCATION 0
#define THIN_VERSION 4
#define THIN_METADATA_CACHE_SIZE 64
#define SECTOR_TO_BLOCK_SHIFT 3
#define SB_BACKUP_MAX_COUNT 128

/*
 *  3 for btree insert +
 *  2 for btree lookup used within space map
 */
#define THIN_MAX_CONCURRENT_LOCKS 5

/* This should be plenty */
#define SPACE_MAP_ROOT_SIZE 40

#define THIN_METADATA_BLOCK_SIZE 8192
#define THIN_METADATA_MAX_SECTORS (511 * (1 << 15) * (THIN_METADATA_BLOCK_SIZE / (1 << SECTOR_SHIFT)))
/*
 * Little endian on-disk superblock and device details.
 */
struct thin_disk_superblock {
	__le32 csum;	/* Checksum of superblock except for this field. */
	__le32 flags;
	__le64 blocknr;	/* This block number, dm_block_t. */

	__u8 uuid[16];
	__le64 magic;
	__le32 version;
	__le32 time;

	__le64 trans_id;

	/*
	 * Root held by userspace transactions.
	 */
	__le64 held_root;

	// PATCH: TIER
	__u8 data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 tier0_data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 tier1_data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__le32 rescan_needed;
	__u8 padding1[4];

	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 tier2_data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 padding2[48];

	/*
	 * 2-level btree mapping (dev_id, (dev block, time)) -> data block
	 */
	__le64 data_mapping_root;

	/*
	 * Device detail root mapping dev_id -> device_details
	 */
	__le64 device_details_root;

	__le32 data_block_size;		/* In 512-byte sectors. */

	__le32 metadata_block_size;	/* In 512-byte sectors. */
	__le64 metadata_nr_blocks;

	__le32 compat_flags;
	__le32 compat_ro_flags;
	__le32 incompat_flags;

	__le64 backup_id;
	__le64 reserve_block_count;

	/*
	 * Clone count root mapping pool block -> clone count
	 */
	__le64 clone_root;

	// PATCH: TIER
	__le32 tier_num;
	__le64 pool_mapping_root;
	__le32 tier_block_size;		/* In 512-byte sectors. */

} __packed;

struct disk_device_details {
	__le64 mapped_blocks;
	__le64 transaction_id;		/* When created. */
	__le32 creation_time;
	__le32 snapshotted_time;
	__le32 cloned_time;
	__le64 scaned_index;
	__le64 snap_origin;
} __packed;

struct dm_thin_device {
	struct list_head list;
	struct dm_pool_metadata *pmd;
	dm_thin_id id;

	int open_count;
	bool changed;
	bool aborted_with_changes;
	uint64_t mapped_blocks;
	uint64_t transaction_id;
	uint32_t creation_time;
	uint32_t snapshotted_time;
	uint32_t cloned_time;
	uint64_t scaned_index;
	uint64_t snap_origin;
};

/*----------------------------------------------------------------
 * superblock validator
 *--------------------------------------------------------------*/

#define SUPERBLOCK_CSUM_XOR 160774

/* ---- TIER ----*/
inline uint64_t pack_tier_block(uint32_t t, dm_block_t b, uint32_t res)
{
	return ((dm_block_t)t << 61) | (b << 24) | res;
}

inline void unpack_tier_block(uint64_t v, uint32_t *t, dm_block_t *b, uint32_t *res)
{
	*t = v >> 61;
	*b = (v >> 24) & (((dm_block_t)1 << 37) - 1);
	if (res)
		*res = v & ((1 << 24) - 1);
}

static bool __is_snapshot(struct dm_thin_device *td)
{
	return (td->snap_origin != ULLONG_MAX);
}

bool dm_thin_is_snapshot(struct dm_thin_device *td)
{
	bool is_snap;

	down_read(&td->pmd->root_lock);
	is_snap = __is_snapshot(td);
	up_read(&td->pmd->root_lock);

	return is_snap;
}

// PATCH: new btree manipulation function for tier_data_sm
static void tier_data_block_inc(void *context, const void *value_le)
{
	struct dm_space_map **sma = context;
	__le64 v_le;
	uint64_t nb;
	uint32_t tierid;
	uint32_t t;

	memcpy(&v_le, value_le, sizeof(v_le));
	unpack_tier_block(le64_to_cpu(v_le), &tierid, &nb, &t);
	dm_sm_inc_block(sma[tierid], nb);
}

static void tier_data_block_dec(void *context, const void *value_le)
{
	struct dm_space_map **sma = context;
	__le64 v_le;
	uint64_t nb;
	uint32_t tierid;
	uint32_t t;

	memcpy(&v_le, value_le, sizeof(v_le));
	unpack_tier_block(le64_to_cpu(v_le), &tierid, &nb, &t);
	dm_sm_dec_block(sma[tierid], nb);
}

static int tier_data_block_equal(void *context, const void *value1_le, const void *value2_le)
{
	__le64 v1_le, v2_le;
	uint64_t b1, b2;
	uint32_t t1, t2, r1, r2;

	memcpy(&v1_le, value1_le, sizeof(v1_le));
	memcpy(&v2_le, value2_le, sizeof(v2_le));
	unpack_tier_block(le64_to_cpu(v1_le), &t1, &b1, &r1);
	unpack_tier_block(le64_to_cpu(v2_le), &t2, &b2, &r2);

	return (b1 == b2) && (t1 == t2);
}

int dm_tier_find_block(struct dm_pool_metadata *pmd, dm_block_t block,
                       int can_block, struct dm_tier_lookup_result *result)
{
	int r = -EINVAL;
	__le64 value;
	uint64_t block_time = 0;
	struct dm_btree_info *info;

	if (can_block) {
		down_read(&pmd->root_lock);
		info = &pmd->pool_map_info;
	} else if (down_read_trylock(&pmd->root_lock))
		info = &pmd->nb_pool_map_info;
	else
		return -EWOULDBLOCK;

	r = dm_btree_lookup(info, pmd->pool_root, &block, &value);

	up_read(&pmd->root_lock);

	if (!r) {
		block_time = le64_to_cpu(value);
		unpack_tier_block(block_time, &result->tierid, &result->block, &result->reserve);
	}

	return r;
}

int dm_tier_set_alloc_tier(struct dm_pool_metadata *pmd, unsigned long alloc_tier)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	pmd->alloc_tier = alloc_tier;
	r = 0;
	up_write(&pmd->root_lock);

	return r;
}

int dm_tier_get_alloc_tier(struct dm_pool_metadata *pmd, unsigned long *alloc_tier)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	*alloc_tier = pmd->alloc_tier;
	r = 0;
	up_read(&pmd->root_lock);

	return r;
}

static const int find_seq[MAX_TIER_LEVEL][MAX_TIER_LEVEL] = {
	{0, 1, 2},
	{1, 2, 0},
	{2, 1, 0}
};

int dm_tier_find_free_tier_and_alloc(struct dm_pool_metadata *pmd, uint32_t *tierid, unsigned int enable_map, dm_block_t *result)
{
	int i, r = -EINVAL;
	const int *seq;
	dm_block_t free_blks = 0;

	down_write(&pmd->root_lock);

	seq = find_seq[pmd->alloc_tier];
	if (pmd->fail_io) {
		goto fail_io;
	}

	for (i = 0; i < MAX_TIER_LEVEL; i++) {
		if (!(enable_map & (1 << seq[i])))
			continue;

		r = dm_sm_get_nr_free(pmd->tier_data_sm[seq[i]], &free_blks);
		if (r)
			goto err_out;

		r = -ENOSPC;
		if (free_blks > pmd->swap_block[seq[i]]) {
			r = dm_sm_new_block(pmd->tier_data_sm[seq[i]], result);
			break;
		}
	}

	if (!r) {
		*tierid = (uint32_t)seq[i];
		pmd->need_commit = 1;
	}

err_out:
fail_io:
	up_write(&pmd->root_lock);

	return r;
}

int dm_tier_alloc_tier_data_block(struct dm_pool_metadata *pmd, dm_block_t *result, unsigned int tierid)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = dm_sm_new_block(pmd->tier_data_sm[tierid], result);
	pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

int dm_tier_insert_block(struct dm_pool_metadata *pmd, dm_block_t block,
                         dm_block_t data_block, uint32_t tierid)
{
	int r, inserted;
	__le64 value;

	value = cpu_to_le64(pack_tier_block(tierid, data_block, 0));
	__dm_bless_for_disk(&value);

	down_write(&pmd->root_lock);
	pmd->need_commit = 1;
	r = dm_btree_insert_notify(&pmd->pool_map_info, pmd->pool_root, &block,
	                           &value, &pmd->pool_root, &inserted);
	up_write(&pmd->root_lock);

	return r;
}

int dm_tier_insert_block_with_reserve(struct dm_pool_metadata *pmd, dm_block_t block,
                                      dm_block_t data_block, uint32_t tierid, uint32_t res)
{
	int r, inserted;
	__le64 value;

	value = cpu_to_le64(pack_tier_block(tierid, data_block, res));
	__dm_bless_for_disk(&value);

	down_write(&pmd->root_lock);
	pmd->need_commit = 1;
	r = dm_btree_insert_notify(&pmd->pool_map_info, pmd->pool_root, &block,
	                           &value, &pmd->pool_root, &inserted);
	up_write(&pmd->root_lock);

	return r;
}

static int __insert_block(struct dm_pool_metadata *pmd, dm_block_t block,
			dm_block_t data_block, uint32_t tierid, uint32_t res)
{
	int r, inserted;
	__le64 value;

	value = cpu_to_le64(pack_tier_block(tierid, data_block, res));
	__dm_bless_for_disk(&value);


	r = dm_btree_insert_notify(&pmd->pool_map_info, pmd->pool_root, &block,
					&value, &pmd->pool_root, &inserted);

	return r;
}

int dm_tier_insert_block_free_swap(struct dm_pool_metadata *pmd,  dm_block_t block, dm_block_t data_block,
							  uint32_t tierid, uint32_t res, uint32_t old_tierid)
{
	int r;

	down_write(&pmd->root_lock);
	r = __insert_block(pmd, block, data_block, tierid, res);
	if (!r) {
		pmd->swap_block[old_tierid]++;
		pmd->need_commit = 1;
	}
	up_write(&pmd->root_lock);

	return r;
}

int dm_tier_remove_block(struct dm_pool_metadata *pmd, dm_block_t block)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	pmd->need_commit = 1;
	r = dm_btree_remove(&pmd->pool_map_info, pmd->pool_root, &block, &pmd->pool_root);
	up_write(&pmd->root_lock);
	if (r)
		return r;

	return 0;
}

int dm_tier_alloc_blk_and_remove_swap(struct dm_pool_metadata *pmd, dm_block_t *result, unsigned int old_tierid, unsigned int new_tierid)
{
	int r = -EINVAL;
	dm_block_t free_blks;

	down_write(&pmd->root_lock);
	if (pmd->swap_block[old_tierid]) {
		pmd->swap_block[old_tierid]--;
	} else {
		r = -EBUSY;
		goto dec_swap_blk_err;
	}

	if (!pmd->fail_io)
		r = dm_sm_get_nr_free(pmd->tier_data_sm[new_tierid], &free_blks);
	if (r)
		goto get_free_err;

	r = -ENOSPC;
	if (free_blks <= pmd->swap_block[new_tierid])
		goto new_blk_err;
	else  {
		r = dm_sm_new_block(pmd->tier_data_sm[new_tierid], result);
		if (r)
			goto new_blk_err;
	}

	pmd->need_commit = 1;
	up_write(&pmd->root_lock);
	return r;

new_blk_err:
get_free_err:
	pmd->swap_block[old_tierid]++;
dec_swap_blk_err:
	pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

int dm_tier_set_swap_block(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t block)
{
	int r;
	dm_block_t result;

	down_write(&pmd->root_lock);
	r = dm_sm_get_nr_free(pmd->tier_data_sm[tierid], &result);
	if (r)
		goto err_out;

	if (result < block)
		r = -ENOSPC;
	else
		pmd->swap_block[tierid] = block;

err_out:
	up_write(&pmd->root_lock);
	return r;
}

int dm_tier_alloc_swap_block(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t *result)
{
	int r = -ENOSPC;

	down_write(&pmd->root_lock);

	if (!pmd->swap_block[tierid])
		goto err_out;

	r = dm_sm_new_block(pmd->tier_data_sm[tierid], result);
	if (r) {
		goto err_out;
	}

	pmd->swap_block[tierid]--;
	pmd->need_commit = 1;

err_out:
	up_write(&pmd->root_lock);

	return r;
}

int dm_tier_free_swap_block(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t block)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	r = dm_sm_dec_block(pmd->tier_data_sm[tierid], block);
	if (!r) {
		pmd->swap_block[tierid]++;
		pmd->need_commit = 1;
	} else
		DMINFO("%s:%d, free swp block error r(%d) !!", __func__, __LINE__, r);

	up_write(&pmd->root_lock);
	return r;
}

int dm_tier_get_swap_blkcnt(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t *blkcnt)
{
	int r = 0;

	down_read(&pmd->root_lock);
	*blkcnt = pmd->swap_block[tierid];
	up_read(&pmd->root_lock);
	return r;
}

int dm_pool_get_tier_data_dev_size(struct dm_pool_metadata *pmd, unsigned int tierid, dm_block_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = dm_sm_get_nr_blocks(pmd->tier_data_sm[tierid], result);
	up_read(&pmd->root_lock);

	return r;
}

int dm_pool_get_tier_data_dev_free_size(struct dm_pool_metadata *pmd, unsigned int tierid, dm_block_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = dm_sm_get_nr_free(pmd->tier_data_sm[tierid], result);
	up_read(&pmd->root_lock);

	return r;
}

static int __resize_space_map(struct dm_space_map *sm, dm_block_t new_count);
int dm_pool_resize_tier_data_dev(struct dm_pool_metadata *pmd, unsigned int tierid, dm_block_t new_count)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io) {
		if (tierid < pmd->tier_num)
			r = __resize_space_map(pmd->tier_data_sm[tierid], new_count);
		else
			DMERR("Cannot resize space map of unused tier");
	}
	pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

int tier_bitmap_scan(struct dm_pool_metadata **pmd, dm_block_t size)
{
	// Initialize bitmap, we will parse this later
	return dm_btree_walk_iter(&((*pmd)->pool_map_info), (*pmd)->pool_root, generator_map, pmd);
}

int tier_bitmap_display(struct dm_pool_metadata **pmd)
{
	return dm_btree_walk_iter(&((*pmd)->pool_map_info), (*pmd)->pool_root, display_map, pmd);
}

void tier_bitmap_set(struct dm_pool_metadata *pmd, int pos)
{
	//DMINFO("%s: set bitmap %u to 1", __func__, pos);
	down_write(&pmd->root_lock);
	bitmap_set(pmd->bitmap, pos, 1);
	up_write(&pmd->root_lock);
}

void tier_bitmap_clear(struct dm_pool_metadata *pmd, int pos)
{
	down_write(&pmd->root_lock);
	bitmap_clear(pmd->bitmap, pos, 1);
	up_write(&pmd->root_lock);
}

unsigned long tier_get_bitmap_size(struct dm_pool_metadata *pmd)
{
	unsigned long bitmapsize;

	down_read(&pmd->root_lock);
	bitmapsize = pmd->bitmapsize;
	up_read(&pmd->root_lock);

	return bitmapsize;
}

int tier_bitmap_copy(struct dm_pool_metadata *pmd, unsigned long **new_bitmap)
{
	*new_bitmap = vzalloc(BITS_TO_LONGS(pmd->bitmapsize) * sizeof(unsigned long));
	if (!(*new_bitmap)) {
		DMINFO("%s: allocate bitmap fail!!", __func__);
		return -ENOMEM;
	}

	down_read(&pmd->root_lock);
	bitmap_copy(*new_bitmap, pmd->bitmap, pmd->bitmapsize);
	up_read(&pmd->root_lock);
	return 0;
}

int dm_tier_inc_block_cnt(struct dm_pool_metadata *pmd, uint32_t tier, dm_block_t block)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	r = dm_sm_inc_block(pmd->tier_data_sm[tier], block);
	up_write(&pmd->root_lock);
	return r;
}

int dm_tier_dec_block_cnt(struct dm_pool_metadata *pmd, uint32_t tier, dm_block_t block)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	r = dm_sm_dec_block(pmd->tier_data_sm[tier], block);
	up_write(&pmd->root_lock);
	return r;
}

int pool_bitmap_maybe_resize(struct dm_pool_metadata *pmd, dm_block_t size)
{
	unsigned long *new_bitmap;
	unsigned long *old_bitmap;
	unsigned long old_size = pmd->bitmapsize;

	if (old_size == size) {
		return 0;
	}

	new_bitmap = vzalloc(BITS_TO_LONGS(size) * sizeof(unsigned long));
	if (!new_bitmap) {
		DMINFO("%s: allocate bitmap fail!!", __func__);
		return -ENOMEM;
	}

	old_bitmap = pmd->bitmap;
	down_write(&pmd->root_lock);
	if (old_size > 0)
		bitmap_copy(new_bitmap, pmd->bitmap, pmd->bitmapsize);
	pmd->bitmapsize = (unsigned long)size;
	pmd->bitmap = new_bitmap;
	up_write(&pmd->root_lock);

	if (old_size > 0)
		vfree(old_bitmap);

	return 0;
}
/* ---- TIER ----*/

static void sb_prepare_for_write(struct dm_block_validator *v,
                                 struct dm_block *b,
                                 size_t block_size)
{
	struct thin_disk_superblock *disk_super = dm_block_data(b);

	disk_super->blocknr = cpu_to_le64(dm_block_location(b));
	disk_super->csum = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
	                               block_size - sizeof(__le32),
	                               SUPERBLOCK_CSUM_XOR));
}

static int sb_check(struct dm_block_validator *v,
                    struct dm_block *b,
                    size_t block_size)
{
	struct thin_disk_superblock *disk_super = dm_block_data(b);
	__le32 csum_le;

	if (dm_block_location(b) != le64_to_cpu(disk_super->blocknr)) {
		DMERR("sb_check failed: blocknr %llu: "
		      "wanted %llu", le64_to_cpu(disk_super->blocknr),
		      (unsigned long long)dm_block_location(b));
		return -ENOTBLK;
	}

	if (le64_to_cpu(disk_super->magic) != THIN_SUPERBLOCK_MAGIC) {
		DMERR("sb_check failed: magic %llu: "
		      "wanted %llu", le64_to_cpu(disk_super->magic),
		      (unsigned long long)THIN_SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

	csum_le = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
	                                     block_size - sizeof(__le32),
	                                     SUPERBLOCK_CSUM_XOR));
	if (csum_le != disk_super->csum) {
		DMERR("sb_check failed: csum %u: wanted %u",
		      le32_to_cpu(csum_le), le32_to_cpu(disk_super->csum));
		return -EILSEQ;
	}

	return 0;
}

static struct dm_block_validator sb_validator = {
	.name = "superblock",
	.prepare_for_write = sb_prepare_for_write,
	.check = sb_check
};

static int sb_backup_check(struct dm_block_validator *v,
                           struct dm_block *b,
                           size_t block_size)
{
	struct thin_disk_superblock *disk_super = dm_block_data(b);
	__le32 csum_le;

	if (dm_block_location(b) != le64_to_cpu(disk_super->blocknr)) {
		DMDEBUG("sb_backup_check failed: blocknr %llu: "
		        "wanted %llu", le64_to_cpu(disk_super->blocknr),
		        (unsigned long long)dm_block_location(b));
		return -ENOTBLK;
	}

	if (le64_to_cpu(disk_super->magic) != THIN_SUPERBLOCK_MAGIC) {
		DMERR("sb_backup_check failed: magic %llu: "
		      "wanted %llu", le64_to_cpu(disk_super->magic),
		      (unsigned long long)THIN_SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

	csum_le = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
	                                     block_size - sizeof(__le32),
	                                     SUPERBLOCK_CSUM_XOR));
	if (csum_le != disk_super->csum) {
		DMERR("sb_backup_check failed: csum %u: wanted %u",
		      le32_to_cpu(csum_le), le32_to_cpu(disk_super->csum));
		return -EILSEQ;
	}

	return 0;
}

static struct dm_block_validator sb_backup_validator = {
	.name = "superblock_backup",
	.prepare_for_write = sb_prepare_for_write,
	.check = sb_backup_check
};

static int __support_sb_backup(struct dm_pool_metadata *pmd)
{
	return (pmd->flags & THIN_FEATURE_SUPERBLOCK_BACKUP) ? 1 : 0;
}

static int __support_fast_block_clone(struct dm_pool_metadata *pmd)
{
	return (pmd->flags & THIN_FEATURE_FAST_BLOCK_CLONE) ? 1 : 0;
}

int support_fast_block_clone(struct dm_pool_metadata *pmd)
{
	int r;

	down_read(&pmd->root_lock);
	r = __support_fast_block_clone(pmd);
	up_read(&pmd->root_lock);

	return r;
}

/*----------------------------------------------------------------
 * Methods for the btree value types
 *--------------------------------------------------------------*/

static uint64_t pack_block_time(dm_block_t b, uint32_t t, unsigned z)
{
	return (b << 24) | ((z & 3) << 22) | (t & ((1 << 22) - 1));
}

static void unpack_block_time(uint64_t v, dm_block_t *b, uint32_t *t, unsigned *z)
{
	*b = v >> 24;
	*z = (v >> 22) & 3;
	*t = v & ((1 << 22) - 1);
}

static void data_block_inc(void *context, const void *value_le)
{
	struct dm_space_map *sm = context;
	__le64 v_le;
	uint64_t b;
	uint32_t t;
	unsigned dummy;

	memcpy(&v_le, value_le, sizeof(v_le));
	unpack_block_time(le64_to_cpu(v_le), &b, &t, &dummy);
	dm_sm_inc_block(sm, b);
}

static void data_block_dec(void *context, const void *value_le)
{
	struct dm_space_map *sm = context;
	__le64 v_le;
	uint64_t b;
	uint32_t t;
	unsigned dummy;

	memcpy(&v_le, value_le, sizeof(v_le));
	unpack_block_time(le64_to_cpu(v_le), &b, &t, &dummy);
	dm_sm_dec_block(sm, b);
}

static int data_block_equal(void *context, const void *value1_le, const void *value2_le)
{
	__le64 v1_le, v2_le;
	uint64_t b1, b2;
	uint32_t t;
	unsigned dummy;

	memcpy(&v1_le, value1_le, sizeof(v1_le));
	memcpy(&v2_le, value2_le, sizeof(v2_le));
	unpack_block_time(le64_to_cpu(v1_le), &b1, &t, &dummy);
	unpack_block_time(le64_to_cpu(v2_le), &b2, &t, &dummy);

	return b1 == b2;
}

static void subtree_inc(void *context, const void *value)
{
	struct dm_btree_info *info = context;
	__le64 root_le;
	uint64_t root;

	memcpy(&root_le, value, sizeof(root_le));
	root = le64_to_cpu(root_le);
	dm_tm_inc(info->tm, root);
}

static void subtree_dec(void *context, const void *value)
{
	struct dm_btree_info *info = context;
	__le64 root_le;
	uint64_t root;

	memcpy(&root_le, value, sizeof(root_le));
	root = le64_to_cpu(root_le);
	if (dm_btree_del(info, root))
		DMERR("btree delete failed\n");
}

static int subtree_equal(void *context, const void *value1_le, const void *value2_le)
{
	__le64 v1_le, v2_le;
	memcpy(&v1_le, value1_le, sizeof(v1_le));
	memcpy(&v2_le, value2_le, sizeof(v2_le));

	return v1_le == v2_le;
}

static int __inc_clone_block(struct dm_pool_metadata *pmd, dm_block_t b);
static int __dec_clone_block(struct dm_pool_metadata *pmd, dm_block_t b);

/*----------------------------------------------------------------*/

static int backup_superblock_lock(struct dm_pool_metadata *pmd,
                                  struct dm_block **sblock, dm_block_t index)
{
	return dm_bm_write_lock(pmd->bm, dm_bm_nr_blocks(pmd->bm) - index,
	                        &sb_backup_validator, sblock);
}

static int backup_superblock_lock_zero(struct dm_pool_metadata *pmd,
                                       struct dm_block **sblock, dm_block_t index)
{
	return dm_bm_write_lock_zero(pmd->bm, dm_bm_nr_blocks(pmd->bm) - index,
	                             &sb_backup_validator, sblock);
}

static int superblock_lock_zero(struct dm_pool_metadata *pmd,
                                struct dm_block **sblock)
{
	return dm_bm_write_lock_zero(pmd->bm, THIN_SUPERBLOCK_LOCATION,
	                             &sb_validator, sblock);
}

static int superblock_lock(struct dm_pool_metadata *pmd,
                           struct dm_block **sblock)
{
	return dm_bm_write_lock(pmd->bm, THIN_SUPERBLOCK_LOCATION,
	                        &sb_validator, sblock);
}

static int __superblock_all_zeroes(struct dm_block_manager *bm, int *result)
{
	int r;
	unsigned i;
	struct dm_block *b;
	__le64 *data_le, zero = cpu_to_le64(0);
	unsigned block_size = dm_bm_block_size(bm) / sizeof(__le64);

	/*
	 * We can't use a validator here - it may be all zeroes.
	 */
	r = dm_bm_read_lock(bm, THIN_SUPERBLOCK_LOCATION, NULL, &b);
	if (r)
		return r;

	data_le = dm_block_data(b);
	*result = 1;
	for (i = 0; i < block_size; i++) {
		if (data_le[i] != zero) {
			*result = 0;
			break;
		}
	}

	return dm_bm_unlock(b);
}

static void __setup_btree_details(struct dm_pool_metadata *pmd)
{
	pmd->info.tm = pmd->tm;
	pmd->info.levels = 2;
	pmd->info.value_type.context = pmd->data_sm;
	pmd->info.value_type.size = sizeof(__le64);
	pmd->info.value_type.inc = data_block_inc;
	pmd->info.value_type.dec = data_block_dec;
	pmd->info.value_type.equal = data_block_equal;

	memcpy(&pmd->nb_info, &pmd->info, sizeof(pmd->nb_info));
	pmd->nb_info.tm = pmd->nb_tm;

	pmd->tl_info.tm = pmd->tm;
	pmd->tl_info.levels = 1;
	pmd->tl_info.value_type.context = &pmd->bl_info;
	pmd->tl_info.value_type.size = sizeof(__le64);
	pmd->tl_info.value_type.inc = subtree_inc;
	pmd->tl_info.value_type.dec = subtree_dec;
	pmd->tl_info.value_type.equal = subtree_equal;

	pmd->bl_info.tm = pmd->tm;
	pmd->bl_info.levels = 1;
	pmd->bl_info.value_type.context = pmd->data_sm;
	pmd->bl_info.value_type.size = sizeof(__le64);
	pmd->bl_info.value_type.inc = data_block_inc;
	pmd->bl_info.value_type.dec = data_block_dec;
	pmd->bl_info.value_type.equal = data_block_equal;

	pmd->details_info.tm = pmd->tm;
	pmd->details_info.levels = 1;
	pmd->details_info.value_type.context = NULL;
	pmd->details_info.value_type.size = sizeof(struct disk_device_details);
	pmd->details_info.value_type.inc = NULL;
	pmd->details_info.value_type.dec = NULL;
	pmd->details_info.value_type.equal = NULL;

	pmd->clone_info.tm = pmd->tm;
	pmd->clone_info.levels = 1;
	pmd->clone_info.value_type.context = NULL;
	pmd->clone_info.value_type.size = sizeof(__le32);
	pmd->clone_info.value_type.inc = NULL;
	pmd->clone_info.value_type.dec = NULL;
	pmd->clone_info.value_type.equal = NULL;

	//PATCH: TIER
	pmd->pool_map_info.tm = pmd->tm;
	pmd->pool_map_info.levels = 1;
	pmd->pool_map_info.value_type.context = pmd->tier_data_sm;
	pmd->pool_map_info.value_type.inc = tier_data_block_inc;
	pmd->pool_map_info.value_type.dec = tier_data_block_dec;
	pmd->pool_map_info.value_type.size = sizeof(__le64);
	pmd->pool_map_info.value_type.equal = tier_data_block_equal;

	memcpy(&pmd->nb_pool_map_info, &pmd->pool_map_info, sizeof(pmd->nb_pool_map_info));
	pmd->nb_pool_map_info.tm = pmd->nb_tm;
}

static int backup_superblock(struct dm_pool_metadata *pmd, struct thin_disk_superblock *new_super)
{
	int r;
	struct dm_block *bsblock;
	struct thin_disk_superblock *disk_super;

	if (!__support_sb_backup(pmd)) {
		DMDEBUG("Superblock backup unsupported, bypass...");
		return 0;
	}

	if (pmd->backup_id / SB_BACKUP_MAX_COUNT)
		r = backup_superblock_lock(pmd, &bsblock, (pmd->backup_id % SB_BACKUP_MAX_COUNT) + 1);
	else
		r = backup_superblock_lock_zero(pmd, &bsblock, (pmd->backup_id % SB_BACKUP_MAX_COUNT) + 1);

	if (r) {
		pmd->backup_id++;
		return r;
	}

	disk_super = dm_block_data(bsblock);
	memcpy(disk_super, new_super, sizeof(struct thin_disk_superblock));

	disk_super->backup_id = cpu_to_le64(pmd->backup_id++);

	return dm_tm_backup_commit(pmd->tm, bsblock);
}

static int locate_backup_id(struct dm_pool_metadata *pmd, uint64_t *backup_id)
{
	int i, r;
	uint64_t bid;
	bool located = false;
	struct dm_block *bsblock;
	struct thin_disk_superblock *b_disk_super;

	*backup_id = 0;

	for (i = 1; i <= SB_BACKUP_MAX_COUNT; i++) {
		r = dm_bm_read_lock(pmd->bm, dm_bm_nr_blocks(pmd->bm) - i,
		                    &sb_backup_validator, &bsblock);
		if (r < 0) {
			DMDEBUG("couldn't read backup superblock, locate_backup_id continue");
			continue;
		}

		b_disk_super = dm_block_data(bsblock);
		bid = le64_to_cpu(b_disk_super->backup_id);
		DMDEBUG("%s: bid = %llu", __func__, bid);

		if (bid >= *backup_id) {
			*backup_id = bid;
			located = true;
		}

		DMDEBUG("%s: block %d, set backup id to %llu", __func__, i, *backup_id);
		dm_bm_unlock(bsblock);
	}

	if (located)
		*backup_id += 1;

	DMDEBUG("%s: return backup_id = %llu", __func__, *backup_id);
	return 0;
}

static int __write_initial_superblock(struct dm_pool_metadata *pmd)
{
	int r, i = 0;
	struct dm_block *sblock;
	size_t metadata_len, data_len;
	struct thin_disk_superblock *disk_super;
	sector_t bdev_size = i_size_read(pmd->bdev->bd_inode) >> SECTOR_SHIFT;
	void *tier_data_space_map_root = NULL;

	if (bdev_size > THIN_METADATA_MAX_SECTORS)
		bdev_size = THIN_METADATA_MAX_SECTORS;

	r = dm_sm_root_size(pmd->metadata_sm, &metadata_len);
	if (r < 0)
		return r;

	r = dm_sm_root_size(pmd->data_sm, &data_len);
	if (r < 0)
		return r;

	r = dm_sm_commit(pmd->data_sm);
	if (r < 0)
		return r;

	// PATCH: TIER
	for (i = 0; i < pmd->tier_num; i++) {
		r = dm_sm_commit(pmd->tier_data_sm[i]);
		if (r < 0)
			return r;
	}

	r = dm_tm_pre_commit(pmd->tm);
	if (r < 0)
		return r;
	DMINFO("%s:%d, commit dm sm complete !!", __func__, __LINE__);

	r = superblock_lock_zero(pmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	disk_super->flags = cpu_to_le32(THIN_FEATURE_SUPERBLOCK_BACKUP | THIN_FEATURE_FAST_BLOCK_CLONE);
	memset(disk_super->uuid, 0, sizeof(disk_super->uuid));
	disk_super->magic = cpu_to_le64(THIN_SUPERBLOCK_MAGIC);
	disk_super->version = cpu_to_le32(THIN_VERSION);
	disk_super->time = 1;
	disk_super->trans_id = 0;
	disk_super->held_root = 0;
	disk_super->reserve_block_count = 0;
	DMINFO("%s:%d, set disk super complete !!", __func__, __LINE__);

	r = dm_sm_copy_root(pmd->metadata_sm, &disk_super->metadata_space_map_root,
	                    metadata_len);
	if (r < 0)
		goto bad_locked;
	DMINFO("%s:%d, copy  metadata_sm complete !!", __func__, __LINE__);

	r = dm_sm_copy_root(pmd->data_sm, &disk_super->data_space_map_root,
	                    data_len);
	if (r < 0)
		goto bad_locked;
	DMINFO("%s:%d, copy  data_sm complete !!", __func__, __LINE__);

	for (i = 0; i < pmd->tier_num; i++) {
		switch (i) {
		case 0:
			tier_data_space_map_root = &disk_super->tier0_data_space_map_root;
			break;
		case 1:
			tier_data_space_map_root = &disk_super->tier1_data_space_map_root;
			break;
		case 2:
			tier_data_space_map_root = &disk_super->tier2_data_space_map_root;
			break;
		}

		r = dm_sm_copy_root(pmd->tier_data_sm[i], tier_data_space_map_root,
		                    data_len);
		if (r < 0)
			goto bad_locked;
	}

	disk_super->data_mapping_root = cpu_to_le64(pmd->root);
	disk_super->device_details_root = cpu_to_le64(pmd->details_root);
	disk_super->clone_root = cpu_to_le64(pmd->clone_root);

	// PATCH: TIER
	disk_super->pool_mapping_root = cpu_to_le64(pmd->pool_root);
	disk_super->tier_block_size = cpu_to_le32(pmd->tier_block_size);

	disk_super->metadata_block_size = cpu_to_le32(THIN_METADATA_BLOCK_SIZE >> SECTOR_SHIFT);
	disk_super->metadata_nr_blocks = cpu_to_le64(bdev_size >> SECTOR_TO_BLOCK_SHIFT);
	disk_super->data_block_size = cpu_to_le32(pmd->data_block_size);

	// PATCH: TIER
	disk_super->tier_num = cpu_to_le32(pmd->tier_num);

	pmd->backup_id = 0;
	if (backup_superblock(pmd, disk_super)) {
		DMERR_LIMIT("%s: backup superblock failed", __func__);
		pmd->sb_backup_fail++;
	}

	DMDEBUG("%s: backup superblock finished. commit origin sb", __func__);

	r = dm_tm_commit(pmd->tm, sblock);
	if (!r)
		pmd->need_commit = 0;

	DMINFO("%s:%d, Leave !!", __func__, __LINE__);
	return r;
bad_locked:
	dm_bm_unlock(sblock);
	return r;
}

static int __format_metadata(struct dm_pool_metadata *pmd)
{
	int r, i = 0, j = 0;

	r = dm_tm_create_with_sm(pmd->bm, THIN_SUPERBLOCK_LOCATION,
	                         SB_BACKUP_MAX_COUNT, &pmd->tm, &pmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_create_with_sm failed");
		return r;
	}

	pmd->data_sm = dm_sm_disk_create(pmd->tm, 0);
	if (IS_ERR(pmd->data_sm)) {
		DMERR("sm_disk_create failed");
		r = PTR_ERR(pmd->data_sm);
		goto bad_cleanup_tm;
	}

	// PATCH: TIER
	for (i = 0; i < pmd->tier_num; i++) {
		pmd->tier_data_sm[i] = dm_sm_disk_create(pmd->tm, 0);
		if (IS_ERR(pmd->tier_data_sm[i])) {
			DMERR("sm_disk_create tier sm failed");
			r = PTR_ERR(pmd->tier_data_sm[i]);
			goto bad_cleanup_data_sm;
		}
	}
	DMINFO("%s: tier_data_sm create finish", __func__);

	pmd->nb_tm = dm_tm_create_non_blocking_clone(pmd->tm);
	if (!pmd->nb_tm) {
		DMERR("could not create non-blocking clone tm");
		r = -ENOMEM;
		goto bad_cleanup_data_sm;
	}

	__setup_btree_details(pmd);

	r = dm_btree_empty(&pmd->info, &pmd->root);
	if (r < 0)
		goto bad_cleanup_nb_tm;

	r = dm_btree_empty(&pmd->details_info, &pmd->details_root);
	if (r < 0) {
		DMERR("couldn't create devices root");
		goto bad_cleanup_nb_tm;
	}

	r = dm_btree_empty(&pmd->clone_info, &pmd->clone_root);
	if (r < 0) {
		DMERR("couldn't create clone root");
		goto bad_cleanup_nb_tm;
	}

	// PATCH: TIER
	r = dm_btree_empty(&pmd->pool_map_info, &pmd->pool_root);
	if (r < 0) {
		DMERR("couldn't create pool map root");
		goto bad_cleanup_nb_tm;
	}

	DMINFO("%s: clear all info and details_info btree", __func__);

	r = __write_initial_superblock(pmd);
	if (r)
		goto bad_cleanup_nb_tm;

	return 0;

bad_cleanup_nb_tm:
	dm_tm_destroy(pmd->nb_tm);
bad_cleanup_data_sm:
	dm_sm_destroy(pmd->data_sm);
	for (; j < i; j++)
		dm_sm_destroy(pmd->tier_data_sm[j]);
bad_cleanup_tm:
	dm_tm_destroy(pmd->tm);
	dm_sm_destroy(pmd->metadata_sm);

	return r;
}

static int __check_incompat_features(struct thin_disk_superblock *disk_super,
                                     struct dm_pool_metadata *pmd)
{
	uint32_t features;
	unsigned long flags;

	features = le32_to_cpu(disk_super->incompat_flags) & ~THIN_FEATURE_INCOMPAT_SUPP;
	if (features) {
		DMERR("could not access metadata due to unsupported optional features (%lx).",
		      (unsigned long)features);
		return -EINVAL;
	}

	/*
	 * Version check
	 */
	if (le32_to_cpu(disk_super->version) > THIN_VERSION) {
		DMERR("metadata version is not compatible with current supported version");
		return -EVERSION;
	} else if (le32_to_cpu(disk_super->version) < THIN_VERSION) {
		flags = le32_to_cpu(disk_super->flags);
		switch (le32_to_cpu(disk_super->version)) {
		case 1:
		case 2:
			DMINFO("pool version: %u, mask superblock and fast block clone feature", le32_to_cpu(disk_super->version));
			flags &= ~(THIN_FEATURE_SUPERBLOCK_BACKUP | THIN_FEATURE_FAST_BLOCK_CLONE);
			break;
		case 3:
			DMINFO("pool version: 3, mask fast block clone feature");
			flags &= ~(THIN_FEATURE_FAST_BLOCK_CLONE);
			break;
		default:
			DMERR("unknown dm-thin version %u", le32_to_cpu(disk_super->version));
			return -EVERSION;
		}
		disk_super->flags = cpu_to_le32(flags);
	}

	/*
	 * Check for read-only metadata to skip the following RDWR checks.
	 */
	if (get_disk_ro(pmd->bdev->bd_disk))
		return 0;

	features = le32_to_cpu(disk_super->compat_ro_flags) & ~THIN_FEATURE_COMPAT_RO_SUPP;
	if (features) {
		DMERR("could not access metadata RDWR due to unsupported optional features (%lx).",
		      (unsigned long)features);
		return -EINVAL;
	}

	return 0;
}

struct old_disk_device_details {
	__le64 mapped_blocks;
	__le64 transaction_id;          /* When created. */
	__le32 creation_time;
	__le32 snapshotted_time;
	__le64 snap_origin;
} __packed;

static int check_clone_root(struct dm_pool_metadata *pmd, struct thin_disk_superblock *disk_super)
{
	dm_block_t root;

	root = le64_to_cpu(disk_super->clone_root);
	if (!root) {
		pmd->old_type = true;
		disk_super->reserve_block_count = 0;
		pmd->details_info.value_type.size = sizeof(struct old_disk_device_details);
	}

	return 0;
}

static int __init_new_features(struct dm_pool_metadata *pmd, struct thin_disk_superblock *disk_super)
{
	int r;

	r = locate_backup_id(pmd, &pmd->backup_id);
	if (r)
		return r;

	r = check_clone_root(pmd, disk_super);
	if (r)
		return r;

	return 0;
}

static int __open_metadata(struct dm_pool_metadata *pmd)
{
	int r, i = 0, j = 0;
	struct dm_block *sblock;
	struct thin_disk_superblock *disk_super;
	void *tier_data_space_map_root = NULL;
	int data_len = 0;

	/* use write lock since we might need to init new feature */
	r = dm_bm_write_lock(pmd->bm, THIN_SUPERBLOCK_LOCATION,
	                     &sb_validator, &sblock);
	if (r < 0) {
		DMERR("couldn't read superblock");
		return r;
	}

	disk_super = dm_block_data(sblock);

	r = __check_incompat_features(disk_super, pmd);
	if (r < 0)
		goto bad_unlock_sblock;

	r = dm_tm_open_with_sm(pmd->bm, THIN_SUPERBLOCK_LOCATION,
	                       disk_super->metadata_space_map_root,
	                       sizeof(disk_super->metadata_space_map_root),
	                       &pmd->tm, &pmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_open_with_sm failed");
		goto bad_unlock_sblock;
	}

	pmd->data_sm = dm_sm_disk_open(pmd->tm, disk_super->data_space_map_root,
	                               sizeof(disk_super->data_space_map_root));
	if (IS_ERR(pmd->data_sm)) {
		DMERR("sm_disk_open failed");
		r = PTR_ERR(pmd->data_sm);
		goto bad_cleanup_tm;
	}

	for (i = 0; i < pmd->tier_num; i++) {
		switch (i) {
		case 0:
			tier_data_space_map_root = disk_super->tier0_data_space_map_root;
			data_len = sizeof(disk_super->tier0_data_space_map_root);
			break;
		case 1:
			tier_data_space_map_root = disk_super->tier1_data_space_map_root;
			data_len = sizeof(disk_super->tier1_data_space_map_root);
			break;
		case 2:
			tier_data_space_map_root = disk_super->tier2_data_space_map_root;
			data_len = sizeof(disk_super->tier2_data_space_map_root);
			break;
		}

		pmd->tier_data_sm[i] = dm_sm_disk_open(pmd->tm, tier_data_space_map_root,
		                                       data_len);
		if (IS_ERR(pmd->tier_data_sm[i])) {
			DMERR("sm_disk_open tier data sm failed");
			r = PTR_ERR(pmd->tier_data_sm[i]);
			goto bad_cleanup_data_sm;
		}
	}


	pmd->nb_tm = dm_tm_create_non_blocking_clone(pmd->tm);
	if (!pmd->nb_tm) {
		DMERR("could not create non-blocking clone tm");
		r = -ENOMEM;
		goto bad_cleanup_data_sm;
	}

	__setup_btree_details(pmd);

	r = __init_new_features(pmd, disk_super);
	if (r < 0) {
		DMERR("init new feature failed");
		goto bad_cleanup_nb_tm;
	}

	dm_bm_unlock(sblock);

	return 0;

bad_cleanup_nb_tm:
	dm_tm_destroy(pmd->nb_tm);
bad_cleanup_data_sm:
	for (; j < i; j++)
		dm_sm_destroy(pmd->tier_data_sm[j]);
	dm_sm_destroy(pmd->data_sm);
bad_cleanup_tm:
	dm_tm_destroy(pmd->tm);
	dm_sm_destroy(pmd->metadata_sm);
bad_unlock_sblock:
	dm_bm_unlock(sblock);

	return r;
}

static int __open_or_format_metadata(struct dm_pool_metadata *pmd, bool format_device, int unformatted)
{
	if (unformatted)
		return format_device ? __format_metadata(pmd) : -EPERM;

	return __open_metadata(pmd);
}

static struct dm_block_manager* __get_correct_block_manager(struct dm_pool_metadata *pmd, int *unformatted)
{
	int version, r = 0;
	struct dm_block *sblock;
	struct dm_block_manager *bm = NULL;

	for (version = 1; version >= 0; version--) {
		if (bm) {
			DMERR("%s: free old bm", __func__);
			dm_block_manager_destroy(bm);
		}

		bm = dm_block_manager_create(pmd->bdev, 4096 << version,
		                             THIN_METADATA_CACHE_SIZE,
		                             THIN_MAX_CONCURRENT_LOCKS);
		if (!IS_ERR(bm)) {
			if (version == 1) {
				r = __superblock_all_zeroes(bm, unformatted);
				if (r || *unformatted)
					break;
			}

			r = dm_bm_read_lock(bm, THIN_SUPERBLOCK_LOCATION, &sb_validator, &sblock);
			if (r)
				continue;

			dm_bm_unlock(sblock);
		}
		break;
	}

	pmd->metadata_block_size = (4096 << version) >> SECTOR_SHIFT;
	if (r)
		bm = ERR_PTR(r);

	return bm;
}

static int __create_persistent_data_objects(struct dm_pool_metadata *pmd, bool format_device)
{
	int r, unformatted;

	pmd->bm = __get_correct_block_manager(pmd, &unformatted);
	if (IS_ERR(pmd->bm)) {
		DMERR("could not create block manager");
		return PTR_ERR(pmd->bm);
	}

	DMERR("%s: block manger get correctly", __func__);

	r = __open_or_format_metadata(pmd, format_device, unformatted);
	if (r)
		dm_block_manager_destroy(pmd->bm);

	return r;
}

static void __destroy_persistent_data_objects(struct dm_pool_metadata *pmd)
{
	unsigned i = 0;

	//PATCH: TIER
	for (; i < pmd->tier_num; i++) {
		if (pmd->tier_data_sm[i])
			dm_sm_destroy(pmd->tier_data_sm[i]);
	}

	dm_sm_destroy(pmd->data_sm);
	dm_sm_destroy(pmd->metadata_sm);
	dm_tm_destroy(pmd->nb_tm);
	dm_tm_destroy(pmd->tm);
	dm_block_manager_destroy(pmd->bm);

	// PATCH: free bitmap
	if (pmd->bitmap)
		vfree(pmd->bitmap);
}

static int __begin_transaction(struct dm_pool_metadata *pmd)
{
	int r;
	struct thin_disk_superblock *disk_super;
	struct dm_block *sblock;

	/*
	 * __maybe_commit_transaction() resets these
	 */
	WARN_ON(pmd->need_commit);

	/*
	 * We re-read the superblock every time.  Shouldn't need to do this
	 * really.
	 */
	r = dm_bm_read_lock(pmd->bm, THIN_SUPERBLOCK_LOCATION,
	                    &sb_validator, &sblock);
	if (r) {
		DMERR("%s: read superblock failed", __func__);
		return r;
	}

	disk_super = dm_block_data(sblock);
	pmd->time = le32_to_cpu(disk_super->time);
	pmd->root = le64_to_cpu(disk_super->data_mapping_root);
	pmd->details_root = le64_to_cpu(disk_super->device_details_root);
	pmd->clone_root = le64_to_cpu(disk_super->clone_root);
	pmd->rescan_needed = le32_to_cpu(disk_super->rescan_needed);

	// PATCH: TIER
	pmd->pool_root = le64_to_cpu(disk_super->pool_mapping_root);
	pmd->tier_block_size = le32_to_cpu(disk_super->tier_block_size);

	pmd->trans_id = le64_to_cpu(disk_super->trans_id);
	pmd->flags = le32_to_cpu(disk_super->flags);
	pmd->data_block_size = le32_to_cpu(disk_super->data_block_size);
	pmd->reserve_block_count = le64_to_cpu(disk_super->reserve_block_count);

	// PATCH: TIER
	pmd->tier_num = le32_to_cpu(disk_super->tier_num);

	dm_bm_unlock(sblock);
	return 0;
}

static int __write_changed_details(struct dm_pool_metadata *pmd)
{
	int r;
	void *comp_details;
	struct dm_thin_device *td, *tmp;
	struct disk_device_details details;
	struct old_disk_device_details old_details;
	uint64_t key;

	list_for_each_entry_safe(td, tmp, &pmd->thin_devices, list) {
		if (!td->changed)
			continue;

		key = td->id;

		if (pmd->old_type) {
			old_details.mapped_blocks = cpu_to_le64(td->mapped_blocks);
			old_details.transaction_id = cpu_to_le64(td->transaction_id);
			old_details.creation_time = cpu_to_le32(td->creation_time);
			old_details.snapshotted_time = cpu_to_le32(td->snapshotted_time);
			old_details.snap_origin = cpu_to_le64(td->snap_origin);
			comp_details = &old_details;
		} else {
			details.mapped_blocks = cpu_to_le64(td->mapped_blocks);
			details.scaned_index = cpu_to_le64(td->scaned_index);
			details.transaction_id = cpu_to_le64(td->transaction_id);
			details.creation_time = cpu_to_le32(td->creation_time);
			details.snapshotted_time = cpu_to_le32(td->snapshotted_time);
			details.cloned_time = cpu_to_le32(td->cloned_time);
			details.snap_origin = cpu_to_le64(td->snap_origin);
			comp_details = &details;
		}

		__dm_bless_for_disk(comp_details);


		r = dm_btree_insert(&pmd->details_info, pmd->details_root,
		                    &key, comp_details, &pmd->details_root);
		if (r)
			return r;

		if (td->open_count)
			td->changed = false;
		else {
			list_del(&td->list);
			kfree(td);
		}

		pmd->need_commit = 1;
	}

	return 0;
}

static int __commit_transaction(struct dm_pool_metadata *pmd)
{
	int r, i = 0;
	size_t metadata_len, data_len;
	struct thin_disk_superblock *disk_super;
	struct dm_block *sblock;
	void *tier_data_space_map_root = NULL;

	/*
	 * We need to know if the thin_disk_superblock exceeds a 512-byte sector.
	 */
	BUILD_BUG_ON(sizeof(struct thin_disk_superblock) > 512);

	r = __write_changed_details(pmd);
	if (r < 0)
		return r;

	if (!pmd->need_commit)
		return r;

	r = dm_sm_commit(pmd->data_sm);
	if (r < 0)
		return r;

	// PATCH: Commit all tiering data sm
	for (i = 0; i < pmd->tier_num; i++) {
		r = dm_sm_commit(pmd->tier_data_sm[i]);
		if (r < 0)
			return r;
	}

	r = dm_tm_pre_commit(pmd->tm);
	if (r < 0)
		return r;

	r = dm_sm_root_size(pmd->metadata_sm, &metadata_len);
	if (r < 0)
		return r;

	r = dm_sm_root_size(pmd->data_sm, &data_len);
	if (r < 0)
		return r;

	r = superblock_lock(pmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	disk_super->time = cpu_to_le32(pmd->time);
	disk_super->data_mapping_root = cpu_to_le64(pmd->root);

	// PATCH: TIER
	disk_super->pool_mapping_root = cpu_to_le64(pmd->pool_root);
	disk_super->tier_block_size = cpu_to_le32(pmd->tier_block_size);

	disk_super->device_details_root = cpu_to_le64(pmd->details_root);
	disk_super->clone_root = cpu_to_le64(pmd->clone_root);
	disk_super->trans_id = cpu_to_le64(pmd->trans_id);
	disk_super->flags = cpu_to_le32(pmd->flags);
	disk_super->reserve_block_count = cpu_to_le64(pmd->reserve_block_count);
	disk_super->rescan_needed = cpu_to_le32(pmd->rescan_needed);

	// PATCH: TIER
	disk_super->tier_num = cpu_to_le32(pmd->tier_num);

	r = dm_sm_copy_root(pmd->metadata_sm, &disk_super->metadata_space_map_root,
	                    metadata_len);
	if (r < 0)
		goto out_locked;

	r = dm_sm_copy_root(pmd->data_sm, &disk_super->data_space_map_root,
	                    data_len);
	if (r < 0)
		goto out_locked;

	for (i = 0; i < pmd->tier_num; i++) {
		switch (i) {
		case 0:
			tier_data_space_map_root = &disk_super->tier0_data_space_map_root;
			break;
		case 1:
			tier_data_space_map_root = &disk_super->tier1_data_space_map_root;
			break;
		case 2:
			tier_data_space_map_root = &disk_super->tier2_data_space_map_root;
			break;
		}

		r = dm_sm_copy_root(pmd->tier_data_sm[i], tier_data_space_map_root,
		                    data_len);
		if (r < 0)
			goto out_locked;
	}


	if (backup_superblock(pmd, disk_super)) {
		DMERR_LIMIT("%s: backup superblock failed", __func__);
		pmd->sb_backup_fail++;
	}

	r = dm_tm_commit(pmd->tm, sblock);
	if (!r)
		pmd->need_commit = 0;

	return r;
out_locked:
	dm_bm_unlock(sblock);
	return r;
}

struct dm_pool_metadata *dm_pool_metadata_open(struct block_device *bdev,
        sector_t data_block_size,
        bool format_device, unsigned int tier_num, unsigned long alloc_tier, dm_block_t tier_blk_size)
{
	int r;
	struct dm_pool_metadata *pmd;

	pmd = kmalloc(sizeof(*pmd), GFP_KERNEL);
	if (!pmd) {
		DMERR("could not allocate metadata struct");
		return ERR_PTR(-ENOMEM);
	}

	init_rwsem(&pmd->root_lock);
	pmd->time = 1;
	INIT_LIST_HEAD(&pmd->thin_devices);
	pmd->read_only = false;
	pmd->fail_io = false;
	pmd->bdev = bdev;
	pmd->data_block_size = data_block_size;
	pmd->need_commit = 0;
	pmd->sb_backup_fail = 0;
	pmd->reserve_threshold = 0;
	pmd->reserve_block_count = 0;
	pmd->old_type = false;

	//PATCH: TIER
	pmd->tier_num = tier_num;
	pmd->alloc_tier = alloc_tier;
	pmd->bitmap = NULL;
	pmd->bitmapsize = 0;
	pmd->tier_block_size = tier_blk_size;


	r = __create_persistent_data_objects(pmd, format_device);
	if (r) {
		kfree(pmd);
		return ERR_PTR(r);
	}

	r = __begin_transaction(pmd);
	if (r < 0) {
		if (dm_pool_metadata_close(pmd) < 0)
			DMWARN("%s: dm_pool_metadata_close() failed.", __func__);
		return ERR_PTR(r);
	}

	return pmd;
}

int dm_pool_metadata_close(struct dm_pool_metadata *pmd)
{
	int r;
	unsigned open_devices = 0;
	struct dm_thin_device *td, *tmp;

	down_read(&pmd->root_lock);
	list_for_each_entry_safe(td, tmp, &pmd->thin_devices, list) {
		if (td->open_count)
			open_devices++;
		else {
			list_del(&td->list);
			kfree(td);
		}
	}
	up_read(&pmd->root_lock);

	if (open_devices) {
		DMERR("attempt to close pmd when %u device(s) are still open",
		      open_devices);
		return -EBUSY;
	}

	if (!pmd->read_only && !pmd->fail_io) {
		r = __commit_transaction(pmd);
		if (r < 0)
			DMWARN("%s: __commit_transaction() failed, error = %d",
			       __func__, r);
	}

	if (!pmd->fail_io)
		__destroy_persistent_data_objects(pmd);

	kfree(pmd);
	return 0;
}

static int __alloc_new_device(struct dm_pool_metadata *pmd,
                              dm_thin_id dev,
                              struct disk_device_details *details_le,
                              struct dm_thin_device **td,
                              bool changed)
{
	*td = kmalloc(sizeof(**td), GFP_NOIO);
	if (!*td)
		return -ENOMEM;

	(*td)->pmd = pmd;
	(*td)->id = dev;
	(*td)->open_count = 1;
	(*td)->changed = changed;
	(*td)->aborted_with_changes = false;
	(*td)->mapped_blocks = le64_to_cpu(details_le->mapped_blocks);
	(*td)->transaction_id = le64_to_cpu(details_le->transaction_id);
	(*td)->creation_time = le32_to_cpu(details_le->creation_time);
	(*td)->snapshotted_time = le32_to_cpu(details_le->snapshotted_time);
	(*td)->cloned_time = le32_to_cpu(details_le->cloned_time);
	(*td)->scaned_index = le64_to_cpu(details_le->scaned_index);
	(*td)->snap_origin = le64_to_cpu(details_le->snap_origin);

	return 0;
}

/*
 * __open_new_device: Returns @td corresponding to device with id @dev,
 * creating it if @create is set and incrementing @td->open_count.
 * On failure, @td is undefined.
 */
static int __open_new_device(struct dm_pool_metadata *pmd,
                             dm_thin_id dev, int create,
                             struct dm_thin_device **td)
{
	int r;
	bool changed = false;
	struct dm_thin_device *td2;
	uint64_t key = dev;
	struct disk_device_details details_le;

	/*
	 * If the device is already open, return it.
	 */
	list_for_each_entry(td2, &pmd->thin_devices, list)
	if (td2->id == dev) {
		/*
		 * May not create an already-open device.
		 */
		if (create)
			return -EEXIST;

		td2->open_count++;
		*td = td2;
		return 0;
	}

	/*
	 * Check the device exists.
	 */
	r = dm_btree_lookup(&pmd->details_info, pmd->details_root,
	                    &key, &details_le);
	if (r) {
		if (r != -ENODATA || !create)
			return r;

		/*
		 * Create new device.
		 */
		changed = true;
		details_le.mapped_blocks = 0;
		details_le.scaned_index = SCAN_FINISH;
		details_le.transaction_id = cpu_to_le64(pmd->trans_id);
		details_le.creation_time = cpu_to_le32(pmd->time);
		details_le.snapshotted_time = cpu_to_le32(pmd->time);
		details_le.cloned_time = cpu_to_le32(pmd->time);
		details_le.snap_origin = cpu_to_le64(ULLONG_MAX);
	}

	r = __alloc_new_device(pmd, dev, &details_le, td, changed);
	if (r)
		return r;

	list_add(&(*td)->list, &pmd->thin_devices);

	return 0;
}

static int __open_old_device(struct dm_pool_metadata *pmd,
                             dm_thin_id dev, int create,
                             struct dm_thin_device **td)
{
	int r;
	bool changed = false;
	struct dm_thin_device *td2;
	uint64_t key = dev;
	struct old_disk_device_details details_le;

	/*
	 * If the device is already open, return it.
	*/
	list_for_each_entry(td2, &pmd->thin_devices, list)
	if (td2->id == dev) {
		/*
		 * May not create an already-open device.
		 */
		if (create)
			return -EEXIST;

		td2->open_count++;
		*td = td2;
		return 0;
	}

	/*
	 * Check the device exists.
	 */
	r = dm_btree_lookup(&pmd->details_info, pmd->details_root,
	                    &key, &details_le);
	if (r) {
		if (r != -ENODATA || !create)
			return r;

		/*
		 * Create new device.
		 */
		changed = true;
		details_le.mapped_blocks = 0;
		details_le.transaction_id = cpu_to_le64(pmd->trans_id);
		details_le.creation_time = cpu_to_le32(pmd->time);
		details_le.snapshotted_time = cpu_to_le32(pmd->time);
		details_le.snap_origin = cpu_to_le64(ULLONG_MAX);
	}

	*td = kmalloc(sizeof(**td), GFP_NOIO);
	if (!*td)
		return -ENOMEM;

	(*td)->pmd = pmd;
	(*td)->id = dev;
	(*td)->open_count = 1;
	(*td)->changed = changed;
	(*td)->aborted_with_changes = false;
	(*td)->mapped_blocks = le64_to_cpu(details_le.mapped_blocks);
	(*td)->transaction_id = le64_to_cpu(details_le.transaction_id);
	(*td)->creation_time = le32_to_cpu(details_le.creation_time);
	(*td)->snapshotted_time = le32_to_cpu(details_le.snapshotted_time);
	(*td)->cloned_time = le32_to_cpu(0);
	(*td)->scaned_index = le64_to_cpu(SCAN_FINISH);
	(*td)->snap_origin = le64_to_cpu(details_le.snap_origin);

	list_add(&(*td)->list, &pmd->thin_devices);

	return 0;
}

static int __open_device(struct dm_pool_metadata *pmd,
                         dm_thin_id dev, int create,
                         struct dm_thin_device **td)
{
	if (pmd->old_type)
		return __open_old_device(pmd, dev, create, td);
	else
		return __open_new_device(pmd, dev, create, td);
}

static void __close_device(struct dm_thin_device *td)
{
	--td->open_count;
}

static int __create_thin(struct dm_pool_metadata *pmd,
                         dm_thin_id dev)
{
	int r;
	dm_block_t dev_root;
	uint64_t key = dev;
	struct disk_device_details details_le;
	struct old_disk_device_details old_details_le;
	struct dm_thin_device *td;
	__le64 value;

	r = dm_btree_lookup(&pmd->details_info, pmd->details_root, &key,
	                    (pmd->old_type ? (void *)&old_details_le : (void *)&details_le));

	if (!r)
		return -EEXIST;

	/*
	 * Create an empty btree for the mappings.
	 */
	r = dm_btree_empty(&pmd->bl_info, &dev_root);
	if (r)
		return r;

	/*
	 * Insert it into the main mapping tree.
	 */
	value = cpu_to_le64(dev_root);
	__dm_bless_for_disk(&value);
	r = dm_btree_insert(&pmd->tl_info, pmd->root, &key, &value, &pmd->root);
	if (r) {
		dm_btree_del(&pmd->bl_info, dev_root);
		return r;
	}

	r = __open_device(pmd, dev, 1, &td);
	if (r) {
		dm_btree_remove(&pmd->tl_info, pmd->root, &key, &pmd->root);
		dm_btree_del(&pmd->bl_info, dev_root);
		return r;
	}
	__close_device(td);

	return r;
}

int dm_pool_create_thin(struct dm_pool_metadata *pmd, dm_thin_id dev)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __create_thin(pmd, dev);
	if (!r)
		pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

static int __set_snapshot_details(struct dm_pool_metadata *pmd,
                                  struct dm_thin_device *snap,
                                  dm_thin_id origin, uint32_t time)
{
	int r;
	struct dm_thin_device *td;

	r = __open_device(pmd, origin, 0, &td);
	if (r)
		return r;

	td->changed = true;
	td->snapshotted_time = time;

	snap->mapped_blocks = td->mapped_blocks;
	snap->snapshotted_time = time;
	snap->cloned_time = 1; // Treat all mappings as non-clone
	snap->snap_origin = origin;
	__close_device(td);

	return 0;
}

static int __set_clone_details(struct dm_pool_metadata *pmd,
                               struct dm_thin_device *clone,
                               dm_thin_id origin, uint32_t time)
{
	int r;
	struct dm_thin_device *td;

	r = __open_device(pmd, origin, 0, &td);
	if (r)
		return r;

	clone->cloned_time = time;
	clone->snapshotted_time = 1;
	clone->snap_origin = ULLONG_MAX;
	clone->scaned_index = 0;
	clone->mapped_blocks = td->mapped_blocks;

	/* For cloning snapshot, we leave snapshot cloned time untouched */
	td->changed = true;
	if (!__is_snapshot(td))
		td->cloned_time = time;

	__close_device(td);

	return 0;
}

static int __create_snap(struct dm_pool_metadata *pmd,
                         dm_thin_id dev, dm_thin_id origin, bool is_clone)
{
	int r;
	dm_block_t origin_root;
	uint64_t key = origin, dev_key = dev;
	struct dm_thin_device *td;
	struct disk_device_details details_le;
	struct old_disk_device_details old_details_le;
	__le64 value;

	/* check this device is unused */
	r = dm_btree_lookup(&pmd->details_info, pmd->details_root,
	                    &dev_key, (pmd->old_type ? &old_details_le : &details_le));
	if (!r)
		return -EEXIST;

	/* find the mapping tree for the origin */
	r = dm_btree_lookup(&pmd->tl_info, pmd->root, &key, &value);
	if (r)
		return r;
	origin_root = le64_to_cpu(value);

	/* clone the origin, an inc will do */
	dm_tm_inc(pmd->tm, origin_root);

	/* insert into the main mapping tree */
	value = cpu_to_le64(origin_root);
	__dm_bless_for_disk(&value);
	key = dev;
	r = dm_btree_insert(&pmd->tl_info, pmd->root, &key, &value, &pmd->root);
	if (r) {
		dm_tm_dec(pmd->tm, origin_root);
		return r;
	}

	pmd->time++;
	r = __open_device(pmd, dev, 1, &td);
	if (r)
		goto bad;

	if (!is_clone)
		r = __set_snapshot_details(pmd, td, origin, pmd->time);
	else
		r = __set_clone_details(pmd, td, origin, pmd->time);

	__close_device(td);

	if (r)
		goto bad;

	return 0;

bad:
	dm_btree_remove(&pmd->tl_info, pmd->root, &key, &pmd->root);
	dm_btree_remove(&pmd->details_info, pmd->details_root,
	                &key, &pmd->details_root);
	return r;
}

int dm_pool_create_snap(struct dm_pool_metadata *pmd,
                        dm_thin_id dev,
                        dm_thin_id origin)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __create_snap(pmd, dev, origin, false);
	if (!r)
		pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

static int __get_origin_mapped_blocks(struct dm_pool_metadata *pmd, dm_block_t *b)
{
	struct dm_thin_device *td;

	*b = 0;
	list_for_each_entry(td, &pmd->thin_devices, list) {
		if (!__is_snapshot(td))
			*b += td->mapped_blocks;
	}

	return 0;
}

int dm_pool_get_origin_mapped_blocks(struct dm_pool_metadata *pmd, dm_block_t *b)
{
	down_write(&pmd->root_lock);
	__get_origin_mapped_blocks(pmd, b);
	up_write(&pmd->root_lock);
	return 0;
}

int dm_pool_register_reserve_threshold(struct dm_pool_metadata *pmd, dm_block_t threshold)
{
	int r = 0;
	dm_block_t b;

	down_write(&pmd->root_lock);
	r = __get_origin_mapped_blocks(pmd, &b);
	if (r)
		goto err_out;

	DMERR("%s: threshold: %llu oc_blocks: %llu", __func__, threshold, b);
	if (threshold && b > threshold)
		r = -EINVAL;
	else
		pmd->reserve_threshold = threshold;
err_out:
	up_write(&pmd->root_lock);

	return r;
}

static int __reserve_block(struct dm_pool_metadata *pmd, int action, dm_block_t size)
{
	dm_block_t free_blks, oc_blocks, *reserve;

	reserve = &pmd->reserve_block_count;

	dm_sm_get_nr_free(pmd->data_sm, &free_blks);
	__get_origin_mapped_blocks(pmd, &oc_blocks);

	if (action & RES_CLONE_INC) {
		if ((free_blks >= pmd->reserve_block_count + size) &&
		    (!pmd->reserve_threshold || pmd->reserve_threshold >= oc_blocks + size))
			*reserve += size;
		else
			return -ENOSPC;
	} else if ((action & RES_CLONE_DEC) && *reserve >= size)
		*reserve -= size;
	else
		return -EINVAL;

	pmd->need_commit = 1;
	return 0;
}

int dm_pool_create_clone(struct dm_pool_metadata *pmd,
                         dm_thin_id dev, dm_thin_id origin)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io && __support_fast_block_clone(pmd))
		r = __create_snap(pmd, dev, origin, true);

	if (!r)
		pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

static int __delete_device(struct dm_pool_metadata *pmd, dm_thin_id dev)
{
	int r;
	uint64_t key = dev;
	struct dm_thin_device *td;

	/* TODO: failure should mark the transaction invalid */
	r = __open_device(pmd, dev, 0, &td);
	if (r)
		return r;

	if (td->open_count > 1) {
		__close_device(td);
		return -EBUSY;
	}

	list_del(&td->list);
	kfree(td);
	r = dm_btree_remove(&pmd->details_info, pmd->details_root,
	                    &key, &pmd->details_root);
	if (r)
		return r;

	r = dm_btree_remove(&pmd->tl_info, pmd->root, &key, &pmd->root);
	if (r)
		return r;

	pmd->need_commit = 1;

	return 0;
}

int dm_pool_delete_thin_device(struct dm_pool_metadata *pmd,
                               dm_thin_id dev)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __delete_device(pmd, dev);
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_set_metadata_transaction_id(struct dm_pool_metadata *pmd,
                                        uint64_t current_id,
                                        uint64_t new_id)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);

	if (pmd->fail_io)
		goto out;

	if (pmd->trans_id != current_id) {
		DMERR("mismatched transaction id");
		goto out;
	}

	pmd->trans_id = new_id;
	pmd->need_commit = 1;
	r = 0;

out:
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_get_metadata_transaction_id(struct dm_pool_metadata *pmd,
                                        uint64_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io) {
		*result = pmd->trans_id;
		r = 0;
	}
	up_read(&pmd->root_lock);

	return r;
}

static int __reserve_metadata_snap(struct dm_pool_metadata *pmd)
{
	int r, inc;
	struct thin_disk_superblock *disk_super;
	struct dm_block *copy, *sblock;
	dm_block_t held_root;

	/*
	 * Copy the superblock.
	 */
	dm_sm_inc_block(pmd->metadata_sm, THIN_SUPERBLOCK_LOCATION);
	r = dm_tm_shadow_block(pmd->tm, THIN_SUPERBLOCK_LOCATION,
	                       &sb_validator, &copy, &inc);
	if (r)
		return r;

	BUG_ON(!inc);

	held_root = dm_block_location(copy);
	disk_super = dm_block_data(copy);

	if (le64_to_cpu(disk_super->held_root)) {
		DMWARN("Pool metadata snapshot already exists: release this before taking another.");

		dm_tm_dec(pmd->tm, held_root);
		dm_tm_unlock(pmd->tm, copy);
		pmd->need_commit = 1;
		return -EBUSY;
	}

	/*
	 * Wipe the spacemap since we're not publishing this.
	 */
	memset(&disk_super->data_space_map_root, 0,
	       sizeof(disk_super->data_space_map_root));
	memset(&disk_super->metadata_space_map_root, 0,
	       sizeof(disk_super->metadata_space_map_root));

	/*
	 * Increment the data structures that need to be preserved.
	 */
	dm_tm_inc(pmd->tm, le64_to_cpu(disk_super->data_mapping_root));
	dm_tm_inc(pmd->tm, le64_to_cpu(disk_super->device_details_root));
	dm_tm_unlock(pmd->tm, copy);

	/*
	 * Write the held root into the superblock.
	 */
	r = superblock_lock(pmd, &sblock);
	if (r) {
		dm_tm_dec(pmd->tm, held_root);
		pmd->need_commit = 1;
		return r;
	}

	disk_super = dm_block_data(sblock);
	disk_super->held_root = cpu_to_le64(held_root);
	dm_bm_unlock(sblock);
	pmd->need_commit = 1;
	return 0;
}

int dm_pool_reserve_metadata_snap(struct dm_pool_metadata *pmd)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __reserve_metadata_snap(pmd);
	up_write(&pmd->root_lock);

	return r;
}

static int __release_metadata_snap(struct dm_pool_metadata *pmd)
{
	int r;
	struct thin_disk_superblock *disk_super;
	struct dm_block *sblock, *copy;
	dm_block_t held_root;

	r = superblock_lock(pmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	held_root = le64_to_cpu(disk_super->held_root);
	disk_super->held_root = cpu_to_le64(0);
	pmd->need_commit = 1;

	dm_bm_unlock(sblock);

	if (!held_root) {
		DMWARN("No pool metadata snapshot found: nothing to release.");
		return -EINVAL;
	}

	r = dm_tm_read_lock(pmd->tm, held_root, &sb_validator, &copy);
	if (r)
		return r;

	disk_super = dm_block_data(copy);
	dm_sm_dec_block(pmd->metadata_sm, le64_to_cpu(disk_super->data_mapping_root));
	dm_sm_dec_block(pmd->metadata_sm, le64_to_cpu(disk_super->device_details_root));
	dm_sm_dec_block(pmd->metadata_sm, held_root);

	return dm_tm_unlock(pmd->tm, copy);
}

int dm_pool_release_metadata_snap(struct dm_pool_metadata *pmd)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __release_metadata_snap(pmd);
	up_write(&pmd->root_lock);

	return r;
}

#define ON true
#define OFF false

static int __turn_feature(struct dm_pool_metadata *pmd, unsigned long feature, bool onoff)
{
	int r;
	unsigned long new_flags;
	struct dm_block *sblock;
	struct thin_disk_superblock *disk_super;

	r = superblock_lock(pmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);

	new_flags = (onoff) ? le32_to_cpu(disk_super->flags) | feature :
	            le32_to_cpu(disk_super->flags) & ~feature;
	pmd->flags = new_flags;
	pmd->need_commit = 1;
	disk_super->flags = cpu_to_le32(new_flags);

	dm_bm_unlock(sblock);
	DMINFO("%s: set flags to %lx", __func__, new_flags);

	return 0;
}

int dm_pool_start_backup_sb(struct dm_pool_metadata *pmd)
{
	int r;

	down_write(&pmd->root_lock);
	r = __turn_feature(pmd, THIN_FEATURE_SUPERBLOCK_BACKUP, ON);
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_stop_backup_sb(struct dm_pool_metadata *pmd)
{
	int r;

	down_write(&pmd->root_lock);
	r = __turn_feature(pmd, THIN_FEATURE_SUPERBLOCK_BACKUP, OFF);
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_enable_block_clone(struct dm_pool_metadata *pmd)
{
	int r;

	down_write(&pmd->root_lock);
	r = __turn_feature(pmd, THIN_FEATURE_FAST_BLOCK_CLONE, ON);
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_disable_block_clone(struct dm_pool_metadata *pmd)
{
	int r;

	down_write(&pmd->root_lock);
	r = __turn_feature(pmd, THIN_FEATURE_FAST_BLOCK_CLONE, OFF);
	up_write(&pmd->root_lock);

	return r;
}

static int __get_metadata_snap(struct dm_pool_metadata *pmd,
                               dm_block_t *result)
{
	int r;
	struct thin_disk_superblock *disk_super;
	struct dm_block *sblock;

	r = dm_bm_read_lock(pmd->bm, THIN_SUPERBLOCK_LOCATION,
	                    &sb_validator, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	*result = le64_to_cpu(disk_super->held_root);

	return dm_bm_unlock(sblock);
}

int dm_pool_get_metadata_snap(struct dm_pool_metadata *pmd,
                              dm_block_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __get_metadata_snap(pmd, result);
	up_read(&pmd->root_lock);

	return r;
}

int dm_pool_open_thin_device(struct dm_pool_metadata *pmd, dm_thin_id dev,
                             struct dm_thin_device **td)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __open_device(pmd, dev, 0, td);
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_close_thin_device(struct dm_thin_device *td)
{
	down_write(&td->pmd->root_lock);
	__close_device(td);
	up_write(&td->pmd->root_lock);

	return 0;
}

dm_thin_id dm_thin_dev_id(struct dm_thin_device *td)
{
	return td->id;
}

/*
 * Check whether @time (of block creation) is older than @td's last snapshot.
 * If so then the associated block is shared with the last snapshot device.
 * Any block on a device created *after* the device last got snapshotted is
 * necessarily not shared.
 */
static bool __snapshotted_since(struct dm_thin_device *td, uint32_t time)
{
	return td->snapshotted_time > time;
}

static bool __cloned_since(struct dm_thin_device *td, uint32_t time)
{
	return td->cloned_time > time;
}

static void unpack_lookup_result(struct dm_thin_device *td,
                                 uint64_t block_time,
                                 struct dm_thin_lookup_result *result)
{
	dm_block_t exception_block;
	uint32_t exception_time;
	unsigned zeroed;

	unpack_block_time(block_time, &exception_block,
	                  &exception_time, &zeroed);

	result->block = exception_block;
	result->cloned = __cloned_since(td, exception_time);
	result->shared = __snapshotted_since(td, exception_time) | result->cloned;
	result->time = exception_time;
	result->zeroed = zeroed;
	//DMERR("%s: block %llu cloned %u shared %u time %u zeroed %u cloned_time %u",
	//      __func__, result->block, result->cloned, result->shared, result->time, result->zeroed, td->cloned_time);
}

int dm_thin_find_block(struct dm_thin_device *td, dm_block_t block,
                       int can_issue_io, struct dm_thin_lookup_result *result)
{
	int r = -EINVAL;
	uint64_t block_time = 0;
	__le64 value;
	struct dm_pool_metadata *pmd = td->pmd;
	dm_block_t keys[2] = { td->id, block };
	struct dm_btree_info *info;

	if (can_issue_io) {
		down_read(&pmd->root_lock);
		info = &pmd->info;
	} else if (down_read_trylock(&pmd->root_lock))
		info = &pmd->nb_info;
	else
		return -EWOULDBLOCK;

	if (pmd->fail_io)
		goto out;

	r = dm_btree_lookup(info, pmd->root, keys, &value);
	if (!r)
		block_time = le64_to_cpu(value);

out:
	up_read(&pmd->root_lock);

	if (!r)
		unpack_lookup_result(td, block_time, result);

	return r;
}

static int __insert(struct dm_thin_device *td, dm_block_t block,
                    dm_block_t data_block, unsigned zeroed, uint32_t *time)
{
	int r, inserted;
	__le64 value;
	struct dm_pool_metadata *pmd = td->pmd;
	dm_block_t keys[2] = { td->id, block };

	pmd->need_commit = 1;
	value = cpu_to_le64(pack_block_time(data_block,
	                                    (time) ? *time : pmd->time,
	                                    zeroed));
	__dm_bless_for_disk(&value);

	r = dm_btree_insert_notify(&pmd->info, pmd->root, keys, &value,
	                           &pmd->root, &inserted);
	if (r)
		return r;

	td->changed = true;
	if (inserted)
		td->mapped_blocks++;

	return 0;
}

int dm_thin_insert_block_with_time(struct dm_thin_device *td, dm_block_t block,
                                   dm_block_t data_block, dm_block_t old_block, unsigned zeroed, uint32_t *time, int flag)
{
	int r = -EINVAL;

	down_write(&td->pmd->root_lock);
	if (!td->pmd->fail_io)
		r = __insert(td, block, data_block, zeroed, time);
	if (!r && !__is_snapshot(td)) {
		switch (flag) {
		case INSERT_OVERWRITE:
			r = __dec_clone_block(td->pmd, old_block);
			if (r)
				break;
		case INSERT_NEW:
			r = __inc_clone_block(td->pmd, data_block);
			break;
		case INSERT_REFLAG:
		default:
			break;
		}
	}
	up_write(&td->pmd->root_lock);

	return r;
}

int dm_thin_insert_block(struct dm_thin_device *td, dm_block_t block,
                         dm_block_t data_block, dm_block_t old_block, unsigned zeroed, int flag)
{
	int r = -EINVAL;

	down_write(&td->pmd->root_lock);
	if (!td->pmd->fail_io)
		r = __insert(td, block, data_block, zeroed, NULL);
	if (!r && !__is_snapshot(td)) {
		switch (flag) {
		case INSERT_OVERWRITE:
			r = __dec_clone_block(td->pmd, old_block);
			if (r)
				break;
		case INSERT_NEW:
			r = __inc_clone_block(td->pmd, data_block);
			break;
		case INSERT_REFLAG:
		default:
			break;
		}
	}
	up_write(&td->pmd->root_lock);

	return r;
}

static int __remove(struct dm_thin_device *td, dm_block_t block)
{
	int r;
	struct dm_pool_metadata *pmd = td->pmd;
	dm_block_t keys[2] = { td->id, block };

	r = dm_btree_remove(&pmd->info, pmd->root, keys, &pmd->root);
	if (r)
		return r;

	td->mapped_blocks--;
	td->changed = true;
	pmd->need_commit = 1;

	return 0;
}

int dm_thin_remove_block(struct dm_thin_device *td, dm_block_t block, dm_block_t *pblock)
{
	int r = -EINVAL;

	down_write(&td->pmd->root_lock);
	if (!td->pmd->fail_io)
		r = __remove(td, block);
	if (!r && !__is_snapshot(td) && block < td->scaned_index) {
		BUG_ON(pblock == NULL);
		r = __dec_clone_block(td->pmd, *pblock);
	}

	up_write(&td->pmd->root_lock);

	return r;
}

int dm_pool_block_is_used(struct dm_pool_metadata *pmd, dm_block_t b, bool *result)
{
	int r;
	uint32_t ref_count;

	down_read(&pmd->root_lock);
	r = dm_sm_get_count(pmd->data_sm, b, &ref_count);
	if (!r)
		*result = (ref_count != 0);
	up_read(&pmd->root_lock);

	return r;
}


bool dm_thin_changed_this_transaction(struct dm_thin_device *td)
{
	int r;

	down_read(&td->pmd->root_lock);
	r = td->changed;
	up_read(&td->pmd->root_lock);

	return r;
}

bool dm_thin_aborted_changes(struct dm_thin_device *td)
{
	bool r;

	down_read(&td->pmd->root_lock);
	r = td->aborted_with_changes;
	up_read(&td->pmd->root_lock);

	return r;
}

int dm_pool_alloc_data_block(struct dm_pool_metadata *pmd, dm_block_t *result, int for_snap)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io) {
		dm_block_t b;

		if (!for_snap) {
			r = __get_origin_mapped_blocks(pmd, &b);
			if (r)
				goto err_out;

			if (pmd->reserve_threshold && b >= pmd->reserve_threshold) {
				r = -ENOSPC;
				goto err_out;
			}
		}

		r = dm_sm_new_block(pmd->data_sm, result);
	}
	if (!r)
		pmd->need_commit = 1;
err_out:
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_alloc_reserve_data_block(struct dm_pool_metadata *pmd, dm_block_t *result)
{
	int r = -EINVAL;
	dm_block_t block = *result;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io) {
		r = __dec_clone_block(pmd, block);
		if (r) {
			DMERR("%s: decrease clone block count for block %llu failed", __func__, *result);
			goto err_out;
		}

		r = dm_sm_new_block(pmd->data_sm, result);
		if (!r)
			pmd->need_commit = 1;
		else
			__inc_clone_block(pmd, block);
	}
err_out:
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_commit_metadata(struct dm_pool_metadata *pmd)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (pmd->fail_io)
		goto out;

	r = __commit_transaction(pmd);
	if (r <= 0)
		goto out;

	/*
	 * Open the next transaction.
	 */
	r = __begin_transaction(pmd);
out:
	up_write(&pmd->root_lock);
	return r;
}

static void __set_abort_with_changes_flags(struct dm_pool_metadata *pmd)
{
	struct dm_thin_device *td;

	list_for_each_entry(td, &pmd->thin_devices, list)
	td->aborted_with_changes = td->changed;
}

int dm_pool_abort_metadata(struct dm_pool_metadata *pmd)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (pmd->fail_io)
		goto out;

	__set_abort_with_changes_flags(pmd);
	__destroy_persistent_data_objects(pmd);
	r = __create_persistent_data_objects(pmd, false);
	if (r)
		pmd->fail_io = true;

out:
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_get_free_block_count(struct dm_pool_metadata *pmd, dm_block_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = dm_sm_get_nr_free(pmd->data_sm, result);

	*result -= pmd->reserve_block_count;
	up_read(&pmd->root_lock);

	return r;
}

int dm_pool_get_free_metadata_block_count(struct dm_pool_metadata *pmd,
        dm_block_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = dm_sm_get_nr_free(pmd->metadata_sm, result);
	up_read(&pmd->root_lock);

	return r;
}

int dm_pool_get_metadata_dev_size(struct dm_pool_metadata *pmd,
                                  dm_block_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = dm_sm_get_nr_blocks(pmd->metadata_sm, result);
	up_read(&pmd->root_lock);

	return r;
}

int dm_pool_get_data_block_size(struct dm_pool_metadata *pmd, sector_t *result)
{
	down_read(&pmd->root_lock);
	*result = pmd->data_block_size;
	up_read(&pmd->root_lock);

	return 0;
}

int dm_pool_get_data_dev_size(struct dm_pool_metadata *pmd, dm_block_t *result)
{
	int r = -EINVAL;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = dm_sm_get_nr_blocks(pmd->data_sm, result);
	up_read(&pmd->root_lock);

	return r;
}

int dm_thin_get_mapped_count(struct dm_thin_device *td, dm_block_t *result)
{
	int r = -EINVAL;
	struct dm_pool_metadata *pmd = td->pmd;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io) {
		*result = td->mapped_blocks;
		r = 0;
	}
	up_read(&pmd->root_lock);

	return r;
}

static int __highest_block(struct dm_thin_device *td, dm_block_t *result)
{
	int r;
	__le64 value_le;
	dm_block_t thin_root;
	struct dm_pool_metadata *pmd = td->pmd;

	r = dm_btree_lookup(&pmd->tl_info, pmd->root, &td->id, &value_le);
	if (r)
		return r;

	thin_root = le64_to_cpu(value_le);

	return dm_btree_find_highest_key(&pmd->bl_info, thin_root, result);
}

int dm_thin_get_highest_mapped_block(struct dm_thin_device *td,
                                     dm_block_t *result)
{
	int r = -EINVAL;
	struct dm_pool_metadata *pmd = td->pmd;

	down_read(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __highest_block(td, result);
	up_read(&pmd->root_lock);

	return r;
}

static int __resize_space_map(struct dm_space_map *sm, dm_block_t new_count)
{
	int r;
	dm_block_t old_count;

	r = dm_sm_get_nr_blocks(sm, &old_count);
	if (r)
		return r;

	if (new_count == old_count)
		return 0;

	if (new_count < old_count) {
		DMERR("cannot reduce size of space map");
		return -EINVAL;
	}

	return dm_sm_extend(sm, new_count - old_count);
}

int dm_pool_resize_data_dev(struct dm_pool_metadata *pmd, dm_block_t new_count)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __resize_space_map(pmd->data_sm, new_count);
	if (!r)
		pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_resize_metadata_dev(struct dm_pool_metadata *pmd, dm_block_t new_count)
{
	int r = -EINVAL;

	down_write(&pmd->root_lock);
	if (!pmd->fail_io)
		r = __resize_space_map(pmd->metadata_sm, new_count);
	if (!r)
		pmd->need_commit = 1;
	up_write(&pmd->root_lock);

	return r;
}

void dm_pool_metadata_read_only(struct dm_pool_metadata *pmd)
{
	down_write(&pmd->root_lock);
	pmd->read_only = true;
	dm_bm_set_read_only(pmd->bm);
	up_write(&pmd->root_lock);
}

void dm_pool_metadata_read_write(struct dm_pool_metadata *pmd)
{
	down_write(&pmd->root_lock);
	pmd->read_only = false;
	dm_bm_set_read_write(pmd->bm);
	up_write(&pmd->root_lock);
}

int dm_pool_register_metadata_threshold(struct dm_pool_metadata *pmd,
                                        dm_block_t threshold,
                                        dm_sm_threshold_fn fn,
                                        void *context)
{
	int r;

	down_write(&pmd->root_lock);
	r = dm_sm_register_threshold_callback(pmd->metadata_sm, threshold, fn, context);
	up_write(&pmd->root_lock);

	return r;
}

int dm_thin_deploy(struct dm_thin_device *td, dm_block_t block, dm_block_t *result)
{
	int r;
	__le64 value;
	struct dm_pool_metadata *pmd = td->pmd;
	dm_block_t keys[2] = { td->id, block };
	uint64_t block_time = 0;
	uint32_t ltime;
	unsigned zeroed;

	r = dm_btree_lookup(&pmd->info, pmd->root, keys, &value);

	if (!r) {
		block_time = le64_to_cpu(value);
		unpack_block_time(block_time, result, &ltime, &zeroed);
	}

	return r;
}

void dm_pool_inc_refcount(struct dm_pool_metadata *pmd, dm_block_t block)
{
	down_write(&pmd->root_lock);
	dm_sm_inc_block(pmd->data_sm, block);
	pmd->need_commit = 1;
	up_write(&pmd->root_lock);
}

void dm_pool_dec_refcount(struct dm_pool_metadata *pmd, dm_block_t block)
{
	down_write(&pmd->root_lock);
	dm_sm_dec_block(pmd->data_sm, block);
	pmd->need_commit = 1;
	up_write(&pmd->root_lock);
}

int dm_pool_get_refcount(struct dm_pool_metadata *pmd, dm_block_t block, uint32_t *count)
{
	int r;
	down_read(&pmd->root_lock);
	r = dm_sm_get_count(pmd->data_sm, block, count);
	up_read(&pmd->root_lock);

	return r;
}

int dm_pool_support_superblock_backup(struct dm_pool_metadata *pmd)
{
	int r;
	down_read(&pmd->root_lock);
	r = __support_sb_backup(pmd);
	up_read(&pmd->root_lock);

	return r;
}

static sector_t warning_metadata_max_sector(struct dm_pool_metadata *pmd)
{
	if (pmd->metadata_block_size == 8) {
		return 16 * (1024 * 1024 * 1024 >> SECTOR_SHIFT);
	} else if (pmd->metadata_block_size == 16) {
		return 128 * (1024 * 1024 * 1024 >> SECTOR_SHIFT);
	} else
		DMERR("unsupported block size");

	return 0;
}

static sector_t thin_metadata_max_sector(struct dm_pool_metadata *pmd)
{
	if (pmd->metadata_block_size == 8) {
		return 255 * (1 << 14) * pmd->metadata_block_size;
	} else if (pmd->metadata_block_size == 16) {
		return 511 * (1 << 15) * pmd->metadata_block_size;
	} else
		DMERR("unsupported block size");

	return 0;
}

static sector_t get_metadata_dev_size(struct dm_pool_metadata *pmd, struct block_device *bdev)
{
	sector_t metadata_dev_size = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	char buffer[BDEVNAME_SIZE];

	if (metadata_dev_size > warning_metadata_max_sector(pmd)) {
		DMWARN("Metadata device %s is larger than %u sectors: excess space will not be used.",
		       bdevname(bdev, buffer), thin_metadata_max_sector(pmd));
		metadata_dev_size = warning_metadata_max_sector(pmd);
	}

	return metadata_dev_size;
}

dm_block_t get_metadata_dev_size_in_blocks(struct dm_pool_metadata *pmd, struct block_device *bdev)
{
	sector_t metadata_dev_size = get_metadata_dev_size(pmd, bdev);

	sector_div(metadata_dev_size, pmd->metadata_block_size);

	return metadata_dev_size;
}

unsigned report_sb_backup_fail(struct dm_pool_metadata *pmd)
{
	unsigned r;

	down_read(&pmd->root_lock);
	r = pmd->sb_backup_fail;
	up_read(&pmd->root_lock);

	return r;
}

unsigned rescan_needed(struct dm_pool_metadata *pmd)
{
	unsigned r;

	down_read(&pmd->root_lock);
	r = pmd->rescan_needed;
	up_read(&pmd->root_lock);

	return r;
}

unsigned need_to_rescan(struct dm_pool_metadata *pmd)
{
	unsigned r;

	down_write(&pmd->root_lock);
	r = pmd->rescan_needed = (pmd->clone_root) ? 1 : 0;
	up_write(&pmd->root_lock);

	return r;
}

void dm_pool_issue_prefetches(struct dm_pool_metadata *pmd)
{
	dm_tm_issue_prefetches(pmd->tm);
}

int dm_pool_get_snap_root(struct dm_pool_metadata *pmd,
                          struct dm_thin_device *td, dm_block_t *root)
{
	int r;
	__le64 value;
	uint64_t key = td->id;

	down_read(&pmd->root_lock);
	r = dm_btree_lookup(&pmd->tl_info, pmd->root, &key, &value);
	up_read(&pmd->root_lock);

	*root = le64_to_cpu(value);

	return r;
}

static int __get_clone_count(struct dm_pool_metadata *pmd,
                             dm_block_t b, uint32_t *count)
{
	int r = -EINVAL;
	__le32 value;

	r = dm_btree_lookup(&pmd->clone_info, pmd->clone_root, &b, &value);
	if (r == -ENODATA) {
		*count = 0;
		return 0;
	} else if (!r) {
		*count = le32_to_cpu(value);
	}

	return r;
}

static int __set_clone_count(struct dm_pool_metadata *pmd,
                             dm_block_t b, uint32_t count)
{
	int r = -EINVAL;
	__le32 value;

	value = cpu_to_le32(count);

	if (!count)
		r = dm_btree_remove(&pmd->clone_info, pmd->clone_root, &b, &pmd->clone_root);
	else
		r = dm_btree_insert(&pmd->clone_info, pmd->clone_root, &b, &value, &pmd->clone_root);

	return r;
}

static int __inc_clone_block(struct dm_pool_metadata *pmd, dm_block_t b)
{
	int r;
	uint32_t count;

	if (!pmd->clone_root || pmd->old_type)
		return 0;

	r = __get_clone_count(pmd, b, &count);
	if (r) {
		DMERR("%s: get origin clone count failed", __func__);
		return r;
	}

	if (count > 0) {
		r = __reserve_block(pmd, RES_CLONE_INC, 1);
		if (r) {
			DMERR("%s: reserve block failed", __func__);
			return r;
		}
	}

	DMDEBUG("%s: increase block %llu clone count for 1 to %u", __func__, b, count + 1);

	r = __set_clone_count(pmd, b, count + 1);
	if (r && count > 0)
		__reserve_block(pmd, RES_CLONE_DEC, 1);

	return r;
}

static int __dec_clone_block(struct dm_pool_metadata *pmd, dm_block_t b)
{
	int r;
	uint32_t count;

	if (!pmd->clone_root || pmd->old_type)
		return 0;

	r = __get_clone_count(pmd, b, &count);
	if (r) {
		DMERR("%s: get origin clone count failed", __func__);
		return r;
	}

	r = __set_clone_count(pmd, b, count - 1);
	if (r) {
		DMERR("%s: set block %llu clone count to %u failed", __func__, b, count - 1);
		return r;
	}

	DMDEBUG("%s: decrease block clone count for 1 to %u", __func__, count - 1);
	if (count > 1) {
		r = __reserve_block(pmd, RES_CLONE_DEC, 1);
		DMDEBUG("%s: reduce reserve block for 1 to %llu", __func__, pmd->reserve_block_count);
	}

	return r;
}

static int __clone_insert(struct dm_thin_device *td,
                          dm_block_t block,
                          struct dm_thin_lookup_result *base,
                          struct dm_thin_lookup_result *target)
{
	int r;
	dm_block_t data_block = target->block;
	struct dm_pool_metadata *pmd = td->pmd;

	if (base) {
		r = __dec_clone_block(pmd, base->block);
		if (r) {
			DMERR("%s: reduce old pblock reference failed", __func__);
			return r;
		}
	}

	r = __inc_clone_block(pmd, data_block);
	if (r) {
		DMERR("%s: reserve block for block cloning failed", __func__);
		goto fail_inc_clone;
	}

	DMDEBUG("%s: insert mapping from %llu to %llu time %llu", __func__, blk, data_block, target->time);
	r = __insert(td, block, data_block, target->zeroed, &target->time);
	if (r) {
		DMERR("%s: return reserve block failed", __func__);
		goto fail_insert;
	}

	return 0;

fail_insert:
	__dec_clone_block(pmd, data_block);
fail_inc_clone:
	if (base)
		__inc_clone_block(pmd, base->block);

	return r;
}

int dm_pool_clone_block(struct dm_pool_metadata *pmd,
                        struct dm_thin_lookup_result *src,
                        struct dm_thin_device *src_td, dm_block_t src_blk,
                        struct dm_thin_lookup_result *dst,
                        struct dm_thin_device *dst_td, dm_block_t dst_blk)
{
	int r = -ENOTSUPP;

	down_write(&pmd->root_lock);

	if (!__support_fast_block_clone(pmd) || pmd->old_type)
		goto fail;

	src->time = dst_td->cloned_time - 1;
	r = __clone_insert(dst_td, dst_blk, dst, src);
	if (r)
		goto fail;

	dm_sm_inc_block(pmd->data_sm, src->block);

	if (!src->cloned) {
		src->time = src_td->cloned_time - 1;
		r = __insert(src_td, src_blk, src->block, src->zeroed, &src->time);
		if (r)
			goto fail;
	}

success:
	pmd->need_commit = 1;
fail:
	up_write(&pmd->root_lock);

	return r;
}

dm_block_t dm_pool_scaned_index(struct dm_thin_device *td)
{
	dm_block_t b;
	struct dm_pool_metadata *pmd = td->pmd;

	down_read(&pmd->root_lock);
	b = td->scaned_index;
	up_read(&pmd->root_lock);

	return b;
}

int dm_pool_scan_block(struct dm_thin_device *td, dm_block_t block,
                       struct dm_thin_lookup_result *map)
{
	int r = 0;
	struct dm_pool_metadata *pmd = td->pmd;

	down_write(&pmd->root_lock);

	if (block == SCAN_FINISH) {
		td->changed = 1;
		td->scaned_index = SCAN_FINISH;
		goto finished;
	} else if (td->scaned_index > block + 1)
		goto finished;

	r = __inc_clone_block(pmd, map->block);
	if (r)
		DMERR("%s: reserve block for block cloning failed", __func__);

	td->scaned_index = block + 1;
	pmd->need_commit = 1;

finished:
	up_write(&pmd->root_lock);

	return r;
}

static int __rebuilt_device(struct dm_thin_device *td)
{
	int r;
	__le64 value;
	dm_block_t highest, keys[2];
	struct dm_thin_lookup_result result;
	struct dm_pool_metadata *pmd = td->pmd;

	r = __highest_block(td, &highest);
	if (r < 0) {
		DMERR("%s: __highest_block return %d", __func__, r);
		return r;
	}

	for (td->scaned_index = 0;
	     td->scaned_index <= highest;
	     td->scaned_index++) {

		keys[0] = td->id;
		keys[1] = td->scaned_index;

		r = dm_btree_lookup(&pmd->info, pmd->root, keys, &value);
		if (!r)
			unpack_lookup_result(td, le64_to_cpu(value), &result);
		else if (r == -ENODATA)
			continue;
		else {
			DMERR("%s: dm_btree_lookup return %d", __func__, r);
			return r;
		}

		r = __inc_clone_block(pmd, result.block);
		if (r) {
			DMERR("%s: __inc_clone_block return %d", __func__, r);
			return r;
		}
	}

	td->changed = 1;
	td->scaned_index = SCAN_FINISH;
	return 0;
}

static int __rebuilt_reserve_space(void *context, uint64_t *keys, void *leaf)
{
	int r;
	struct dm_thin_device *td;
	struct dm_pool_metadata *pmd = (struct dm_pool_metadata *)context;

	r = __alloc_new_device(pmd, *keys, leaf, &td, false);
	if (r)
		return r;

	r = __rebuilt_device(td);
	if (r)
		DMERR("%s: rebuild device %llu failed", __func__, *keys);

	kfree(td);
	return r;
}

int dm_pool_rebuilt_reserve_space(struct dm_pool_metadata *pmd)
{
	int r = 0;

	down_write(&pmd->root_lock);
	/* reset reserve_block_count for following rebuilt*/
	pmd->reserve_block_count = 0;

	if (!pmd->clone_root || pmd->old_type)
		goto no_clone_root;

	if (dm_btree_del(&pmd->clone_info, pmd->clone_root))
		DMERR("%s: delete old clone info btree failed", __func__);

	r = dm_btree_empty(&pmd->clone_info, &pmd->clone_root);
	if (r) {
		DMERR("%s: create new empty clone info btree failed", __func__);
		goto err_out;
	}

	r = dm_btree_walk(&pmd->details_info, pmd->details_root, __rebuilt_reserve_space, (void *)pmd);
	if (r)
		goto err_out;

	pmd->rescan_needed = 0;
no_clone_root:
	pmd->need_commit = 1;
err_out:
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_get_reserve_count(struct dm_pool_metadata *pmd, dm_block_t *clone_reserve)
{
	down_read(&pmd->root_lock);
	*clone_reserve = pmd->reserve_block_count;
	up_read(&pmd->root_lock);

	return 0;
}

int dm_pool_set_reserve_count(struct dm_pool_metadata *pmd, dm_block_t clone_reserve)
{
	down_write(&pmd->root_lock);
	pmd->reserve_block_count = clone_reserve;
	up_write(&pmd->root_lock);

	return 0;
}

int dm_pool_fix_reserve_count(struct dm_pool_metadata *pmd)
{
	int r = 0;
	struct dm_thin_device *td;

	down_write(&pmd->root_lock);
	/* reset reserve_block_count for following rebuilt*/
	pmd->reserve_block_count = 0;

	if (!pmd->clone_root || pmd->old_type)
		goto no_clone_root;

	if (dm_btree_del(&pmd->clone_info, pmd->clone_root))
		DMERR("%s: delete old clone info btree failed", __func__);

	r = dm_btree_empty(&pmd->clone_info, &pmd->clone_root);
	if (r) {
		DMERR("%s: create new empty clone info btree failed", __func__);
		goto err_out;
	}

no_clone_root:
	list_for_each_entry(td, &pmd->thin_devices, list) {
		if (__is_snapshot(td)) {
			td->cloned_time = 0;
		}
	}
	pmd->need_commit = 1;

err_out:
	up_write(&pmd->root_lock);

	return r;
}

int dm_pool_dump_clone_refcount(struct dm_thin_device *td)
{
	int r;
	__le64 value;
	uint32_t count;
	dm_block_t i, highest, keys[2];
	struct dm_thin_lookup_result result;
	struct dm_pool_metadata *pmd = td->pmd;

	down_read(&pmd->root_lock);

	r = __highest_block(td, &highest);
	if (r < 0) {
		DMERR("%s: __highest_block return %d", __func__, r);
		goto out;
	}

	for (i = 0; i <= highest; i++) {
		keys[0] = td->id;
		keys[1] = i;

		r = dm_btree_lookup(&pmd->info, pmd->root, keys, &value);
		if (!r)
			unpack_lookup_result(td, le64_to_cpu(value), &result);
		else if (r == -ENODATA)
			continue;
		else {
			DMERR("%s: dm_btree_lookup return %d", __func__, r);
			goto out;
		}

		r = __get_clone_count(pmd, result.block, &count);
		if (r) {
			DMERR("%s: __inc_clone_block return %d", __func__, r);
			goto out;
		}

		DMINFO("%s: block %llu -> %llu [%lu]", __func__, i, result.block, count);
	}

out:
	DMINFO("%s: highest: %llu i: %llu r: %d", __func__, highest, i, r);
	up_read(&pmd->root_lock);
	return r;
}
