/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_THIN_METADATA_H
#define DM_THIN_METADATA_H

#include "persistent-data/dm-block-manager.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-btree.h"

#ifdef QNAP_HAL
#include <qnap/hal_event.h>
extern int send_hal_netlink(NETLINK_EVT *event);
#endif

/*----------------------------------------------------------------*/

struct dm_pool_metadata;
struct dm_thin_device;

/*
 * Device identifier
 */
typedef uint64_t dm_thin_id;

/*
 * Reopens or creates a new, empty metadata volume.
 */
//PATCH: TIER
struct dm_pool_metadata *dm_pool_metadata_open(struct block_device *bdev,
											   sector_t data_block_size,
        									   bool format_device,
        									   unsigned int tier_num,
        									   unsigned long alloc_tier,
        									   dm_block_t tier_blk_size);

int dm_pool_metadata_close(struct dm_pool_metadata *pmd);

/*
 * Compat feature flags.  Any incompat flags beyond the ones
 * specified below will prevent use of the thin metadata.
 */
#define THIN_FEATURE_SUPERBLOCK_BACKUP (1UL << 31)
#define THIN_FEATURE_FAST_BLOCK_CLONE  (1UL << 30)
#define THIN_FEATURE_COMPAT_SUPP	  0UL
#define THIN_FEATURE_COMPAT_RO_SUPP	  0UL
#define THIN_FEATURE_INCOMPAT_SUPP	  0UL

/*
 * Reserve space manuplate flag
 */
#define RES_CLONE_INC (1)
#define RES_CLONE_DEC (1 << 1)

#define SCAN_FINISH ULLONG_MAX

/*
 * Data allocation flag
 */
#define ALLOC_NEW     0
#define ALLOC_RESERVE (1 << 1)
#define ALLOC_SHARE   (1 << 2)

/*
 * Insert mapping flag
 */
#define INSERT_REFLAG     (0)
#define INSERT_NEW        (1)
#define INSERT_OVERWRITE  (2)

/*
 * Device creation/deletion.
 */
int dm_pool_create_thin(struct dm_pool_metadata *pmd, dm_thin_id dev);

/*
 * An internal snapshot.
 *
 * You can only snapshot a quiesced origin i.e. one that is either
 * suspended or not instanced at all.
 */
int dm_pool_create_snap(struct dm_pool_metadata *pmd, dm_thin_id dev,
                        dm_thin_id origin);

/*
 * An internal clone.
 *
 * You can only clone a quiesced origin i.e. one that is either
 * suspended or not instanced at all.
 */
int dm_pool_create_clone(struct dm_pool_metadata *pmd,
                         dm_thin_id dev, dm_thin_id origin);

/*
 * Deletes a virtual device from the metadata.  It _is_ safe to call this
 * when that device is open.  Operations on that device will just start
 * failing.  You still need to call close() on the device.
 */
int dm_pool_delete_thin_device(struct dm_pool_metadata *pmd,
                               dm_thin_id dev);

/*
 * Commits _all_ metadata changes: device creation, deletion, mapping
 * updates.
 */
int dm_pool_commit_metadata(struct dm_pool_metadata *pmd);

/*
 * Discards all uncommitted changes.  Rereads the superblock, rolling back
 * to the last good transaction.  Thin devices remain open.
 * dm_thin_aborted_changes() tells you if they had uncommitted changes.
 *
 * If this call fails it's only useful to call dm_pool_metadata_close().
 * All other methods will fail with -EINVAL.
 */
int dm_pool_abort_metadata(struct dm_pool_metadata *pmd);

/*
 * Set/get userspace transaction id.
 */
int dm_pool_set_metadata_transaction_id(struct dm_pool_metadata *pmd,
                                        uint64_t current_id,
                                        uint64_t new_id);

int dm_pool_get_metadata_transaction_id(struct dm_pool_metadata *pmd,
                                        uint64_t *result);

/*
 * Hold/get root for userspace transaction.
 *
 * The metadata snapshot is a copy of the current superblock (minus the
 * space maps).  Userland can access the data structures for READ
 * operations only.  A small performance hit is incurred by providing this
 * copy of the metadata to userland due to extra copy-on-write operations
 * on the metadata nodes.  Release this as soon as you finish with it.
 */
int dm_pool_reserve_metadata_snap(struct dm_pool_metadata *pmd);
int dm_pool_release_metadata_snap(struct dm_pool_metadata *pmd);

int dm_pool_enable_block_clone(struct dm_pool_metadata *pmd);
int dm_pool_disable_block_clone(struct dm_pool_metadata *pmd);

int dm_pool_start_backup_sb(struct dm_pool_metadata *pmd);
int dm_pool_stop_backup_sb(struct dm_pool_metadata *pmd);

int dm_pool_get_metadata_snap(struct dm_pool_metadata *pmd,
                              dm_block_t *result);

int support_fast_block_clone(struct dm_pool_metadata *pmd);
/*
 * Actions on a single virtual device.
 */

/*
 * Opening the same device more than once will fail with -EBUSY.
 */
int dm_pool_open_thin_device(struct dm_pool_metadata *pmd, dm_thin_id dev,
                             struct dm_thin_device **td);

int dm_pool_close_thin_device(struct dm_thin_device *td);

dm_thin_id dm_thin_dev_id(struct dm_thin_device *td);

struct dm_thin_lookup_result {
	dm_block_t block;
	uint32_t time;
	unsigned zeroed: 1;
	unsigned shared: 1;
	unsigned cloned: 1;
};

int dm_thin_deploy(struct dm_thin_device *td, dm_block_t block, dm_block_t *result);

/*
 * Returns:
 *   -EWOULDBLOCK iff @can_issue_io is set and would issue IO.
 *   -ENODATA iff that mapping is not present.
 *   0 success
 */
int dm_thin_find_block(struct dm_thin_device *td, dm_block_t block,
                       int can_issue_io, struct dm_thin_lookup_result *result);

/*
 * Obtain an unused block.
 */
int dm_pool_alloc_data_block(struct dm_pool_metadata *pmd, dm_block_t *result, int for_snap);
int dm_pool_alloc_reserve_data_block(struct dm_pool_metadata *pmd, dm_block_t *result);

/*
 * Insert or remove block.
 */
int dm_thin_insert_block(struct dm_thin_device *td, dm_block_t block,
                         dm_block_t data_block, dm_block_t old_block, unsigned zeroed, int flag);

int dm_thin_insert_block_with_time(struct dm_thin_device *td, dm_block_t block,
                                   dm_block_t data_block, dm_block_t old_block, unsigned zeroed, uint32_t *time, int flag);

/*
 * If pool_block is given, reduce the clone counts of it
 */
int dm_thin_remove_block(struct dm_thin_device *td, dm_block_t block, dm_block_t *pblock);

/*
 * Queries.
 */
bool dm_thin_changed_this_transaction(struct dm_thin_device *td);

bool dm_thin_aborted_changes(struct dm_thin_device *td);

int dm_thin_get_highest_mapped_block(struct dm_thin_device *td,
                                     dm_block_t *highest_mapped);

int dm_thin_get_mapped_count(struct dm_thin_device *td, dm_block_t *result);

int dm_pool_get_free_block_count(struct dm_pool_metadata *pmd,
                                 dm_block_t *result);

int dm_pool_get_free_metadata_block_count(struct dm_pool_metadata *pmd,
        dm_block_t *result);

int dm_pool_get_metadata_dev_size(struct dm_pool_metadata *pmd,
                                  dm_block_t *result);

int dm_pool_get_data_block_size(struct dm_pool_metadata *pmd, sector_t *result);

int dm_pool_get_data_dev_size(struct dm_pool_metadata *pmd, dm_block_t *result);

int dm_pool_block_is_used(struct dm_pool_metadata *pmd, dm_block_t b, bool *result);
/*
 * Returns -ENOSPC if the new size is too small and already allocated
 * blocks would be lost.
 */
int dm_pool_resize_data_dev(struct dm_pool_metadata *pmd, dm_block_t new_size);
int dm_pool_resize_metadata_dev(struct dm_pool_metadata *pmd, dm_block_t new_size);

/*
 * Flicks the underlying block manager into read only mode, so you know
 * that nothing is changing.
 */
void dm_pool_metadata_read_only(struct dm_pool_metadata *pmd);
void dm_pool_metadata_read_write(struct dm_pool_metadata *pmd);

int dm_pool_register_reserve_threshold(struct dm_pool_metadata *pmd, dm_block_t threshold);
int dm_pool_register_metadata_threshold(struct dm_pool_metadata *pmd,
                                        dm_block_t threshold,
                                        dm_sm_threshold_fn fn,
                                        void *context);

void dm_pool_inc_refcount(struct dm_pool_metadata *pmd, dm_block_t block);
void dm_pool_dec_refcount(struct dm_pool_metadata *pmd, dm_block_t block);
int dm_pool_get_refcount(struct dm_pool_metadata *pmd, dm_block_t block, uint32_t *count);
int dm_pool_support_superblock_backup(struct dm_pool_metadata *pmd);

dm_block_t get_metadata_dev_size_in_blocks(struct dm_pool_metadata *pmd, struct block_device *bdev);
unsigned report_sb_backup_fail(struct dm_pool_metadata *pmd);
unsigned rescan_needed(struct dm_pool_metadata *pmd);
unsigned need_to_rescan(struct dm_pool_metadata *pmd);
bool dm_thin_is_snapshot(struct dm_thin_device *td);

/*
 * Issue any prefetches that may be useful.
 */
void dm_pool_issue_prefetches(struct dm_pool_metadata *pmd);
int dm_pool_get_snap_root(struct dm_pool_metadata *pmd, struct dm_thin_device *td, dm_block_t *root);

int dm_pool_clone_block(struct dm_pool_metadata *pmd,
                        struct dm_thin_lookup_result *src,
                        struct dm_thin_device *src_td, dm_block_t src_blk,
                        struct dm_thin_lookup_result *dst,
                        struct dm_thin_device *dst_td, dm_block_t dst_blk);
int dm_pool_scan_block(struct dm_thin_device *td, dm_block_t block,
                       struct dm_thin_lookup_result *map);
int dm_pool_rebuilt_reserve_space(struct dm_pool_metadata *pmd);
int dm_pool_get_origin_mapped_blocks(struct dm_pool_metadata *pmd, dm_block_t *b);
dm_block_t dm_pool_scaned_index(struct dm_thin_device *td);
int dm_pool_get_reserve_count(struct dm_pool_metadata *pmd, dm_block_t *clone_reserve);
int dm_pool_set_reserve_count(struct dm_pool_metadata *pmd, dm_block_t clone_reserve);
int dm_pool_fix_reserve_count(struct dm_pool_metadata *pmd);
int dm_pool_dump_clone_refcount(struct dm_thin_device *td);
/*----------------------------------------------------------------*/

/* ---- TIER ----*/
#define MAX_TIER_LEVEL 3

struct dm_pool_metadata {
	struct hlist_node hash;

	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *metadata_sm;

	// PATCH: TIER
	struct dm_space_map *tier_data_sm[MAX_TIER_LEVEL];

	struct dm_space_map *data_sm;
	struct dm_transaction_manager *tm;
	struct dm_transaction_manager *nb_tm;

	/*
	 * Two-level btree.
	 * First level holds thin_dev_t.
	 * Second level holds mappings.
	 */
	struct dm_btree_info info;

	/*
	 * Non-blocking version of the above.
	 */
	struct dm_btree_info nb_info;

	/*
	 * Just the top level for deleting whole devices.
	 */
	struct dm_btree_info tl_info;

	/*
	 * Just the bottom level for creating new devices.
	 */
	struct dm_btree_info bl_info;

	/*
	 * Describes the device details btree.
	 */
	struct dm_btree_info details_info;

	//PATCH: TIER
	struct dm_btree_info pool_map_info;
	struct dm_btree_info nb_pool_map_info;

	/*
	 * Describes the clone count btree.
	 */
	struct dm_btree_info clone_info;

	struct rw_semaphore root_lock;
	uint32_t time;

	/*
	 * FIXME: we add these, for we can't find anything better
	 */
	int need_commit;
	uint32_t sb_backup_fail;

	dm_block_t root;

	// PATCH: TIER
	dm_block_t pool_root;

	dm_block_t details_root;
	dm_block_t clone_root;

	dm_block_t reserve_block_count;
	dm_block_t thick_reserve;
	dm_block_t reserve_threshold;

	struct list_head thin_devices;
	uint64_t trans_id;
	unsigned long flags;
	sector_t metadata_block_size;
	sector_t data_block_size;
	uint64_t backup_id;
	bool read_only;
	bool old_type;

	/*
	 * Set if a transaction has to be aborted but the attempt to roll back
	 * to the previous (good) transaction failed.  The only pool metadata
	 * operation possible in this state is the closing of the device.
	 */
	bool fail_io;
	unsigned rescan_needed;

	//PATCH: TIER
	unsigned long bitmapsize;
	unsigned long *bitmap;
	uint32_t tier_num; //metadata doesn't support for online increasing tier number
	unsigned long alloc_tier;
	sector_t tier_block_size;
	dm_block_t swap_block[MAX_TIER_LEVEL];
};

struct dm_tier_lookup_result {
	dm_block_t block;
	unsigned tierid;
	unsigned reserve; //using lowest 8 bits as discard bits
};

inline uint64_t pack_tier_block(uint32_t t, dm_block_t b, uint32_t res);
inline void unpack_tier_block(uint64_t v, uint32_t *t, dm_block_t *b, uint32_t *res);
int dm_tier_find_block(struct dm_pool_metadata *pmd, dm_block_t block,
                       int can_block, struct dm_tier_lookup_result *result);
int dm_tier_set_alloc_tier(struct dm_pool_metadata *pmd, unsigned long alloc_tier);
int dm_tier_get_alloc_tier(struct dm_pool_metadata *pmd, unsigned long *alloc_tier);
int dm_tier_find_free_tier_and_alloc(struct dm_pool_metadata *pmd, uint32_t *tierid, unsigned int enable_map, dm_block_t *result);
int dm_tier_alloc_tier_data_block(struct dm_pool_metadata *pmd, dm_block_t *result, unsigned int tierid);
int dm_tier_insert_block(struct dm_pool_metadata *pmd, dm_block_t block,
                         dm_block_t data_block, uint32_t tierid);
int dm_tier_insert_block_with_reserve(struct dm_pool_metadata *pmd, dm_block_t block,
                                      dm_block_t data_block, uint32_t tierid, uint32_t res);
int dm_tier_insert_block_free_swap(struct dm_pool_metadata *pmd,  dm_block_t block, dm_block_t data_block,
							  uint32_t tierid, uint32_t res, uint32_t old_tierid);
int dm_tier_remove_block(struct dm_pool_metadata *pmd, dm_block_t block);
int dm_tier_alloc_blk_and_remove_swap(struct dm_pool_metadata *pmd, dm_block_t *result, unsigned int old_tierid, unsigned int new_tierid);
int dm_pool_get_tier_data_dev_size(struct dm_pool_metadata *pmd, unsigned int tierid, dm_block_t *result);
int dm_pool_get_tier_data_dev_free_size(struct dm_pool_metadata *pmd, unsigned int tierid, dm_block_t *result);
int dm_pool_resize_tier_data_dev(struct dm_pool_metadata *pmd, unsigned int tierid, dm_block_t new_count);

int tier_bitmap_scan(struct dm_pool_metadata **pmd, dm_block_t size);
int tier_bitmap_display(struct dm_pool_metadata **pmd);
void tier_bitmap_set(struct dm_pool_metadata *pmd, int pos);
void tier_bitmap_clear(struct dm_pool_metadata *pmd, int pos);
unsigned long tier_get_bitmap_size(struct dm_pool_metadata *pmd);
int tier_bitmap_copy(struct dm_pool_metadata *pmd, unsigned long **new_bitmap);

int display_map(void *context, uint64_t *keys, void *leaf);
int generator_map(void *context, uint64_t *keys, void *leaf);

int dm_tier_inc_block_cnt(struct dm_pool_metadata *pmd, uint32_t tier, dm_block_t block);
int dm_tier_dec_block_cnt(struct dm_pool_metadata *pmd, uint32_t tier, dm_block_t block);
int pool_bitmap_maybe_resize(struct dm_pool_metadata *pmd, dm_block_t size);

int dm_tier_set_swap_block(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t block);
int dm_tier_alloc_swap_block(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t *result);
int dm_tier_free_swap_block(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t block);
int dm_tier_get_swap_blkcnt(struct dm_pool_metadata *pmd, uint32_t tierid, dm_block_t *blkcnt);

/* ---- TIER ----*/

#endif
