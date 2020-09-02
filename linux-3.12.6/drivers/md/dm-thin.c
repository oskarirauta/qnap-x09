/*
 * Copyright (C) 2011-2012 Red Hat UK.
 *
 * This file is released under the GPL.
 */

/*
 * Feature: thick, preremove, thin-to-thick, write_same(undone this),
 *          GET_LBA_STATUS, thin_discard_passdown
 */
#include <linux/fast_clone.h>
#include <linux/delay.h>

#include "dm-thin-metadata.h"
#include "dm-bio-prison.h"
#include "dm.h"
#include "dm-tier.h"

#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/rbtree.h>
#include <linux/kthread.h>
#include <linux/sysfs.h>

#define	DM_MSG_PREFIX	"thin"

/*
 * Tunable constants
 */
#define ENDIO_HOOK_POOL_SIZE 1024
#define MAPPING_POOL_SIZE 1024
#define PRISON_CELLS 1024
#define COMMIT_PERIOD HZ

DECLARE_DM_KCOPYD_THROTTLE_WITH_MODULE_PARM(snapshot_copy_throttle,
        "A percentage of time allocated for copy on write");

/*
 * The block size of the device holding pool data must be
 * between 64KB and 1GB.
 */
#define DATA_DEV_BLOCK_SIZE_MIN_SECTORS (64 * 1024 >> SECTOR_SHIFT)
#define DATA_DEV_BLOCK_SIZE_MAX_SECTORS (1024 * 1024 * 1024 >> SECTOR_SHIFT)

/*
 * Device id is restricted to 24 bits.
 */
#define MAX_DEV_ID ((1 << 24) - 1)

/*
 * Reserved sectors constants
 */
#define MAX_QNAP_RESERVED_SECTORS 67108864
#define MIN_QNAP_RESERVED_SECTORS 2097152

/*
 * How do we handle breaking sharing of data blocks?
 * =================================================
 *
 * We use a standard copy-on-write btree to store the mappings for the
 * devices (note I'm talking about copy-on-write of the metadata here, not
 * the data).  When you take an internal snapshot you clone the root node
 * of the origin btree.  After this there is no concept of an origin or a
 * snapshot.  They are just two device trees that happen to point to the
 * same data blocks.
 *
 * When we get a write in we decide if it's to a shared data block using
 * some timestamp magic.  If it is, we have to break sharing.
 *
 * Let's say we write to a shared block in what was the origin.  The
 * steps are:
 *
 * i) plug io further to this physical block. (see bio_prison code).
 *
 * ii) quiesce any read io to that shared data block.  Obviously
 * including all devices that share this block.  (see dm_deferred_set code)
 *
 * iii) copy the data block to a newly allocate block.  This step can be
 * missed out if the io covers the block. (schedule_copy).
 *
 * iv) insert the new mapping into the origin's btree
 * (process_prepared_mapping).  This act of inserting breaks some
 * sharing of btree nodes between the two devices.  Breaking sharing only
 * effects the btree of that specific device.  Btrees for the other
 * devices that share the block never change.  The btree for the origin
 * device as it was after the last commit is untouched, ie. we're using
 * persistent data structures in the functional programming sense.
 *
 * v) unplug io to this physical block, including the io that triggered
 * the breaking of sharing.
 *
 * Steps (ii) and (iii) occur in parallel.
 *
 * The metadata _doesn't_ need to be committed before the io continues.  We
 * get away with this because the io is always written to a _new_ block.
 * If there's a crash, then:
 *
 * - The origin mapping will point to the old origin block (the shared
 * one).  This will contain the data as it was before the io that triggered
 * the breaking of sharing came in.
 *
 * - The snap mapping still points to the old block.  As it would after
 * the commit.
 *
 * The downside of this scheme is the timestamp magic isn't perfect, and
 * will continue to think that data block in the snapshot device is shared
 * even after the write to the origin has broken sharing.  I suspect data
 * blocks will typically be shared by many different devices, so we're
 * breaking sharing n + 1 times, rather than n, where n is the number of
 * devices that reference this data block.  At the moment I think the
 * benefits far, far outweigh the disadvantages.
 */

/*----------------------------------------------------------------*/

/*
 * Key building.
 */
static void build_data_key(struct dm_thin_device *td,
						   dm_block_t a,
                           dm_block_t b, struct dm_cell_key *key)
{
	key->virtual = 0;
	key->dev = dm_thin_dev_id(td);
	key->addr = a;
	key->block = b;
}

static void build_virtual_key(struct dm_thin_device *td, dm_block_t b,
                              struct dm_cell_key *key)
{
	key->virtual = 1;
	key->dev = dm_thin_dev_id(td);
	key->addr = 0; // virtual key requires no addr
	key->block = b;
}

/*----------------------------------------------------------------*/

#define THROTTLE_THRESHOLD (1 * HZ)

struct throttle {
	struct rw_semaphore lock;
	unsigned long threshold;
	bool throttle_applied;
};

static void throttle_init(struct throttle *t)
{
	init_rwsem(&t->lock);
	t->throttle_applied = false;
}

static void throttle_work_start(struct throttle *t)
{
	t->threshold = jiffies + THROTTLE_THRESHOLD;
}

static void throttle_work_update(struct throttle *t)
{
	if (!t->throttle_applied && jiffies > t->threshold) {
		down_write(&t->lock);
		t->throttle_applied = true;
	}
}

static void throttle_work_complete(struct throttle *t)
{
	if (t->throttle_applied) {
		t->throttle_applied = false;
		up_write(&t->lock);
	}
}

static void throttle_lock(struct throttle *t)
{
	down_read(&t->lock);
}

static void throttle_unlock(struct throttle *t)
{
	up_read(&t->lock);
}

/*----------------------------------------------------------------*/

/*
 * A pool device ties together a metadata device and a data device.  It
 * also provides the interface for creating and destroying internal
 * devices.
 */
struct dm_thin_new_mapping;

/*
 * The pool runs in 3 modes.  Ordered in degraded order for comparisons.
 */
enum pool_mode {
	PM_WRITE,		/* metadata may be changed */
	PM_READ_ONLY,		/* metadata may not be changed */
	PM_FAIL,		/* all I/O fails */
};

struct pool_features {
	enum pool_mode mode;

	bool zero_new_blocks: 1;
	bool discard_enabled: 1;
	bool discard_passdown: 1;

	struct pool_features_tier_private pool_features_tier_data;
};

struct thin_c;
struct pool;
typedef void (*process_bio_fn)(struct thin_c *tc, struct bio *bio);
typedef void (*process_cell_fn)(struct thin_c *tc, struct dm_bio_prison_cell *cell);
typedef int  (*process_clone_fn)(struct pool *pool, dm_thin_id src_dev_id, sector_t src_addr,
                                 dm_thin_id dst_dev_id, sector_t dst_addr, sector_t length);
typedef void (*process_mapping_fn)(struct dm_thin_new_mapping *m);

#define CELL_SORT_ARRAY_SIZE 8192

struct pool {
	struct list_head list;
	struct dm_target *ti;	/* Only set if a pool target is bound */
	struct kobject kobj;

	struct mapped_device *pool_md;
	struct block_device *md_dev;
	struct dm_pool_metadata *pmd;

	dm_block_t low_water_blocks;
	uint32_t sectors_per_block;
	int sectors_per_block_shift;
	dm_block_t origin_max_blocks;
	dm_block_t sync_io_threshold;
	dm_block_t snap_delete_threshold;

	struct pool_features pf;
	unsigned low_water_triggered: 1;	/* A dm event has been sent */
	unsigned no_free_space: 1;	/* A -ENOSPC warning has been issued */
	unsigned sync_io_triggered: 1;
	unsigned snap_delete: 1;
	unsigned sb_backup_fail_reported: 1;
	unsigned io_error_reported: 1;

	struct dm_bio_prison *prison;
	struct dm_kcopyd_client *copier;

	struct workqueue_struct *wq;
	struct throttle throttle;
	struct work_struct worker;
	struct delayed_work waker;

	unsigned long last_commit_jiffies;
	unsigned ref_count;

	spinlock_t lock;
	struct workqueue_struct *convert_wq;

	struct bio_list deferred_flush_bios;
	struct list_head prepared_mappings;
	struct list_head prepared_discards;
	struct list_head prepared_clones;

	struct list_head active_thins;

	struct dm_deferred_set *shared_read_ds;
	struct dm_deferred_set *all_io_ds;

	struct dm_thin_new_mapping *next_mapping;
	mempool_t *mapping_pool;

	process_bio_fn process_bio;
	process_bio_fn process_discard;
	process_bio_fn process_fast_zero;

	process_cell_fn process_cell;
	process_cell_fn process_discard_cell;
	process_cell_fn process_fast_zero_cell;

	process_clone_fn process_clone;

	process_mapping_fn process_prepared_mapping;
	process_mapping_fn process_prepared_discard;
	process_mapping_fn process_prepared_clone;

	struct dm_bio_prison_cell *cell_sort_array[CELL_SORT_ARRAY_SIZE];

	//PATCH:TIER
	struct pool_tier_private *pool_tier_data;
};

static enum pool_mode get_pool_mode(struct pool *pool);
static void set_pool_mode(struct pool *pool, enum pool_mode mode);

/*
 * Target context for a pool.
 */
struct pool_c {
	struct dm_target *ti;
	struct pool *pool;
	struct dm_dev *data_dev;
	struct dm_dev *metadata_dev;
	struct dm_target_callbacks callbacks;

	dm_block_t low_water_blocks;
	struct pool_features requested_pf; /* Features requested during table load */
	struct pool_features adjusted_pf;  /* Features used after adjusting for constituent devices */

	//PATCH:TIER
	struct pool_c_tier_private pool_c_tier_data;
};

#define THIN  0
#define THICK 1

enum T2T_STATE {
	T2T_READY,
	/* WORK_BUSY_PENDING = 1 */
	/* WORK_BUSY_RUNNING = 2 */
	T2T_FAIL = 3,
	T2T_CANCEL,
	T2T_SUCCESS,
	__MAX_NR_STATE
};

static char * const t2t_state_name[__MAX_NR_STATE + 1] = {
	"READY",
	"PENDING",
	"RUNNING",
	"FAIL",
	"CANCEL",
	"SUCCESS",
	"UNKNOWN",
};

struct convert_work {
	enum T2T_STATE status;
	int cancel;
	struct work_struct work;
	spinlock_t lock;
};
/*
 * Target context for a thin.
 */
struct thin_c {
	struct list_head list;
	struct dm_dev *pool_dev;
	struct dm_dev *origin_dev;
	dm_thin_id dev_id;

	struct pool *pool;
	struct dm_thin_device *td;
	struct dm_target *ti;

	sector_t len;

	struct convert_work thick_work;
	struct convert_work remove_work;

	void (*dm_monitor_fn)(void *, int);
	void *lundev;

	bool is_thick;
	bool is_lun;
	bool discard_passdown;
	spinlock_t lock;
	struct list_head deferred_cells;
	struct bio_list deferred_bio_list;
	struct bio_list retry_on_resume_list;
	struct rb_root sort_bio_list; /* sorted list of deferred bios */

	/*
	 * Ensures the thin is not destroyed until the worker has finished
	 * iterating the active_thins list.
	 */
	atomic_t refcount;
	struct completion can_destroy;
};

#define DEFER_IO_FLAGS (REQ_DISCARD | REQ_FLUSH | REQ_FUA | REQ_QNAP_MAP | REQ_QNAP_MAP_ZERO)

struct dm_thin_clone_data {
	void *src_p;
	void *dst_p;
	dm_block_t src_blk;
	dm_block_t dst_blk;
	struct dm_thin_lookup_result *sresult;
	struct dm_thin_lookup_result *dresult;
	struct dm_bio_prison_cell *s_vcell, *s_dcell;
	struct dm_bio_prison_cell *d_vcell, *d_dcell;
	struct completion *complete;
	atomic_t *on_the_fly;
	atomic_t *err_count;
	atomic_t *no_space_count;
};

/*----------------------------------------------------------------*/

/*
 * wake_worker() is used when new work is queued and when pool_resume is
 * ready to continue deferred IO processing.
 */
static void wake_worker(struct pool *pool)
{
	queue_work(pool->wq, &pool->worker);
}

/*----------------------------------------------------------------*/

static int bio_detain(struct pool *pool, struct dm_cell_key *key, struct bio *bio,
                      struct dm_bio_prison_cell **cell_result)
{
	int r;
	struct dm_bio_prison_cell *cell_prealloc;

	/*
	 * Allocate a cell from the prison's mempool.
	 * This might block but it can't fail.
	 */
	cell_prealloc = dm_bio_prison_alloc_cell(pool->prison, GFP_NOIO);

	r = dm_bio_detain(pool->prison, key, bio, cell_prealloc, cell_result);
	if (r)
		/*
		 * We reused an old cell; we can get rid of
		 * the new one.
		 */
		dm_bio_prison_free_cell(pool->prison, cell_prealloc);

	return r;
}

static void cell_release(struct pool *pool,
                         struct dm_bio_prison_cell *cell,
                         struct bio_list *bios)
{
	dm_cell_release(pool->prison, cell, bios);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static void cell_visit_release(struct pool *pool,
                               void (*fn)(void *, struct dm_bio_prison_cell *),
                               void *context,
                               struct dm_bio_prison_cell *cell)
{
	dm_cell_visit_release(pool->prison, fn, context, cell);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static void cell_release_no_holder(struct pool *pool,
                                   struct dm_bio_prison_cell *cell,
                                   struct bio_list *bios)
{
	dm_cell_release_no_holder(pool->prison, cell, bios);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static void cell_error_with_code(struct pool *pool,
                                 struct dm_bio_prison_cell *cell, int error_code)
{
	dm_cell_error(pool->prison, cell, error_code);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static void cell_error(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	cell_error_with_code(pool, cell, -EIO);
}

static void cell_success(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	cell_error_with_code(pool, cell, 0);
}

static void cell_requeue(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	cell_error_with_code(pool, cell, DM_ENDIO_REQUEUE);
}

/*----------------------------------------------------------------*/

/*
 * A global list of pools that uses a struct mapped_device as a key.
 */
static struct dm_thin_pool_table {
	struct mutex mutex;
	struct list_head pools;
} dm_thin_pool_table;

static void pool_table_init(void)
{
	mutex_init(&dm_thin_pool_table.mutex);
	INIT_LIST_HEAD(&dm_thin_pool_table.pools);
}

static void __pool_table_insert(struct pool *pool)
{
	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));
	list_add(&pool->list, &dm_thin_pool_table.pools);
}

static void __pool_table_remove(struct pool *pool)
{
	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));
	list_del(&pool->list);
}

static struct pool *__pool_table_lookup(struct mapped_device *md)
{
	struct pool *pool = NULL, *tmp;

	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));

	list_for_each_entry(tmp, &dm_thin_pool_table.pools, list) {
		if (tmp->pool_md == md) {
			pool = tmp;
			break;
		}
	}

	return pool;
}

static struct pool *__pool_table_lookup_metadata_dev(struct block_device *md_dev)
{
	struct pool *pool = NULL, *tmp;

	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));

	list_for_each_entry(tmp, &dm_thin_pool_table.pools, list) {
		if (tmp->md_dev == md_dev) {
			pool = tmp;
			break;
		}
	}

	return pool;
}

/*----------------------------------------------------------------*/

#define HAL_SB_BACKUP_FAIL   1
#define HAL_IO_ERROR         2
#define HAL_THIN_ERR_VERSION 3

static void send_hal_msg(void *context, int type)
{
#ifdef QNAP_HAL
	NETLINK_EVT hal_event;
	struct pool *pool;
	struct mapped_device *md;

	switch (type) {
	case HAL_SB_BACKUP_FAIL:
		pool = (struct pool *)context;
		md = pool->pool_md;

		if (pool->sb_backup_fail_reported)
			return;
		else
			pool->sb_backup_fail_reported = 1;

		hal_event.arg.action = THIN_SB_BACKUP_FAIL;
		break;
	case HAL_IO_ERROR:
		pool = (struct pool *)context;
		md = pool->pool_md;

		if (pool->io_error_reported)
			return;
		else
			pool->io_error_reported = 1;

		hal_event.arg.action = THIN_IO_ERROR;
		break;
	case HAL_THIN_ERR_VERSION:
		md = (struct mapped_device *)context;
		hal_event.arg.action = THIN_ERR_VERSION_DETECT;
		break;
	default:
		DMERR("%s: unknown hal message type: %d", __func__, type);
		return;
	};

	hal_event.type = HAL_EVENT_THIN;
	dm_copy_name_and_uuid(md, hal_event.arg.param.pool_message.pool_name, NULL);
	send_hal_netlink(&hal_event);
#endif
}

/*----------------------------------------------------------------*/

struct dm_thin_endio_hook {
	struct thin_c *tc;
	struct dm_deferred_entry *shared_read_entry;
	struct dm_deferred_entry *all_io_entry;
	struct dm_thin_new_mapping *overwrite_mapping;
	struct rb_node rb_node;
};

static void __requeue_bio_list(struct thin_c *tc, struct bio_list *master)
{
	struct bio *bio;
	struct bio_list bios;
	unsigned long flags;

	bio_list_init(&bios);
	spin_lock_irqsave(&tc->lock, flags);
	bio_list_merge(&bios, master);
	bio_list_init(master);
	spin_unlock_irqrestore(&tc->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		bio_endio(bio, DM_ENDIO_REQUEUE);
}

static void requeue_deferred_cells(struct thin_c *tc)
{
	struct pool *pool = tc->pool;
	unsigned long flags;
	struct list_head cells;
	struct dm_bio_prison_cell *cell, *tmp;

	INIT_LIST_HEAD(&cells);

	spin_lock_irqsave(&tc->lock, flags);
	list_splice_init(&tc->deferred_cells, &cells);
	spin_unlock_irqrestore(&tc->lock, flags);

	list_for_each_entry_safe(cell, tmp, &cells, user_list)
	cell_requeue(pool, cell);
}

static void requeue_io(struct thin_c *tc)
{
	__requeue_bio_list(tc, &tc->deferred_bio_list);
	__requeue_bio_list(tc, &tc->retry_on_resume_list);
}

/*
 * This section of code contains the logic for processing a thin device's IO.
 * Much of the code depends on pool object resources (lists, workqueues, etc)
 * but most is exclusively called from the thin target rather than the thin-pool
 * target.
 */

static bool block_size_is_power_of_two(struct pool *pool)
{
	return pool->sectors_per_block_shift >= 0;
}

static dm_block_t get_bio_block(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;
	sector_t block_nr = bio->bi_sector;

	if (block_size_is_power_of_two(pool))
		block_nr >>= pool->sectors_per_block_shift;
	else
		(void) sector_div(block_nr, pool->sectors_per_block);

	return block_nr;
}

static void remap(struct thin_c *tc, struct bio *bio, dm_block_t block)
{
	struct pool *pool = tc->pool;
	sector_t bi_sector = bio->bi_sector;

	bio->bi_bdev = tc->pool_dev->bdev;
	if (block_size_is_power_of_two(pool))
		bio->bi_sector = (block << pool->sectors_per_block_shift) |
		                 (bi_sector & (pool->sectors_per_block - 1));
	else
		bio->bi_sector = (block * pool->sectors_per_block) +
		                 sector_div(bi_sector, pool->sectors_per_block);
}

static void remap_to_origin(struct thin_c *tc, struct bio *bio)
{
	bio->bi_bdev = tc->origin_dev->bdev;
}

static int bio_triggers_commit(struct thin_c *tc, struct bio *bio)
{
	return (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) &&
	       dm_thin_changed_this_transaction(tc->td);
}

static void inc_all_io_entry(struct pool *pool, struct bio *bio)
{
	struct dm_thin_endio_hook *h;

	if (bio->bi_rw & REQ_DISCARD)
		return;

	h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	h->all_io_entry = dm_deferred_entry_inc(pool->all_io_ds);
}

static void issue(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;
	unsigned long flags;

	if (!bio_triggers_commit(tc, bio)) {
		generic_make_request(bio);
		return;
	}

	/*
	 * Complete bio with an error if earlier I/O caused changes to
	 * the metadata that can't be committed e.g, due to I/O errors
	 * on the metadata device.
	 */
	if (dm_thin_aborted_changes(tc->td)) {
		bio_io_error(bio);
		return;
	}

	/*
	 * Batch together any bios that trigger commits and then issue a
	 * single commit for them in process_deferred_bios().
	 */
	spin_lock_irqsave(&pool->lock, flags);
	bio_list_add(&pool->deferred_flush_bios, bio);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static void remap_to_origin_and_issue(struct thin_c *tc, struct bio *bio)
{
	remap_to_origin(tc, bio);
	issue(tc, bio);
}

static void remap_and_issue(struct thin_c *tc, struct bio *bio,
                            dm_block_t block)
{
	remap(tc, bio, block);
	issue(tc, bio);
}

/*----------------------------------------------------------------*/

/*
 * Bio endio functions.
 */
struct dm_thin_new_mapping {
	struct list_head list;

	unsigned quiesced: 1;
	unsigned prepared: 1;
	unsigned cloned: 1;
	unsigned pass_discard: 1;
	unsigned definitely_not_shared: 1;

	struct thin_c *tc;
	dm_block_t virt_block;
	dm_block_t data_block;
	dm_block_t old_block;
	struct dm_bio_prison_cell *cell, *cell2;
	int err;
	int insert_flag;

	struct dm_thin_clone_data *clone_data;
	/*
	 * If the bio covers the whole area of a block then we can avoid
	 * zeroing or copying.  Instead this bio is hooked.  The bio will
	 * still be in the cell, so care has to be taken to avoid issuing
	 * the bio twice.
	 */
	struct bio *bio;
	bio_end_io_t *saved_bi_end_io;
};

static void __maybe_add_mapping(struct dm_thin_new_mapping *m)
{
	struct pool *pool = m->tc->pool;

	if (m->quiesced && m->prepared) {
		list_add_tail(&m->list, &pool->prepared_mappings);
		wake_worker(pool);
	}
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct dm_thin_new_mapping *m = context;
	struct pool *pool = m->tc->pool;

	m->err = read_err || write_err ? -EIO : 0;

	spin_lock_irqsave(&pool->lock, flags);
	m->prepared = 1;
	__maybe_add_mapping(m);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static void overwrite_endio(struct bio *bio, int err)
{
	unsigned long flags;
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	struct dm_thin_new_mapping *m = h->overwrite_mapping;
	struct pool *pool = m->tc->pool;

	m->err = err;

	spin_lock_irqsave(&pool->lock, flags);
	m->prepared = 1;
	__maybe_add_mapping(m);
	spin_unlock_irqrestore(&pool->lock, flags);
}

/*----------------------------------------------------------------*/

/*
 * Workqueue.
 */

/*
 * Prepared mapping jobs.
 */

/*
 * This sends the bios in the cell, except the original holder, back
 * to the deferred_bios list.
 */
static void cell_defer_no_holder(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	struct pool *pool = tc->pool;
	unsigned long flags;

	if (!cell)
		return;

	spin_lock_irqsave(&tc->lock, flags);
	cell_release_no_holder(pool, cell, &tc->deferred_bio_list);
	spin_unlock_irqrestore(&tc->lock, flags);

	wake_worker(pool);
}

static void thin_defer_bio(struct thin_c *tc, struct bio *bio);

struct remap_info {
	struct thin_c *tc;
	struct bio_list defer_bios;
	struct bio_list issue_bios;
};

static void __inc_remap_and_issue_cell(void *context,
                                       struct dm_bio_prison_cell *cell)
{
	struct remap_info *info = context;
	struct bio *bio;

	while ((bio = bio_list_pop(&cell->bios))) {
		if (bio->bi_rw & DEFER_IO_FLAGS)
			bio_list_add(&info->defer_bios, bio);
		else {
			inc_all_io_entry(info->tc->pool, bio);

			/*
			* We can't issue the bios with the bio prison lock
			* held, so we add them to a list to issue on
			* return from this function.
			*/
			bio_list_add(&info->issue_bios, bio);
		}
	}
}

static void inc_remap_and_issue_cell(struct thin_c *tc,
                                     struct dm_bio_prison_cell *cell,
                                     dm_block_t block)
{
	struct bio *bio;
	struct remap_info info;

	info.tc = tc;
	bio_list_init(&info.defer_bios);
	bio_list_init(&info.issue_bios);
	/*
	* We have to be careful to inc any bios we're about to issue
	* before the cell is released, and avoid a race with new bios
	* being added to the cell.
	*/
	cell_visit_release(tc->pool, __inc_remap_and_issue_cell,
	                   &info, cell);

	while ((bio = bio_list_pop(&info.defer_bios)))
		thin_defer_bio(tc, bio);

	while ((bio = bio_list_pop(&info.issue_bios)))
		remap_and_issue(info.tc, bio, block);
}

static void process_prepared_mapping_fail(struct dm_thin_new_mapping *m)
{
	if (m->bio)
		m->bio->bi_end_io = m->saved_bi_end_io;
	cell_error(m->tc->pool, m->cell);
	list_del(&m->list);
	mempool_free(m, m->tc->pool->mapping_pool);
}

static void process_prepared_mapping(struct dm_thin_new_mapping *m)
{
	struct thin_c *tc = m->tc;
	struct pool *pool = tc->pool;
	struct bio *bio;
	int r;

	bio = m->bio;
	if (bio)
		bio->bi_end_io = m->saved_bi_end_io;

	if (m->err) {
		cell_error(pool, m->cell);
		goto out;
	}

	/*
	 * Commit the prepared block into the mapping btree.
	 * Any I/O for this block arriving after this point will get
	 * remapped to it directly.
	 */
	DMDEBUG("%s: insert block from %llu to %llu", __func__, m->virt_block, m->data_block);
	r = dm_thin_insert_block(tc->td, m->virt_block, m->data_block,
	                         m->old_block, 0, m->insert_flag);
	if (r) {
		DMERR_LIMIT("%s: dm_thin_insert_block() failed: error = %d",
		            dm_device_name(pool->pool_md), r);
		set_pool_mode(pool, PM_READ_ONLY);
		cell_error(pool, m->cell);
		goto out;
	}

	/*
	 * Release any bios held while the block was being provisioned.
	 * If we are processing a write bio that completely covers the block,
	 * we already processed it so can ignore it now when processing
	 * the bios in the cell.
	 */
	if (bio) {
		inc_remap_and_issue_cell(tc, m->cell, m->data_block);
		bio_endio(bio, 0);
	} else {
		inc_all_io_entry(tc->pool, m->cell->holder);
		remap_and_issue(tc, m->cell->holder, m->data_block);
		inc_remap_and_issue_cell(tc, m->cell, m->data_block);
	}

out:
	list_del(&m->list);
	mempool_free(m, pool->mapping_pool);
}

static void process_prepared_discard_fail(struct dm_thin_new_mapping *m)
{
	struct thin_c *tc = m->tc;

	bio_io_error(m->bio);
	cell_defer_no_holder(tc, m->cell);
	cell_defer_no_holder(tc, m->cell2);
	mempool_free(m, tc->pool->mapping_pool);
}

static void process_prepared_discard_passdown(struct dm_thin_new_mapping *m)
{
	struct thin_c *tc = m->tc;

	inc_all_io_entry(tc->pool, m->bio);
	cell_defer_no_holder(tc, m->cell);
	cell_defer_no_holder(tc, m->cell2);

	if (m->pass_discard) {
		if (m->definitely_not_shared)
			remap_and_issue(tc, m->bio, m->data_block);
		else {
			bool used = false;
			if (dm_pool_block_is_used(tc->pool->pmd, m->data_block, &used) || used)
				bio_endio(m->bio, 0);
			else
				remap_and_issue(tc, m->bio, m->data_block);
		}
	} else
		bio_endio(m->bio, 0);

	mempool_free(m, tc->pool->mapping_pool);
}

static void process_prepared_discard(struct dm_thin_new_mapping *m)
{
	int r;
	dm_block_t *pblock = &m->data_block;
	struct thin_c *tc = m->tc;

	r = dm_thin_remove_block(tc->td, m->virt_block, pblock);
	if (r)
		DMERR_LIMIT("dm_thin_remove_block() failed");

	process_prepared_discard_passdown(m);
}

static void process_prepared(struct pool *pool, struct list_head *head,
                             process_mapping_fn *fn)
{
	unsigned long flags;
	struct list_head maps;
	struct dm_thin_new_mapping *m, *tmp;

	INIT_LIST_HEAD(&maps);
	spin_lock_irqsave(&pool->lock, flags);
	list_splice_init(head, &maps);
	spin_unlock_irqrestore(&pool->lock, flags);

	list_for_each_entry_safe(m, tmp, &maps, list)
	(*fn)(m);
}

/*
 * Deferred bio jobs.
 */
static int io_overlaps_block(struct pool *pool, struct bio *bio)
{
	return bio->bi_size == (pool->sectors_per_block << SECTOR_SHIFT);
}

static int io_overwrites_block(struct pool *pool, struct bio *bio)
{
	return (bio_data_dir(bio) == WRITE) &&
	       io_overlaps_block(pool, bio);
}

static int fast_zeroed(struct pool *pool, struct bio *bio)
{
	return io_overwrites_block(pool, bio) && (bio->bi_rw & REQ_QNAP_MAP_ZERO);
}

static void save_and_set_endio(struct bio *bio, bio_end_io_t **save,
                               bio_end_io_t *fn)
{
	*save = bio->bi_end_io;
	bio->bi_end_io = fn;
}

static int ensure_next_mapping(struct pool *pool)
{
	if (pool->next_mapping)
		return 0;

	pool->next_mapping = mempool_alloc(pool->mapping_pool, GFP_ATOMIC);

	return pool->next_mapping ? 0 : -ENOMEM;
}

static struct dm_thin_new_mapping *get_next_mapping(struct pool *pool)
{
	struct dm_thin_new_mapping *r = pool->next_mapping;

	BUG_ON(!pool->next_mapping);

	pool->next_mapping = NULL;

	return r;
}

static void remap_and_issue_overwrite(struct thin_c *tc, struct bio *bio,
                                      dm_block_t data_block,
                                      struct dm_thin_new_mapping *m)
{
	struct pool *pool = tc->pool;
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));

	h->overwrite_mapping = m;
	m->bio = bio;
	save_and_set_endio(bio, &m->saved_bi_end_io, overwrite_endio);
	inc_all_io_entry(pool, bio);
	remap_and_issue(tc, bio, data_block);
}


static void schedule_copy(struct thin_c *tc, dm_block_t virt_block,
                          struct dm_dev *origin, dm_block_t data_origin,
                          dm_block_t data_dest,
                          struct dm_bio_prison_cell *cell, struct bio *bio, unsigned bypass_copy, unsigned cloned)
{
	int r;
	struct pool *pool = tc->pool;
	struct dm_thin_new_mapping *m = get_next_mapping(pool);

	INIT_LIST_HEAD(&m->list);
	m->quiesced = 0;
	m->prepared = 0;
	m->tc = tc;
	m->virt_block = virt_block;
	m->data_block = data_dest;
	m->old_block = data_origin;
	m->cell = cell;
	m->err = 0;
	m->bio = NULL;
	m->insert_flag = (cloned) ? INSERT_NEW : INSERT_OVERWRITE;
	m->clone_data = NULL;

	if (!dm_deferred_set_add_work(pool->shared_read_ds, &m->list))
		m->quiesced = 1;

	/*
	 * IO to pool_dev remaps to the pool target's data_dev.
	 *
	 * If the whole block of data is being overwritten, we can issue the
	 * bio immediately. Otherwise we use kcopyd to clone the data first.
	 */
	if (io_overwrites_block(pool, bio) || bypass_copy)
		remap_and_issue_overwrite(tc, bio, data_dest, m);

	else {
		struct dm_io_region from, to;

		from.bdev = origin->bdev;
		from.sector = data_origin * pool->sectors_per_block;
		from.count = pool->sectors_per_block;

		to.bdev = tc->pool_dev->bdev;
		to.sector = data_dest * pool->sectors_per_block;
		to.count = pool->sectors_per_block;

		r = dm_kcopyd_copy(pool->copier, &from, 1, &to,
		                   0, copy_complete, m);
		if (r < 0) {
			mempool_free(m, pool->mapping_pool);
			DMERR_LIMIT("dm_kcopyd_copy() failed");
			cell_error(pool, cell);
		}
	}
}

static void schedule_internal_copy(struct thin_c *tc, dm_block_t virt_block,
                                   dm_block_t data_origin, dm_block_t data_dest,
                                   struct dm_bio_prison_cell *cell, struct bio *bio, unsigned bypass_copy, unsigned cloned)
{
	schedule_copy(tc, virt_block, tc->pool_dev,
	              data_origin, data_dest, cell, bio, bypass_copy, cloned);
}

static void schedule_external_copy(struct thin_c *tc, dm_block_t virt_block,
                                   dm_block_t data_dest,
                                   struct dm_bio_prison_cell *cell, struct bio *bio)
{
	schedule_copy(tc, virt_block, tc->origin_dev,
	              virt_block, data_dest, cell, bio, 0, 0);
}

static void schedule_zero(struct thin_c *tc, dm_block_t virt_block,
                          dm_block_t data_block, dm_block_t *old_block,
                          struct dm_bio_prison_cell *cell,
                          struct bio *bio, unsigned zeroed, unsigned shared)
{
	struct pool *pool = tc->pool;
	struct dm_thin_new_mapping *m = get_next_mapping(pool);

	INIT_LIST_HEAD(&m->list);
	m->quiesced = (shared) ? 0 : 1;
	m->prepared = 0;
	m->tc = tc;
	m->virt_block = virt_block;
	m->data_block = data_block;
	m->cell = cell;
	m->err = 0;
	m->bio = NULL;
	m->clone_data = NULL;

	if (old_block) {
		if (*old_block == data_block)
			m->insert_flag = INSERT_REFLAG;
		else {
			m->insert_flag = INSERT_OVERWRITE;
			m->old_block = *old_block;
		}
	} else
		m->insert_flag = INSERT_NEW;

	if (shared) {
		if (!dm_deferred_set_add_work(pool->shared_read_ds, &m->list))
			m->quiesced = 1;
	} else {
		if (!pool->pf.zero_new_blocks && !zeroed) {
			process_prepared_mapping(m);
			return;
		}
	}
	/*
	 * If the whole block of data is being overwritten or we are not
	 * zeroing pre-existing data, we can issue the bio immediately.
	 * Otherwise we use kcopyd to zero the data first.
	 */


	if (io_overwrites_block(pool, bio))
		remap_and_issue_overwrite(tc, bio, data_block, m);

	else {
		int r;
		struct dm_io_region to;

		to.bdev = tc->pool_dev->bdev;
		to.sector = data_block * pool->sectors_per_block;
		to.count = pool->sectors_per_block;

		r = dm_kcopyd_zero(pool->copier, 1, &to, 0, copy_complete, m);
		if (r < 0) {
			mempool_free(m, pool->mapping_pool);
			DMERR_LIMIT("dm_kcopyd_zero() failed");
			cell_error(pool, cell);
		}
	}
}

static int sync_io_threshold_reached(struct pool *pool)
{
	int r;
	dm_block_t oc_blocks, free_blocks;

	dm_pool_get_origin_mapped_blocks(pool->pmd, &oc_blocks);
	r = dm_pool_get_free_block_count(pool->pmd, &free_blocks);
	if (r) {
		DMWARN("check pool free block count failed");
		return -EINVAL;
	}

	if (free_blocks <= pool->sync_io_threshold ||
	    (pool->origin_max_blocks && oc_blocks >= pool->origin_max_blocks - pool->sync_io_threshold))
		return 1;
	else
		return 0;
}

static void clear_space_monitor_triggers(struct pool *pool)
{
	int r;
	unsigned long flags;
	dm_block_t free_blocks;

	r = dm_pool_get_free_block_count(pool->pmd, &free_blocks);
	if (r) {
		DMWARN("check pool free block count failed");
		return;
	}

	if (free_blocks) {
		spin_lock_irqsave(&pool->lock, flags);
		pool->no_free_space = 0;
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	if (!sync_io_threshold_reached(pool)) {
		spin_lock_irqsave(&pool->lock, flags);
		pool->sync_io_triggered = 0;
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	if (free_blocks > pool->low_water_blocks) {
		spin_lock_irqsave(&pool->lock, flags);
		pool->low_water_triggered = 0;
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	if (free_blocks > pool->snap_delete_threshold) {
		spin_lock_irqsave(&pool->lock, flags);
		pool->snap_delete = 0;
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	return;
}

/*
 * A non-zero return indicates read_only or fail_io mode.
 * Many callers don't care about the return value.
 */
static int commit(struct pool *pool)
{
	int r;

	if (get_pool_mode(pool) != PM_WRITE)
		return -EINVAL;

	r = dm_pool_commit_metadata(pool->pmd);
	if (r) {
		DMERR_LIMIT("%s: dm_pool_commit_metadata failed: error = %d",
		            dm_device_name(pool->pool_md), r);
		set_pool_mode(pool, PM_READ_ONLY);
	} else if (!pool->sb_backup_fail_reported &&
	           report_sb_backup_fail(pool->pmd))
		send_hal_msg(pool, HAL_SB_BACKUP_FAIL);

	clear_space_monitor_triggers(pool);

	return r;
}

static int alloc_data_block(struct thin_c *tc, dm_block_t *result, int action)
{
	int r;
	dm_block_t free_blocks;
	unsigned long flags;
	struct pool *pool = tc->pool;

	/*
	 * Once no_free_space is set we must not allow allocation to succeed.
	 * Otherwise it is difficult to explain, debug, test and support.
	 */
	if (pool->no_free_space)
		return -ENOSPC;

	r = dm_pool_get_free_block_count(pool->pmd, &free_blocks);
	if (r)
		return r;

	if (free_blocks <= pool->low_water_blocks && !pool->low_water_triggered) {
		DMWARN("%s: reached low water mark for data device: sending event.",
		       dm_device_name(pool->pool_md));
		spin_lock_irqsave(&pool->lock, flags);
		pool->low_water_triggered = 1;
		spin_unlock_irqrestore(&pool->lock, flags);
		dm_table_event(pool->ti->table);
	}

	if ((sync_io_threshold_reached(pool) > 0) && !pool->sync_io_triggered) {
		DMWARN("%s: reached sync io threshold for data device: sending event.",
		       dm_device_name(pool->pool_md));
		spin_lock_irqsave(&pool->lock, flags);
		pool->sync_io_triggered = 1;
		spin_unlock_irqrestore(&pool->lock, flags);
		dm_table_event(pool->ti->table);
	}

	if (free_blocks <= pool->snap_delete_threshold && !pool->snap_delete) {
		DMWARN("%s: reached snapshot deleteion threshold for data device: sending event.",
		       dm_device_name(pool->pool_md));
		spin_lock_irqsave(&pool->lock, flags);
		pool->snap_delete = 1;
		spin_unlock_irqrestore(&pool->lock, flags);
		dm_table_event(pool->ti->table);
	}

	if (action & ALLOC_RESERVE)
		r = dm_pool_alloc_reserve_data_block(pool->pmd, result);
	else {
		if (!free_blocks) {
			/*
			 * Try to commit to see if that will free up some
			 * more space.
			 */
			r = commit(pool);
			if (r)
				return r;

			r = dm_pool_get_free_block_count(pool->pmd, &free_blocks);
			if (r)
				return r;

			/*
			 * If we still have no space we set a flag to avoid
			 * doing all this checking and return -ENOSPC.  This
			 * flag serves as a latch that disallows allocations from
			 * this pool until the admin takes action (e.g. resize or
			 * table reload).
			 */
			if (!free_blocks) {
				DMWARN("%s: no free data space available.",
				       dm_device_name(pool->pool_md));
				spin_lock_irqsave(&pool->lock, flags);
				pool->no_free_space = 1;
				spin_unlock_irqrestore(&pool->lock, flags);
				return -ENOSPC;
			}
		}

		r = dm_pool_alloc_data_block(pool->pmd, result, action);
	}

	if (r) {
		if (r == -ENOSPC &&
		    !dm_pool_get_free_metadata_block_count(pool->pmd, &free_blocks) &&
		    !free_blocks) {
			DMWARN("%s: no free metadata space available.",
			       dm_device_name(pool->pool_md));
			set_pool_mode(pool, PM_READ_ONLY);
		}
		return r;
	}

	return 0;
}

/*
 * If we have run out of space, queue bios until the device is
 * resumed, presumably after having been reloaded with more space.
 */
static void retry_on_resume(struct bio *bio)
{
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	struct thin_c *tc = h->tc;
	unsigned long flags;

	spin_lock_irqsave(&tc->lock, flags);
	bio_list_add(&tc->retry_on_resume_list, bio);
	spin_unlock_irqrestore(&tc->lock, flags);
}

static void no_space(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);
	cell_release(pool, cell, &bios);

	while ((bio = bio_list_pop(&bios)))
//		retry_on_resume(bio);
		bio_endio(bio, -ENOSPC);
}

static void process_discard_cell(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	int r;
	struct bio *bio = cell->holder;
	struct pool *pool = tc->pool;
	struct dm_bio_prison_cell *cell2;
	struct dm_cell_key key2;
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_thin_lookup_result lookup_result;
	struct dm_thin_new_mapping *m;

	r = dm_thin_find_block(tc->td, block, 1, &lookup_result);
	switch (r) {
	case 0:
		/*
		 * Check nobody is fiddling with this pool block.  This can
		 * happen if someone's in the process of breaking sharing
		 * on this block.
		 */
		build_data_key(tc->td, block, lookup_result.block, &key2);
		if (bio_detain(tc->pool, &key2, bio, &cell2)) {
			cell_defer_no_holder(tc, cell);
			break;
		}

		if (io_overlaps_block(pool, bio) && !tc->is_thick) {
			/*
			 * IO may still be going to the destination block.  We must
			 * quiesce before we can do the removal.
			 */
			m = get_next_mapping(pool);
			m->tc = tc;
			m->pass_discard = pool->pf.discard_passdown && tc->discard_passdown;
			m->definitely_not_shared = !lookup_result.shared;
			m->cloned = (lookup_result.cloned) ? 1 : 0;
			m->virt_block = block;
			m->data_block = lookup_result.block;
			m->cell = cell;
			m->cell2 = cell2;
			m->err = 0;
			m->bio = bio;
			m->clone_data = NULL;

			if (!dm_deferred_set_add_work(pool->all_io_ds, &m->list))
				pool->process_prepared_discard(m);

		} else {
			inc_all_io_entry(pool, bio);
			cell_defer_no_holder(tc, cell);
			cell_defer_no_holder(tc, cell2);

			/*
			 * The DM core makes sure that the discard doesn't span
			 * a block boundary.  So we submit the discard of a
			 * partial block appropriately.
			 */
			if ((!lookup_result.shared) && pool->pf.discard_passdown && tc->discard_passdown)
				remap_and_issue(tc, bio, lookup_result.block);
			else
				bio_endio(bio, 0);
		}
		break;

	case -ENODATA:
		/*
		 * It isn't provisioned, just forget it.
		 */
		cell_defer_no_holder(tc, cell);
		bio_endio(bio, 0);
		break;

	default:
		DMERR_LIMIT("%s: dm_thin_find_block() failed: error = %d",
		            __func__, r);
		cell_defer_no_holder(tc, cell);
		bio_io_error(bio);
		break;
	}
}

static void process_discard_bio(struct thin_c *tc, struct bio *bio)
{
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;
	dm_block_t block = get_bio_block(tc, bio);

	build_virtual_key(tc->td, block, &key);
	if (bio_detain(tc->pool, &key, bio, &cell))
		return;

	process_discard_cell(tc, cell);
}

static void break_sharing(struct thin_c *tc, struct bio *bio, dm_block_t block,
                          struct dm_cell_key *key,
                          struct dm_thin_lookup_result *lookup_result,
                          struct dm_bio_prison_cell *cell)
{
	int r;
	dm_block_t data_block = lookup_result->block;
	struct pool *pool = tc->pool;

	r = alloc_data_block(tc, &data_block, (lookup_result->cloned) ? ALLOC_RESERVE : ALLOC_SHARE);
	switch (r) {
	case 0:
		schedule_internal_copy(tc, block, lookup_result->block,
		                       data_block, cell, bio, lookup_result->zeroed, lookup_result->cloned);
		break;

	case -ENOSPC:
		no_space(pool, cell);
		break;

	default:
		DMERR_LIMIT("%s: alloc_data_block() failed: error = %d",
		            __func__, r);
		set_pool_mode(pool, PM_READ_ONLY);
		cell_error(pool, cell);
		break;
	}
}

static void __remap_and_issue_shared_cell(void *context,
        struct dm_bio_prison_cell *cell)
{
	struct remap_info *info = context;
	struct bio *bio;

	while ((bio = bio_list_pop(&cell->bios))) {
		if ((bio_data_dir(bio) == WRITE) ||
		    (bio->bi_rw & DEFER_IO_FLAGS))
			bio_list_add(&info->defer_bios, bio);
		else {
			struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));;

			h->shared_read_entry = dm_deferred_entry_inc(info->tc->pool->shared_read_ds);
			inc_all_io_entry(info->tc->pool, bio);
			bio_list_add(&info->issue_bios, bio);
		}
	}
}

static void remap_and_issue_shared_cell(struct thin_c *tc,
                                        struct dm_bio_prison_cell *cell,
                                        dm_block_t block)
{
	struct bio *bio;
	struct remap_info info;

	info.tc = tc;
	bio_list_init(&info.defer_bios);
	bio_list_init(&info.issue_bios);

	cell_visit_release(tc->pool, __remap_and_issue_shared_cell,
	                   &info, cell);

	while ((bio = bio_list_pop(&info.defer_bios)))
		thin_defer_bio(tc, bio);

	while ((bio = bio_list_pop(&info.issue_bios)))
		remap_and_issue(tc, bio, block);
}

static void process_shared_bio(struct thin_c *tc, struct bio *bio,
                               dm_block_t block,
                               struct dm_thin_lookup_result *lookup_result,
                               struct dm_bio_prison_cell *virt_cell)
{
	struct dm_bio_prison_cell *data_cell;
	struct pool *pool = tc->pool;
	struct dm_cell_key key;

	/*
	 * If cell is already occupied, then sharing is already in the process
	 * of being broken so we have nothing further to do here.
	 */
	build_data_key(tc->td, block, lookup_result->block, &key);
	if (bio_detain(pool, &key, bio, &data_cell)) {
		cell_defer_no_holder(tc, virt_cell);
		return;
	}

	if (bio_data_dir(bio) == WRITE && bio->bi_size) {
		break_sharing(tc, bio, block, &key, lookup_result, data_cell);
		cell_defer_no_holder(tc, virt_cell);
	} else {
		struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));

		h->shared_read_entry = dm_deferred_entry_inc(pool->shared_read_ds);
		inc_all_io_entry(pool, bio);

		remap_and_issue(tc, bio, lookup_result->block);
		remap_and_issue_shared_cell(tc, data_cell, lookup_result->block);
		remap_and_issue_shared_cell(tc, virt_cell, lookup_result->block);
	}
}

static void provision_block(struct thin_c *tc, struct bio *bio, dm_block_t block,
                            struct dm_bio_prison_cell *cell)
{
	int r;
	dm_block_t data_block;
	struct pool *pool = tc->pool;

	/*
	 * Remap empty bios (flushes) immediately, without provisioning.
	 */
	if (!bio->bi_size) {
		inc_all_io_entry(pool, bio);
		cell_defer_no_holder(tc, cell);
		remap_and_issue(tc, bio, 0);
		return;
	}

	/*
	 * Fill read bios with zeroes and complete them immediately.
	 */
	if (bio_data_dir(bio) == READ) {
		zero_fill_bio(bio);
		cell_defer_no_holder(tc, cell);
		set_bit(BIO_THIN_UNMAPPED, &bio->bi_flags);
		bio_endio(bio, 0);
		return;
	}

	r = alloc_data_block(tc, &data_block, ALLOC_NEW);
	switch (r) {
	case 0:
		if (tc->origin_dev)
			schedule_external_copy(tc, block, data_block, cell, bio);
		else
			schedule_zero(tc, block, data_block, NULL, cell, bio, 0, 0);
		break;

	case -ENOSPC:
		no_space(pool, cell);
		break;

	default:
		DMERR_LIMIT("%s: alloc_data_block() failed: error = %d",
		            __func__, r);
		set_pool_mode(pool, PM_READ_ONLY);
		cell_error(pool, cell);
		break;
	}
}

static void zero_block(struct thin_c *tc, struct bio *bio, dm_block_t block,
                       dm_block_t data_block, struct dm_bio_prison_cell *cell,
                       struct dm_thin_lookup_result *result)
{
	int r = 0;
	struct pool *pool = tc->pool;
	dm_block_t old_block = data_block;

	/*
	 * Remap empty bios (flushes) immediately, without zeroing.
	 */
	if (!bio->bi_size) {
		inc_all_io_entry(pool, bio);
		cell_defer_no_holder(tc, cell);
		remap_and_issue(tc, bio, 0);
		return;
	}

	/*
	 * Fill read bios with zeroes and complete them immediately.
	 */
	if (bio_data_dir(bio) == READ) {
		zero_fill_bio(bio);
		cell_defer_no_holder(tc, cell);
		bio_endio(bio, 0);
		return;
	}

	if (result->shared)
		r = alloc_data_block(tc, &data_block, (result->cloned) ? ALLOC_RESERVE : ALLOC_SHARE);

	switch (r) {
	case 0:
		schedule_zero(tc, block, data_block, (result->cloned) ? NULL : &old_block, cell, bio, 1, result->shared);
		break;

	case -ENOSPC:
		no_space(pool, cell);
		break;

	default:
		DMERR_LIMIT("%s: alloc_data_block() failed: error = %d",
		            __func__, r);
		set_pool_mode(pool, PM_READ_ONLY);
		cell_error(pool, cell);
		break;
	}
}

static void process_cell(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	int r;
	struct pool *pool = tc->pool;
	struct bio *bio = cell->holder;
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_thin_lookup_result lookup_result;


	r = dm_thin_find_block(tc->td, block, 1, &lookup_result);
	switch (r) {
	case 0:
		if (lookup_result.zeroed)
			zero_block(tc, bio, block, lookup_result.block, cell, &lookup_result);
		else {
			if (lookup_result.shared) {
				process_shared_bio(tc, bio, block, &lookup_result, cell);
			} else {
				inc_all_io_entry(pool, bio);
				remap_and_issue(tc, bio, lookup_result.block);
				inc_remap_and_issue_cell(tc, cell, lookup_result.block);
			}
		}
		break;

	case -ENODATA:
		if (bio_data_dir(bio) == READ && tc->origin_dev) {
			inc_all_io_entry(pool, bio);
			cell_defer_no_holder(tc, cell);
			remap_to_origin_and_issue(tc, bio);
		} else
			provision_block(tc, bio, block, cell);
		break;

	default:
		DMERR_LIMIT("%s: dm_thin_find_block() failed: error = %d",
		            __func__, r);
		cell_defer_no_holder(tc, cell);
		bio_io_error(bio);
		break;
	}
}

static void process_bio(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;

	/*
	* If cell is already occupied, then the block is already
	* being provisioned so we have nothing further to do here.
	*/
	build_virtual_key(tc->td, block, &key);
	if (bio_detain(pool, &key, bio, &cell))
		return;

	process_cell(tc, cell);
}

static void process_fast_zero_cell(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	int r;
	struct pool *pool = tc->pool;
	struct bio *bio = cell->holder;
	struct dm_bio_prison_cell *cell2;
	struct dm_cell_key key2;
	dm_block_t block = get_bio_block(tc, bio), new_block;
	struct dm_thin_lookup_result lookup_result;
	uint32_t map_and_zero = (bio->bi_rw & REQ_QNAP_MAP) ? 0 : 1;


	r = dm_thin_find_block(tc->td, block, 1, &lookup_result);
	switch (r) {
	case 0:
		/* Nothing we can do, it has already been zeroed */
		if (lookup_result.zeroed || bio->bi_rw & REQ_QNAP_MAP) {
			cell_defer_no_holder(tc, cell);
			bio_endio(bio, 0);
			break;
		}

		/*
		 * Check nobody is fiddling with this pool block.  This can
		 * happen if someone's in the process of breaking sharing
		 * on this block.
		 */
		build_data_key(tc->td, block, lookup_result.block, &key2);
		if (bio_detain(tc->pool, &key2, bio, &cell2)) {
			cell_defer_no_holder(tc, cell);
			break;
		}

		BUG_ON(!io_overlaps_block(pool, bio));

		if (dm_thin_insert_block_with_time(tc->td, block, lookup_result.block, 0,
		                                   map_and_zero, &lookup_result.time, INSERT_REFLAG)) {
			DMERR("%s: error when trying to write zero to block %llu with fast zeroing", __func__, lookup_result.block);
			cell_defer_no_holder(tc, cell);
			cell_defer_no_holder(tc, cell2);
			bio_io_error(bio);
			break;
		}
		cell_defer_no_holder(tc, cell);
		cell_defer_no_holder(tc, cell2);

		bio_endio(bio, 0);
		break;
	case -ENODATA:
		/*
		 * It isn't provisioned, just allocate space for it.
		 */
		r = alloc_data_block(tc, &new_block, ALLOC_NEW);
		if (r) {
			DMERR_LIMIT("%s: cannot provision new block to handle fast_zeroing", __func__);
			if (r == -ENOSPC)
				no_space(pool, cell);
			else {
				cell_defer_no_holder(tc, cell);
				bio_io_error(bio);
			}
			break;
		}

		if (dm_thin_insert_block(tc->td, block, new_block, 0, map_and_zero, INSERT_NEW)) {
			DMERR_LIMIT("%s: cannot insert new block to handle fast zeroing", __func__);
			cell_defer_no_holder(tc, cell);
			bio_io_error(bio);
			break;
		}

		cell_defer_no_holder(tc, cell);
		bio_endio(bio, 0);
		break;

	default:
		DMERR_LIMIT("%s: dm_thin_find_block() failed: error = %d",
		            __func__, r);
		cell_defer_no_holder(tc, cell);
		bio_io_error(bio);
		break;
	}
}

static void process_fast_zero(struct thin_c *tc, struct bio *bio)
{
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;

	build_virtual_key(tc->td, block, &key);
	if (bio_detain(tc->pool, &key, bio, &cell))
		return;

	process_fast_zero_cell(tc, cell);
}

static void __process_bio_read_only(struct thin_c *tc, struct bio *bio,
                                    struct dm_bio_prison_cell *cell)
{
	int r;
	int rw = bio_data_dir(bio);
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_thin_lookup_result lookup_result;

	r = dm_thin_find_block(tc->td, block, 1, &lookup_result);
	switch (r) {
	case 0:
		if (lookup_result.shared && (rw == WRITE) && bio->bi_size) {
			bio_io_error(bio);
			if (cell)
				cell_defer_no_holder(tc, cell);
		} else {
			inc_all_io_entry(tc->pool, bio);
			remap_and_issue(tc, bio, lookup_result.block);
			if (cell)
				inc_remap_and_issue_cell(tc, cell, lookup_result.block);
		}
		break;

	case -ENODATA:
		if (cell)
			cell_defer_no_holder(tc, cell);

		if (rw != READ) {
			bio_io_error(bio);
			break;
		}

		if (tc->origin_dev) {
			inc_all_io_entry(tc->pool, bio);
			remap_to_origin_and_issue(tc, bio);
			break;
		}

		zero_fill_bio(bio);
		bio_endio(bio, 0);
		break;

	default:
		DMERR_LIMIT("%s: dm_thin_find_block() failed: error = %d",
		            __func__, r);
		if (cell)
			cell_defer_no_holder(tc, cell);
		bio_io_error(bio);
		break;
	}
}

static void process_bio_read_only(struct thin_c *tc, struct bio *bio)
{
	__process_bio_read_only(tc, bio, NULL);
}

static void process_cell_read_only(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	__process_bio_read_only(tc, cell->holder, cell);
}

static void process_bio_success(struct thin_c *tc, struct bio *bio)
{
	bio_endio(bio, 0);
}

static void process_bio_fail(struct thin_c *tc, struct bio *bio)
{
	bio_io_error(bio);
}

static void process_cell_success(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	cell_success(tc->pool, cell);
}

static void process_cell_fail(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	cell_error(tc->pool, cell);
}

/*
 * FIXME: should we also commit due to size of transaction, measured in
 * metadata blocks?
 */
static int need_commit_due_to_time(struct pool *pool)
{
	return jiffies < pool->last_commit_jiffies ||
	       jiffies > pool->last_commit_jiffies + COMMIT_PERIOD;
}

#define thin_pbd(node) rb_entry((node), struct dm_thin_endio_hook, rb_node)
#define thin_bio(pbd) dm_bio_from_per_bio_data((pbd), sizeof(struct dm_thin_endio_hook))

static void __thin_bio_rb_add(struct thin_c *tc, struct bio *bio)
{
	struct rb_node **rbp, *parent;
	struct dm_thin_endio_hook *pbd;
	sector_t bi_sector = bio->bi_sector;

	rbp = &tc->sort_bio_list.rb_node;
	parent = NULL;
	while (*rbp) {
		parent = *rbp;
		pbd = thin_pbd(parent);

		if (bi_sector < thin_bio(pbd)->bi_sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}

	pbd = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	rb_link_node(&pbd->rb_node, parent, rbp);
	rb_insert_color(&pbd->rb_node, &tc->sort_bio_list);
}

static void __extract_sorted_bios(struct thin_c *tc)
{
	struct rb_node *node;
	struct dm_thin_endio_hook *pbd;
	struct bio *bio;

	for (node = rb_first(&tc->sort_bio_list); node; node = rb_next(node)) {
		pbd = thin_pbd(node);
		bio = thin_bio(pbd);

		bio_list_add(&tc->deferred_bio_list, bio);
		rb_erase(&pbd->rb_node, &tc->sort_bio_list);
	}

	WARN_ON(!RB_EMPTY_ROOT(&tc->sort_bio_list));
}

static void __sort_thin_deferred_bios(struct thin_c *tc)
{
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);
	bio_list_merge(&bios, &tc->deferred_bio_list);
	bio_list_init(&tc->deferred_bio_list);

	/* Sort deferred_bio_list using rb-tree */
	while ((bio = bio_list_pop(&bios)))
		__thin_bio_rb_add(tc, bio);

	/*
	 * Transfer the sorted bios in sort_bio_list back to
	 * deferred_bio_list to allow lockless submission of
	 * all bios.
	 */
	__extract_sorted_bios(tc);
}

static void process_thin_deferred_bios(struct thin_c *tc)
{
	struct pool *pool = tc->pool;
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;
	struct blk_plug plug;
	unsigned count = 0;

	bio_list_init(&bios);

	spin_lock_irqsave(&tc->lock, flags);

	/*
	 * FIXME: allow sorting to be enabled/disabled via ctr and/or
	 * message (and auto-disable if data device is non-rotational?)
	 */
	__sort_thin_deferred_bios(tc);

	bio_list_merge(&bios, &tc->deferred_bio_list);
	bio_list_init(&tc->deferred_bio_list);

	spin_unlock_irqrestore(&tc->lock, flags);

	blk_start_plug(&plug);
	while ((bio = bio_list_pop(&bios))) {

		/*
		 * If we've got no free new_mapping structs, and processing
		 * this bio might require one, we pause until there are some
		 * prepared mappings to process.
		 */
		if (ensure_next_mapping(pool)) {
			spin_lock_irqsave(&tc->lock, flags);
			bio_list_merge(&tc->deferred_bio_list, &bios);
			spin_unlock_irqrestore(&tc->lock, flags);
			break;
		}

		if (fast_zeroed(pool, bio) || bio->bi_rw & REQ_QNAP_MAP)
			pool->process_fast_zero(tc, bio);
		else if (bio->bi_rw & REQ_DISCARD)
			pool->process_discard(tc, bio);
		else
			pool->process_bio(tc, bio);

		if ((count++ & 127) == 0)
			dm_pool_issue_prefetches(pool->pmd);
	}
	blk_finish_plug(&plug);
}

static int cmp_cells(const void *lhs, const void *rhs)
{
	struct dm_bio_prison_cell *lhs_cell = *((struct dm_bio_prison_cell **) lhs);
	struct dm_bio_prison_cell *rhs_cell = *((struct dm_bio_prison_cell **) rhs);

	BUG_ON(!lhs_cell->holder);
	BUG_ON(!rhs_cell->holder);

	if (lhs_cell->holder->bi_size < rhs_cell->holder->bi_size)
		return -1;

	if (lhs_cell->holder->bi_size > rhs_cell->holder->bi_size)
		return 1;

	return 0;
}

static unsigned sort_cells(struct pool *pool, struct list_head *cells)
{
	unsigned count = 0;
	struct dm_bio_prison_cell *cell, *tmp;

	list_for_each_entry_safe(cell, tmp, cells, user_list) {
		if (count >= CELL_SORT_ARRAY_SIZE)
			break;

		pool->cell_sort_array[count++] = cell;
		list_del(&cell->user_list);
	}

	sort(pool->cell_sort_array, count, sizeof(cell), cmp_cells, NULL);

	return count;
}

static void process_thin_deferred_cells(struct thin_c *tc)
{
	struct pool *pool = tc->pool;
	unsigned long flags;
	struct list_head cells;
	struct dm_bio_prison_cell *cell;
	unsigned i, j, count;

	INIT_LIST_HEAD(&cells);

	spin_lock_irqsave(&tc->lock, flags);
	list_splice_init(&tc->deferred_cells, &cells);
	spin_unlock_irqrestore(&tc->lock, flags);

	if (list_empty(&cells))
		return;

	do {
		count = sort_cells(tc->pool, &cells);

		for (i = 0; i < count; i++) {
			cell = pool->cell_sort_array[i];
			BUG_ON(!cell->holder);
			/*
			 * If we've got no free new_mapping structs, and processing
			 * this bio might require one, we pause until there are some
			 * prepared mappings to process.
			 */
			if (ensure_next_mapping(pool)) {
				for (j = i; j < count; j++)
					list_add(&pool->cell_sort_array[j]->user_list, &cells);
				spin_lock_irqsave(&tc->lock, flags);
				list_splice(&cells, &tc->deferred_cells);
				spin_unlock_irqrestore(&tc->lock, flags);
				return;
			}

			if (cell->holder->bi_rw & REQ_DISCARD)
				pool->process_discard_cell(tc, cell);
			else
				pool->process_cell(tc, cell);
		}
	} while (!list_empty(&cells));
}

static void thin_get(struct thin_c *tc);
static void thin_put(struct thin_c *tc);

/*
 * We can't hold rcu_read_lock() around code that can block. So we
 * find a thin with the rcu lock held; bump a refcount; then drop
 * the lock.
 */
static struct thin_c *get_first_thin(struct pool *pool)
{
	struct thin_c *tc = NULL;

	rcu_read_lock();
	if (!list_empty(&pool->active_thins)) {
		tc = list_entry_rcu(pool->active_thins.next, struct thin_c, list);
		thin_get(tc);
	}
	rcu_read_unlock();

	return tc;
}

static struct thin_c *get_next_thin(struct pool *pool, struct thin_c *tc)
{
	struct thin_c *old_tc = tc;

	rcu_read_lock();
	list_for_each_entry_continue_rcu(tc, &pool->active_thins, list) {
		thin_get(tc);
		thin_put(old_tc);
		rcu_read_unlock();
		return tc;
	}
	thin_put(old_tc);
	rcu_read_unlock();

	return NULL;
}

static struct thin_c *find_thin(struct pool *pool, dm_thin_id id)
{
	struct thin_c *tc = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(tc, &pool->active_thins, list) {
		if (tc->dev_id == id) {
			thin_get(tc);
			break;
		}
	}
	rcu_read_unlock();

	return tc;
}

static void process_deferred_bios(struct pool *pool)
{
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;
	struct thin_c *tc;

	tc = get_first_thin(pool);
	while (tc) {
		process_thin_deferred_cells(tc);
		process_thin_deferred_bios(tc);
		tc = get_next_thin(pool, tc);
	}

	/*
	 * If there are any deferred flush bios, we must commit
	 * the metadata before issuing them.
	 */
	bio_list_init(&bios);
	spin_lock_irqsave(&pool->lock, flags);
	bio_list_merge(&bios, &pool->deferred_flush_bios);
	bio_list_init(&pool->deferred_flush_bios);
	spin_unlock_irqrestore(&pool->lock, flags);

	if (bio_list_empty(&bios) && !need_commit_due_to_time(pool))
		return;

	if (commit(pool)) {
		while ((bio = bio_list_pop(&bios)))
			bio_io_error(bio);
		return;
	}
	pool->last_commit_jiffies = jiffies;

	while ((bio = bio_list_pop(&bios)))
		generic_make_request(bio);
}

static void do_worker(struct work_struct *ws)
{
	struct pool *pool = container_of(ws, struct pool, worker);

	throttle_work_start(&pool->throttle);
	dm_pool_issue_prefetches(pool->pmd);
	throttle_work_update(&pool->throttle);
	process_prepared(pool, &pool->prepared_mappings, &pool->process_prepared_mapping);
	throttle_work_update(&pool->throttle);
	process_prepared(pool, &pool->prepared_discards, &pool->process_prepared_discard);
	throttle_work_update(&pool->throttle);
	process_prepared(pool, &pool->prepared_clones, &pool->process_prepared_clone);
	throttle_work_update(&pool->throttle);
	process_deferred_bios(pool);
	throttle_work_complete(&pool->throttle);
}

/*
 * We want to commit periodically so that not too much
 * unwritten data builds up.
 */
static void do_waker(struct work_struct *ws)
{
	struct pool *pool = container_of(to_delayed_work(ws), struct pool, waker);
	wake_worker(pool);
	queue_delayed_work(pool->wq, &pool->waker, COMMIT_PERIOD);
}

static int overlapped(sector_t start, sector_t tstart, sector_t length)
{
	if (tstart > start && (tstart < start + length))
		return 1;
	else if (start > tstart && (start < tstart + length))
		return 1;
	else
		return 0;
}

static void process_prepared_clone_fail(struct dm_thin_new_mapping *m)
{
	struct dm_thin_clone_data *cd = m->clone_data;
	struct thin_c *src_tc = cd->src_p, *dst_tc = cd->dst_p;
	struct pool *pool = src_tc->pool;

	if (cd->d_dcell)
		cell_defer_no_holder(dst_tc, cd->d_dcell);
	cell_defer_no_holder(dst_tc, cd->d_vcell);
	cell_defer_no_holder(src_tc, cd->s_dcell);
	cell_defer_no_holder(src_tc, cd->s_vcell);

	atomic_inc(cd->err_count);
	if (atomic_dec_and_test(cd->on_the_fly))
		complete(cd->complete);

	kfree(cd->dresult);
	kfree(cd->sresult);
	kfree(cd);
	mempool_free(m, pool->mapping_pool);
}

static void process_prepared_clone(struct dm_thin_new_mapping *m)
{
	int r;
	struct dm_thin_clone_data *cd = m->clone_data;
	struct thin_c *src_tc = cd->src_p, *dst_tc = cd->dst_p;
	struct pool *pool = src_tc->pool;

	r = dm_pool_clone_block(pool->pmd, cd->sresult,
									   src_tc->td,
									   cd->src_blk,
									   cd->dresult,
									   dst_tc->td,
									   cd->dst_blk);
	if (r) {
		atomic_inc(cd->err_count);
		if (r != -ENOSPC && r != -ENOTSUPP)
			set_pool_mode(pool, PM_READ_ONLY);
		else if (r == -ENOSPC)
			atomic_inc(cd->no_space_count);
	}

	if (cd->d_dcell)
		cell_defer_no_holder(dst_tc, cd->d_dcell);
	cell_defer_no_holder(dst_tc, cd->d_vcell);
	cell_defer_no_holder(src_tc, cd->s_dcell);
	cell_defer_no_holder(src_tc, cd->s_vcell);

	if (atomic_dec_and_test(cd->on_the_fly))
		complete(cd->complete);

	kfree(cd->dresult);
	kfree(cd->sresult);
	kfree(cd);
	mempool_free(m, pool->mapping_pool);
}

static int process_clone(struct pool *pool,
						 dm_thin_id src_dev_id,
						 sector_t src_addr,
						 dm_thin_id dst_dev_id,
						 sector_t dst_addr,
						 sector_t length)
{
	int i, r = -EINVAL;
	struct dm_cell_key key;
	struct completion complete;
	struct thin_c *src_tc, *dst_tc;
	struct dm_thin_new_mapping *m;
	struct dm_thin_lookup_result *sresult, *dresult;
	struct dm_bio_prison_cell *src_vcell, *src_dcell, *dst_vcell, *dst_dcell = NULL;
	dm_block_t src_blk = src_addr, dst_blk = dst_addr, blk_num = length;
	atomic_t on_the_fly, err_count, no_space_count;

	(void) sector_div(src_blk, pool->sectors_per_block);
	(void) sector_div(dst_blk, pool->sectors_per_block);

	if (length && sector_div(blk_num, pool->sectors_per_block)) {
		DMERR("%s: unaligned, failed", __func__);
		return -EINVAL;
	}

	if (src_dev_id == dst_dev_id && overlapped(src_addr, dst_addr, length)) {
		DMERR("%s: clone range overlapped", __func__);
		return -EINVAL;
	}

	src_tc = find_thin(pool, src_dev_id);
	if (!src_tc)
		return -EINVAL;

	dst_tc = find_thin(pool, dst_dev_id);
	if (!dst_tc)
		goto put_src_dev;

	if (dm_thin_is_snapshot(src_tc->td) || dm_thin_is_snapshot(dst_tc->td)) {
		r = -EINVAL;
		goto put_dst_dev;
	}

	atomic_set(&err_count, 0);
	atomic_set(&no_space_count, 0);
	atomic_set(&on_the_fly, 1);
	init_completion(&complete);
	DMDEBUG("%s: clone from dev-%u to dev-%u for %llu blocks", __func__, src_dev_id, dst_dev_id, blk_num);

	for (i = 0; i < (uint64_t)blk_num; i++) {

		m = NULL;
		src_vcell = src_dcell = dst_vcell = dst_dcell = NULL;
		sresult = kzalloc(sizeof(struct dm_thin_lookup_result), GFP_KERNEL);
		if (!sresult) {
			r = -ENOMEM;
			goto put_dst_dev;
		}

		dresult = kzalloc(sizeof(struct dm_thin_lookup_result), GFP_KERNEL);
		if (!dresult) {
			r = -ENOMEM;
			goto free_src_result;
		}

		build_virtual_key(src_tc->td, src_blk, &key);
		if (bio_detain(pool, &key, NULL, &src_vcell)) {
			r = -EBUSY;
			goto free_dst_result;
		}

		r = dm_thin_find_block(src_tc->td, src_blk, 1, sresult);
		switch (r) {
		case 0:
			build_data_key(src_tc->td, src_blk, sresult->block, &key);
			if (bio_detain(pool, &key, NULL, &src_dcell)) {
				r = -EBUSY;
				goto free_src_vcell;
			}

			build_virtual_key(dst_tc->td, dst_blk, &key);
			if (bio_detain(pool, &key, NULL, &dst_vcell)) {
				r = -EBUSY;
				goto free_src_dcell;
			}

			DMDEBUG("%s: src find block from %llu to %llu", __func__, src_blk, sresult->block);
			r = dm_thin_find_block(dst_tc->td, dst_blk, 1, dresult);
			if (r && r != -ENODATA)
				goto free_dst_vcell;

			if (!r) {
				build_data_key(dst_tc->td, dst_blk, dresult->block, &key);
				if (bio_detain(pool, &key, NULL, &dst_dcell)) {
					r = -EBUSY;
					goto free_dst_vcell;
				}

				/* fast path, this clone had been carried out before and not yet been break sharing */
				if (dresult->block == sresult->block &&
				    dresult->zeroed == sresult->zeroed &&
				    dresult->cloned == sresult->cloned) {
					DMDEBUG("%s: copy block to the same position, bypass", __func__);
						cell_defer_no_holder(dst_tc, dst_dcell);
						cell_defer_no_holder(dst_tc, dst_vcell);
						cell_defer_no_holder(src_tc, src_dcell);
						cell_defer_no_holder(src_tc, src_vcell);
						kfree(dresult);
						kfree(sresult);
					break;
				}
			} else {
				r = 0;
				kfree(dresult);
				dresult = NULL;
			}

			BUG_ON(!sresult->shared && sresult->cloned);

			m = mempool_alloc(pool->mapping_pool, GFP_ATOMIC);
			if (!m) {
				r = -ENOMEM;
				goto free_dst_dcell;
			}

			m->clone_data = kzalloc(sizeof(struct dm_thin_clone_data), GFP_KERNEL);
			if (!m->clone_data) {
				r = -ENOMEM;
				goto free_mapping;
			}

			INIT_LIST_HEAD(&m->list);
			m->err = 0;
			m->clone_data->src_p = src_tc;
			m->clone_data->dst_p = dst_tc;
			m->clone_data->s_vcell = src_vcell;
			m->clone_data->s_dcell = src_dcell;
			m->clone_data->d_vcell = dst_vcell;
			m->clone_data->d_dcell = dst_dcell;
			m->clone_data->src_blk = src_blk;
			m->clone_data->dst_blk = dst_blk;
			m->clone_data->sresult = sresult;
			m->clone_data->dresult = dresult;
			m->clone_data->complete = &complete;
			m->clone_data->on_the_fly = &on_the_fly;
			m->clone_data->err_count = &err_count;
			m->clone_data->no_space_count = &no_space_count;

			atomic_inc(&on_the_fly);
			if (!dm_deferred_set_add_work(pool->all_io_ds, &m->list))
				pool->process_prepared_clone(m);

			break;
		default:
			goto free_src_vcell;
		}

		src_blk += 1;
		dst_blk += 1;
	}

	if (!atomic_dec_and_test(&on_the_fly))
		wait_for_completion(&complete);

	if (atomic_read(&err_count)) {
		if (atomic_read(&err_count) == atomic_read(&no_space_count))
			r = -ENOSPC;
		else
			r = -EINVAL;
	} else
		r = 0;

	goto put_dst_dev;

free_mapping:
	if (m)
		mempool_free(m, pool->mapping_pool);
free_dst_dcell:
	if (dst_dcell)
		cell_defer_no_holder(dst_tc, dst_dcell);
free_dst_vcell:
	cell_defer_no_holder(dst_tc, dst_vcell);
free_src_dcell:
	cell_defer_no_holder(src_tc, src_dcell);
free_src_vcell:
	cell_defer_no_holder(src_tc, src_vcell);
free_dst_result:
	kfree(dresult);
free_src_result:
	kfree(sresult);
put_dst_dev:
	thin_put(dst_tc);
put_src_dev:
	thin_put(src_tc);

	DMDEBUG("%s: close all device, ready to return", __func__);

	return r;
}

static int process_clone_fail(struct pool *pool, dm_thin_id src_dev_id, sector_t src_addr,
                              dm_thin_id dst_dev_id, sector_t dst_addr, sector_t length)
{
	return -EINVAL;
}

/*----------------------------------------------------------------*/

static enum pool_mode get_pool_mode(struct pool *pool)
{
	return pool->pf.mode;
}

static void set_pool_mode(struct pool *pool, enum pool_mode mode)
{
	int r;

	pool->pf.mode = mode;

	switch (mode) {
	case PM_FAIL:
		DMERR("%s: switching pool to failure mode",
		      dm_device_name(pool->pool_md));
		dm_pool_metadata_read_only(pool->pmd);
		pool->process_bio = process_bio_fail;
		pool->process_discard = process_bio_fail;
		pool->process_fast_zero = process_bio_fail;
		pool->process_cell = process_cell_fail;
		pool->process_discard_cell = process_cell_fail;
		pool->process_fast_zero_cell = process_cell_fail;
		pool->process_prepared_mapping = process_prepared_mapping_fail;
		pool->process_prepared_discard = process_prepared_discard_fail;
		pool->process_prepared_clone = process_prepared_clone_fail;
		pool->process_clone = process_clone_fail;
		break;

	case PM_READ_ONLY:
		DMERR("%s: switching pool to read-only mode",
		      dm_device_name(pool->pool_md));
		r = dm_pool_abort_metadata(pool->pmd);
		if (r) {
			DMERR("%s: aborting transaction failed",
			      dm_device_name(pool->pool_md));
			set_pool_mode(pool, PM_FAIL);
		} else {
			/*
			 * FIXME: add process_fast_zero support for read-only mode
			 */
			dm_pool_metadata_read_only(pool->pmd);
			pool->process_bio = process_bio_read_only;
			pool->process_discard = process_bio_success;
			pool->process_fast_zero = process_bio_fail;
			pool->process_cell = process_cell_read_only;
			pool->process_discard_cell = process_cell_success;
			pool->process_fast_zero_cell = process_cell_fail;
			pool->process_prepared_mapping = process_prepared_mapping_fail;
			pool->process_prepared_discard = process_prepared_discard_passdown;
			pool->process_prepared_clone = process_prepared_clone_fail;
			pool->process_clone = process_clone_fail;
		}
		break;

	case PM_WRITE:
		dm_pool_metadata_read_write(pool->pmd);
		pool->process_bio = process_bio;
		pool->process_discard = process_discard_bio;
		pool->process_fast_zero = process_fast_zero;
		pool->process_cell = process_cell;
		pool->process_discard_cell = process_discard_cell;
		pool->process_fast_zero_cell = process_fast_zero_cell;
		pool->process_prepared_mapping = process_prepared_mapping;
		pool->process_prepared_discard = process_prepared_discard;
		pool->process_prepared_clone = process_prepared_clone;
		pool->process_clone = process_clone;
		break;
	}
}

/*----------------------------------------------------------------*/

/*
 * Mapping functions.
 */

/*
 * Called only while mapping a thin bio to hand it over to the workqueue.
 */
static void thin_defer_bio(struct thin_c *tc, struct bio *bio)
{
	unsigned long flags;
	struct pool *pool = tc->pool;

	spin_lock_irqsave(&tc->lock, flags);
	bio_list_add(&tc->deferred_bio_list, bio);
	spin_unlock_irqrestore(&tc->lock, flags);

	wake_worker(pool);
}

static void thin_defer_bio_with_throttle(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;

	throttle_lock(&pool->throttle);
	thin_defer_bio(tc, bio);
	throttle_unlock(&pool->throttle);
}

static void thin_defer_cell(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	unsigned long flags;
	struct pool *pool = tc->pool;

	throttle_lock(&pool->throttle);
	spin_lock_irqsave(&tc->lock, flags);
	list_add_tail(&cell->user_list, &tc->deferred_cells);
	spin_unlock_irqrestore(&tc->lock, flags);
	throttle_unlock(&pool->throttle);

	wake_worker(pool);
}

static void thin_hook_bio(struct thin_c *tc, struct bio *bio)
{
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));

	h->tc = tc;
	h->shared_read_entry = NULL;
	h->all_io_entry = NULL;
	h->overwrite_mapping = NULL;
}

/*
 * Non-blocking function called from the thin target's map function.
 */
static int thin_bio_map(struct dm_target *ti, struct bio *bio)
{
	int r;
	struct thin_c *tc = ti->private;
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_thin_device *td = tc->td;
	struct dm_thin_lookup_result result;
	struct dm_bio_prison_cell *virt_cell, *data_cell;
	struct dm_cell_key key;

	thin_hook_bio(tc, bio);

	if (get_pool_mode(tc->pool) == PM_FAIL) {
		bio_io_error(bio);
		return DM_MAPIO_SUBMITTED;
	}

	if (bio->bi_rw & DEFER_IO_FLAGS) {
		thin_defer_bio_with_throttle(tc, bio);
		return DM_MAPIO_SUBMITTED;
	}

	/*
	* We must hold the virtual cell before doing the lookup, otherwise
	* there's a race with discard.
	*/
	build_virtual_key(tc->td, block, &key);
	if (bio_detain(tc->pool, &key, bio, &virt_cell))
		return DM_MAPIO_SUBMITTED;

	r = dm_thin_find_block(td, block, 0, &result);

	/*
	 * Note that we defer readahead too.
	 */
	switch (r) {
	case 0:
		if (unlikely(result.shared) ||
		    (bio_data_dir(bio) == WRITE && result.zeroed)) {
			/*
			 * We have a race condition here between the
			 * result.shared value returned by the lookup and
			 * snapshot creation, which may cause new
			 * sharing.
			 *
			 * To avoid this always quiesce the origin before
			 * taking the snap.  You want to do this anyway to
			 * ensure a consistent application view
			 * (i.e. lockfs).
			 *
			 * More distant ancestors are irrelevant. The
			 * shared flag will be set in their case.
			 */
			thin_defer_cell(tc, virt_cell);
			return DM_MAPIO_SUBMITTED;
		}

		if (bio_data_dir(bio) == READ && result.zeroed) {
			zero_fill_bio(bio);
			cell_defer_no_holder(tc, virt_cell);
			bio_endio(bio, 0);
			return DM_MAPIO_SUBMITTED;
		}

		build_data_key(tc->td, block, result.block, &key);
		if (bio_detain(tc->pool, &key, bio, &data_cell)) {
			cell_defer_no_holder(tc, virt_cell);
			return DM_MAPIO_SUBMITTED;
		}

		inc_all_io_entry(tc->pool, bio);
		cell_defer_no_holder(tc, data_cell);
		cell_defer_no_holder(tc, virt_cell);

		remap(tc, bio, result.block);
		return DM_MAPIO_REMAPPED;

	case -ENODATA:
		if (get_pool_mode(tc->pool) == PM_READ_ONLY) {
			/*
			 * This block isn't provisioned, and we have no way
			 * of doing so.  Just error it.
			 */
			bio_io_error(bio);
			cell_defer_no_holder(tc, virt_cell);
			return DM_MAPIO_SUBMITTED;
		}
	/* fall through */

	case -EWOULDBLOCK:
		thin_defer_cell(tc, virt_cell);
		return DM_MAPIO_SUBMITTED;

	default:
		/*
		 * Must always call bio_io_error on failure.
		 * dm_thin_find_block can fail with -EINVAL if the
		 * pool is switched to fail-io mode.
		 */
		bio_io_error(bio);
		cell_defer_no_holder(tc, virt_cell);
		return DM_MAPIO_SUBMITTED;
	}
}

static int pool_is_congested(struct dm_target_callbacks *cb, int bdi_bits)
{
	int r;
	struct request_queue *q;
	unsigned long flags;
	struct pool_c *pt = container_of(cb, struct pool_c, callbacks);
	struct pool_c_tier_private *pool_c_tier_data = &(pt->pool_c_tier_data);
	struct pool_features_tier_private *pool_features_tier_data = &(pt->adjusted_pf.pool_features_tier_data);
	int i;

	spin_lock_irqsave(&pt->pool->lock, flags);
	r = pt->pool->no_free_space;
	spin_unlock_irqrestore(&pt->pool->lock, flags);

	if (!r) {
		if (!pool_features_tier_data->enable_tier) {
			q = bdev_get_queue(pt->data_dev->bdev);
			return bdi_congested(&q->backing_dev_info, bdi_bits);
		} else {
			for (i = 0; i < pool_features_tier_data->tier_num; i++) {
				q = bdev_get_queue(pool_c_tier_data->tier_data_dev[i]->bdev);
				r |= bdi_congested(&q->backing_dev_info, bdi_bits);
			}
		}
	}

	return r;
}

static void requeue_bios(struct pool *pool)
{
	unsigned long flags;
	struct thin_c *tc;

	rcu_read_lock();
	list_for_each_entry_rcu(tc, &pool->active_thins, list) {
		spin_lock_irqsave(&tc->lock, flags);
		bio_list_merge(&tc->deferred_bio_list, &tc->retry_on_resume_list);
		bio_list_init(&tc->retry_on_resume_list);
		spin_unlock_irqrestore(&tc->lock, flags);
	}
	rcu_read_unlock();
}

/*----------------------------------------------------------------
 * Binding of control targets to a pool object
 *--------------------------------------------------------------*/
static bool data_dev_supports_discard(struct pool_c *pt)
{
	struct request_queue *q = bdev_get_queue(pt->data_dev->bdev);

	return q && blk_queue_discard(q);
}

static bool is_factor(sector_t block_size, uint32_t n)
{
	return !sector_div(block_size, n);
}

/*
 * If discard_passdown was enabled verify that the data device
 * supports discards.  Disable discard_passdown if not.
 */
static void disable_passdown_if_not_supported(struct pool_c *pt)
{
	struct pool *pool = pt->pool;
	struct block_device *data_bdev;
	struct queue_limits *data_limits;
	sector_t block_size = pool->sectors_per_block << SECTOR_SHIFT;
	const char *reason = NULL;
	char buf[BDEVNAME_SIZE];
	struct pool_features_tier_private pool_features_tier_data = pt->adjusted_pf.pool_features_tier_data;
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	if (!pt->adjusted_pf.discard_passdown)
		return;

	//PATCH:TIER
	if (!pool_features_tier_data.enable_tier) {
		data_bdev = pt->data_dev->bdev;
		data_limits = &bdev_get_queue(data_bdev)->limits;

		if (!data_dev_supports_discard(pt))
			reason = "discard unsupported";

		else if (data_limits->max_discard_sectors < pool->sectors_per_block)
			reason = "max discard sectors smaller than a block";

		else if (data_limits->discard_granularity > block_size)
			reason = "discard granularity larger than a block";

		else if (!is_factor(block_size, data_limits->discard_granularity))
			reason = "discard granularity not a factor of block size";

		if (reason) {
			DMWARN("Data device (%s) %s: Disabling discard passdown.", bdevname(data_bdev, buf), reason);
			pt->adjusted_pf.discard_passdown = false;
		}
	} else
		tier_passdown_check(&pool_features_tier_data, pool_tier_data);
}

static int bind_control_target(struct pool *pool, struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;
	int r = 0;

	/*
	 * We want to make sure that a pool in PM_FAIL mode is never upgraded.
	 */
	enum pool_mode old_mode = pool->pf.mode;
	enum pool_mode new_mode = pt->adjusted_pf.mode;

	/*
	 * If we were in PM_FAIL mode, rollback of metadata failed.  We're
	 * not going to recover without a thin_repair.  So we never let the
	 * pool move out of the old mode.  On the other hand a PM_READ_ONLY
	 * may have been due to a lack of metadata or data space, and may
	 * now work (ie. if the underlying devices have been resized).
	 */
	if (old_mode == PM_FAIL)
		new_mode = old_mode;

	pool->ti = ti;
	pool->low_water_blocks = pt->low_water_blocks;
	pool->pf = pt->adjusted_pf;

	r = bind_tier_target(&pool->pf.pool_features_tier_data, pool_tier_data);
	if (r)
		return r;

	set_pool_mode(pool, new_mode);

	return 0;
}

static void unbind_control_target(struct pool *pool, struct dm_target *ti)
{
	if (pool->ti == ti)
		pool->ti = NULL;
}

/*----------------------------------------------------------------
 * Pool creation
 *--------------------------------------------------------------*/
/* Initialize pool features. */
static void pool_features_init(struct pool_features *pf)
{
	pf->mode = PM_WRITE;
	pf->zero_new_blocks = true;
	pf->discard_enabled = true;
	pf->discard_passdown = true;

	//PATCH: TIER
	init_pool_features_tier_data(&(pf->pool_features_tier_data));
}

static void __pool_destroy(struct pool *pool)
{
	__pool_table_remove(pool);

	if (dm_pool_metadata_close(pool->pmd) < 0)
		DMWARN("%s: dm_pool_metadata_close() failed.", __func__);

	//PATCH:TIER
	destroy_pool_tier_data(pool->pool_tier_data, 1);

	dm_bio_prison_destroy(pool->prison);
	dm_kcopyd_client_destroy(pool->copier);

	if (pool->wq)
		destroy_workqueue(pool->wq);

	if (pool->convert_wq)
		destroy_workqueue(pool->convert_wq);

	if (pool->next_mapping)
		mempool_free(pool->next_mapping, pool->mapping_pool);
	mempool_destroy(pool->mapping_pool);
	dm_deferred_set_destroy(pool->shared_read_ds);
	dm_deferred_set_destroy(pool->all_io_ds);
	kfree(pool);
}

static struct kmem_cache *_new_mapping_cache;

static struct pool *pool_create(struct mapped_device *pool_md,
                                struct block_device *metadata_dev,
                                unsigned long block_size,
                                int read_only, char **error, struct pool_features_tier_private *pool_features_tier_data)
{
	int r;
	void *err_p;
	struct pool *pool;
	struct dm_pool_metadata *pmd;
	bool format_device = read_only ? false : true;
	struct pool_tier_private *pool_tier_data;

	pmd = dm_pool_metadata_open(metadata_dev, block_size, format_device, pool_features_tier_data->tier_num, pool_features_tier_data->alloc_tier, pool_features_tier_data->tier_blk_size);
	if (IS_ERR(pmd)) {
		*error = "Error creating metadata object";
		return (struct pool *)pmd;
	}

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool) {
		*error = "Error allocating memory for pool";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_pool;
	}

	pool->pmd = pmd;
	pool->sectors_per_block = block_size;
	if (block_size & (block_size - 1))
		pool->sectors_per_block_shift = -1;
	else
		pool->sectors_per_block_shift = __ffs(block_size);
	pool->low_water_blocks = 0;
	pool->sync_io_threshold = 0;
	pool_features_init(&pool->pf);
	pool->prison = dm_bio_prison_create();
	if (!pool->prison) {
		*error = "Error creating pool's bio prison";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_prison;
	}

	pool->copier = dm_kcopyd_client_create(&dm_kcopyd_throttle);
	if (IS_ERR(pool->copier)) {
		r = PTR_ERR(pool->copier);
		*error = "Error creating pool's kcopyd client";
		err_p = ERR_PTR(r);
		goto bad_kcopyd_client;
	}

	/*
	 * Create singlethreaded workqueue that will service all devices
	 * that use this metadata.
	 */
	pool->wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pool->wq) {
		*error = "Error creating pool's workqueue";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_wq;
	}

	throttle_init(&pool->throttle);
	INIT_WORK(&pool->worker, do_worker);
	INIT_DELAYED_WORK(&pool->waker, do_waker);
	spin_lock_init(&pool->lock);

	pool->convert_wq = alloc_ordered_workqueue("dm-convert-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pool->convert_wq) {
		*error = "Error creating pool's convert workqueue";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_convert_wq;
	}

	bio_list_init(&pool->deferred_flush_bios);
	INIT_LIST_HEAD(&pool->prepared_mappings);
	INIT_LIST_HEAD(&pool->prepared_discards);
	INIT_LIST_HEAD(&pool->prepared_clones);
	INIT_LIST_HEAD_RCU(&pool->active_thins);
	pool->low_water_triggered = 0;
	pool->sync_io_triggered = 0;
	pool->no_free_space = 0;
	pool->sb_backup_fail_reported = 0;
	pool->io_error_reported = 0;
	pool->origin_max_blocks = 0;

	pool->shared_read_ds = dm_deferred_set_create();
	if (!pool->shared_read_ds) {
		*error = "Error creating pool's shared read deferred set";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_shared_read_ds;
	}

	pool->all_io_ds = dm_deferred_set_create();
	if (!pool->all_io_ds) {
		*error = "Error creating pool's all io deferred set";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_all_io_ds;
	}

	pool->next_mapping = NULL;
	pool->mapping_pool = mempool_create_slab_pool(MAPPING_POOL_SIZE,
	                     _new_mapping_cache);
	if (!pool->mapping_pool) {
		*error = "Error creating pool's mapping mempool";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_mapping_pool;
	}

	pool_tier_data = create_pool_tier_data(pool_features_tier_data);
	if (IS_ERR(pool_tier_data)) {
		*error = "Error creating pool tier data";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_pool_tier_data;
	}

	pool_tier_data->migrator = dm_kcopyd_client_create(&dm_kcopyd_throttle);
	if (IS_ERR(pool_tier_data->migrator)) {
		r = PTR_ERR(pool_tier_data->migrator);
		*error = "Error creating migration's kcopyd client";
		err_p = ERR_PTR(r);
		goto bad_migrate_kcopyd_client;
	}
	pool_tier_data->pmd = pmd;
	pool->pool_tier_data = pool_tier_data;

	pool->ref_count = 1;
	pool->last_commit_jiffies = jiffies;
	pool->pool_md = pool_md;
	pool->md_dev = metadata_dev;
	__pool_table_insert(pool);

	DMINFO("%s: %d,  pool successfully created !!", __func__, __LINE__);

	return pool;


bad_migrate_kcopyd_client:
	destroy_pool_tier_data(pool_tier_data, 0);
bad_pool_tier_data:
	mempool_destroy(pool->mapping_pool);
bad_mapping_pool:
	dm_deferred_set_destroy(pool->all_io_ds);
bad_all_io_ds:
	dm_deferred_set_destroy(pool->shared_read_ds);
bad_shared_read_ds:
	destroy_workqueue(pool->convert_wq);
bad_convert_wq:
	destroy_workqueue(pool->wq);
bad_wq:
	dm_kcopyd_client_destroy(pool->copier);
bad_kcopyd_client:
	dm_bio_prison_destroy(pool->prison);
bad_prison:
	kfree(pool);
bad_pool:
	if (dm_pool_metadata_close(pmd))
		DMWARN("%s: dm_pool_metadata_close() failed.", __func__);

	return err_p;
}

static struct pool *__pool_find(struct mapped_device *pool_md,
                                struct block_device *metadata_dev,
                                unsigned long block_size, int read_only,
                                char **error, int *created, struct pool_features_tier_private *pool_features_tier_data)
{
	struct pool *pool = __pool_table_lookup_metadata_dev(metadata_dev);

	if (pool) {
		if (pool->pool_md != pool_md) {
			*error = "metadata device already in use by a pool";
			return ERR_PTR(-EBUSY);
		}
	} else {
		pool = __pool_table_lookup(pool_md);
		if (pool) {
			if (pool->md_dev != metadata_dev) {
				*error = "different pool cannot replace a pool";
				return ERR_PTR(-EINVAL);
			}
		} else {
			pool = pool_create(pool_md, metadata_dev, block_size, read_only, error, pool_features_tier_data);
			*created = 1;
		}
	}

	return pool;
}

/*----------------------------------------------------------------
 * Pool target methods
 *--------------------------------------------------------------*/
static void pool_dtr(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool_features_tier_private tf = pt->adjusted_pf.pool_features_tier_data;

	//PATCH:TIER
	if (tf.enable_tier)
		stop_auto_tiering_thread(pt->pool->pool_tier_data);

	mutex_lock(&dm_thin_pool_table.mutex);

	unbind_control_target(pt->pool, ti);

	kobject_put(&pt->pool->kobj);

	//PATCH:TIER
	if (tf.tier_dev)
		destroy_tier_devices(ti, tf.tier_num, tf.tier_dev);

	dm_put_device(ti, pt->metadata_dev);
	if (pt->data_dev)
		dm_put_device(ti, pt->data_dev);
	kfree(pt);

	mutex_unlock(&dm_thin_pool_table.mutex);
}

static int parse_pool_features(struct dm_arg_set *as, struct pool_features *pf,
                               struct dm_target *ti)
{
	int r;
	unsigned argc;
	const char *arg_name;

	static struct dm_arg _args[] = {
		{0, 10, "Invalid number of pool feature arguments"},
	};

	/*
	 * No feature arguments supplied.
	 */
	if (!as->argc)
		return 0;

	r = dm_read_arg_group(_args, as, &argc, &ti->error);
	if (r)
		return -EINVAL;

	while (argc && !r) {
		arg_name = dm_shift_arg(as);
		argc--;

		if (!strcasecmp(arg_name, "skip_block_zeroing"))
			pf->zero_new_blocks = false;

		else if (!strcasecmp(arg_name, "ignore_discard"))
			pf->discard_enabled = false;

		else if (!strcasecmp(arg_name, "no_discard_passdown"))
			pf->discard_passdown = false;

		else if (!strcasecmp(arg_name, "read_only"))
			pf->mode = PM_READ_ONLY;

		else if (!strncasecmp(arg_name, "TIER:", 5)) { //PATCH:TIER
			r = parse_tier_features(as, &argc, (char *)arg_name, ti, &(pf->pool_features_tier_data));
			if (r)
				break;
		} else if (!strncasecmp(arg_name, "enable_map:", 11)) { //PATCH:TIER
			r = parse_tier_enableMap(as, &argc, (char *)arg_name, ti, &(pf->pool_features_tier_data));
			if (r)
				break;

		} else if (!strcasecmp(arg_name, "bypass_off"))
			set_bypass_off(&(pf->pool_features_tier_data));

		else {
			ti->error = "Unrecognised pool feature requested";
			r = -EINVAL;
			break;
		}
	}

	return r;
}

static void metadata_low_callback(void *context)
{
	struct pool *pool = context;

	DMWARN("%s: reached low water mark for metadata device: sending event.",
	       dm_device_name(pool->pool_md));

	dm_table_event(pool->ti->table);
}

/*
 * When a metadata threshold is crossed a dm event is triggered, and
 * userland should respond by growing the metadata device.  We could let
 * userland set the threshold, like we do with the data threshold, but I'm
 * not sure they know enough to do this well.
 */
static dm_block_t calc_metadata_threshold(struct pool_c *pt)
{
	/*
	 * 4M is ample for all ops with the possible exception of thin
	 * device deletion which is harmless if it fails (just retry the
	 * delete after you've grown the device).
	 */
	dm_block_t quarter = get_metadata_dev_size_in_blocks(pt->pool->pmd, pt->metadata_dev->bdev) / 4;
	return min((dm_block_t)1024ULL /* 4M */, quarter);
}

/* -------------------------------------------------------------------- */

struct dm_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct pool *, char *);
	ssize_t (*store)(struct pool *, const char *, size_t);
};

#define DM_ATTR_RO(_name) \
    struct dm_sysfs_attr dm_attr_##_name = \
    __ATTR(_name, S_IRUGO, dm_attr_##_name##_show, NULL)

#define DM_ATTR_WO(_name) \
    struct dm_sysfs_attr dm_attr_##_name = \
    __ATTR(_name, S_IWUSR, NULL, dm_attr_##_name##_store)

#define DM_ATTR_WR(_name) \
    struct dm_sysfs_attr dm_attr_##_name = \
    __ATTR(_name, S_IRUGO|S_IWUSR, dm_attr_##_name##_show, dm_attr_##_name##_store)

static ssize_t dm_attr_show(struct kobject *kobj, struct attribute *attr,
                            char *page)
{
	struct dm_sysfs_attr *dm_attr;
	struct pool *pool;
	ssize_t ret;

	dm_attr = container_of(attr, struct dm_sysfs_attr, attr);
	if (!dm_attr->show)
		return -EIO;

	mutex_lock(&dm_thin_pool_table.mutex);

	pool = container_of(kobj, struct pool, kobj);
	ret = dm_attr->show(pool, page);

	mutex_unlock(&dm_thin_pool_table.mutex);

	return ret;
}

static ssize_t dm_attr_store(struct kobject *kobj, struct attribute *attr,
                             const char *buf, size_t count)
{
	struct dm_sysfs_attr *dm_attr;
	struct pool *pool;
	ssize_t ret;

	dm_attr = container_of(attr, struct dm_sysfs_attr, attr);
	if (!dm_attr->show)
		return -EIO;

	mutex_lock(&dm_thin_pool_table.mutex);

	pool = container_of(kobj, struct pool, kobj);
	ret = dm_attr->store(pool, buf, count);

	mutex_unlock(&dm_thin_pool_table.mutex);

	return ret;
}

static ssize_t dm_attr_origin_max_blocks_show(struct pool *pool, char *buf)
{
	sprintf(buf, "%llu\n", pool->origin_max_blocks);

	return strlen(buf);
}

static ssize_t dm_attr_origin_max_blocks_store(struct pool *pool, const char *buf, size_t count)
{
	dm_block_t blocks;
	unsigned long flags;

	if (kstrtoull(buf, 10, &blocks))
		return -EIO;

	if (dm_pool_register_reserve_threshold(pool->pmd, blocks))
		return -EIO;

	spin_lock_irqsave(&pool->lock, flags);
	pool->origin_max_blocks = blocks;
	spin_unlock_irqrestore(&pool->lock, flags);

	return count;
}

static ssize_t dm_attr_sync_io_threshold_show(struct pool *pool, char *buf)
{
	sprintf(buf, "%llu\n", pool->sync_io_threshold);

	return strlen(buf);
}

static ssize_t dm_attr_sync_io_threshold_store(struct pool *pool, const char *buf, size_t count)
{
	dm_block_t blocks;
	unsigned long flags;

	if (kstrtoull(buf, 10, &blocks))
		return -EIO;

	spin_lock_irqsave(&pool->lock, flags);
	pool->sync_io_threshold = blocks;
	spin_unlock_irqrestore(&pool->lock, flags);

	return count;
}

static ssize_t dm_attr_snap_delete_threshold_show(struct pool *pool, char *buf)
{
	sprintf(buf, "%llu\n", pool->snap_delete_threshold);

	return strlen(buf);
}

static ssize_t dm_attr_snap_delete_threshold_store(struct pool *pool, const char *buf, size_t count)
{
	dm_block_t blocks;
	unsigned long flags;

	if (kstrtoull(buf, 10, &blocks))
		return -EIO;

	spin_lock_irqsave(&pool->lock, flags);
	pool->snap_delete_threshold = blocks;
	spin_unlock_irqrestore(&pool->lock, flags);

	return count;
}

static ssize_t dm_attr_snap_delete_show(struct pool *pool, char *buf)
{
	sprintf(buf, "%d\n", pool->snap_delete);

	return strlen(buf);
}

static ssize_t dm_attr_origin_mapped_blocks_show(struct pool *pool, char *buf)
{
	dm_block_t b;

	if (dm_pool_get_origin_mapped_blocks(pool->pmd, &b))
		return -EIO;

	sprintf(buf, "%llu\n", b);

	return strlen(buf);
}

//PATCH:TIER
static ssize_t dm_attr_tier_statistics_show(struct pool *pool, char *buf)
{
	unsigned int i = 0, total, processed;
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	unsigned long alloc_tier;

	if (!pool_migrateable(pool_tier_data))
		return -EIO;

	if (dm_tier_get_alloc_tier(pool_tier_data->pmd, &alloc_tier))
		return -EIO;

	sprintf(buf + strlen(buf), "Allocate Tier - Tier%lu\n", alloc_tier);

	for (i = 0; i < tf.tier_num; i++) {
		dm_block_t free_blks = 0, alloc_blks = 0, total_blks = 0, swap_blks = 0;

		if (! (pool_tier_data->pool_features_tier_data.enable_map & (0x1 << i)))
			continue;

		get_tier_dev_size_info(pool_tier_data, i, &free_blks, &alloc_blks, &total_blks, &swap_blks);

		//sprintf(buf + strlen(buf), "Tier %d swap blocks: %llu blocks\n", i, swap_blks);
		sprintf(buf + strlen(buf), "Tier %d free blocks: %llu blocks\n", i, free_blks);
		sprintf(buf + strlen(buf), "Tier %d allocated blocks: %llu blocks\n", i, alloc_blks);
		sprintf(buf + strlen(buf), "Tier %d total_blks blocks: %llu blocks\n", i, total_blks);
		sprintf(buf + strlen(buf), "Tier %d data move up: %d blocks\n", i, get_tier_move_data(pool_tier_data, i, MOVE_UP));
		sprintf(buf + strlen(buf), "Tier %d data move within: %d blocks\n", i, get_tier_move_data(pool_tier_data, i, MOVE_WITHIN));
		sprintf(buf + strlen(buf), "Tier %d data move down: %d blocks\n", i, get_tier_move_data(pool_tier_data, i, MOVE_DOWN));
	}

	get_migration_progress(pool_tier_data, &total, &processed);
	sprintf(buf + strlen(buf), "Migration Progress: %d/%d \n", processed, total);
	return strlen(buf);
}

static ssize_t dm_attr_migration_status_show(struct pool *pool, char *buf)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	 if (work_busy(&pool_tier_data->issue_worker.work))
	 	sprintf(buf, "Migration processing \n");
	 else
	 	sprintf(buf, "Migration finish \n");

	 return strlen(buf);
}

static ssize_t dm_attr_relocation_rate_show(struct pool *pool, char *buf)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	sprintf(buf, get_relocation_rate(pool_tier_data));
	return strlen(buf);
}

static ssize_t dm_attr_relocation_rate_store(struct pool *pool, const char *buf, size_t count)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	set_relocation_rate(pool_tier_data, (char *)buf);

	return count;
}

static ssize_t dm_attr_auto_tiering_setting_show(struct pool *pool, char *buf)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	sprintf(buf, "%d\n", atomic_read(&pool_tier_data->stats_switch));

	return strlen(buf);
}


static ssize_t dm_attr_auto_tiering_setting_store(struct pool *pool, const char *buf, size_t count)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;
	int temp;

	kstrtoint(buf, 10, &temp);
	atomic_set(&pool_tier_data->stats_switch, temp);

	return count;
}

static ssize_t dm_attr_tier_info_show(struct pool *pool, char *buf)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	if (!tf.enable_tier)
		return -EIO;

	sprintf(buf, get_swap_ready(pool_tier_data));
	sprintf(buf + strlen(buf), get_tier_bypass(pool_tier_data));

	return strlen(buf);
}

static ssize_t dm_attr_btier_show(struct pool *pool, char *buf)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	if (!pool_migrateable(pool_tier_data))
		return -EIO;

	sprintf(buf + strlen(buf), "cool_down: %d second\n", btier_params_get(pool_tier_data, COOL_DOWN));
	sprintf(buf + strlen(buf), "degrade_ratio: %d percent\n", btier_params_get(pool_tier_data, DEGRADE_RATIO));
	sprintf(buf + strlen(buf), "reserve_ratio: %d percent\n", btier_params_get(pool_tier_data, RESERVE_RATIO));
	//sprintf(buf + strlen(buf), "collect_time: %d \n", btier_params_get(pool_tier_data, COLLECT_TIME));

	return strlen(buf);
}

static ssize_t dm_attr_tiering_analysis_show(struct pool *pool, char *buf)
{
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	return pool_migrateable(pool_tier_data) ? show_analysis_data(&pool_tier_data->data_analysis , buf) : -EIO;
}

static void dm_pool_kobj_release(struct kobject *kobj)
{
	struct pool *pool = container_of(kobj, struct pool, kobj);
	struct pool_features_tier_private tf = pool->pool_tier_data->pool_features_tier_data;

	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));
	if (!tf.bypass)
		free_migration_stats(pool->pool_tier_data);
	__pool_destroy(pool);

	return;
}

static DM_ATTR_WR(origin_max_blocks);
static DM_ATTR_WR(sync_io_threshold);
static DM_ATTR_WR(snap_delete_threshold);
static DM_ATTR_RO(snap_delete);
static DM_ATTR_RO(origin_mapped_blocks);
static DM_ATTR_RO(tier_statistics);
static DM_ATTR_RO(migration_status);
static DM_ATTR_WR(relocation_rate);
static DM_ATTR_WR(auto_tiering_setting);
static DM_ATTR_RO(tier_info);
static DM_ATTR_RO(btier);
static DM_ATTR_RO(tiering_analysis);

static struct attribute *dm_attrs[] = {
	&dm_attr_origin_mapped_blocks.attr,
	&dm_attr_origin_max_blocks.attr,
	&dm_attr_sync_io_threshold.attr,
	&dm_attr_snap_delete_threshold.attr,
	&dm_attr_snap_delete.attr,
	&dm_attr_tier_statistics.attr,
	&dm_attr_migration_status.attr,
	&dm_attr_relocation_rate.attr,
	&dm_attr_auto_tiering_setting.attr,
	&dm_attr_tier_info.attr,
	&dm_attr_btier.attr,
	&dm_attr_tiering_analysis.attr,
	NULL,
};

static const struct sysfs_ops dm_sysfs_ops = {
	.show   = dm_attr_show,
	.store  = dm_attr_store,
};

static struct kobj_type dm_ktype = {
	.sysfs_ops      = &dm_sysfs_ops,
	.default_attrs  = dm_attrs,
	.release = dm_pool_kobj_release,
};

/* --------------------------------------------------------------------- */

/*
 * thin-pool <metadata dev> <data dev>
 *	     <data block size (sectors)>
 *	     <low water mark (blocks)>
 *	     [<#feature args> [<arg>]*]
 *
 * Optional feature arguments are:
 *	     skip_block_zeroing: skips the zeroing of newly-provisioned blocks.
 *	     ignore_discard: disable discard
 *	     no_discard_passdown: don't pass discards down to the data device
 */
static int pool_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r, pool_created = 0;
	struct pool_c *pt;
	struct pool *pool;
	struct pool_features pf;
	struct dm_arg_set as;
	struct dm_dev *data_dev;
	unsigned long block_size;
	dm_block_t low_water_blocks;
	struct dm_dev *metadata_dev;
	fmode_t metadata_mode;
	int ret = 0;
	struct pool_tier_private *pool_tier_data;
	struct pool_features_tier_private *pool_features_tier_data;

	/*
	 * FIXME Remove validation from scope of lock.
	 */
	mutex_lock(&dm_thin_pool_table.mutex);

	/*
	 * Set default pool features.
	 */
	pool_features_init(&pf);
	pool_features_tier_data = &(pf.pool_features_tier_data);

	if (argc < 4) {
		ti->error = "Invalid argument count";
		r = -EINVAL;
		goto out_unlock;
	}

	as.argc = argc;
	as.argv = argv;

	dm_consume_args(&as, 4);
	r = parse_pool_features(&as, &pf, ti);
	if (r)
		goto out_unlock;

	metadata_mode = FMODE_READ | ((pf.mode == PM_READ_ONLY) ? 0 : FMODE_WRITE);
	r = dm_get_device(ti, argv[0], metadata_mode, &metadata_dev);
	if (r) {
		ti->error = "Error opening metadata block device";
		goto out_unlock;
	}

	/*
	 * Run for the side-effect of possibly issuing a warning if the
	 * device is too big.
	 * Mark this since we don't know the metadata size now
	 */
	//PATCH: TIER
	ret = is_tier_enable(argv[1], &(pf.pool_features_tier_data));
	if (ret == 1)
		data_dev = NULL;
	else if (ret == 0) {
		r = dm_get_device(ti, argv[1], FMODE_READ | FMODE_WRITE, &data_dev);
		if (r) {
			ti->error = "Error getting data device";
			goto out_metadata;
		}
	} else {
		ti->error = "Either specify \"TIER\" without tiering device setting or enable tiering support without \"TIER\" as data device";
		goto out_metadata;
	}

	if (kstrtoul(argv[2], 10, &block_size) || !block_size ||
	    block_size < DATA_DEV_BLOCK_SIZE_MIN_SECTORS ||
	    block_size > DATA_DEV_BLOCK_SIZE_MAX_SECTORS ||
	    block_size & (DATA_DEV_BLOCK_SIZE_MIN_SECTORS - 1)) {
		ti->error = "Invalid block size";
		r = -EINVAL;
		goto out;
	}

	//PATCH: TIER
	if (ret == 0)
		set_tier_blk_tier_disable(block_size, &(pf.pool_features_tier_data));

	if (kstrtoull(argv[3], 10, (unsigned long long *)&low_water_blocks)) {
		ti->error = "Invalid low water mark";
		r = -EINVAL;
		goto out;
	}

	pt = kzalloc(sizeof(*pt), GFP_KERNEL);
	if (!pt) {
		r = -ENOMEM;
		goto out;
	}


	pool = __pool_find(dm_table_get_md(ti->table), metadata_dev->bdev,
	                   block_size, pf.mode == PM_READ_ONLY, &ti->error, &pool_created, &(pf.pool_features_tier_data));
	if (IS_ERR(pool)) {
		r = PTR_ERR(pool);
		if (r == -EVERSION)
			send_hal_msg(dm_table_get_md(ti->table), HAL_THIN_ERR_VERSION);
		goto out_free_pt;
	}

	if (report_sb_backup_fail(pool->pmd))
		send_hal_msg(pool, HAL_SB_BACKUP_FAIL);
	else if (rescan_needed(pool->pmd))
		DMERR("%s: pool metadata is inconsistent, rescan is needed", __func__);

	if (pool_created) {
		if (kobject_init_and_add(&pool->kobj, &dm_ktype,
		                         dm_kobject(pool->pool_md), "%s", "pool"))
			goto out_free_pt;
	} else
		kobject_get(&pool->kobj);


	pool_tier_data = pool->pool_tier_data;
	pool_tier_data->tier_created = pool_created;

	/*
	 * 'pool_created' reflects whether this is the first table load.
	 * Top level discard support is not allowed to be changed after
	 * initial load.  This would require a pool reload to trigger thin
	 * device changes.
	 */
	if (!pool_created && pf.discard_enabled != pool->pf.discard_enabled) {
		ti->error = "Discard support cannot be disabled once enabled";
		r = -EINVAL;
		goto out_flags_changed;
	}

	pt->pool = pool;
	pt->ti = ti;
	pt->metadata_dev = metadata_dev;
	pt->data_dev = data_dev;
	pt->low_water_blocks = low_water_blocks;
	pt->adjusted_pf = pt->requested_pf = pf;

	//PATCH:TIER
	init_pool_c_tier_data(&pt->pool_c_tier_data, pool_features_tier_data);
	ti->per_bio_data_size = sizeof(struct dm_tier_endio_hook);
	if (pool_features_tier_data->enable_tier) {
		/*set number of flush bios according to underlying device*/
		ti->num_flush_bios = pool_features_tier_data->tier_num;
	} else
		ti->num_flush_bios = 1;

	/*
	 * Only need to enable discards if the pool should pass
	 * them down to the data device.  The thin device's discard
	 * processing will cause mappings to be removed from the btree.
	 */
	ti->discard_zeroes_data_unsupported = true;
	if (pf.discard_enabled && pf.discard_passdown) {
		ti->num_discard_bios = 1;

		/*
		 * Setting 'discards_supported' circumvents the normal
		 * stacking of discard limits (this keeps the pool and
		 * thin devices' discard limits consistent).
		 */
		ti->discards_supported = true;
	}
	ti->private = pt;

	r = dm_pool_register_metadata_threshold(pt->pool->pmd,
	                                        calc_metadata_threshold(pt),
	                                        metadata_low_callback,
	                                        pool);
	if (r)
		goto out_flags_changed;

	pt->callbacks.congested_fn = pool_is_congested;
	dm_table_add_target_callbacks(ti->table, &pt->callbacks);

	mutex_unlock(&dm_thin_pool_table.mutex);

	return 0;

out_flags_changed:
	kobject_put(&pool->kobj);
out_free_pt:
	kfree(pt);
out:
	//PATCH:TIER
	if (data_dev)
		dm_put_device(ti, data_dev);
out_metadata:
	dm_put_device(ti, metadata_dev);
out_unlock:
	if (pool_features_tier_data->tier_dev)
		destroy_tier_devices(ti, pool_features_tier_data->tier_num, pool_features_tier_data->tier_dev);	

	mutex_unlock(&dm_thin_pool_table.mutex);

	return r;
}

static int pool_map(struct dm_target *ti, struct bio *bio)
{
	int r;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	unsigned long flags;
	struct pool_features_tier_private pool_features_tier_data = pool->pf.pool_features_tier_data;
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;
	struct dm_tier_endio_hook *h;

	/*
	 * As this is a singleton target, ti->begin is always zero.
	 */
	//PATCH:TIER
	tier_hook_bio(pool->pool_tier_data, bio);
	if (pool_features_tier_data.enable_tier)
		r = tier_bio_map(pool_tier_data, bio);
	else {
		h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));
		spin_lock_irqsave(&pool->lock, flags);
		bio->bi_bdev = pt->data_dev->bdev;
		r = DM_MAPIO_REMAPPED;
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	return r;
}


static int maybe_resize_data_dev(struct dm_target *ti, bool *need_commit)
{
	int r;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	sector_t data_size = ti->len;
	dm_block_t sb_data_size;

	*need_commit = false;

	(void) sector_div(data_size, pool->sectors_per_block);

	r = dm_pool_get_data_dev_size(pool->pmd, &sb_data_size);
	if (r) {
		DMERR("%s: failed to retrieve data device size",
		      dm_device_name(pool->pool_md));
		return r;
	}

	if (data_size < sb_data_size) {
		DMERR("%s: pool target (%llu blocks) too small: expected %llu",
		      dm_device_name(pool->pool_md),
		      (unsigned long long)data_size, sb_data_size);
		return -EINVAL;

	} else if (data_size > sb_data_size) {
		r = dm_pool_resize_data_dev(pool->pmd, data_size);
		if (r) {
			DMERR("%s: failed to resize data device",
			      dm_device_name(pool->pool_md));
			set_pool_mode(pool, PM_READ_ONLY);
			return r;
		}

		*need_commit = true;
	}

	return 0;
}

static int maybe_resize_metadata_dev(struct dm_target *ti, bool *need_commit)
{
	int r;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	dm_block_t metadata_dev_size, sb_metadata_dev_size;

	*need_commit = false;

	metadata_dev_size = get_metadata_dev_size_in_blocks(pool->pmd, pool->md_dev);

	r = dm_pool_get_metadata_dev_size(pool->pmd, &sb_metadata_dev_size);
	if (r) {
		DMERR("%s: failed to retrieve metadata device size",
		      dm_device_name(pool->pool_md));
		return r;
	}

	if (metadata_dev_size < sb_metadata_dev_size) {
		DMERR("%s: metadata device (%llu blocks) too small: expected %llu",
		      dm_device_name(pool->pool_md),
		      metadata_dev_size, sb_metadata_dev_size);
		return -EINVAL;

	} else if (metadata_dev_size > sb_metadata_dev_size) {
		r = dm_pool_resize_metadata_dev(pool->pmd, metadata_dev_size);
		if (r) {
			DMERR("%s: failed to resize metadata device",
			      dm_device_name(pool->pool_md));
			return r;
		}

		*need_commit = true;
	}

	return 0;
}

/*
 * Retrieves the number of blocks of the data device from
 * the superblock and compares it to the actual device size,
 * thus resizing the data device in case it has grown.
 *
 * This both copes with opening preallocated data devices in the ctr
 * being followed by a resume
 * -and-
 * calling the resume method individually after userspace has
 * grown the data device in reaction to a table event.
 */
static int pool_preresume(struct dm_target *ti)
{
	int r;
	bool need_commit1, need_commit2;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	bool need_commit3;
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;
	struct pool_c_tier_private *pool_c_tier_data = &(pt->pool_c_tier_data);
	sector_t data_size = ti->len;
	unsigned int active_tier_num;
	struct pool_features_tier_private tf;

	/*
	 * Take control of the pool object.
	 */
	r = bind_control_target(pool, ti);
	if (r)
		return r;

	//PATCH:TIER
	need_commit1 = need_commit2 = need_commit3 = false;

	tf = pool_tier_data->pool_features_tier_data;
	if (tf.enable_tier) {
		r = maybe_resize_tier_data_dev(ti, pool_tier_data, pool_c_tier_data, &need_commit3);
		if (r)
			return r;
	}

	r = maybe_resize_data_dev(ti, &need_commit1);
	if (r)
		return r;

	r = maybe_resize_metadata_dev(ti, &need_commit2);
	if (r)
		return r;

	if (need_commit1 || need_commit2 || need_commit3)
		(void) commit(pool);

	//PATCH:TIER
	if (tf.enable_tier) {
		stop_auto_tiering_thread(pool_tier_data);

		active_tier_num = get_bit_num(tf.enable_map);
		if (tf.bypass && active_tier_num > 1) {
			DMINFO("%s:%d, bypass_off is false but active %d Tiers  !!", __func__, __LINE__, active_tier_num);
			return -EINVAL;
		}

		(void) sector_div(data_size, pool_tier_data->tier_sec_per_blk);

		/*reset swap_not_ready*/
		atomic_set(&pool_tier_data->swap_not_ready, 0);

		if (!tf.bypass) {
			pool_tier_data->bypass_tierid = -1;

			r = maybe_resize_migr_stats(pool_tier_data, (dm_block_t )data_size);
			if (r)
				return r;

			r = pool_bitmap_maybe_resize(pool_tier_data->pmd, data_size);
			if(r)
				return r;

			//we should scan bitmap only as pool new created
			if (pool_tier_data->tier_created) {
				r = tier_bitmap_scan(&pool_tier_data->pmd, data_size);
				if (r) {
					DMINFO("Parse pool block mapping's bitmap failed");
					return r;
				}
			}

			/*We don't need to build mapping now*/
			/*
			if (ifneed_build_tier_mapping(pool_tier_data, &build_tierid)) {
				r = build_bypass_tier_mapping(pool_tier_data, build_tierid);
				if (r) {
					DMINFO("%s:%d, build bypass tier mapping fail !!", __func__, __LINE__);
					return r;
				}
			}
			*/
			pool_tier_data->enable_map = tf.enable_map;

			r = maybe_resize_swap_space(pool_tier_data);
			if (r)
				return r;
		} else {
			set_bypass_tierid(pool_tier_data);
			atomic_or(1, &pool_tier_data->swap_not_ready);
		}
	}

	pool_tier_data->tier_created = 0;
	return 0;
}

static void pool_resume(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	unsigned long flags;
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	spin_lock_irqsave(&pool->lock, flags);
	pool->low_water_triggered = 0;
	pool->sync_io_triggered = 0;
	pool->no_free_space = 0;
	pool->snap_delete = 0;
	requeue_bios(pool);
	spin_unlock_irqrestore(&pool->lock, flags);

	do_waker(&pool->waker.work);

	//PATCH:TIER
	do_tier_waker(&pool_tier_data->tier_waker.work);
}

static void pool_postsuspend(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	struct pool_tier_private *pool_tier_data = pool->pool_tier_data;

	cancel_delayed_work(&pool->waker);
	flush_workqueue(pool->wq);

	//PATCH:TIER
	cancel_delayed_work(&pool_tier_data->tier_waker);
	flush_workqueue(pool_tier_data->tier_wq);

	(void) commit(pool);
}

static int check_arg_count(unsigned argc, unsigned args_required)
{
	if (argc != args_required) {
		DMWARN("Message received with %u arguments instead of %u.",
		       argc, args_required);
		return -EINVAL;
	}

	return 0;
}

static int read_dev_id(char *arg, dm_thin_id *dev_id, int warning)
{
	if (!kstrtoull(arg, 10, (unsigned long long *)dev_id) &&
	    *dev_id <= MAX_DEV_ID)
		return 0;

	if (warning)
		DMWARN("Message received with invalid device id: %s", arg);

	return -EINVAL;
}

static int process_create_thin_mesg(unsigned argc, char **argv, struct pool *pool)
{
	dm_thin_id dev_id;
	int r;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = read_dev_id(argv[1], &dev_id, 1);
	if (r)
		return r;

	r = dm_pool_create_thin(pool->pmd, dev_id);
	if (r) {
		DMWARN("Creation of new thinly-provisioned device with id %s failed.",
		       argv[1]);
		return r;
	}

	return 0;
}

static int process_create_snap_mesg(unsigned argc, char **argv, struct pool *pool)
{
	dm_thin_id dev_id;
	dm_thin_id origin_dev_id;
	int r;

	r = check_arg_count(argc, 3);
	if (r)
		return r;

	r = read_dev_id(argv[1], &dev_id, 1);
	if (r)
		return r;

	r = read_dev_id(argv[2], &origin_dev_id, 1);
	if (r)
		return r;

	r = dm_pool_create_snap(pool->pmd, dev_id, origin_dev_id);
	if (r) {
		DMWARN("Creation of new snapshot %s of device %s failed.",
		       argv[1], argv[2]);
		return r;
	}

	return 0;
}

static int process_create_clone_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	dm_thin_id dev_id;
	dm_thin_id origin_dev_id;

	r = check_arg_count(argc, 3);
	if (r)
		return r;

	r = read_dev_id(argv[1], &dev_id, 1);
	if (r)
		return r;

	r = read_dev_id(argv[2], &origin_dev_id, 1);
	if (r)
		return r;

	r = dm_pool_create_clone(pool->pmd, dev_id, origin_dev_id);
	if (r)
		DMWARN("Creation of clone device %s from %s failed.",
		       argv[1], argv[2]);

	return r;
}

static int process_delete_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	dm_thin_id dev_id;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = read_dev_id(argv[1], &dev_id, 1);
	if (r)
		return r;

	r = dm_pool_delete_thin_device(pool->pmd, dev_id);
	if (r)
		DMWARN("Deletion of thin device %s failed.", argv[1]);

	return r;
}

static int process_set_transaction_id_mesg(unsigned argc, char **argv, struct pool *pool)
{
	dm_thin_id old_id, new_id;
	int r;

	r = check_arg_count(argc, 3);
	if (r)
		return r;

	if (kstrtoull(argv[1], 10, (unsigned long long *)&old_id)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[1]);
		return -EINVAL;
	}

	if (kstrtoull(argv[2], 10, (unsigned long long *)&new_id)) {
		DMWARN("set_transaction_id message: Unrecognised new id %s.", argv[2]);
		return -EINVAL;
	}

	r = dm_pool_set_metadata_transaction_id(pool->pmd, old_id, new_id);
	if (r) {
		DMWARN("Failed to change transaction id from %s to %s.",
		       argv[1], argv[2]);
		return r;
	}

	return 0;
}

static int process_reserve_metadata_snap_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	(void) commit(pool);

	r = dm_pool_reserve_metadata_snap(pool->pmd);
	if (r)
		DMWARN("reserve_metadata_snap message failed.");

	return r;
}

static int process_release_metadata_snap_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = dm_pool_release_metadata_snap(pool->pmd);
	if (r)
		DMWARN("release_metadata_snap message failed.");

	return r;
}

static int process_start_backup_sb_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = dm_pool_start_backup_sb(pool->pmd);
	if (r)
		DMWARN("start backup superblock failed");

	return r;
}

static int process_stop_backup_sb_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = dm_pool_stop_backup_sb(pool->pmd);
	if (r)
		DMWARN("stop backup superblock failed");

	return r;
}

static int process_thin_support_clone_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	unsigned long block_size;
	THIN_BLOCKCLONE_DESC clone_desc;

	r = check_arg_count(argc, 6);
	if (r)
		return r;

	clone_desc.src_dev = lookup_bdev(argv[1]);
	if (IS_ERR(clone_desc.src_dev)) {
		DMERR("Cannot find block_device structure for path %s", argv[1]);
		return -EINVAL;
	}

	if (kstrtoull(argv[2], 10, (unsigned long long *)&clone_desc.src_block_addr)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[2]);
		return -EINVAL;
	}

	clone_desc.dest_dev = lookup_bdev(argv[3]);
	if (IS_ERR(clone_desc.dest_dev)) {
		DMERR("Cannot find block_device structure for path %s", argv[3]);
		return -EINVAL;
	}

	if (kstrtoull(argv[4], 10, (unsigned long long *)&clone_desc.dest_block_addr)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[4]);
		return -EINVAL;
	}

	if (kstrtoull(argv[5], 10, (unsigned long long *)&clone_desc.transfer_blocks)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[5]);
		return -EINVAL;
	}

	DMINFO("\"%s\" and \"%s\" do%ssupport fast block cloning", argv[1], argv[3], thin_support_block_cloning(&clone_desc, &block_size) ? " not " : " ");
	DMINFO("Underlying pool block size is %lu", block_size);
	return 0;
}

static int process_thin_do_clone_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	THIN_BLOCKCLONE_DESC *clone_desc;

	clone_desc = kzalloc(sizeof(THIN_BLOCKCLONE_DESC), GFP_KERNEL);
	if (!clone_desc)
		return -ENOMEM;

	r = check_arg_count(argc, 6);
	if (r)
		goto err_do_clone;

	clone_desc->src_dev = lookup_bdev(argv[1]);
	if (IS_ERR(clone_desc->src_dev)) {
		DMERR("Cannot find block_device structure for path %s", argv[1]);
		goto err_do_clone;
	}

	if (kstrtoull(argv[2], 10, (unsigned long long *)&clone_desc->src_block_addr)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[2]);
		goto err_do_clone;
	}

	clone_desc->dest_dev = lookup_bdev(argv[3]);
	if (IS_ERR(clone_desc->dest_dev)) {
		DMERR("Cannot find block_device structure for path %s", argv[3]);
		goto err_do_clone;
	}

	if (kstrtoull(argv[4], 10, (unsigned long long *)&clone_desc->dest_block_addr)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[4]);
		goto err_do_clone;
	}

	if (kstrtoull(argv[5], 10, (unsigned long long *)&clone_desc->transfer_blocks)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[5]);
		goto err_do_clone;
	}

	return thin_do_block_cloning(clone_desc, NULL);

err_do_clone:
	kfree(clone_desc);
	return -EINVAL;
}

static int process_fast_block_clone_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 2);
	if (r) {
		DMERR("fast_block_clone message take exactly two arguments");
		return -EINVAL;
	}

	if (!strcasecmp(argv[1], "enable"))
		r = dm_pool_enable_block_clone(pool->pmd);
	else if (!strcasecmp(argv[1], "disable"))
		r = dm_pool_disable_block_clone(pool->pmd);
	else {
		DMERR("fast_block_clone message command %s unrecognised", argv[1]);
		r = -EINVAL;
	}

	return r;
}

static int process_get_count_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	dm_block_t block;
	uint32_t refcount;

	r = check_arg_count(argc, 2);
	if (r) {
		DMERR("get count message take exactly two arguments");
		return -EINVAL;
	}

	if (kstrtoull(argv[1], 10, (unsigned long long *)&block)) {
		DMWARN("cannot identify block number %s", argv[1]);
		return -EINVAL;
	}

	r = dm_pool_get_refcount(pool->pmd, block, &refcount);
	if (!r)
		DMERR("%s: block %llu refcount = %u", __func__, block, refcount);

	return r;
}

static int process_rebuilt_reserve_space_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	struct thin_c *tc;

	r = check_arg_count(argc, 1);
	if (r) {
		DMERR("rebuilt reserve space message take exactly no argument");
		return -EINVAL;
	}

	tc = get_first_thin(pool);
	if (tc) {
		DMERR("Still active thins around, deactivate them before rebuilt is needed");
		thin_put(tc);
		return -EINVAL;
	}

	r = dm_pool_rebuilt_reserve_space(pool->pmd);
	if (r)
		DMERR("rebuilt reserve space fail, return = %d", r);

	return r;
}

static int process_dump_reserve_count_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	dm_block_t clone_reserve;

	r = check_arg_count(argc, 1);
	if (r) {
		DMERR("dump reserve count message take exactly no argument");
		return -EINVAL;
	}

	r = dm_pool_get_reserve_count(pool->pmd, &clone_reserve);
	if (r)
		DMERR("get reserve count fail, return = %d", r);
	else
		DMERR("pool reserve %llu blocks for clone", clone_reserve);

	return r;
}

static int process_reset_reserve_count_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;
	dm_block_t clone_reserve;

	r = check_arg_count(argc, 1);
	if (r) {
		DMERR("reset reserve count message take exactly no argument");
		return -EINVAL;
	}

	r = dm_pool_set_reserve_count(pool->pmd, 0);
	if (r)
		DMERR("set reserve count fail, return = %d", r);
	else {
		r = dm_pool_get_reserve_count(pool->pmd, &clone_reserve);
		if (r)
			DMERR("get reserve count fail, return = %d", r);
		else
			DMERR("pool reserve %llu blocks for clone", clone_reserve);
	}

	return r;
}

static int process_fix_reserve_count_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r) {
		DMERR("dump reserve count message take exactly no argument");
		return -EINVAL;
	}

	r = dm_pool_fix_reserve_count(pool->pmd);
	if (r)
		DMERR("fix reserve count fail, return = %d", r);
	else
		DMERR("fix reserve count success");

	return r;
}

/*
 * Messages supported:
 *   create_thin	<dev_id>
 *   create_snap	<dev_id> <origin_id>
 *   delete		<dev_id>
 *   trim		<dev_id> <new_size_in_sectors>
 *   set_transaction_id <current_trans_id> <new_trans_id>
 *   reserve_metadata_snap
 *   release_metadata_snap
 */
static int pool_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = -EINVAL;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	struct pool_tier_private *pool_tier_data;

	if (!strcasecmp(argv[0], "create_thin"))
		r = process_create_thin_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "create_snap"))
		r = process_create_snap_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "create_clone"))
		r = process_create_clone_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "delete"))
		r = process_delete_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "set_transaction_id"))
		r = process_set_transaction_id_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "reserve_metadata_snap"))
		r = process_reserve_metadata_snap_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "release_metadata_snap"))
		r = process_release_metadata_snap_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "thin_support_clone"))
		r = process_thin_support_clone_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "thin_do_clone"))
		r = process_thin_do_clone_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "fast_block_clone"))
		r = process_fast_block_clone_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "get_count"))
		r = process_get_count_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "start_backup_sb"))
		r = process_start_backup_sb_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "stop_backup_sb"))
		r = process_stop_backup_sb_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "rebuilt_reserve_space"))
		r = process_rebuilt_reserve_space_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "dump_reserve_count"))
		r = process_dump_reserve_count_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "reset_reserve_count"))
		r = process_reset_reserve_count_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "fix_reserve_count"))
		r = process_fix_reserve_count_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "display_tiering_hitcount")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_display_tiering_hitcount(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "display_mapping")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_display_mapping_msg(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "tiering_analysis")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_tiering_analysis_msg(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "auto_tiering")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_auto_tiering_mesg(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "stop_auto_tiering")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_stop_auto_tiering_mesg(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "set_alloc_tier")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_set_alloc_tier_mesg(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "display_swap")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_display_swap_mesg(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "remove_swap")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_remove_swap_mesg(argc, argv, pool_tier_data);
	} else if (!strcasecmp(argv[0], "set_btier")) {
		pool_tier_data = pool->pool_tier_data;
		r = process_set_btier_mesg(argc, argv, pool_tier_data);
	} else
		DMWARN("Unrecognised thin pool target message received: %s", argv[0]);

	if (!r)
		(void) commit(pool);

	return r;
}

static void emit_flags(struct pool_features *pf, char *result,
                       unsigned sz, unsigned maxlen)
{
	unsigned count = !pf->zero_new_blocks + !pf->discard_enabled +
	                 !pf->discard_passdown + (pf->mode == PM_READ_ONLY);
	struct pool_features_tier_private *pool_features_tier_data = &(pf->pool_features_tier_data);
	unsigned int i = 0;

	//PATCH:TIER
	if (pool_features_tier_data->enable_tier) {
		if (pool_features_tier_data->bypass)
			count += (pool_features_tier_data->tier_num + 3);
		else
			count += (pool_features_tier_data->tier_num + 4);
	}

	DMEMIT("%u ", count);

	//PATCH:TIER
	if (pool_features_tier_data->enable_tier) {
		DMEMIT("TIER:%d %lu ", pool_features_tier_data->tier_num, pool_features_tier_data->alloc_tier);
		for ( i = 0; i < pool_features_tier_data->tier_num; i++) {
			char buf[BDEVNAME_SIZE];
			DMEMIT("%s ", format_dev_t(buf, pool_features_tier_data->tier_dev[i]->bdev->bd_dev));
		}
		DMEMIT("enable_map:%d ", pool_features_tier_data->enable_map);
		if (!pool_features_tier_data->bypass)
			DMEMIT("bypass_off ");
	}

	if (!pf->zero_new_blocks)
		DMEMIT("skip_block_zeroing ");

	if (!pf->discard_enabled)
		DMEMIT("ignore_discard ");

	if (!pf->discard_passdown)
		DMEMIT("no_discard_passdown ");

	if (pf->mode == PM_READ_ONLY)
		DMEMIT("read_only ");

}

/*
 * Status line is:
 *    <transaction id> <used metadata sectors>/<total metadata sectors>
 *    <used data sectors>/<total data sectors> <held metadata root>
 */
static void pool_status(struct dm_target *ti, status_type_t type,
                        unsigned status_flags, char *result, unsigned maxlen)
{
	int r;
	unsigned sz = 0;
	uint64_t transaction_id;
	dm_block_t nr_free_blocks_data;
	dm_block_t nr_free_blocks_metadata;
	dm_block_t nr_blocks_data;
	dm_block_t nr_blocks_metadata;
	dm_block_t held_root;
	char buf[BDEVNAME_SIZE];
	char buf2[BDEVNAME_SIZE];
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	struct pool_features_tier_private *pool_features_tier_data = &(pt->requested_pf.pool_features_tier_data);

	switch (type) {
	case STATUSTYPE_INFO:
		if (get_pool_mode(pool) == PM_FAIL) {
			DMEMIT("Fail");
			break;
		}

		/* Commit to ensure statistics aren't out-of-date */
		if (!(status_flags & DM_STATUS_NOFLUSH_FLAG) && !dm_suspended(ti))
			(void) commit(pool);

		r = dm_pool_get_metadata_transaction_id(pool->pmd, &transaction_id);
		if (r) {
			DMERR("%s: dm_pool_get_metadata_transaction_id returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_free_metadata_block_count(pool->pmd, &nr_free_blocks_metadata);
		if (r) {
			DMERR("%s: dm_pool_get_free_metadata_block_count returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_metadata_dev_size(pool->pmd, &nr_blocks_metadata);
		if (r) {
			DMERR("%s: dm_pool_get_metadata_dev_size returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_free_block_count(pool->pmd, &nr_free_blocks_data);
		if (r) {
			DMERR("%s: dm_pool_get_free_block_count returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_data_dev_size(pool->pmd, &nr_blocks_data);
		if (r) {
			DMERR("%s: dm_pool_get_data_dev_size returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_metadata_snap(pool->pmd, &held_root);
		if (r) {
			DMERR("%s: dm_pool_get_metadata_snap returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		DMEMIT("%llu %llu/%llu %llu/%llu ",
		       (unsigned long long)transaction_id,
		       (unsigned long long)(nr_blocks_metadata - nr_free_blocks_metadata),
		       (unsigned long long)nr_blocks_metadata,
		       (unsigned long long)(nr_blocks_data - nr_free_blocks_data),
		       (unsigned long long)nr_blocks_data);

		if (held_root)
			DMEMIT("%llu ", held_root);
		else
			DMEMIT("- ");

		if (pool->pf.mode == PM_READ_ONLY)
			DMEMIT("ro ");
		else
			DMEMIT("rw ");

		if (!pool->pf.discard_enabled)
			DMEMIT("ignore_discard ");
		else if (pool->pf.discard_passdown)
			DMEMIT("discard_passdown ");
		else
			DMEMIT("no_discard_passdown ");

		if (support_fast_block_clone(pool->pmd))
			DMEMIT("fast_block_clone ");

		if (dm_pool_support_superblock_backup(pool->pmd))
			DMEMIT("sb_backup ");
		break;

	case STATUSTYPE_TABLE:
		//PATCH:TIER
		DMEMIT("%s %s %lu %llu ",
		       format_dev_t(buf, pt->metadata_dev->bdev->bd_dev),
		       pool_features_tier_data->enable_tier ? "TIER" : format_dev_t(buf2, pt->data_dev->bdev->bd_dev),
		       (unsigned long)pool->sectors_per_block,
		       (unsigned long long)pt->low_water_blocks);
		emit_flags(&pt->requested_pf, result, sz, maxlen);

		break;
	}
	return;

err:
	DMEMIT("Error");
}

static int pool_iterate_devices(struct dm_target *ti,
                                iterate_devices_callout_fn fn, void *data)
{
	struct pool_c *pt = ti->private;
	struct pool_c_tier_private *pool_c_tier_data = &(pt->pool_c_tier_data);
	unsigned i = 0;
	int ret = 0;
	struct pool_features_tier_private pool_features_tier_data = pt->adjusted_pf.pool_features_tier_data;

	//PATCH:TIER
	if (!pool_features_tier_data.enable_tier) {
		return fn(ti, pt->data_dev, 0, ti->len, data);
	} else {
		do {
			if (!(pool_features_tier_data.enable_map & (0x1 << i)))
				continue;
			ret = fn(ti, pool_c_tier_data->tier_data_dev[i], 0, get_data_dev_size_in_blocks(pool_c_tier_data->tier_data_dev[i]->bdev, 1), data);
		} while (!ret && ++i < pool_features_tier_data.tier_num);
		return ret;
	}
}

static int pool_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
                      struct bio_vec *biovec, int max_size)
{
	struct pool_c *pt = ti->private;
	struct request_queue *q;
	struct pool_features_tier_private tf = pt->adjusted_pf.pool_features_tier_data;
	int tmp;
	int i;

	if (tf.enable_tier) {
		tmp = max_size;
		for (i = 0; i < tf.tier_num; i++) {
			if (tf.enable_map & (0x1 << i)) {
				q = bdev_get_queue(tf.tier_dev[i]->bdev);

				if (!q->merge_bvec_fn)
					continue;

				bvm->bi_bdev = tf.tier_dev[i]->bdev;
				tmp = min(tmp, q->merge_bvec_fn(q, bvm, biovec));
			}
		}

		return tmp;
	}

	q = bdev_get_queue(pt->data_dev->bdev);
	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = pt->data_dev->bdev;

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void set_discard_limits(struct pool_c *pt, struct queue_limits *limits)
{
	struct pool *pool = pt->pool;
	struct queue_limits *data_limits;
	struct pool_features_tier_private pool_features_tier_data = pt->adjusted_pf.pool_features_tier_data;

	limits->max_discard_sectors = pool->sectors_per_block;

	/*
	 * discard_granularity is just a hint, and not enforced.
	 */
	if (pt->adjusted_pf.discard_passdown && !pool_features_tier_data.enable_tier) {
		data_limits = &bdev_get_queue(pt->data_dev->bdev)->limits;
		limits->discard_granularity = data_limits->discard_granularity;
	} else
		limits->discard_granularity = pool->sectors_per_block << SECTOR_SHIFT;
}

static int pool_do_fast_block_clone(struct dm_target *ti, THIN_REMAP_DESC *srd,
									THIN_REMAP_DESC *drd, sector_t len)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;

	return pool->process_clone(pool, srd->dev_id, srd->addr, drd->dev_id, drd->addr, len);
}

static void pool_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	uint64_t io_opt_sectors = limits->io_opt >> SECTOR_SHIFT;

	/*
	 * If the system-determined stacked limits are compatible with the
	 * pool's blocksize (io_opt is a factor) do not override them.
	 */
	//PATH:TIER
	if (io_opt_sectors < pool->sectors_per_block ||
	    do_div(io_opt_sectors, pool->sectors_per_block)) {
		blk_limits_io_min(limits, 0);
		blk_limits_io_opt(limits, pool->sectors_per_block << SECTOR_SHIFT);
	}

	/*
	 * pt->adjusted_pf is a staging area for the actual features to use.
	 * They get transferred to the live pool in bind_control_target()
	 * called from pool_preresume().
	 */
	if (!pt->adjusted_pf.discard_enabled) {
		/*
		 * Must explicitly disallow stacking discard limits otherwise the
		 * block layer will stack them if pool's data device has support.
		 * QUEUE_FLAG_DISCARD wouldn't be set but there is no way for the
		 * user to see that, so make sure to set all discard limits to 0.
		 */
		limits->discard_granularity = 0;
		return;
	}

	disable_passdown_if_not_supported(pt);

	set_discard_limits(pt, limits);
}

static struct target_type pool_target = {
	.name = "thin-pool",
	.features = DM_TARGET_SINGLETON | DM_TARGET_ALWAYS_WRITEABLE |
	DM_TARGET_IMMUTABLE,
	.version = {1, 9, 0},
	.module = THIS_MODULE,
	.ctr = pool_ctr,
	.dtr = pool_dtr,
	.map = pool_map,
	.postsuspend = pool_postsuspend,
	.preresume = pool_preresume,
	.resume = pool_resume,
	.message = pool_message,
	.status = pool_status,
	.merge = pool_merge,
	.iterate_devices = pool_iterate_devices,
	.io_hints = pool_io_hints,
	.fast_block_clone = pool_do_fast_block_clone,
	.end_io = tier_endio, //PATCH:TIER
};

/*----------------------------------------------------------------
 * Thin target methods
 *--------------------------------------------------------------*/
static void scan_clone(struct work_struct *ws);
static void allocate_thick(struct work_struct *ws);
static void thin_clean_all(struct work_struct *ws);

static int add_job(struct thin_c *tc, struct convert_work *cw)
{
	int r = 0;
	unsigned long flags;

	spin_lock_irqsave(&cw->lock, flags);
	/*
	 * Since we check if this work is work busy, we should never found
	 * the same job in the workqueue.
	 */
	if (!work_busy(&cw->work)) {
		cw->status = T2T_READY;
		WARN_ON(!queue_work(tc->pool->convert_wq, &cw->work));
	} else {
		r = -EINVAL;
	}

	spin_unlock_irqrestore(&cw->lock, flags);

	return r;
}

static void cancel_job(struct thin_c *tc, struct convert_work *cw)
{
	unsigned long flags;

	spin_lock_irqsave(&cw->lock, flags);
	cw->cancel = 1;
	spin_unlock_irqrestore(&cw->lock, flags);

	cancel_work_sync(&cw->work);

	spin_lock_irqsave(&cw->lock, flags);
	cw->cancel = 0;
	spin_unlock_irqrestore(&cw->lock, flags);
}

static void thin_get(struct thin_c *tc)
{
	atomic_inc(&tc->refcount);
}

static void thin_put(struct thin_c *tc)
{
	if (atomic_dec_and_test(&tc->refcount))
		complete(&tc->can_destroy);
}

static void thin_dtr(struct dm_target *ti)
{
	struct thin_c *tc = ti->private;
	unsigned long flags;

	spin_lock_irqsave(&tc->pool->lock, flags);
	list_del_rcu(&tc->list);
	spin_unlock_irqrestore(&tc->pool->lock, flags);

	synchronize_rcu();

	thin_put(tc);
	wait_for_completion(&tc->can_destroy);

	cancel_job(tc, &tc->thick_work);

	WARN_ON(flush_work(&(tc->remove_work.work)));

	mutex_lock(&dm_thin_pool_table.mutex);

	if (tc->dm_monitor_fn)
		tc->dm_monitor_fn(tc->lundev, 1);

	kobject_put(&tc->pool->kobj);
	dm_pool_close_thin_device(tc->td);
	dm_put_device(ti, tc->pool_dev);
	if (tc->origin_dev)
		dm_put_device(ti, tc->origin_dev);
	kfree(tc);

	mutex_unlock(&dm_thin_pool_table.mutex);
}

static void init_convert_work(struct convert_work *cw, work_func_t func)
{
	spin_lock_init(&cw->lock);
	cw->cancel = 0;
	cw->status = T2T_READY;
	INIT_WORK(&cw->work, func);
}

/*
 * Thin target parameters:
 *
 * <pool_dev> <dev_id> [origin_dev]
 *
 * pool_dev: the path to the pool (eg, /dev/mapper/my_pool)
 * dev_id: the internal device identifier
 * origin_dev: a device external to the pool that should act as the origin
 *
 * If the pool device has discards disabled, they get disabled for the thin
 * device as well.
 */
static int thin_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	struct thin_c *tc;
	struct dm_dev *pool_dev, *origin_dev;
	struct mapped_device *pool_md;

	mutex_lock(&dm_thin_pool_table.mutex);

	/*
	 * FIXME: remove the thin_prealloc
	 */
	if (argc != 2 && argc != 3) {
		ti->error = "Invalid argument count";
		r = -EINVAL;
		goto out_unlock;
	}

	tc = ti->private = kzalloc(sizeof(*tc), GFP_KERNEL);
	if (!tc) {
		ti->error = "Out of memory";
		r = -ENOMEM;
		goto out_unlock;
	}

	spin_lock_init(&tc->lock);
	INIT_LIST_HEAD(&tc->deferred_cells);
	bio_list_init(&tc->deferred_bio_list);
	bio_list_init(&tc->retry_on_resume_list);
	tc->sort_bio_list = RB_ROOT;

	if (argc == 3) {
		r = dm_get_device(ti, argv[2], FMODE_READ, &origin_dev);
		if (r) {
			ti->error = "Error opening origin device";
			goto bad_origin_dev;
		}
		tc->origin_dev = origin_dev;
	}

	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &pool_dev);
	if (r) {
		ti->error = "Error opening pool device";
		goto bad_pool_dev;
	}
	tc->pool_dev = pool_dev;

	if (read_dev_id(argv[1], (unsigned long long *)&tc->dev_id, 0)) {
		ti->error = "Invalid device id";
		r = -EINVAL;
		goto bad_common;
	}

	pool_md = dm_get_md(tc->pool_dev->bdev->bd_dev);
	if (!pool_md) {
		ti->error = "Couldn't get pool mapped device";
		r = -EINVAL;
		goto bad_common;
	}

	tc->pool = __pool_table_lookup(pool_md);
	if (!tc->pool) {
		ti->error = "Couldn't find pool object";
		r = -EINVAL;
		goto bad_pool_lookup;
	}
	kobject_get(&tc->pool->kobj);

	if (get_pool_mode(tc->pool) == PM_FAIL) {
		ti->error = "Couldn't open thin device, Pool is in fail mode";
		goto bad_thin_open;
	}

	r = dm_pool_open_thin_device(tc->pool->pmd, tc->dev_id, &tc->td);
	if (r) {
		ti->error = "Couldn't open thin internal device";
		goto bad_thin_open;
	}

	r = dm_set_target_max_io_len(ti, tc->pool->sectors_per_block);
	if (r)
		goto bad_thin_open;

	ti->num_flush_bios = 1;
	ti->flush_supported = true;
	ti->per_bio_data_size = sizeof(struct dm_thin_endio_hook);

	/* In case the pool supports discards, pass them on. */
	ti->discard_zeroes_data_unsupported = true;
	if (tc->pool->pf.discard_enabled) {
		ti->discards_supported = true;
		ti->num_discard_bios = 1;
		/* Discard bios must be split on a block boundary */
		ti->split_discard_bios = true;
	} else
		ti->discards_supported = false;

	tc->ti = ti;
	tc->len = ti->len;
	init_convert_work(&tc->remove_work, thin_clean_all);

	tc->dm_monitor_fn = NULL;
	tc->lundev = NULL;
	tc->is_lun = false;

	tc->discard_passdown = tc->pool->pf.discard_passdown;

	dm_put(pool_md);

	mutex_unlock(&dm_thin_pool_table.mutex);

	atomic_set(&tc->refcount, 1);
	init_completion(&tc->can_destroy);

	spin_lock(&tc->pool->lock);
	list_add_tail_rcu(&tc->list, &tc->pool->active_thins);
	spin_unlock(&tc->pool->lock);
	/*
	 * This synchronize_rcu() call is needed here otherwise we risk a
	 * wake_worker() call finding no bios to process (because the newly
	 * added tc isn't yet visible).  So this reduces latency since we
	 * aren't then dependent on the periodic commit to wake_worker().
	 */
	synchronize_rcu();

	// FIXME: We should remove thick target
	// DMERR("%s: scaned_index status: %llu", __func__, (dm_pool_scaned_index(tc->td) != SCAN_FINISH));
	if (dm_pool_scaned_index(tc->td) != SCAN_FINISH) {
		init_convert_work(&tc->thick_work, scan_clone);
		add_job(tc, &tc->thick_work);
	}

	if (!strcasecmp(ti->type->name, "thick")) {
		tc->is_thick = true;
		if (dm_pool_scaned_index(tc->td) == SCAN_FINISH) {
			init_convert_work(&tc->thick_work, allocate_thick);
			add_job(tc, &tc->thick_work);
		}
	} else
		tc->is_thick = false;

	return 0;

bad_thin_open:
	kobject_put(&tc->pool->kobj);
bad_pool_lookup:
	dm_put(pool_md);
bad_common:
	dm_put_device(ti, tc->pool_dev);
bad_pool_dev:
	if (tc->origin_dev)
		dm_put_device(ti, tc->origin_dev);
bad_origin_dev:
	kfree(tc);
out_unlock:
	mutex_unlock(&dm_thin_pool_table.mutex);

	return r;
}

static int thin_map(struct dm_target *ti, struct bio *bio)
{
	bio->bi_sector = dm_target_offset(ti, bio->bi_sector);

	return thin_bio_map(ti, bio);
}

static int thin_endio(struct dm_target *ti, struct bio *bio, int err)
{
	unsigned long flags;
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	struct list_head work;
	struct dm_thin_new_mapping *m, *tmp;
	struct pool *pool = h->tc->pool;

	if (h->shared_read_entry) {
		INIT_LIST_HEAD(&work);
		dm_deferred_entry_dec(h->shared_read_entry, &work);

		spin_lock_irqsave(&pool->lock, flags);
		list_for_each_entry_safe(m, tmp, &work, list) {
			list_del(&m->list);
			m->quiesced = 1;
			__maybe_add_mapping(m);
		}
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	if (h->all_io_entry) {
		INIT_LIST_HEAD(&work);
		dm_deferred_entry_dec(h->all_io_entry, &work);
		if (!list_empty(&work)) {
			spin_lock_irqsave(&pool->lock, flags);
			list_for_each_entry_safe(m, tmp, &work, list)
				list_add_tail(&m->list, m->clone_data ?
										&pool->prepared_clones :
										&pool->prepared_discards);
			spin_unlock_irqrestore(&pool->lock, flags);
			wake_worker(pool);
		}
	}

	if (err && !pool->io_error_reported && need_to_rescan(pool->pmd)) {
		DMERR("thin I/O error code: %d, send HAL message", err);
		//send_hal_msg(pool, HAL_IO_ERROR);
	}

	return 0;
}

static void thin_postsuspend(struct dm_target *ti)
{
	if (dm_noflush_suspending(ti))
		requeue_io((struct thin_c *)ti->private);
}

static void set_work_status(struct convert_work *cw, enum T2T_STATE status)
{
	unsigned long flags;

	spin_lock_irqsave(&cw->lock, flags);
	cw->status = status;
	spin_unlock_irqrestore(&cw->lock, flags);
}

static char* report_work_status(struct convert_work *cw)
{
	unsigned int index;
	unsigned long flags;

	index = work_busy(&cw->work);
	index &= (WORK_BUSY_RUNNING | WORK_BUSY_PENDING);
	if (index)
		goto status_confirm;

	spin_lock_irqsave(&cw->lock, flags);
	index = cw->status;
	spin_unlock_irqrestore(&cw->lock, flags);

	if (index > __MAX_NR_STATE)
		index = __MAX_NR_STATE;

status_confirm:
	return t2t_state_name[index];
}

/*
 * <nr mapped sectors> <highest mapped sector>
 */
static void thin_status(struct dm_target *ti, status_type_t type,
                        unsigned status_flags, char *result, unsigned maxlen)
{
	int r;
	ssize_t sz = 0;
	dm_block_t mapped, highest, root;
	char buf[BDEVNAME_SIZE];
	struct thin_c *tc = ti->private;

	if (get_pool_mode(tc->pool) == PM_FAIL) {
		DMEMIT("Fail");
		return;
	}

	if (!tc->td)
		DMEMIT("-");
	else {
		switch (type) {
		case STATUSTYPE_INFO:
			r = dm_thin_get_mapped_count(tc->td, &mapped);
			if (r) {
				DMERR("dm_thin_get_mapped_count returned %d", r);
				goto err;
			}

			r = dm_thin_get_highest_mapped_block(tc->td, &highest);
			if (r < 0) {
				DMERR("dm_thin_get_highest_mapped_block returned %d", r);
				goto err;
			}

			DMEMIT("%llu ", mapped * tc->pool->sectors_per_block);
			if (r)
				DMEMIT("%llu ", ((highest + 1) *
				                 tc->pool->sectors_per_block) - 1);
			else
				DMEMIT("- ");


			DMEMIT("%s %s ", report_work_status(&tc->thick_work),
			       report_work_status(&tc->remove_work));

			r = dm_pool_get_snap_root(tc->pool->pmd, tc->td, &root);
			if (r) {
				DMERR("dm_pool_get_snap_root returned %d", r);
				goto err;
			}
			DMEMIT("%llu ", root);

			break;

		case STATUSTYPE_TABLE:
			DMEMIT("%s %lu",
			       format_dev_t(buf, tc->pool_dev->bdev->bd_dev),
			       (unsigned long) tc->dev_id);
			if (tc->origin_dev)
				DMEMIT(" %s", format_dev_t(buf, tc->origin_dev->bdev->bd_dev));
			break;
		}
	}

	return;

err:
	DMEMIT("Error");
}

static int thin_iterate_devices(struct dm_target *ti,
                                iterate_devices_callout_fn fn, void *data)
{
	sector_t blocks;
	struct thin_c *tc = ti->private;
	struct pool *pool = tc->pool;

	/*
	 * We can't call dm_pool_get_data_dev_size() since that blocks.  So
	 * we follow a more convoluted path through to the pool's target.
	 */
	if (!pool->ti)
		return 0;	/* nothing is bound */

	blocks = pool->ti->len;
	(void) sector_div(blocks, pool->sectors_per_block);
	if (blocks)
		return fn(ti, tc->pool_dev, 0, pool->sectors_per_block * blocks, data);

	return 0;
}

static void allocate_thick(struct work_struct *ws)
{
	int r = 0, cancel = 0;
	unsigned long flags;
	struct convert_work *cw = container_of(ws, struct convert_work, work);
	struct thin_c *tc = container_of(cw, struct thin_c, thick_work);
	struct pool *pool = tc->pool;
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;
	struct dm_thin_device *td = tc->td;
	sector_t len = tc->len;
	dm_block_t i, result, granu = 100, start = 0;

	do_div(len, pool->sectors_per_block);

	DMDEBUG("%s: volume %llu allocate_thick thread start running", __func__, tc->dev_id);

	do {
		for (i = 0; i < granu; i++, start++) {
			if (start >= len)
				goto out;

			build_virtual_key(td, start, &key);
			if (bio_detain(pool, &key, NULL, &cell))
				continue;

			r = dm_thin_deploy(td, start, &result);
			if (!r) {
				DMDEBUG("%s: block %llu deployed", __func__, start);
				cell_defer_no_holder(tc, cell);
				continue;
			}

			if (pool->sync_io_triggered) {
				DMERR("%s: sync io triggered, thick create failed when allocating %llu", __func__, start);
				r = -ENOSPC;
				goto err_out;
			}

			r = alloc_data_block(tc, &result, ALLOC_NEW);
			if (r) {
				cell_defer_no_holder(tc, cell);
				goto err_out;
			}

			r = dm_thin_insert_block(td, start, result, 0, 0, INSERT_NEW);
			if (r) {
				cell_defer_no_holder(tc, cell);
				goto err_out;
			}

			cell_defer_no_holder(tc, cell);
		}
		spin_lock_irqsave(&cw->lock, flags);
		cancel = cw->cancel;
		spin_unlock_irqrestore(&cw->lock, flags);
	} while (!cancel);

out:
	set_work_status(cw, cancel ? T2T_CANCEL : T2T_SUCCESS);
	DMDEBUG("%s: volume %llu allocate_thick thread stop successfully", __func__, tc->dev_id);
	return;
err_out:
	set_work_status(cw, T2T_FAIL);
	DMDEBUG("%s: volume %llu allocate_thick thread stop due to %s", __func__, tc->dev_id, (r != -ENOSPC) ? "unexpected error" : "no space");
	return;
}

static void scan_clone(struct work_struct *ws)
{
	int r = 0;
	dm_block_t len, block;
	struct dm_thin_lookup_result result;
	struct convert_work *cw = container_of(ws, struct convert_work, work);
	struct thin_c *tc = container_of(cw, struct thin_c, thick_work);
	struct pool *pool = tc->pool;

	r = dm_thin_get_highest_mapped_block(tc->td, &len);
	if (r < 0) {
		DMERR("%s: dm_thin_get_highest_mapped_block returned %d", __func__, r);
		DMERR("%s: fallback to scan all blocks", __func__);

		len = (dm_block_t)tc->len;
		do_div(len, pool->sectors_per_block);
	}

	for (block = dm_pool_scaned_index(tc->td); block <= len; block++) {
		r = dm_thin_find_block(tc->td, block, 1, &result);
		switch (r) {
		case 0:
			//DMERR("%s: scan block %llu to %llu is %sclone", __func__, block, result.block, (result.cloned)? "" : "not ");
			if (sync_io_threshold_reached(pool))
				goto err_out;

			r = dm_pool_scan_block(tc->td, block, &result);
			if (r)
				goto err_out;

		case -ENODATA:
			break;

		default:
			DMERR("%s: find block return %d, failed", __func__, r);
			goto err_out;
		}
	}
	dm_pool_scan_block(tc->td, SCAN_FINISH, NULL);
	set_work_status(cw, T2T_SUCCESS);
	return;
err_out:
	DMERR("%s: scan block failure, last scan index = %llu", __func__, dm_pool_scaned_index(tc->td));
	set_work_status(cw, T2T_FAIL);
	return;
}

static int process_thin_to_thick_mesg(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	struct thin_c *tc = ti->private;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	if (!strcasecmp(argv[1], "start"))
		add_job(tc, &tc->thick_work);

	else if (!strcasecmp(argv[1], "stop"))
		cancel_job(tc, &tc->thick_work);

	return r;
}

static void thin_clean_all(struct work_struct *ws)
{
	int r = 0;
	struct convert_work *cw = container_of(ws, struct convert_work, work);
	struct thin_c *tc = container_of(cw, struct thin_c, remove_work);
	struct pool *pool = tc->pool;
	struct dm_thin_device *td = tc->td;
	struct dm_thin_lookup_result lookup_result;
	dm_block_t start = 0, len = 0;

	DMDEBUG("%s: volume %llu thin_clean_all thread start running", __func__, tc->dev_id);

	r = dm_thin_get_highest_mapped_block(tc->td, &len);
	if (r < 0) {
		DMERR("%s: dm_thin_get_highest_mapped_block returned %d", __func__, r);
		DMERR("%s: fallback to discard all blocks", __func__);

		len = (dm_block_t)tc->len;
		do_div(len, pool->sectors_per_block);
	}

	for (start = 0; start <= len; start++) {
		dm_block_t *pblock = NULL;

		DMDEBUG("%s: remove block %llu", __func__, start);
		if (dm_thin_is_snapshot(td))
			goto is_snapshot;

		r = dm_thin_find_block(td, start, 1, &lookup_result);
		if (r == -ENODATA)
			continue;
		else if (r) {
			DMERR_LIMIT("%s: dm_thin_find_block() failed", __func__);
			set_work_status(cw, T2T_FAIL);
			return;
		}

		pblock = &lookup_result.block;
is_snapshot:
		r = dm_thin_remove_block(td, start, pblock);
		if (r && r != -ENODATA) {
			DMERR("%s block %llu removed fail, ret = %d", __func__, start, r);
			set_work_status(cw, T2T_FAIL);
			return;
		}
	}

	set_work_status(cw, T2T_SUCCESS);
	DMDEBUG("%s: volume %llu thin_clean_all thread stop", __func__, tc->dev_id);
}

static int process_thin_pre_remove(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = 0;
	struct thin_c *tc = ti->private;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	cancel_job(tc, &tc->thick_work);

	add_job(tc, &tc->remove_work);

	return r;
}

static int process_thin_set_discard_passdown(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	struct thin_c *tc = ti->private;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	if (!strcasecmp(argv[0], "discard_passdown"))
		tc->discard_passdown = true;
	else if (!strcasecmp(argv[0], "no_discard_passdown"))
		tc->discard_passdown = false;

	return 0;
}

static int process_thin_is_lun_mesg(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	struct thin_c *tc = ti->private;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	spin_lock(&tc->lock);
	tc->is_lun = true;
	spin_unlock(&tc->lock);

	return 0;
}

static int process_thin_dump_clone_refcount_mesg(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	struct thin_c *tc = ti->private;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = dm_pool_dump_clone_refcount(tc->td);
	if (r)
		return r;

	return 0;
}

static int thin_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = -EINVAL;

	if (!strcasecmp(argv[0], "pre_remove"))
		r = process_thin_pre_remove(ti, argc, argv);

	else if (!strcasecmp(argv[0], "to_thick"))
		r = process_thin_to_thick_mesg(ti, argc, argv);

	else if (!strcasecmp(argv[0], "is_lun"))
		r = process_thin_is_lun_mesg(ti, argc, argv);

	else if (!strcasecmp(argv[0], "discard_passdown") || !strcasecmp(argv[0], "no_discard_passdown"))
		r = process_thin_set_discard_passdown(ti, argc, argv);

	else if (!strcasecmp(argv[0], "dump_clone_refcount"))
		r = process_thin_dump_clone_refcount_mesg(ti, argc, argv);

	else
		DMWARN("Unrecognised thin target message received: %s", argv[0]);

	return r;
}

/* Some help functions for iSCSI or other modules internal use */

static bool is_thin_target(struct dm_target *ti)
{
	if (!ti || !ti->private)
		return false;

	if (strcasecmp(ti->type->name, "thin"))
		return false;

	return true;
}

/*
 * ti: dm_targe of thin or thick get from thin_get_dmtarget()
 * dev: LUN struct link
 * dm_monitor_fn: dmmonitor call back function
 * return -1: fail, 0: successful
 */
int thin_set_dm_monitor(struct dm_target *ti, void *dev, void (*dm_monitor_fn)(void*, int))
{
	struct thin_c *tc;

	if (!is_thin_target(ti))
		return -1;

	mutex_lock(&dm_thin_pool_table.mutex);

	tc = ti->private;
	tc->dm_monitor_fn = dm_monitor_fn;
	tc->lundev = dev;

	mutex_unlock(&dm_thin_pool_table.mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(thin_set_dm_monitor);

int thin_get_dmtarget(char *name, struct dm_target **result);
/*
 * name: myvg-thin0
 * index: start index number of block data
 * len: query total number
 * result 0: deployed (mapped)
 * result 1: not deployed (deallocated)
 * return -1: fail, 0: successful
 */
int thin_get_lba_status(char *name, uint64_t index, uint64_t len, uint8_t *result)
{
	int r;
	uint64_t i;
	dm_block_t d;
	struct dm_target *ti;
	struct thin_c *tc;

	if (!len || thin_get_dmtarget(name, &ti))
		return -1;

	if (!is_thin_target(ti))
		return -1;

	tc = ti->private;

	mutex_lock(&dm_thin_pool_table.mutex);

	for ( i = 0; i < len; i++) {
		r = dm_thin_deploy(tc->td, index + i, &d);
		if (r && r != -ENODATA)
			return -1;

		result[i] = (r) ? 1 : 0;
	}

	mutex_unlock(&dm_thin_pool_table.mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(thin_get_lba_status);

/*
 * name: myvg-thin0
 * result: the number of sectors per block
 * return -1: fail, 0: success
 */
int thin_get_sectors_per_block(char *name, uint32_t *result)
{
	struct dm_target *ti;
	struct thin_c *tc;

	if (thin_get_dmtarget(name, &ti) || !is_thin_target(ti))
		return -1;

	tc = ti->private;
	*result = tc->pool->sectors_per_block;

	return 0;
}
EXPORT_SYMBOL_GPL(thin_get_sectors_per_block);

/*
 * name: myvg-thin0
 * total_size: thin volume total size (unit is sector)
 * used_size: thin volume used size (unit is sector)
 * return -1: fail, 0: successful
 */
int thin_get_data_status(struct dm_target *ti, uint64_t *total_size, uint64_t *used_size)
{
	struct thin_c *tc;
	dm_block_t mapped;

	if (!is_thin_target(ti))
		return -1;

	tc = ti->private;
	*total_size = (uint64_t)ti->len;

	if (dm_thin_get_mapped_count(tc->td, &mapped))
		return -1;

	*used_size = (uint64_t)(mapped * tc->pool->sectors_per_block);

	return 0;
}
EXPORT_SYMBOL_GPL(thin_get_data_status);

/*
 * Let other modules query pool status
 * return 1 : switch to sync I/O
 *        0 : normal I/O
 *        -ENOSPC: no space in pool
 */
int dm_thin_volume_is_full(void *data)
{
	int r = -EINVAL;
	struct thin_c *tc;
	struct pool *pool;

	if (unlikely(!data))
		goto out;

	tc = (struct thin_c *)data;
	pool = tc->pool;

	if (pool->no_free_space)
		return -ENOSPC;

	if (pool->sync_io_triggered)
		return 1;

	return 0;
out:
	DMDEBUG("%s: return %d", __func__, r);
	return r;
}
EXPORT_SYMBOL(dm_thin_volume_is_full);

static int thin_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
                      struct bio_vec *biovec, int max_size)
{
	struct thin_c *tc = ti->private;
	struct pool *pool = tc->pool;
	struct request_queue *q = bdev_get_queue(tc->pool_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = tc->pool_dev->bdev;
	if (block_size_is_power_of_two(pool))
		bvm->bi_sector = bvm->bi_sector & (pool->sectors_per_block - 1);
	else
		bvm->bi_sector = sector_div(bvm->bi_sector, pool->sectors_per_block);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int thin_locate_thin(struct dm_target * ti, locate_thin_callout_fn fn, sector_t start, sector_t len, void *remap_desc, void **thin)
{
	struct thin_c *tc = ti->private;
	THIN_REMAP_DESC *rd = (THIN_REMAP_DESC *)remap_desc;

	if (thin)
		*thin = (void *)tc;

	if (ti->len < start + len)
		return -EINVAL;

	if (!support_fast_block_clone(tc->pool->pmd)) {
		DMDEBUG("Users disable fast block clone feature, return failed");
		return -EINVAL;
	}

	if (rd) {
		rd->ti = tc->pool->ti;
		rd->pool = (void *)tc->pool;
		rd->dev_id = tc->dev_id;
		rd->addr = start;
		rd->block_size = tc->pool->sectors_per_block << SECTOR_SHIFT;
	}

	return 0;
}

static int thin_invalidate(struct dm_target * ti, sector_t start, sector_t len, invalidate_callback_fn fn, void *data)
{
	DMDEBUG("%s: ready to invalidate");
	return (*fn)(data, NULL, 0);
}

static struct target_type thin_target = {
	.name = "thin",
	.version = {1, 9, 0},
	.module	= THIS_MODULE,
	.ctr = thin_ctr,
	.dtr = thin_dtr,
	.map = thin_map,
	.end_io = thin_endio,
	.postsuspend = thin_postsuspend,
	.status = thin_status,
	.iterate_devices = thin_iterate_devices,
	.locate_thin = thin_locate_thin,
	.invalidate = thin_invalidate,
	.message = thin_message,
	.merge = thin_merge,
};

static struct target_type thick_target = {
	.name = "thick",
	.version = {1, 9, 0},
	.module = THIS_MODULE,
	.ctr = thin_ctr,
	.dtr = thin_dtr,
	.map = thin_map,
	.end_io = thin_endio,
	.postsuspend = thin_postsuspend,
	.status = thin_status,
	.iterate_devices = thin_iterate_devices,
	.locate_thin = thin_locate_thin,
	.invalidate = thin_invalidate,
	.message = thin_message,
	.merge = thin_merge,
};

/*----------------------------------------------------------------*/

static int __init dm_thin_init(void)
{
	int r;
	pool_table_init();

	r = dm_register_target(&thin_target);
	if (r)
		return r;

	r = dm_register_target(&thick_target);
	if (r)
		goto bad_thick_target;

	r = dm_register_target(&pool_target);
	if (r)
		goto bad_pool_target;

	r = -ENOMEM;

	_new_mapping_cache = KMEM_CACHE(dm_thin_new_mapping, 0);
	if (!_new_mapping_cache)
		goto bad_new_mapping_cache;

	r = create_migrate_mapping_cache();
	if (r)
		goto bad_migrate_mapping_cache;

	return 0;

bad_migrate_mapping_cache:
	kmem_cache_destroy(_new_mapping_cache);
bad_new_mapping_cache:
	dm_unregister_target(&pool_target);
bad_pool_target:
	dm_unregister_target(&thick_target);
bad_thick_target:
	dm_unregister_target(&thin_target);

	return r;
}

static void dm_thin_exit(void)
{
	dm_unregister_target(&thin_target);
	dm_unregister_target(&thick_target);
	dm_unregister_target(&pool_target);
	kmem_cache_destroy(_new_mapping_cache);
	destroy_migrate_mapping_cache();
}

module_init(dm_thin_init);
module_exit(dm_thin_exit);

MODULE_DESCRIPTION(DM_NAME " thin provisioning target");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
