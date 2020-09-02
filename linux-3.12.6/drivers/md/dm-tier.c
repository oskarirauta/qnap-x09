#include "dm-tier.h"

#define DM_MSG_PREFIX   "tier"
#define MAPPING_POOL_SIZE 1024
#define COMMIT_PERIOD HZ

#define ISSUE 1
#define NO_ISSUE 0

#define MAX_STAT_COUNT 10000000	/* We count max 10 million hits, hits are reset upon migration */
#define MAX_STAT_DECAY 500000	/* Loose 5% hits per walk when we have reached the max */

//#define TIERMAXAGE 86400	/* When a chunk has not been used TIERMAXAGE it will migrate to a slower (higher) tier */
//#define TIERHITCOLLECTTIME 10

#define MIGRATION_NUM 10

#define SWAP_BLK_RATIO 100
#define SWAP_BLK_DEFAULT 400

#define TIER_STATS_ON 1
#define TIER_STATS_OFF 0

#define SSD_TIER_ID 0

#define BLKS_PER_BYTE 4
#define PER_BLK_WIDTH 2

/*---- Task type ----*/
#define TASK_MIGR_NORMAL 0
#define TASK_MIGR_SWAP 2
#define TASK_DISCARD 1

static struct kmem_cache *_migrate_mapping_cache;

static DECLARE_WAIT_QUEUE_HEAD(data_migr_thread_wait);
static DECLARE_WAIT_QUEUE_HEAD(data_migr_task_wait);

static int check_arg_count(unsigned argc, unsigned args_required)
{
	if (argc != args_required) {
		DMWARN("Message received with %u arguments instead of %u.",
		       argc, args_required);
		return -EINVAL;
	}

	return 0;
}

/*----------------------------------------------------------------*/

#define SLEEP_LONG 1000
#define SLEEP_MEDIUM 500
#define SLEEP_SHORT 0

static void gate_init(struct migration_gate *gate)
{
	init_rwsem(&gate->lock);
    	gate->applied = false;
    	gate->sleep = SLEEP_LONG;
}

static void gate_check(struct migration_gate *gate, struct bio_list *bl)
{
	if (!gate->applied && !bio_list_empty(bl)) {
        		down_write(&gate->lock);
        		gate->applied = true;
    	}
}

static void gate_complete(struct migration_gate *gate)
{
	if (gate->applied) {
        		gate->applied = false;
        		up_write(&gate->lock);
    	}
}

static int gate_lock(struct migration_gate *gate)
{
	return down_read_trylock(&gate->lock);
}

static void gate_unlock(struct migration_gate *gate)
{
	up_read(&gate->lock);
}

static void gate_sleep(struct migration_gate *gate)
{
	msleep(gate->sleep);
}

static void set_gate_sleep(struct migration_gate *gate, char *relocation_rate)
{
	if (strcmp(relocation_rate, "Low\n") == 0)
		gate->sleep = SLEEP_LONG;
	else if (strcmp(relocation_rate, "Medium\n") == 0)
		gate->sleep = SLEEP_MEDIUM;
	else if (strcmp(relocation_rate, "High\n") == 0)
		gate->sleep = SLEEP_SHORT;
	else
		DMINFO("%s:%d, Error!! Set unknow relocation rate !!", __func__, __LINE__);
}


static char* get_gate_sleep(struct migration_gate *gate)
{
	int sleep = gate->sleep;

	switch (sleep)
	{
		case SLEEP_LONG:
			return "Low\n";
		case SLEEP_MEDIUM:
			return "Medium\n";
		case SLEEP_SHORT:
			return "High\n";
		default:
			return "Error!! unknow relocation rate!!\n";
	}
	return "Error!! unknow relocation rate!!\n";
}

/*----------------------------------------------------------------*/
static void progress_reset(struct progress_data *progress)
{
	atomic_set(&progress->processed, 0);
	atomic_set(&progress->total, 0);
}

static void progress_start(struct progress_data *progress, int total)
{
	atomic_set(&progress->processed, 0);
	atomic_set(&progress->total, total);
}

static void progress_update(struct progress_data *progress)
{
	atomic_inc(&progress->processed);
}

static void get_progress(struct progress_data *progress, int *total, int *processed)
{
	*total = atomic_read(&progress->total);
	*processed = atomic_read(&progress->processed);
}

static void bparams_init(struct btier_params *bparams)
{
	atomic_set(&bparams->cool_down, COOL_DOWN_DEFAULT);
	atomic_set(&bparams->degrad_ratio, DEGRADE_RATIO_DEFAULT);
	atomic_set(&bparams->collect_time, COLLECT_TIME_DEFAULT);
	atomic_set(&bparams->reserve_ratio, RESERVE_RATIO_DEFAULT);
}


static int bparams_get(struct btier_params *bparams, int type)
{
	atomic_t *param = NULL;

	switch (type)
	{
		case COOL_DOWN:
			param = &bparams->cool_down;
			break;
		case DEGRADE_RATIO:
			param = &bparams->degrad_ratio;
			break;
		case COLLECT_TIME:
			param = &bparams->collect_time;
			break;
		case RESERVE_RATIO:
			param = &bparams->reserve_ratio;
			break;

	}	

	return atomic_read(param);
}

static int bparams_set(struct btier_params *bparams, char *type, int setValue)
{
	atomic_t *param;

	if (strcmp(type, "cool_down") == 0)
		param = &bparams->cool_down;
	else if (strcmp(type, "degrade_ratio") == 0)
		param = &bparams->degrad_ratio;
	else if (strcmp(type, "collect_time") == 0)
		param = &bparams->collect_time;
	else if (strcmp(type, "reserve_ratio") == 0)
		param = &bparams->reserve_ratio;	
	else
		return -EINVAL;

	if (strcmp(type, "degrade_ratio") == 0 && !setValue)
		return -EINVAL;

	atomic_set(param, setValue);
	return 0;
}

int btier_params_get(struct pool_tier_private *pool_tier_data, int type)
{
	return bparams_get(&pool_tier_data->bparams, type);
	
}

int btier_params_set(struct pool_tier_private *pool_tier_data, char *type, int value)
{
	return bparams_set(&pool_tier_data->bparams, type, value);
}


static void init_issue_work(struct issue_work *ws, work_func_t func)
{
	atomic_set(&ws->cancel, 0);
	INIT_WORK(&ws->work, func);
}

static int cancel_tiering(struct pool_tier_private *pool_tier_data)
{
	return atomic_read(&pool_tier_data->issue_worker.cancel);
}

void init_pool_features_tier_data(struct pool_features_tier_private *pool_features_tier_data)
{
	pool_features_tier_data->enable_tier = false;
	pool_features_tier_data->tier_num = 0;
	pool_features_tier_data->alloc_tier = 0;
	pool_features_tier_data->tier_dev = NULL;
	pool_features_tier_data->tier_blk_size = 0;
	pool_features_tier_data->enable_map = 0x0;
	pool_features_tier_data->bypass = true;
}

int parse_tier_features(struct dm_arg_set *as, unsigned *argc, char *arg_name, struct dm_target *ti, struct pool_features_tier_private *pool_features_tier_data)
{
	int i = 0, j, r;
	char *temp = arg_name;
	pool_features_tier_data->enable_tier = true;

	strsep(&temp, ":");
	r = kstrtouint(strsep(&temp,":"), 10, &(pool_features_tier_data->tier_num));
	if(r || pool_features_tier_data->tier_num <= 0 || pool_features_tier_data->tier_num > MAX_TIER_LEVEL){
		ti->error = "Incorrect tier num";
		return r;
	}

	pool_features_tier_data->tier_dev = kmalloc(pool_features_tier_data->tier_num * sizeof(struct dm_dev *), GFP_KERNEL);
	if(!pool_features_tier_data->tier_dev){
		ti->error = "No memory for tiering device structure";
		r = -ENOMEM;
		return r;
	}

	arg_name = (char *)dm_shift_arg(as);
	(*argc)--;

	i = 0;
	if (kstrtoul(arg_name, 10, &(pool_features_tier_data->alloc_tier)) || (pool_features_tier_data->alloc_tier) >=  (pool_features_tier_data->tier_num)) {
		ti->error = "Invalid allocate tier id";
		r = -EINVAL;
		goto tier_error;
	}

	for (i = 0; i < pool_features_tier_data->tier_num; i++) {

		arg_name = (char *)dm_shift_arg(as);
		(*argc)--;

		r = dm_get_device(ti, arg_name, FMODE_READ | FMODE_WRITE, &pool_features_tier_data->tier_dev[i]);
		if(r){
			ti->error = "Error getting tiering device";
			goto tier_error;
		}
	}

	pool_features_tier_data->tier_blk_size = 8192;

	return r;

tier_error:
	for (j = 0; j < i; j++)
		dm_put_device(ti, pool_features_tier_data->tier_dev[j]);

	if (pool_features_tier_data->tier_dev) {
		kfree(pool_features_tier_data->tier_dev);
		pool_features_tier_data->tier_dev = NULL;
	}

	return r;
}

int parse_tier_enableMap(struct dm_arg_set *as, unsigned *argc, char *arg_name, struct dm_target *ti, struct pool_features_tier_private *pool_features_tier_data)
{
	char *temp = arg_name;
	int r;

	strsep(&temp, ":");
	r = kstrtouint(strsep(&temp,":"), 10, &(pool_features_tier_data->enable_map));
	if(r) {
		ti->error = "Tier enable map";
		return r;
	}

	return r;
}

void set_bypass_off(struct pool_features_tier_private *pool_features_tier_data)
{
	pool_features_tier_data -> bypass = false;
}

/*
Return valuse:
	0 tier is not enable
	1 tier is enable
	2 undefined
*/
int is_tier_enable(char *arg, struct pool_features_tier_private *pool_features_tier_data)
{
	int ret;

	if(!strcasecmp(arg, "TIER") && pool_features_tier_data->enable_tier)
		ret = 1;
	else if(strcasecmp(arg, "TIER") && !pool_features_tier_data->enable_tier)
		ret = 0;
	else
		ret = 2;

	return ret;
}

void set_tier_blk_tier_disable(unsigned long block_size, struct pool_features_tier_private *pool_features_tier_data)
{
	pool_features_tier_data->tier_blk_size = (dm_block_t)block_size;
	DMINFO("%s:%d, tier_blk_size(%llu) !!", __func__, __LINE__, pool_features_tier_data->tier_blk_size);
}

int create_migrate_mapping_cache()
{
	_migrate_mapping_cache = KMEM_CACHE(dm_tier_new_mapping, 0);
	if (!_migrate_mapping_cache){
		return -ENOMEM ;
	}

	return 0;
}

static int data_migration(struct work_struct *ws);
static void reset_analysis_data(struct data_analysis *data_analysis);

struct pool_tier_private *create_pool_tier_data(struct pool_features_tier_private *pool_features_tier_data)
{
	struct pool_tier_private *pool_tier_data;
	void *err_p;
	dm_block_t tier_blk_size = pool_features_tier_data->tier_blk_size;

	pool_tier_data = kmalloc(sizeof(*pool_tier_data), GFP_KERNEL);
	if (!pool_tier_data) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_pool_tier_data;
	}

	pool_tier_data->tier_sec_per_blk = tier_blk_size;
	if (tier_blk_size & (tier_blk_size - 1))
		pool_tier_data->tier_sec_per_blk_shift = -1;
	else
		pool_tier_data->tier_sec_per_blk_shift = __ffs(tier_blk_size);

	pool_tier_data->migration_wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pool_tier_data->migration_wq) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_migration_wq;
	}

	gate_init(&pool_tier_data->gate);
	INIT_WORK(&pool_tier_data->migrate_worker, do_migration_worker);

	rwlock_init(&pool_tier_data->migr_tiermap_rwlock);
	spin_lock_init(&pool_tier_data->migr_data_lock);
	atomic_set(&pool_tier_data->migration_count, 0);

	init_migration_stats(pool_tier_data);

	pool_tier_data->migr_data = kzalloc(sizeof(struct migration_data), GFP_KERNEL);
	if (!pool_tier_data->migr_data) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_migration_data;
	}

	pool_tier_data->migr_data->bitmap = NULL;
	pool_tier_data->migr_data->bitmap_issued = NULL;
	pool_tier_data->migr_data->bitmap_migr_down = NULL;
	pool_tier_data->migr_data->bitmap_migr_up = NULL;

	bio_list_init(&pool_tier_data->block_pm_bios);

	INIT_LIST_HEAD(&pool_tier_data->prepared_migrates);
	INIT_LIST_HEAD(&pool_tier_data->tier_prepared_discards);

	// PATCH: init new deferred_set pool
	pool_tier_data->tier_io_ds = dm_deferred_set_create();
	if(!pool_tier_data->tier_io_ds) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_tier_io_ds;
	}

	pool_tier_data->migrate_mapping_pool = mempool_create_slab_pool(MAPPING_POOL_SIZE,
							_migrate_mapping_cache);
	if(!pool_tier_data->migrate_mapping_pool) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_migration_mapping_pool;
	}

	pool_tier_data->tier_prison = dm_bio_prison_create();
	if (!pool_tier_data->tier_prison) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_tier_prison;
	}

	pool_tier_data->tier_wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pool_tier_data->tier_wq) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_tier_wq;
	}

	INIT_WORK(&pool_tier_data->tier_worker, do_tier_worker);
	INIT_DELAYED_WORK(&pool_tier_data->tier_waker, do_tier_waker);

	pool_tier_data->issue_wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pool_tier_data->issue_wq) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_issue_wq;
	}
	init_issue_work(&pool_tier_data->issue_worker, (work_func_t)data_migration);

	spin_lock_init(&pool_tier_data->tier_lock);

	/*set to actual value in pool_preresume()*/
	pool_tier_data->tier_num = 0;

	/*set to actual value in tier_passdown_check()*/
	pool_tier_data->discard_passdown = 0;

	atomic_set(&pool_tier_data->migration_num, MIGRATION_NUM);
	atomic_set(&pool_tier_data->stats_switch, TIER_STATS_OFF);

	/*set to actual value in pool_preresume()*/
	atomic_set(&pool_tier_data->swap_not_ready, 0);

	/*set to actual value in pool_preresume()*/
	pool_tier_data->bypass_tierid = -1;

	pool_tier_data->tier_created = 0;

	/*set to actual value in pool_preresume()*/
	pool_tier_data->enable_map = pool_features_tier_data->enable_map;

	progress_reset(&pool_tier_data->progress);
	bparams_init(&pool_tier_data->bparams);
	reset_analysis_data(&pool_tier_data->data_analysis);

	return pool_tier_data;

bad_issue_wq:
	destroy_workqueue(pool_tier_data->tier_wq);
bad_tier_wq:
	dm_bio_prison_destroy(pool_tier_data->tier_prison);
bad_tier_prison:
	mempool_destroy(pool_tier_data->migrate_mapping_pool);
bad_migration_mapping_pool:
	dm_deferred_set_destroy(pool_tier_data->tier_io_ds);
bad_tier_io_ds:	
	kfree(pool_tier_data->migr_data);
bad_migration_data:
	destroy_workqueue(pool_tier_data->migration_wq);
bad_migration_wq:
	kfree(pool_tier_data);
bad_pool_tier_data:
	return 	err_p;
}

void init_migration_stats(struct pool_tier_private *pool_tier_data)
{
	/*set to actual value in pool_preresume()*/
	pool_tier_data->migr_stats_size = 0;

	pool_tier_data->readcount = NULL;
	pool_tier_data->writecount = NULL;
	pool_tier_data->lastused = NULL;
	pool_tier_data->total_reads = NULL;
	pool_tier_data->total_writes = NULL;
	pool_tier_data->tier_map = NULL;
	pool_tier_data->average_reads = NULL;
	pool_tier_data->average_writes = NULL;
	pool_tier_data->move_up = NULL;
	pool_tier_data->move_within = NULL;
	pool_tier_data->move_down = NULL;
}

void destroy_migrate_mapping_cache()
{
	kmem_cache_destroy(_migrate_mapping_cache);
}

void destroy_pool_tier_data(struct pool_tier_private *pool_tier_data, int destroy_migrator)
{
	destroy_workqueue(pool_tier_data->tier_wq);
	dm_bio_prison_destroy(pool_tier_data->tier_prison);
	mempool_destroy(pool_tier_data->migrate_mapping_pool);
	dm_deferred_set_destroy(pool_tier_data->tier_io_ds);

	if(pool_tier_data->migr_data)
		kfree(pool_tier_data->migr_data);

	if (pool_tier_data->migration_wq)
		destroy_workqueue(pool_tier_data->migration_wq);

	if(destroy_migrator)
		dm_kcopyd_client_destroy(pool_tier_data->migrator);

	if (pool_tier_data->issue_wq)
		destroy_workqueue(pool_tier_data->issue_wq);

	kfree(pool_tier_data);
}

void free_migration_stats(struct pool_tier_private *pool_tier_data)
{
	pool_tier_data->migr_stats_size = 0;
	if(pool_tier_data->average_writes){
		vfree(pool_tier_data->average_writes);
		pool_tier_data->average_writes = NULL;
	}
	if(pool_tier_data->average_reads){
		vfree(pool_tier_data->average_reads);
		pool_tier_data->average_reads = NULL;
	}
	if(pool_tier_data->tier_map){
		vfree(pool_tier_data->tier_map);
		pool_tier_data->tier_map = NULL;
	}
	if(pool_tier_data->total_writes){
		vfree(pool_tier_data->total_writes);
		pool_tier_data->total_writes = NULL;
	}
	if(pool_tier_data->total_reads){
		vfree(pool_tier_data->total_reads);
		pool_tier_data->total_reads = NULL;
	}
	if(pool_tier_data->lastused){
		vfree(pool_tier_data->lastused);
		pool_tier_data->lastused = NULL;
	}
	if(pool_tier_data->writecount){
		vfree(pool_tier_data->writecount);
		pool_tier_data->writecount = NULL;
	}
	if(pool_tier_data->readcount){
		vfree(pool_tier_data->readcount);
		pool_tier_data->readcount = NULL;
	}

	if(pool_tier_data->move_up){
		vfree(pool_tier_data->move_up);
		pool_tier_data->move_up = NULL;
	}

	if(pool_tier_data->move_within){
		vfree(pool_tier_data->move_within);
		pool_tier_data->move_within = NULL;
	}

	if(pool_tier_data->move_down){
		vfree(pool_tier_data->move_down);
		pool_tier_data->move_down = NULL;
	}
}

void init_pool_c_tier_data(struct pool_c_tier_private *pool_c_tier_data, struct pool_features_tier_private *pool_features_tier_data)
{
	pool_c_tier_data ->tier_num = pool_features_tier_data->tier_num;
	pool_c_tier_data->tier_data_dev = pool_features_tier_data->tier_dev;
}

void destroy_tier_devices(struct dm_target *ti, unsigned int tier_num, struct dm_dev **tier_data_dev)
{
	int i;

	for (i = 0; i < tier_num; i++) {
		DMDEBUG("%s:%d, put device %s !!", __func__, __LINE__, tier_data_dev[i]->name);
		dm_put_device(ti, tier_data_dev[i]);
	}

	kfree(tier_data_dev);
	tier_data_dev = NULL;
}

void tier_hook_bio(struct pool_tier_private *pool_tier_data, struct bio *bio)
{
	struct dm_tier_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));

	h->pool_tier_data = pool_tier_data;
	h->tier_io_entry = NULL;
	h->tier_mapping = NULL;
}

void tier_defer_bio(struct pool_tier_private *pool_tier_data, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	bio_list_add(&pool_tier_data->block_pm_bios, bio);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	wake_tier_worker(pool_tier_data);
}

bool tier_blk_size_is_power_of_two(struct pool_tier_private *pool_tier_data)
{
	return pool_tier_data->tier_sec_per_blk_shift >= 0;
}

sector_t convert_tier_address(struct pool_tier_private *pool_tier_data, dm_block_t b)
{
	dm_block_t db_fix = b;

	return (tier_blk_size_is_power_of_two(pool_tier_data))? db_fix << pool_tier_data->tier_sec_per_blk_shift : db_fix * pool_tier_data->tier_sec_per_blk;
}

void remap_to_tier(struct pool_tier_private *pool_tier_data, struct bio *bio, dm_block_t block, uint32_t tierid, int issue)
{
	sector_t bi_sector = bio->bi_sector;
	struct pool_features_tier_private pool_features_tier_data = pool_tier_data->pool_features_tier_data;

	bio->bi_bdev = pool_features_tier_data.tier_dev[tierid]->bdev;

	if (tier_blk_size_is_power_of_two(pool_tier_data))
		bio->bi_sector = convert_tier_address(pool_tier_data, block) |
				(bi_sector & (pool_tier_data->tier_sec_per_blk - 1));
	else
		bio->bi_sector = convert_tier_address(pool_tier_data, block) +
				 sector_div(bi_sector, pool_tier_data->tier_sec_per_blk);

	if(issue)
		generic_make_request(bio);
}

void get_remain_sector(struct pool_tier_private *pool_tier_data, struct bio *bio, dm_block_t block, uint32_t tierid)
{
	sector_t start_sector;
	sector_t bi_sector = bio->bi_sector;

	if (tier_blk_size_is_power_of_two(pool_tier_data))
		start_sector = (bi_sector & (pool_tier_data->tier_sec_per_blk - 1));
	else
		start_sector = sector_div(bi_sector, pool_tier_data->tier_sec_per_blk);
	DMDEBUG("%s:%d, bio length(%u) sectors, starts from sector(%lu) in PBA[%d-%llu] !!", __func__, __LINE__, bio->bi_size >> SECTOR_SHIFT, start_sector, tierid, block);
}

static int set_discard_bit(struct pool_tier_private *pool_tier_data, struct bio *bio, dm_block_t block, struct dm_tier_lookup_result *result, sector_t thin_blk_size)
{
	sector_t start_sector;
	sector_t bi_sector = bio->bi_sector;
	int discard_bit;

	if (tier_blk_size_is_power_of_two(pool_tier_data))
		start_sector = (bi_sector & (pool_tier_data->tier_sec_per_blk - 1));
	else
		start_sector = sector_div(bi_sector, pool_tier_data->tier_sec_per_blk);
	discard_bit = start_sector;
	sector_div(discard_bit, thin_blk_size);
	result->reserve |= (0x1 << discard_bit);
	DMDEBUG("%s:%d, set  for LBA[%llu]  PBA[%d-%llu] discard bits(%d) with reserve(0x%x)!!", __func__, __LINE__, 
		block, result->tierid, result->block, discard_bit, result->reserve);
	return dm_tier_insert_block_with_reserve(pool_tier_data->pmd, block, result->block, result->tierid, result->reserve); 
}

static bool discard_bit_match(struct pool_tier_private *pool_tier_data, struct bio *bio, dm_block_t block, struct dm_tier_lookup_result *result, sector_t thin_blk_size)
{
	sector_t start_sector;
	sector_t bi_sector = bio->bi_sector;
	int io_bits = 0;
	int head_section, tail_section;
	int i = 0;

	if (tier_blk_size_is_power_of_two(pool_tier_data))
		start_sector = (bi_sector & (pool_tier_data->tier_sec_per_blk - 1));
	else
		start_sector = sector_div(bi_sector, pool_tier_data->tier_sec_per_blk);

	head_section = start_sector;
	sector_div(head_section, thin_blk_size);
	tail_section = start_sector + (bio->bi_size >> SECTOR_SHIFT) - 1;
	sector_div(tail_section, thin_blk_size);

	for (i = head_section; i <= tail_section; i++){
		io_bits |=  (0x1 << i);
	}

	if (result->reserve & io_bits)
		return true;
	else 
		return false;

}

static int clear_discard_bit_ifneeded(struct pool_tier_private *pool_tier_data, struct bio *bio, dm_block_t block, struct dm_tier_lookup_result *result, sector_t thin_blk_size)
{
	sector_t start_sector;
	sector_t bi_sector = bio->bi_sector;
	int io_bits = 0;
	int head_section, tail_section;
	int i = 0;

	if (tier_blk_size_is_power_of_two(pool_tier_data))
		start_sector = (bi_sector & (pool_tier_data->tier_sec_per_blk - 1));
	else
		start_sector = sector_div(bi_sector, pool_tier_data->tier_sec_per_blk);

	head_section = start_sector;
	sector_div(head_section, thin_blk_size);
	tail_section = start_sector + (bio->bi_size >> SECTOR_SHIFT) - 1;
	sector_div(tail_section, thin_blk_size);

	for (i = head_section; i <= tail_section; i++){
		io_bits |=  (0x1 << i);
	}

	if (!(result->reserve & io_bits))
		return 0;

	DMDEBUG("%s:%d, origin LBA[%llu] PBA[%d-%llu] bio length(%u) sectors, starts from sector(%lu): section [%d~%d]=> reserve(0x%x) get io_bits(0x%x)!!", __func__, __LINE__,
		block, result->tierid, result->block, bio->bi_size >> SECTOR_SHIFT, start_sector, head_section, tail_section, result->reserve, io_bits);

	result->reserve &= (~io_bits);
	DMDEBUG("%s:%d, clear for LBA[%llu] PBA[%d-%llu] clear io_bits(0x%x) with reserve(0x%x)!!", __func__, __LINE__, 
		block, result->tierid, result->block, io_bits, result->reserve);
	return dm_tier_insert_block_with_reserve(pool_tier_data->pmd, block, result->block, result->tierid, result->reserve);
}

static bool is_discard_bit_full(struct pool_tier_private *pool_tier_data, sector_t thin_blk_size, struct dm_tier_lookup_result *result)
{
	sector_t thin_blocks = pool_tier_data->tier_sec_per_blk;

	sector_div(thin_blocks, thin_blk_size);
	if (result->reserve == ((1 << thin_blocks) - 1)) {
		DMDEBUG("%s:%d, PBA[%d-%llu] discard bit is full !!", __func__, __LINE__, result->tierid, result->block);
		return true;
	}
	else
		return false;
}

dm_block_t tier_get_bio_blk(struct pool_tier_private *pool_tier_data, struct bio *bio)
{
	sector_t block_nr = bio->bi_sector;

	if (tier_blk_size_is_power_of_two(pool_tier_data))
		block_nr >>= pool_tier_data->tier_sec_per_blk_shift;
	else
		(void) sector_div(block_nr, pool_tier_data->tier_sec_per_blk);

	return block_nr;
}

void build_tier_key(struct pool_tier_private *pool_tier_data, dm_block_t b, struct dm_cell_key *key)
{
	key->virtual = 2; // Actually this is more like a group ID
	key->dev = 0;
	key->addr = 0; // tier doesn't need this
	key->block = b;
}

void inc_tier_io_entry(struct pool_tier_private *pool_tier_data, struct bio *bio)
{
	struct dm_tier_endio_hook *h;

	if (bio->bi_rw & REQ_DISCARD)
		return;

	h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));
	h->tier_io_entry = dm_deferred_entry_inc(pool_tier_data->tier_io_ds);
}

static void cell_release_no_holder(struct pool_tier_private *pool_tier_data,
				   struct dm_bio_prison_cell *cell,
				   struct bio_list *bios)
{
	dm_cell_release_no_holder(pool_tier_data->tier_prison, cell, bios);
	dm_bio_prison_free_cell(pool_tier_data->tier_prison, cell);
}

void cell_defer_nhnf_tier(struct pool_tier_private *pool_tier_data, struct dm_bio_prison_cell *cell)
{
	unsigned long flags;

	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	dm_cell_release_no_holder(pool_tier_data->tier_prison, cell, &pool_tier_data->block_pm_bios);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	wake_tier_worker(pool_tier_data);
}

void cell_defer_no_holder_tier(struct pool_tier_private *pool_tier_data, struct dm_bio_prison_cell *cell)
{
	unsigned long flags;

	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	cell_release_no_holder(pool_tier_data, cell, &pool_tier_data->block_pm_bios);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	wake_tier_worker(pool_tier_data);
}

static int bio_detain(struct pool_tier_private *pool_tier_data, struct dm_cell_key *key, struct bio *bio,
		      struct dm_bio_prison_cell **cell_result)
{
	int r;
	struct dm_bio_prison_cell *cell_prealloc;

	/*
	 * Allocate a cell from the prison's mempool.
	 * This might block but it can't fail.
	 */
	cell_prealloc = dm_bio_prison_alloc_cell(pool_tier_data->tier_prison, GFP_NOIO);

	r = dm_bio_detain(pool_tier_data->tier_prison, key, bio, cell_prealloc, cell_result);
	if (r)
		/*
		 * We reused an old cell; we can get rid of
		 * the new one.
		 */
		dm_bio_prison_free_cell(pool_tier_data->tier_prison, cell_prealloc);

	return r;
}

static bool check_tier_discard_passdown(struct pool_tier_private *pool_tier_data, unsigned tierid);
int tier_bio_bypass_map(struct pool_tier_private *pool_tier_data, struct bio *bio)
{
	int r;
	struct dm_tier_endio_hook *h;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	bool discard_passdown = check_tier_discard_passdown(pool_tier_data, pool_tier_data->bypass_tierid);

	h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));
	if ((bio->bi_rw & REQ_DISCARD) && !discard_passdown) {
		bio_endio(bio, 0);
		return DM_MAPIO_SUBMITTED;
	} 

	if (pool_tier_data->bypass_tierid == -1) 
		DMINFO("%s:%d, bypass_tierid invalid !!", __func__, __LINE__);
	else
		bio->bi_bdev = tf.tier_dev[pool_tier_data->bypass_tierid]->bdev;
	r = DM_MAPIO_REMAPPED;

	return r;
}

int tier_bio_map(struct pool_tier_private *pool_tier_data, struct bio *bio)
{
	int r;
	struct dm_tier_lookup_result result;
	struct dm_bio_prison_cell cell, *cell_result;
	struct dm_cell_key key;
	sector_t thin_blk_size = 0;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	if (tf.bypass)
		return tier_bio_bypass_map(pool_tier_data, bio);

	/* DM-TIERING: We bypass REQ_FUA in this layer */
	if (bio->bi_rw & REQ_DISCARD) {
		tier_defer_bio(pool_tier_data, bio);
		return DM_MAPIO_SUBMITTED;
	} else if (bio->bi_rw & REQ_FLUSH) {
		unsigned target_tier = dm_bio_get_target_bio_nr(bio); //get 0~ #tier-1 by set "ti->num_flush_bios" in pool_ctr()
		remap_to_tier(pool_tier_data, bio, 0, target_tier, NO_ISSUE);
		return DM_MAPIO_REMAPPED;
	}

	build_tier_key(pool_tier_data, tier_get_bio_blk(pool_tier_data, bio), &key);
	if(dm_bio_detain(pool_tier_data->tier_prison, &key, bio, &cell, &cell_result))
		return DM_MAPIO_SUBMITTED;

	r = dm_tier_find_block(pool_tier_data->pmd, tier_get_bio_blk(pool_tier_data, bio), 0, &result);
	switch (r) {
		case 0:
			dm_pool_get_data_block_size(pool_tier_data->pmd ,&thin_blk_size);
			if (discard_bit_match(pool_tier_data, bio, tier_get_bio_blk(pool_tier_data, bio), &result, thin_blk_size))
				goto defer_bio;

			update_migration_stats(pool_tier_data, tier_get_bio_blk(pool_tier_data, bio), bio);
			inc_tier_io_entry(pool_tier_data, bio);
			cell_defer_nhnf_tier(pool_tier_data, &cell);
			if (result.tierid == SSD_TIER_ID)
				set_bit(BIO_TIER_SSD, &bio->bi_flags);
			remap_to_tier(pool_tier_data, bio, result.block, result.tierid, NO_ISSUE);
			return DM_MAPIO_REMAPPED;
defer_bio:
		case -EWOULDBLOCK:
		case -ENODATA:
			cell_defer_nhnf_tier(pool_tier_data, &cell);
			tier_defer_bio(pool_tier_data, bio);
			return DM_MAPIO_SUBMITTED;
		default:
			cell_defer_nhnf_tier(pool_tier_data, &cell);
			DMERR("%s: find block return error code %d", __func__, r);
			bio_io_error(bio);
			return DM_MAPIO_SUBMITTED;
	}
}

int tier_new_block(struct pool_tier_private *pool_tier_data, struct bio *bio,
					struct dm_tier_lookup_result *result, struct dm_bio_prison_cell *cell)
{
	int r = 0;
	int retry_chance = 1;

	if (bio_data_dir(bio) == READ) {
		zero_fill_bio(bio);
		cell_defer_no_holder_tier(pool_tier_data, cell);
		bio_endio(bio, 0);
		return r;
	}

	if (!bio->bi_size) {
		inc_tier_io_entry(pool_tier_data, bio);
		cell_defer_no_holder_tier(pool_tier_data, cell);
		remap_to_tier(pool_tier_data, bio, 0, 0, 1);
		return r;
	}

retry_alloc:
	r = dm_tier_find_free_tier_and_alloc(pool_tier_data->pmd, &result->tierid, pool_tier_data->pool_features_tier_data.enable_map, &result->block);
	if (r == -ENOSPC && retry_chance) {
		retry_chance = 0;
		dm_pool_commit_metadata(pool_tier_data->pmd);
		goto retry_alloc;
	} else if (r) {
		DMINFO("%s:%d, Error !! Allocate tier data block fail with r(%d) !!", __func__, __LINE__, r);
		return r;
	}		

	r = dm_tier_insert_block(pool_tier_data->pmd, tier_get_bio_blk(pool_tier_data, bio), result->block, result->tierid);
	if (r) {
		DMINFO("%s:%d, Error !! Insert tier data block fail !!", __func__, __LINE__);
		return r;
	}

	DMDEBUG("%s:%d, insert mapping LBA[%llu] to PBA[%u-%llu]", __func__, __LINE__, 
		tier_get_bio_blk(pool_tier_data, bio), result->tierid, result->block);

	update_migration_stats(pool_tier_data, tier_get_bio_blk(pool_tier_data, bio), bio);
	store_logic_block_tierid(pool_tier_data,  tier_get_bio_blk(pool_tier_data, bio), result->tierid);

	tier_bitmap_set(pool_tier_data->pmd, (int)tier_get_bio_blk(pool_tier_data, bio));

	inc_tier_io_entry(pool_tier_data, bio);
	cell_defer_no_holder_tier(pool_tier_data, cell);

	if (result->tierid == SSD_TIER_ID)
		set_bit(BIO_TIER_SSD, &bio->bi_flags);
	remap_to_tier(pool_tier_data, bio, result->block, result->tierid, 1);

	return 0;
}

 int tier_io_overlaps_blk(struct pool_tier_private *pool_tier_data, struct bio *bio)
{
	return bio->bi_size == (pool_tier_data->tier_sec_per_blk << SECTOR_SHIFT);
}

static bool io_overlaps_thin_blk(sector_t thin_blk_size, struct bio *bio)
{
	return bio->bi_size == (thin_blk_size << SECTOR_SHIFT);
}

static bool check_tier_discard_passdown(struct pool_tier_private *pool_tier_data, unsigned tierid)
{
	return (pool_tier_data->discard_passdown & 0x1 << tierid) ? true : false;
}

void process_tier_prepared_discard(struct pool_tier_private *pool_tier_data)
{
	struct list_head discards;
	struct dm_tier_new_mapping *m, *tmp;
	dm_block_t old_block;
	uint32_t old_tier;
	int r;
	unsigned long flags;

	INIT_LIST_HEAD(&discards);
	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	list_splice_init(&pool_tier_data->tier_prepared_discards, &discards);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	list_for_each_entry_safe(m, tmp, &discards, list)
	{
		unpack_tier_block(m->old_block, &old_tier, &old_block, NULL);

		r = dm_tier_remove_block(pool_tier_data->pmd, m->virt_block);
		if (r) {
			DMINFO("%s: dm_tier_remove_block failed", __func__);
			cell_defer_no_holder_tier(pool_tier_data, m->cell);
			bio_io_error(m->bio);
			mempool_free(m, pool_tier_data->migrate_mapping_pool);
			continue;
		}
		DMDEBUG("%s: Remove mapping LBA[%llu] to  PBA[%d-%llu] sucess !!", __func__, m->virt_block, old_tier, old_block);

		clear_migration_stats(pool_tier_data, m->virt_block);
		inc_tier_io_entry(pool_tier_data, m->bio);

		tier_bitmap_clear(pool_tier_data->pmd, (int)m->virt_block);		
		cell_defer_no_holder_tier(pool_tier_data, m->cell);

		if (check_tier_discard_passdown(pool_tier_data, (unsigned)old_tier))
			remap_to_tier(pool_tier_data, m->bio, old_block, old_tier, ISSUE);
		else
			bio_endio(m->bio, 0);

		mempool_free(m, pool_tier_data->migrate_mapping_pool);
	}

}

static void tier_defer_task(struct pool_tier_private *pool_tier_data, struct dm_tier_new_mapping *m);
void process_tier_discard(struct pool_tier_private *pool_tier_data, struct bio *bio, struct dm_bio_prison_cell *cell)
{
	int r;
	struct dm_tier_lookup_result result;
	struct dm_tier_new_mapping *m;
	sector_t thin_block_size = 0;

	r = dm_tier_find_block(pool_tier_data->pmd, tier_get_bio_blk(pool_tier_data, bio), 1, &result);
	switch (r) {
		case -ENODATA:
			cell_defer_no_holder_tier(pool_tier_data, cell);
			bio_endio(bio, 0);
			break;
		case 0:
			dm_pool_get_data_block_size(pool_tier_data->pmd ,&thin_block_size);
			if (io_overlaps_thin_blk(thin_block_size, bio))
			{
				r = set_discard_bit(pool_tier_data, bio, tier_get_bio_blk(pool_tier_data, bio), &result, thin_block_size);
				if (r) {
					DMINFO("%s:%d, set_discard_bit return with unexpected r(%d) !!", __func__, __LINE__, r);
					return;
				}
			}

			 if (is_discard_bit_full(pool_tier_data, thin_block_size, &result)) {

				m = mempool_alloc(pool_tier_data->migrate_mapping_pool, GFP_ATOMIC);

				INIT_LIST_HEAD(&m->list);
				m->pool_tier_data = pool_tier_data;
				m->type = TASK_DISCARD;
				m->bio = bio;
				m->virt_block = tier_get_bio_blk(pool_tier_data, bio);
				m->old_block = pack_tier_block(result.tierid, result.block, result.reserve);
				m->cell = cell;

				if (!dm_deferred_set_add_work(pool_tier_data->tier_io_ds, &m->list))
					tier_defer_task(pool_tier_data, m);

			} else{
				inc_tier_io_entry(pool_tier_data, bio);
				cell_defer_no_holder_tier(pool_tier_data, cell);

				if (check_tier_discard_passdown(pool_tier_data, result.tierid))
					remap_to_tier(pool_tier_data, bio, result.block, result.tierid, 1);
				else
					bio_endio(bio, 0);
			}
			break;
		default:
			cell_defer_no_holder_tier(pool_tier_data, cell);
			bio_io_error(bio);
			break;
	}
}

void process_block_bios(struct pool_tier_private *pool_tier_data)
{
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);

	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	bio_list_merge(&bios, &pool_tier_data->block_pm_bios);
	bio_list_init(&pool_tier_data->block_pm_bios);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	while ((bio = bio_list_pop(&bios))) {
		int r;
		struct dm_tier_lookup_result result;
		struct dm_bio_prison_cell *cell;
		struct dm_cell_key key;
		sector_t thin_blk_size = 0;

		build_tier_key(pool_tier_data, tier_get_bio_blk(pool_tier_data, bio), &key);
		if(bio_detain(pool_tier_data, &key, bio, &cell))
			continue;

		if (bio->bi_rw & REQ_DISCARD) {
			process_tier_discard(pool_tier_data, bio, cell);
			continue;
		}

		r = dm_tier_find_block(pool_tier_data->pmd, tier_get_bio_blk(pool_tier_data, bio), 1, &result);
		switch (r) {
			case -ENODATA:
				r = tier_new_block(pool_tier_data, bio, &result, cell);
				if (r)
					bio_io_error(bio);
				break;
			case 0:
				dm_pool_get_data_block_size(pool_tier_data->pmd ,&thin_blk_size);
				r = clear_discard_bit_ifneeded(pool_tier_data, bio, tier_get_bio_blk(pool_tier_data, bio), &result, thin_blk_size);
				if (r)
					DMINFO("%s:%d, clear discard bit return with unexpected r(%d) !!", __func__, __LINE__, r);

				update_migration_stats(pool_tier_data, tier_get_bio_blk(pool_tier_data, bio), bio);
				inc_tier_io_entry(pool_tier_data, bio);
				cell_defer_no_holder_tier(pool_tier_data, cell);
				if (result.tierid == SSD_TIER_ID)
					set_bit(BIO_TIER_SSD, &bio->bi_flags);
				remap_to_tier(pool_tier_data, bio, result.block, result.tierid, 1);
				break;
			default:
				bio_io_error(bio);
				break;
		}
	}
}


static void tier_defer_task(struct pool_tier_private *pool_tier_data, struct dm_tier_new_mapping *m)
{
	unsigned long flags;

	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	list_add(&m->list, m->type == TASK_DISCARD ? 
		&pool_tier_data->tier_prepared_discards : &pool_tier_data->prepared_migrates);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	m->type == TASK_DISCARD ? 
		wake_tier_worker(m->pool_tier_data) : wake_migration_worker(pool_tier_data);
}

int tier_endio(struct dm_target *ti, struct bio *bio, int err)
{
	struct list_head work;
	struct dm_tier_new_mapping *m, *tmp;
	struct dm_tier_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));
	struct pool_tier_private *pool_tier_data = h->pool_tier_data;
	struct pool_features_tier_private pool_features_tier_data = pool_tier_data->pool_features_tier_data;

	if( pool_features_tier_data.enable_tier && h->tier_io_entry ) {
		INIT_LIST_HEAD(&work);
		dm_deferred_entry_dec(h->tier_io_entry, &work);

		if(!list_empty(&work)){

			list_for_each_entry_safe(m, tmp, &work, list) {
				tier_defer_task(pool_tier_data, m);
			}
		}
	}

	return 0;
}

void do_tier_worker(struct work_struct *ws)
{
	struct pool_tier_private *pool_tier_data = container_of(ws, struct pool_tier_private, tier_worker);

	//PATCH: TIER
	process_tier_prepared_discard(pool_tier_data);
	gate_check(&pool_tier_data->gate, &pool_tier_data->block_pm_bios);
	process_block_bios(pool_tier_data);
	gate_complete(&pool_tier_data->gate);
}

void wake_tier_worker(struct pool_tier_private *pool_tier_data)
{
	queue_work(pool_tier_data->tier_wq, &pool_tier_data->tier_worker);
}

void do_tier_waker(struct work_struct *ws)
{
	struct pool_tier_private *pool_tier_data = container_of(to_delayed_work(ws), struct pool_tier_private, tier_waker);
	wake_tier_worker(pool_tier_data);
	queue_delayed_work(pool_tier_data->tier_wq, &pool_tier_data->tier_waker, COMMIT_PERIOD);
}

void do_migration_worker(struct work_struct *ws)
{
	struct pool_tier_private *pool_tier_data = container_of(ws, struct pool_tier_private, migrate_worker);

	process_tier_prepared_migration(pool_tier_data);
}

void wake_migration_worker(struct pool_tier_private *pool_tier_data)
{
	queue_work(pool_tier_data->migration_wq, &pool_tier_data->migrate_worker);
}

int calculate_tier_data_total_size(struct pool_tier_private *pool_tier_data, dm_block_t *size)
{
	int r = 0;
	unsigned int i;

	dm_block_t temp;

	*size = (dm_block_t)0;

	for(i=0;i < pool_tier_data->pool_features_tier_data.tier_num;i++){
		r = dm_pool_get_tier_data_dev_size(pool_tier_data->pmd, i, &temp);
		if (r) {
			DMERR("failed to retrieve data device size");
			return r;
		}
		*size += temp;
	}
	return 0;
}

dm_block_t get_data_dev_size_in_blocks(struct block_device *bdev, sector_t data_block_size)
{
	sector_t data_dev_size = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	sector_div(data_dev_size, data_block_size);

	return data_dev_size;
}


int maybe_resize_tier_data_dev(struct dm_target *ti, struct pool_tier_private *pool_tier_data,  struct pool_c_tier_private *pool_c_tier_data, bool *need_commit)
{
	int r = 0;
	unsigned int i;
	dm_block_t tier_data_size;
	struct pool_features_tier_private pool_features_tier_data = pool_tier_data->pool_features_tier_data;

	*need_commit = false;
	for (i = 0; i < pool_features_tier_data.tier_num; i++) {
		if(! (pool_features_tier_data.enable_map & ( 0x1<< i ))) {
			continue;
		}

		tier_data_size = get_data_dev_size_in_blocks(pool_c_tier_data->tier_data_dev[i]->bdev, (sector_t) pool_tier_data->tier_sec_per_blk);		
		r = dm_pool_resize_tier_data_dev(pool_tier_data->pmd, i, tier_data_size);
		if (r) {
			DMERR("failed to resize tier data device");
			return r;
		}
	}
	*need_commit = true;	
	return r;
}

static bool dev_supports_discard(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);
	return q && blk_queue_discard(q);
}

static bool is_factor(sector_t block_size, uint32_t n)
{
	return !sector_div(block_size, n);
}

static bool passdown_checking(struct pool_tier_private *pool_tier_data, struct block_device *data_bdev)
{
	struct queue_limits *data_limits;
	sector_t block_size = pool_tier_data->tier_sec_per_blk << SECTOR_SHIFT;
	const char *reason = NULL;
	char buf[BDEVNAME_SIZE];

	data_limits = &bdev_get_queue(data_bdev)->limits;

	if (!dev_supports_discard(data_bdev))
		reason = "discard unsupported";

	else if (data_limits->max_discard_sectors < pool_tier_data->tier_sec_per_blk)
		reason = "max discard sectors smaller than a block";

	else if (data_limits->discard_granularity > block_size)
		reason = "discard granularity larger than a block";

	else if (!is_factor(block_size, data_limits->discard_granularity))
		reason = "discard granularity not a factor of block size";

	if (reason) {
		DMWARN("Data device (%s) %s: Disabling discard passdown.", bdevname(data_bdev, buf), reason);
		return false;
	}

	return true;
}

void tier_passdown_check(struct pool_features_tier_private *tf, struct pool_tier_private *pool_tier_data)
{
	unsigned int i;

	for (i = 0; i < tf->tier_num; i++) {
		if (!(tf->enable_map & (0x1 << i)))
			continue;

		if(passdown_checking(pool_tier_data, tf->tier_dev[i]->bdev))
			pool_tier_data->discard_passdown |= (0x1 << i);
	}
}

int display_map(void *context, uint64_t *keys, void *leaf)
{
	uint32_t tierid;
	__le64 value = *(__le64*)leaf;
	dm_block_t block;

	unpack_tier_block(le64_to_cpu(value), &tierid, &block, NULL);
	DMINFO("%s: LBA[%llu] in PBA[%d-%llu]", __func__, *keys, tierid, block);	
	return 0;	
}


int generator_map(void *context, uint64_t *keys, void *leaf)
{
	struct dm_pool_metadata **pmd = context;
	struct pool_tier_private *pool_tier_data = container_of(pmd, struct pool_tier_private, pmd);
	uint32_t tierid;
	__le64 value = *(__le64*)leaf;
	dm_block_t block;

	unpack_tier_block(le64_to_cpu(value), &tierid, &block, NULL);
	bitmap_set( (*pmd)->bitmap, (int)*keys, 1);
	store_logic_block_tierid_nolock(pool_tier_data, (dm_block_t)*keys, tierid);
	DMDEBUG("%s:%d, LBA[%llu] in PBA[%d-%llu]", __func__, __LINE__, *keys, tierid, block);	
	return 0;	
}

void update_migration_stats(struct pool_tier_private *pool_tier_data, dm_block_t b, struct bio *bio)
{
	if (bio_data_dir(bio) == READ) {
		atomic_inc(pool_tier_data->readcount+b);
	}
	else if (bio_data_dir(bio) == WRITE) {
		atomic_inc(pool_tier_data->writecount+b);
	}

	atomic_set(pool_tier_data->lastused+b, (int)get_seconds());

	if ( atomic_read(pool_tier_data->readcount+b) > MAX_STAT_COUNT) {
		atomic_sub(MAX_STAT_DECAY, pool_tier_data->readcount+b);
	}

	if ( atomic_read(pool_tier_data->writecount+b) > MAX_STAT_COUNT) {
		atomic_sub(MAX_STAT_DECAY, pool_tier_data->writecount+b);
	}

}

void clear_migration_stats(struct pool_tier_private *pool_tier_data, dm_block_t b)
{
	atomic_set(pool_tier_data->readcount+b, 0);
	atomic_set(pool_tier_data->writecount+b, 0);
}

void update_timestamp(struct pool_tier_private *pool_tier_data, dm_block_t b)
{
	atomic_set(pool_tier_data->lastused+b, (int)get_seconds());
}

static uint64_t transfor_stats_to_points(struct pool_tier_private *pool_tier_data, dm_block_t b)
{
	uint64_t hitcount;
	int lastused = atomic_read(pool_tier_data->lastused+b);
	int curseconds = (int)get_seconds();
	int cool_down = bparams_get(&pool_tier_data->bparams, COOL_DOWN);
	bool reach_cd = false;

	hitcount = atomic_read(pool_tier_data->readcount + b)+atomic_read(pool_tier_data->writecount + b);
	reach_cd = (cool_down && (curseconds - lastused > cool_down));

	return reach_cd ? 0 : hitcount;
}

void store_logic_block_tierid(struct pool_tier_private *pool_tier_data, dm_block_t block, uint32_t tierid)
{
	dm_block_t byteNum = block;
	uint64_t offset = sector_div(byteNum, BLKS_PER_BYTE);
	uint8_t mask = (1 << PER_BLK_WIDTH) - 1;
	unsigned long flags;

	mask = ~(mask << (offset*PER_BLK_WIDTH));
	write_lock_irqsave(&pool_tier_data->migr_tiermap_rwlock, flags);
	pool_tier_data->tier_map[byteNum] &=mask;
	pool_tier_data->tier_map[byteNum] |= (tierid<< (offset*PER_BLK_WIDTH));
	write_unlock_irqrestore(&pool_tier_data->migr_tiermap_rwlock, flags);
}

void store_logic_block_tierid_nolock(struct pool_tier_private *pool_tier_data, dm_block_t block, uint32_t tierid)
{
	dm_block_t byteNum = block;
	uint64_t offset = sector_div(byteNum, BLKS_PER_BYTE);
	uint8_t mask = (1 << PER_BLK_WIDTH) - 1;

	if( !pool_tier_data->tier_map ) {
		DMINFO("%s: pool->tier_map is NULL", __func__);
		return;
	}

	mask = ~(mask << (offset*PER_BLK_WIDTH));
	pool_tier_data->tier_map[byteNum] &=mask;
	pool_tier_data->tier_map[byteNum] |= (tierid<< (offset*PER_BLK_WIDTH));
}

uint8_t get_logic_block_tierid(struct pool_tier_private *pool_tier_data, dm_block_t block)
{
	dm_block_t byteNum = block;
	uint64_t offset = sector_div(byteNum, BLKS_PER_BYTE);
	uint8_t mask = (1 << PER_BLK_WIDTH) - 1;
	uint8_t tierid;
	unsigned long flags;

	mask = (mask << (offset*PER_BLK_WIDTH));
	read_lock_irqsave(&pool_tier_data->migr_tiermap_rwlock, flags);
	tierid = (pool_tier_data->tier_map[byteNum] & mask);
	read_unlock_irqrestore(&pool_tier_data->migr_tiermap_rwlock, flags);


	return  (tierid >> (offset*PER_BLK_WIDTH));
}

int process_display_mapping_msg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	if (!pool_migrateable(pool_tier_data)) {
		return -EINVAL;
	}

	if (work_busy(&pool_tier_data->issue_worker.work))
		return -EBUSY;

	DMINFO("%s:%d, Start of display tiering mapping !!", __func__, __LINE__);
	r = tier_bitmap_display(&pool_tier_data->pmd);
	if (r)
		DMINFO("display tiering mapping failed");

	DMINFO("%s:%d, End of display tiering mapping !!", __func__, __LINE__);
	return r;
}

static int tiering_analysis(void *data);
int process_tiering_analysis_msg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	if (!pool_migrateable(pool_tier_data)) {
		DMINFO("%s:%d, pool do not support display migration profile !!", __func__, __LINE__);
		return -EINVAL;
	}

	if (work_busy(&pool_tier_data->issue_worker.work))
		return -EBUSY;	

	r = tiering_analysis(pool_tier_data);

	return r;
}

int display_tiering_hitcount(struct pool_tier_private *pool_tier_data)
{
	unsigned long size = tier_get_bitmap_size(pool_tier_data->pmd);
	unsigned int index = 0;
	unsigned long *bitmap = NULL;
	struct list_head hitcounts;
	struct hitcount_info *hitcountInfo, *tmp2;
	int cnt = 0;

	if (!pool_migrateable(pool_tier_data)) {
		return -EINVAL;
	}

	if (work_busy(&pool_tier_data->issue_worker.work))
		return -EBUSY;

	DMINFO("%s:%d, Start of display tiering hitcount !!", __func__, __LINE__);
	INIT_LIST_HEAD(&hitcounts);

	if( tier_bitmap_copy(pool_tier_data->pmd, &bitmap)){
		DMINFO("%s: copy bitmap fail", __func__);
		return -ENOMEM;
	}

	while (index<size) {
		int readcount = 0, writecount = 0;
		struct hitcount_info *tmp;
		index = find_next_bit(bitmap, size, index);

		if(index >= size)
			break;

		tmp = kzalloc(sizeof(struct hitcount_info), GFP_KERNEL);
		if(!tmp){
			DMINFO("%s:%d, allocate hitcount_info fail for LBA[%d]", __func__, __LINE__, index);
			return -ENOMEM;
		}		

		readcount = atomic_read(pool_tier_data->readcount+index);
		writecount = atomic_read(pool_tier_data->writecount+index);

		tmp->index = index;
		tmp->readcount = readcount;
		tmp->writecount = writecount;
		INIT_LIST_HEAD(&tmp->list);
		list_add_tail(&tmp->list, &hitcounts);

		index += 1;
	}

	list_for_each_entry_safe(hitcountInfo, tmp2, &hitcounts, list){
		DMINFO("%s:%d, %d %d %d %d ", __func__, __LINE__,
			hitcountInfo->index, hitcountInfo->readcount, hitcountInfo->writecount, hitcountInfo->readcount+hitcountInfo->writecount);
		cnt++;
		if( (cnt % 400) == 0 )
			msleep(1000);

		kfree(hitcountInfo);
	}

	if(bitmap)
		vfree(bitmap);

	DMINFO("%s:%d, End of display tiering hitcount !!", __func__, __LINE__);
	return 0;
}

int process_display_tiering_hitcount(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = display_tiering_hitcount(pool_tier_data);
	if (r)
		DMINFO("display  tiering hitcount failed");

	return r;
}

void update_migr_stats_mem(void **ptr_addr, void **new_addr, uint64_t size)
{
	if (size > 0) {
		memcpy(*new_addr, *ptr_addr, size);
		vfree(*ptr_addr);
	}
	*ptr_addr = *new_addr;
}

int maybe_resize_migr_stats(struct pool_tier_private *pool_tier_data, dm_block_t block_num)
{
	atomic_t *new_readcount, *new_writecount, *new_lastused, *new_move_up, *new_move_within, *new_move_down;
	uint8_t *new_tier_map;
	uint64_t *new_total_reads, *new_total_writes, *new_average_reads, *new_average_writes;
	int r = 0, current_time;
	dm_block_t i, old_migr_stats_size = pool_tier_data->migr_stats_size;
	unsigned int old_tier_num = pool_tier_data->tier_num;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	if( old_migr_stats_size == block_num){
		return 0;
	}
	pool_tier_data->migr_stats_size = block_num;

	/*---- new readcount ----*/
	new_readcount = vzalloc(block_num * sizeof(atomic_t));
	if (!new_readcount) {
		r = -ENOMEM;
		DMINFO("%s: allocate migration readcount failed", __func__);
		return r;
	}
	update_migr_stats_mem( (void**)&pool_tier_data->readcount, (void**)&new_readcount, old_migr_stats_size*sizeof(atomic_t));

	/*---- new writecount ----*/
	new_writecount = vzalloc(block_num * sizeof(atomic_t));
	if (!new_writecount) {
		r = -ENOMEM;
		DMINFO("%s: allocate migration writecount failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->writecount, (void**)&new_writecount, old_migr_stats_size*sizeof(atomic_t));

	/*---- new lastused ----*/
	new_lastused = vzalloc(block_num * sizeof(atomic_t));
	if (!new_lastused) {
		r = -ENOMEM;
		DMINFO("%s: allocate migration lastused failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->lastused, (void**)&new_lastused, old_migr_stats_size*sizeof(atomic_t));

	current_time = (int)get_seconds();
	for (i = old_migr_stats_size; i < block_num; i++) {
		atomic_set(pool_tier_data->lastused+i, current_time);
	}

	/*---- new tier_map ----*/
	new_tier_map = vzalloc( DIV_ROUND_UP_ULL(block_num, BLKS_PER_BYTE) * sizeof(uint8_t));
	if (!new_tier_map) {
		r = -ENOMEM;
		DMINFO("%s: allocate migration tier_map failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->tier_map, (void**)&new_tier_map, DIV_ROUND_UP_ULL(old_migr_stats_size, BLKS_PER_BYTE));	

	if( old_tier_num == tf.tier_num){
		return 0;
	}
	pool_tier_data->tier_num = tf.tier_num;

	/*---- new total read ----*/
	new_total_reads = vzalloc(tf.tier_num * sizeof(uint64_t));
	if (!new_total_reads) {
		r = -ENOMEM;
		DMINFO("%s: allocate total reads failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->total_reads, (void**)&new_total_reads, old_tier_num*sizeof(uint64_t));

	/*---- new total write ----*/
	new_total_writes = vzalloc(tf.tier_num * sizeof(uint64_t));
	if (!new_total_writes) {
		r = -ENOMEM;
		DMINFO("%s: allocate total writes failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->total_writes, (void**)&new_total_writes, old_tier_num*sizeof(uint64_t));

	/*---- new average reads ----*/
	new_average_reads = vzalloc(tf.tier_num * sizeof(uint64_t));
	if (!new_average_reads) {
		r = -ENOMEM;
		DMINFO("%s: allocate average reads failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->average_reads, (void**)&new_average_reads, old_tier_num*sizeof(uint64_t));

	/*---- new average writes ----*/
	new_average_writes = vzalloc(tf.tier_num * sizeof(uint64_t));
	if (!new_average_writes) {
		r = -ENOMEM;
		DMINFO("%s: allocate average writes failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->average_writes, (void**)&new_average_writes, old_tier_num*sizeof(uint64_t));

	/*---- new move up ----*/
	new_move_up = vzalloc(tf.tier_num * sizeof(atomic_t));
	if (!new_move_up) {
		r = -ENOMEM;
		DMINFO("%s: allocate move up failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->move_up, (void**)&new_move_up, old_tier_num*sizeof(atomic_t));

	/*---- new move within ----*/
	new_move_within = vzalloc(tf.tier_num * sizeof(atomic_t));
	if (!new_move_within) {
		r = -ENOMEM;
		DMINFO("%s: allocate move within failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->move_within, (void**)&new_move_within, old_tier_num*sizeof(atomic_t));	

	/*---- new move down ----*/
	new_move_down = vzalloc(tf.tier_num * sizeof(atomic_t));
	if (!new_move_down) {
		r = -ENOMEM;
		DMINFO("%s: allocate move down failed", __func__);
		return r;
	}
	update_migr_stats_mem((void**)&pool_tier_data->move_down, (void**)&new_move_down, old_tier_num*sizeof(atomic_t));

	init_move_data(pool_tier_data);

	return 0;
}

int process_auto_tiering_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = create_auto_tiering_thread(pool_tier_data);
	if (r)
		DMINFO("create auto tiering thread failed");

	return r;
}

bool pool_migrateable(struct pool_tier_private *pool_tier_data)
{
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	if (!tf.enable_tier) {
		DMDEBUG("%s:%d, Non-tiering pool do not support Tiering function !!", __func__, __LINE__);
		return false;
	}

	if (atomic_read(&pool_tier_data->swap_not_ready)) {
		DMDEBUG("%s:%d, Swap space is not ready for Tiering function !!", __func__, __LINE__);
		return false;
	}

	if (tf.bypass) {
		DMDEBUG("%s:%d, pool bypass tiering not support Tiering function !!", __func__, __LINE__);
		return false;
	}	

	return true;
}

int create_auto_tiering_thread(struct pool_tier_private *pool_tier_data)
{
	if (!pool_migrateable(pool_tier_data))
		return -EINVAL;	

	if (!work_busy(&pool_tier_data->issue_worker.work)) {
		atomic_set(&pool_tier_data->issue_worker.cancel, 0);
		WARN_ON(!queue_work(pool_tier_data->issue_wq, &pool_tier_data->issue_worker.work));
		return 0;
	}

	return -EBUSY;
}

int create_tier_migration_data(struct pool_tier_private *pool_tier_data)
{
	unsigned long size = tier_get_bitmap_size(pool_tier_data->pmd);
	unsigned int index = 0;
	int i;
	dm_block_t temp;
	struct migration_data *migr_data = pool_tier_data->migr_data;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	int r = -EINVAL;

	r = tier_bitmap_copy(pool_tier_data->pmd, &migr_data->bitmap);
	if (r) {
		DMINFO("%s: copy bitmap fail", __func__);
		return r;
	}

	migr_data->bitmap_issued = vzalloc(BITS_TO_LONGS(tier_get_bitmap_size(pool_tier_data->pmd)) * sizeof(unsigned long));
	if (!migr_data->bitmap_issued) {
		DMINFO("%s:%d, allocate bitmap_issued fail!!", __func__, __LINE__);
		return -ENOMEM;
	}

	migr_data->bitmap_migr_down = kzalloc(tf.tier_num * sizeof(unsigned long*), GFP_KERNEL);
	if (!migr_data->bitmap_migr_down) {
		DMINFO("%s:%d, allocate bitmap_migr_down fail!!", __func__, __LINE__);
		return -ENOMEM;
	}

	migr_data->bitmap_migr_up = kzalloc(tf.tier_num * sizeof(unsigned long*), GFP_KERNEL);
	if (!migr_data->bitmap_migr_up) {
		DMINFO("%s:%d, allocate bitmap_migr_up fail!!", __func__, __LINE__);
		return -ENOMEM;
	}

	for (i = 0; i < tf.tier_num; i++) {

		pool_tier_data->total_reads[i] = 0;
		pool_tier_data->total_writes[i] = 0;
		pool_tier_data->average_reads[i] = 0;
		pool_tier_data->average_writes[i] = 0;

		migr_data->bitmap_migr_down[i] = vzalloc(BITS_TO_LONGS(tier_get_bitmap_size(pool_tier_data->pmd)) * sizeof(unsigned long));
		if( !migr_data->bitmap_migr_down[i] ){
			DMINFO("%s: allocate bitmap_migr_down for tier(%d) fail!!", __func__, i);
			return -ENOMEM;
		}

		migr_data->bitmap_migr_up[i] = vzalloc(BITS_TO_LONGS(tier_get_bitmap_size(pool_tier_data->pmd)) * sizeof(unsigned long));
		if( !migr_data->bitmap_migr_up[i] ){
			DMINFO("%s: allocate bitmap_migr_up for tier(%d) fail!!", __func__, i);
			return -ENOMEM;
		}
	}


	while (index < size) {
		uint8_t tierid;
		index = find_next_bit(migr_data->bitmap, size, index);
		if(index >= size)
			break;

		tierid = get_logic_block_tierid(pool_tier_data, (dm_block_t)index);

		pool_tier_data->total_reads[tierid] += atomic_read(pool_tier_data->readcount+index);
		pool_tier_data->total_writes[tierid] += atomic_read(pool_tier_data->writecount+index);
		index += 1;
	}

	for (i = 0; i < tf.tier_num; i++) {
		int r;

		if (!(pool_tier_data->pool_features_tier_data.enable_map & (0x1 << i)))
			continue;

		r = dm_pool_get_tier_data_dev_size(pool_tier_data->pmd, i, &temp);
		if (r) {
			DMERR("failed to retrieve data device size for tier(%d)",  i);
			return r;
		}

		pool_tier_data->average_reads[i] = pool_tier_data->total_reads[i];
		sector_div(pool_tier_data->average_reads[i], temp);

		pool_tier_data->average_writes[i] =  pool_tier_data->total_writes[i];
		sector_div(pool_tier_data->average_writes[i], temp);

	}

	return 0;
}

unsigned int get_bit_num(unsigned int enable_map)
{
	int get_bit_num = 1;

	if (!enable_map)
		return 0;

	while (enable_map & (enable_map - 1)) {
		get_bit_num++;
		enable_map = (enable_map & (enable_map-1));
	}

	return get_bit_num;
}

void set_bypass_tierid(struct pool_tier_private *pool_tier_data)
{
	unsigned int i = 0;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	for (i = 0; i < tf.tier_num; i++) {
		if (tf.enable_map & ( 0x1<< i )) {
			pool_tier_data->bypass_tierid = (int)i;
			return;
		}
	}

	if (i >= tf.tier_num)
		DMINFO("%s:%d, Error !!  fail to get bypass tierid !!", __func__, __LINE__);
}

bool ifneed_build_tier_mapping(struct pool_tier_private *pool_tier_data, unsigned int *build_tierid)
{
	unsigned int old_act_tier_num, add_act_tier_num, old_enable_map, new_enable_map, map;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	unsigned int i = 0;

	old_enable_map = pool_tier_data->enable_map;
	new_enable_map = tf.enable_map;

	map = (old_enable_map ^ new_enable_map);
	add_act_tier_num = get_bit_num(map);
	old_act_tier_num = get_bit_num(old_enable_map);

	if (add_act_tier_num == 0) {
		return false;
	} else if (old_act_tier_num > 1) {
		return false;
	}

	for (i = 0; i < tf.tier_num; i++) {
		if (old_enable_map & ( 0x1<< i )) {
			*build_tierid = i;
			return true;
		}
	}

	DMINFO("%s:%d, Error !!  fail to get build_tierid !!", __func__, __LINE__);
	return false;
}

/* ---------------------------------------------------- profile result ----------------------------------------------------*/
static int init_profile_result(struct pool_tier_private *pool_tier_data, struct profile_result **profile_result)
{
	int r = 0;
	unsigned int i;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	int reserve_ratio = bparams_get(&pool_tier_data->bparams, RESERVE_RATIO);


	*profile_result = kzalloc(sizeof(struct profile_result) * tf.tier_num, GFP_KERNEL);
	if (!*profile_result) {
		DMINFO("%s:%d, create profile result fail !!", __func__, __LINE__);
		return -ENOMEM;
	}
		
	for (i = 0; i < tf.tier_num; i++) {
		dm_block_t swap_blks;
		dm_block_t free_blks;
		dm_block_t total_blks;

		if (!(tf.enable_map & (0x1 << i)))
			continue;

		(*profile_result)[i].down = 0;
		(*profile_result)[i].up = 0;

		r = dm_tier_get_swap_blkcnt(pool_tier_data->pmd, i, &swap_blks);
		if (r) {
			DMERR("failed to retrieve swap size");
			goto free_profile_result;
		}		

		r = dm_pool_get_tier_data_dev_free_size(pool_tier_data->pmd, i, &free_blks);
		if (r) {
			DMERR("failed to retrieve free size");
			goto free_profile_result;
		}

		r = dm_pool_get_tier_data_dev_size(pool_tier_data->pmd, i, &total_blks);
		if (r) {
			DMERR("failed to retrieve data device size");
			goto free_profile_result;
		}

		(*profile_result)[i].free_blks = (free_blks - swap_blks);
		(*profile_result)[i].total_blks = (total_blks - swap_blks);
		(*profile_result)[i].res_blks = (*profile_result)[i].total_blks*reserve_ratio/ONE_HUNDRED;
	}

	return r;

free_profile_result:
	kfree(*profile_result);
	return r;
}

static void destroy_profile_result(struct profile_result *profile_result)
{
	kfree(profile_result);
}

static int inc_profile_result(struct profile_result *profile_result, unsigned int tierid, int type)
{
	int r = 0;

	switch (type)
	{
		case PROFILE_DOWN:
			profile_result[tierid].down ++;
			break;
		case PROFILE_UP:
			profile_result[tierid].up ++;
			break;
		case PROFILE_FREE:
			profile_result[tierid].free_blks ++;
			break;			
		default:
			r = -EINVAL;
			DMINFO("%s:%d, increate profile result with unknow type(%d) !!", 
				__func__, __LINE__, type);
			break;
	}
	return r;
}

static int dec_profile_result(struct profile_result *profile_result, unsigned int tierid, int type)
{
	int r = 0;

	switch (type)
	{
		case PROFILE_DOWN:
			profile_result[tierid].down --;
			break;
		case PROFILE_UP:
			profile_result[tierid].up --;
			break;
		case PROFILE_FREE:
			profile_result[tierid].free_blks --;
			break;			
		default:
			r = -EINVAL;
			DMINFO("%s:%d, decreate profile result with unknow type(%d) !!", 
				__func__, __LINE__, type);
			break;
	}
	return r;
}

static bool reach_reserve(struct profile_result *profile_result, unsigned int tierid)
{
	dm_block_t total_blks = profile_result[tierid].total_blks;
	dm_block_t free_blks = profile_result[tierid].free_blks;
	dm_block_t res_blks = profile_result[tierid].res_blks;

	return (total_blks - free_blks) > res_blks ? false : true;
}

static void simulate_migr_down(struct profile_result *profile_result, unsigned int src_tier, unsigned int dst_tier)
{
	struct profile_result *profile_src = profile_result + src_tier;
	struct profile_result *profile_dst = profile_result + dst_tier;

	if (profile_src->down <= profile_dst->free_blks) {
		profile_dst->free_blks -= profile_src->down;
		profile_src->free_blks += profile_src->down;
		profile_src->down = 0;
	} else {
		profile_src->down -= profile_dst->free_blks;
		profile_src->free_blks += profile_dst->free_blks;
		profile_dst->free_blks = 0;

		/*---- Enter Swap Mode ----*/
		if (profile_src->down <= profile_dst->up) {
			profile_dst->up -= profile_src->down;
			profile_src->down = 0;			
		} else {
			profile_src->down -= profile_dst->up;
			profile_dst->up = 0;
		}
	}
}

static void simulate_migr_up(struct profile_result *profile_result, unsigned int src_tier, unsigned int dst_tier)
{
	struct profile_result *profile_src = profile_result + src_tier;
	struct profile_result *profile_dst = profile_result + dst_tier;

	if (profile_src->up <= profile_dst->free_blks) {
		profile_dst->free_blks -= profile_src->up;
		profile_src->free_blks += profile_src->up;
		profile_src->up = 0;
	} else {
		profile_src->up -= profile_dst->free_blks;
		profile_src->free_blks += profile_dst->free_blks;
		profile_dst->free_blks = 0;

		/*---- Enter Swap Mode ----*/
		if (profile_src->up <= profile_dst->down) {
			profile_dst->down -= profile_src->up;
			profile_src->up = 0;			
		} else {
			profile_src->up -= profile_dst->down;
			profile_dst->down = 0;
		}
	}
}

static void simulate_tiers_down(struct pool_tier_private *pool_tier_data, struct profile_result *profile_result)
{
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	int src_tier;

	for ( src_tier = (tf.tier_num - 2) ; src_tier >= 0 ; src_tier --) {
		int dst_tier;
		if (!(tf.enable_map & (0x1 << src_tier)))
			continue;

		for (dst_tier = (src_tier + 1); dst_tier < tf.tier_num; dst_tier ++) {
			if (tf.enable_map & (0x1 << dst_tier))
				break;
		}

		if (dst_tier >= (tf.tier_num)) {
			DMDEBUG("%s:%d, Corresponding tier for tier(%d) migrate down doesn't exist !!", __func__, __LINE__, tierid);
			continue;
		}
		simulate_migr_down(profile_result, (unsigned int)src_tier, (unsigned int)dst_tier);
	}
}

static void simulate_tiers_up(struct pool_tier_private *pool_tier_data, struct profile_result *profile_result)
{
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	int src_tier;

	for( src_tier = 1; src_tier < tf.tier_num; src_tier++) {
		int dst_tier;
		if (!(tf.enable_map & (0x1 << src_tier)))
			continue;

		for (dst_tier = (src_tier - 1); dst_tier >= 0; dst_tier --) {
			if(tf.enable_map & (0x1 << dst_tier))
				break;
		}

		if (dst_tier < 0) {
			DMDEBUG("%s:%d, Corresponding tier for tier(%d) migrate up doesn't exist !!", __func__, __LINE__, tierid);
			continue;
		}
		simulate_migr_up(profile_result, (unsigned int)src_tier, (unsigned int)dst_tier);
	}
}

static void simulate_profile(struct pool_tier_private *pool_tier_data, struct profile_result *profile_result)
{
	simulate_tiers_down(pool_tier_data, profile_result);
	simulate_tiers_up(pool_tier_data, profile_result);
}

static void dump_profile_result(struct pool_tier_private *pool_tier_data, struct profile_result *profile_result)
{
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	unsigned int i;

	DMINFO("%s:%d, ---- Dump Profile Result ----", __func__, __LINE__);
	for (i = 0; i < tf.tier_num; i++) {
		if (!(tf.enable_map & (0x1 << i)))
			continue;

		DMINFO("%s:%d, Tier[%d] down(%llu)", __func__, __LINE__, i, profile_result[i].down);
		DMINFO("%s:%d, Tier[%d] up(%llu)", __func__, __LINE__, i, profile_result[i].up);
		DMINFO("%s:%d, Tier[%d] free_blks(%llu)", __func__, __LINE__, i, profile_result[i].free_blks);
		DMINFO("%s:%d, Tier[%d] total_blks(%llu)", __func__, __LINE__, i, profile_result[i].total_blks);
		DMINFO("%s:%d, Tier[%d] res_blks(%llu)", __func__, __LINE__, i, profile_result[i].res_blks);
		DMINFO("%s:%d, ", __func__, __LINE__);
	}

}

static void clear_profile_result(struct pool_tier_private *pool_tier_data, struct profile_result *profile_result)
{
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	unsigned int i;

	for (i = 0; i < tf.tier_num; i++) {
		if (!(tf.enable_map & (0x1 << i)))
			continue;
		profile_result[i].down = 0;
		profile_result[i].up = 0;
	}

}

/* ----------------------------------------------------------------------------------------------------------------------------------------*/

/* ---------------------------------------------------- analysis data ----------------------------------------------------*/
#define INVALID_TIER_ID 4
#define UP 0
#define DOWN 1

static void reset_blk_analysis(struct per_blk_analysis *blk_analysis)
{
	blk_analysis->tierid = INVALID_TIER_ID;
	blk_analysis->points = 0;
}

static void reset_tier_analysis(struct per_tier_analysis *tier_analysis)
{
	tier_analysis->down = 0;
	tier_analysis->up = 0;
}

static void reset_analysis_data(struct data_analysis *data_analysis)
{
	unsigned long i;
	unsigned int tierid;

	data_analysis->blk_idx = 0;
	for (i = 0; i < MAX_TIER_LEVEL*ONE_HUNDRED; i++)
		reset_blk_analysis(&(data_analysis->blk_analysis[i]));

	for (tierid = 0; tierid < MAX_TIER_LEVEL; tierid++)
		reset_tier_analysis(&(data_analysis->tier_analysis[tierid]));

}

static int set_blk_analysis(struct data_analysis *data_analysis, unsigned int tierid, uint64_t points)
{
	unsigned long blk_idx = data_analysis->blk_idx;

	if (blk_idx >= MAX_TIER_LEVEL*ONE_HUNDRED)
		return -EINVAL;

	data_analysis->blk_analysis[blk_idx].tierid = tierid;
	data_analysis->blk_analysis[blk_idx].points = points;	
	data_analysis->blk_idx ++;	

	return 0;
}

static int set_tier_analysis(struct data_analysis *data_analysis, unsigned int tierid, int type, dm_block_t updown)
{
	dm_block_t *target;

	if (tierid >= MAX_TIER_LEVEL)
		return -EINVAL;

	switch (type) {
		case DOWN:
			target = &(data_analysis->tier_analysis[tierid].down);
			break;
		case UP:
			target = &(data_analysis->tier_analysis[tierid].up);
			break;
		default:
			return -EINVAL;		
	}

	*target = updown;
	return 0;
}

ssize_t  show_analysis_data(struct data_analysis *data_analysis, char *buf)
{
	unsigned long i;
	unsigned int tierid;
	struct per_blk_analysis *blk_analysis;
	struct per_tier_analysis *tier_analysis;

	sprintf(buf + strlen(buf), "Score Distribution\n");
	for (i = 0; i < data_analysis->blk_idx; i++) {
		blk_analysis = &(data_analysis->blk_analysis[i]);
		sprintf(buf + strlen(buf), "%d %llu\n", blk_analysis->tierid, blk_analysis->points);
	}

	sprintf(buf + strlen(buf), "Migrate Intention\n");
	for (tierid = 0; tierid < MAX_TIER_LEVEL; tierid++) {
		tier_analysis = &(data_analysis->tier_analysis[tierid]);
		sprintf(buf + strlen(buf), "%d D%llu U%llu\n", tierid, 
			tier_analysis->down, tier_analysis->up);
	}
	return strlen(buf);		
}
/* ----------------------------------------------------------------------------------------------------------------------------------------*/

/* ---------------------------------------------------- btier score ----------------------------------------------------*/
static int create_score_lists(struct score_list **score_lists, unsigned int tier_num)
{
	unsigned int i;

	*score_lists = kzalloc(sizeof(struct score_list) * tier_num, GFP_KERNEL);
	if (!*score_lists) {
		DMINFO("%s:%d, create score lists fail !!", __func__, __LINE__);
		return -ENOMEM;
	}

	for (i = 0; i < tier_num; i++)
		(*score_lists)[i].head = RB_ROOT;

	return 0;
}

static void destroy_score_lists(struct score_list *score_lists)
{
	kfree(score_lists);
}

static unsigned long get_score_list_sz(struct score_list *score_list)
{
	return score_list->elements;
}

static int create_scores(struct score **scores, unsigned long size)
{

	*scores = vzalloc(sizeof(struct score) * size);
	if (!*scores) {
		DMINFO("%s:%d, create scores !!", __func__, __LINE__);
		return -ENOMEM;
	}
	return 0;
}

static void destroy_scores(struct score *scores)
{
	vfree(scores);
}

static void set_score(struct score *score, uint64_t points, unsigned int tierid)
{
	score->points = points;
	score->tierid = tierid;
}

#define get_score(node) rb_entry((node), struct score, rb_node)
static void add_new_score(struct score_list *score_list, struct score *new_score)
{
	struct rb_node **rbp, *parent;
	struct score *score;

	rbp = &score_list->head.rb_node;
	parent = NULL;
	while (*rbp) {
		parent = *rbp;
		score = get_score(parent);

		if (new_score->points >= score->points)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&new_score->rb_node, parent, rbp);
	rb_insert_color(&new_score->rb_node, &score_list->head);
	score_list->elements ++;
}

static void extract_sorted_score_list(struct score_list *score_list, unsigned long unit, struct data_analysis *data_analysis)
{
	struct rb_node *node;
	struct score *score = NULL;
	unsigned long count = 0;
	int temp = 0;

	for (node = rb_first(&score_list->head); node; node = rb_next(node)) {
		count ++;
		score = get_score(node);

		if (!unit || (count % unit == 0 && temp < ONE_HUNDRED)) {
			if (set_blk_analysis(data_analysis, score->tierid, score->points))
				DMINFO("%s:%d, set block analysis Tierid(%d) points(%llu) fail !!", __func__, __LINE__,
					score->tierid, score->points);
			temp ++;
		}
		rb_erase(&score->rb_node, &score_list->head);
	}
	WARN_ON(!RB_EMPTY_ROOT(&score_list->head));
}
/* ----------------------------------------------------------------------------------------------------------------------------------------*/

static bool ifneed_migr_down_hitcount(void *data, dm_block_t block, uint8_t tierid)
{
	struct pool_tier_private *pool_tier_data = data;
	time_t curseconds = get_seconds();
	uint64_t hitcount=0;
	uint64_t avghitcount = 0;
	uint64_t hysteresis = 0;
	bool res = false;
	unsigned int active_tier_num = get_bit_num(pool_tier_data->pool_features_tier_data.enable_map);
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	int collect_time = bparams_get(&pool_tier_data->bparams, COLLECT_TIME);

	if (tierid >= (tf.tier_num - 1))
		return false;

	if (active_tier_num == 1)
		return false;

	hitcount = atomic_read(pool_tier_data->readcount + block)+atomic_read(pool_tier_data->writecount + block);
	avghitcount = pool_tier_data->average_reads[tierid] + pool_tier_data->average_writes[tierid];
	hysteresis = avghitcount;
	sector_div(hysteresis, active_tier_num);

	if (hitcount < avghitcount - hysteresis && (int)curseconds - atomic_read(pool_tier_data->lastused + block) > collect_time) 
		return true;

	return res;
}

static bool ifneed_migr_down_cd_SSD(void *data, dm_block_t block, uint8_t tierid)
{
	struct pool_tier_private *pool_tier_data = data;
	time_t curseconds = get_seconds();
	int cool_down = bparams_get(&pool_tier_data->bparams, COOL_DOWN);

	if ((tierid ==  SSD_TIER_ID) && cool_down && ((int)curseconds - atomic_read(pool_tier_data->lastused+block) > cool_down))
		return true;

	return false;
}

static bool ifneed_migr_down_cd(void *data, dm_block_t block, uint8_t tierid)
{
	struct pool_tier_private *pool_tier_data = data;
	time_t curseconds = get_seconds();
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	int cool_down = bparams_get(&pool_tier_data->bparams, COOL_DOWN);
	
	if (tierid >= (tf.tier_num - 1))
		return false;

	if (tierid == SSD_TIER_ID)
		return false;	

	if (cool_down && ((int)curseconds - atomic_read(pool_tier_data->lastused+block) > cool_down)) 
		return true;

	return false;
}


static bool ifneed_migrate_up(void *data, dm_block_t block, uint8_t tierid)
{
	struct pool_tier_private *pool_tier_data = data;
	uint64_t hitcount=0;
	uint64_t avghitcount = 0;
	uint64_t hysteresis = 0;
	uint64_t avghitcountprevtier = 0;
	bool res = false;
	int target_tierid;
	unsigned int active_tier_num = get_bit_num(pool_tier_data->pool_features_tier_data.enable_map);

	if (tierid <= 0)
		return false;

	if (active_tier_num == 1)
		return false;

	hitcount = atomic_read(pool_tier_data->readcount + block)+atomic_read(pool_tier_data->writecount + block);
	avghitcount = pool_tier_data->average_reads[tierid] + pool_tier_data->average_writes[tierid];
	hysteresis = avghitcount;
	sector_div(hysteresis, active_tier_num);

	if (hitcount > avghitcount + hysteresis) {
		for (target_tierid = (tierid - 1); target_tierid >= 0; target_tierid --) {
			if (pool_tier_data->pool_features_tier_data.enable_map & (0x1 << target_tierid))
				break;
		}

		if (target_tierid < 0) {
			return false;
		}

		avghitcountprevtier = pool_tier_data->average_reads[target_tierid]+pool_tier_data->average_writes[target_tierid];
		hysteresis = avghitcountprevtier;
		sector_div(hysteresis, active_tier_num);

		if (hitcount >  avghitcountprevtier - hysteresis) {
			return true;
		}
	}

	return res;

}

void degrade_hitcount(struct pool_tier_private *pool_tier_data, dm_block_t b)
 {
 	int readcount, writecount, degarde_ratio;

 	degarde_ratio = bparams_get(&pool_tier_data->bparams, DEGRADE_RATIO);
 	readcount = atomic_read(pool_tier_data->readcount+b);
 	writecount = atomic_read(pool_tier_data->writecount+b);

 	atomic_set(pool_tier_data->readcount+b, readcount*degarde_ratio/ONE_HUNDRED);
 	atomic_set(pool_tier_data->writecount+b, writecount*degarde_ratio/ONE_HUNDRED);
  }

static void set_migr_down(struct migration_data *migr_data, unsigned int tierid, 
	unsigned int index, struct profile_result *profile_result)
{
	bitmap_set(migr_data->bitmap_migr_down[tierid], index, 1);
	inc_profile_result(profile_result, tierid, PROFILE_DOWN);
}

static void set_migr_down_cd_SSD(struct migration_data *migr_data, unsigned int tierid, 
	unsigned int index, struct profile_result *profile_result)
{
	bitmap_set(migr_data->bitmap_migr_down[tierid], index, 1);
	inc_profile_result(profile_result, tierid, PROFILE_DOWN);
	inc_profile_result(profile_result, tierid, PROFILE_FREE);
}

static void set_migr_up(struct migration_data *migr_data, unsigned int tierid, 
	unsigned int index, struct profile_result *profile_result)
{
	bitmap_set(migr_data->bitmap_migr_up[tierid], index, 1);
	inc_profile_result(profile_result, tierid, PROFILE_UP);
}

static int store_sort_score(struct pool_tier_private *pool_tier_data, unsigned long size)
{
	unsigned int index = 0, i;
	int r = 0;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	struct score_list *score_lists = NULL;
	struct score *scores = NULL;
	struct migration_data *migr_data = pool_tier_data->migr_data;

	r = create_score_lists(&score_lists, tf.tier_num);
	if (r) {
		DMINFO("%s:%d, create score lists fail !!", __func__, __LINE__);
		return r;
	}

	r = create_scores(&scores, size);
	if (r) {
		DMINFO("%s:%d, create scores fail !!", __func__, __LINE__);
		goto free_score_lists;
	}


	while (index < size) {
		uint8_t tierid;
		uint64_t points;

		index = find_next_bit(migr_data->bitmap, size, index);
		if (index >= size)
			break;

		tierid = get_logic_block_tierid(pool_tier_data, (dm_block_t)index);
		points = transfor_stats_to_points(pool_tier_data, (dm_block_t)index);
		set_score(scores+index, points, (unsigned int)tierid);
		add_new_score(score_lists+tierid, scores+index);

		index += 1;
	}

	for (i = 0; i < tf.tier_num; i++) {
		unsigned long unit = 0;
		if (!(tf.enable_map & ( 0x1<< i )))
			continue;

		unit = get_score_list_sz(score_lists+i);
		sector_div(unit, ONE_HUNDRED);
		extract_sorted_score_list(score_lists+i, unit, &pool_tier_data->data_analysis);
	}

	destroy_scores(scores);
free_score_lists:
	destroy_score_lists(score_lists);
	return r;
}


static void profile_first_round(struct pool_tier_private *pool_tier_data, unsigned long size, struct profile_result *profile_result, bool degrade)
{
	unsigned int index = 0;
	struct migration_data *migr_data = pool_tier_data->migr_data;

	while (index < size) {
		uint8_t tierid;
		index = find_next_bit(migr_data->bitmap, size, index);
		if (index >= size)
			break;

		tierid = get_logic_block_tierid(pool_tier_data, (dm_block_t)index);

		if (ifneed_migr_down_hitcount(pool_tier_data, (dm_block_t)index, tierid))
			set_migr_down(migr_data, (unsigned int)tierid, index, profile_result);
		else if (ifneed_migrate_up(pool_tier_data, (dm_block_t)index, tierid))
		 	set_migr_up(migr_data, (unsigned int)tierid, index, profile_result);
		else if (ifneed_migr_down_cd(pool_tier_data, (dm_block_t)index, tierid))
			set_migr_down(migr_data, (unsigned int)tierid, index, profile_result);

		 if (degrade)
			degrade_hitcount(pool_tier_data, (dm_block_t)index);

		index += 1;
	}
}

static void profile_second_round(struct pool_tier_private *pool_tier_data, unsigned long size, 
	struct profile_result *profile_result, int *blkcnt)
{
	unsigned int index = 0;
	struct migration_data *migr_data = pool_tier_data->migr_data;
	unsigned long *bitmap_up;
	unsigned long *bitmap_down;	

	while (index < size) {
		uint8_t tierid;
		index = find_next_bit(migr_data->bitmap, size, index);
		if (index >= size)
			break;

		tierid = get_logic_block_tierid(pool_tier_data, (dm_block_t)index);
		bitmap_up = migr_data->bitmap_migr_up[tierid];
		bitmap_down = migr_data->bitmap_migr_down[tierid];

		if (test_bit(index, bitmap_up) || test_bit(index, bitmap_down)) {
			if (blkcnt)
				(*blkcnt) ++;
			goto inc_idx;
		}	

		if (!reach_reserve(profile_result, (unsigned int )tierid)) {
			if (ifneed_migr_down_cd_SSD(pool_tier_data, (dm_block_t)index, tierid)) {
				if (blkcnt)
					(*blkcnt) ++;
				set_migr_down_cd_SSD(migr_data, (unsigned int)tierid, index, profile_result);
				goto inc_idx;
			}
		}

		if (blkcnt)
			inc_tier_move_data(pool_tier_data, (unsigned int)tierid, MOVE_WITHIN);
inc_idx:		
		index += 1;
	}	
}

static int profile_migr_direction(struct pool_tier_private *pool_tier_data, unsigned long size, int *blkcnt, bool degrade)
{
	struct profile_result *profile_result;
	int r;

	r = init_profile_result(pool_tier_data, &profile_result);
	if (r)
		return r;

	profile_first_round(pool_tier_data, size, profile_result, degrade);
	simulate_profile(pool_tier_data, profile_result);
	clear_profile_result(pool_tier_data, profile_result);
	profile_second_round(pool_tier_data, size, profile_result, blkcnt);
	destroy_profile_result(profile_result);

	return r;
}

static dm_block_t get_bitmap_num(unsigned long *bitmap, unsigned long size)
{
	unsigned int index = 0;
	dm_block_t blk_cnt = 0;

	while (index < size) {
		index = find_next_bit(bitmap, size, index);
		if (index < size) {
			blk_cnt ++;
		}
		index += 1;
	}
	return blk_cnt;
}

static void store_migr_down(struct pool_tier_private *pool_tier_data, unsigned long size)
 {
 	unsigned int i;
 	struct migration_data *migr_data = pool_tier_data->migr_data;
	dm_block_t blk_cnt = 0;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

 	for (i = 0; i < tf.tier_num; i++) {
 		blk_cnt = get_bitmap_num(migr_data->bitmap_migr_down[i], size);
		if (set_tier_analysis(&pool_tier_data->data_analysis, i, DOWN, blk_cnt))
			DMINFO("%s:%d, set tier analysis tierid(%d) DOWN blk_cnt(%llu) fail !!", __func__, __LINE__,
				i, blk_cnt);
  	}

 }

 static void store_migr_up(struct pool_tier_private *pool_tier_data, unsigned long size)
 {
 	unsigned int i;
 	struct migration_data *migr_data = pool_tier_data->migr_data;
	dm_block_t blk_cnt = 0;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

 	for( i = 0; i < tf.tier_num; i++){
 		blk_cnt = get_bitmap_num(migr_data->bitmap_migr_up[i], size);
		if (set_tier_analysis(&pool_tier_data->data_analysis, i, UP, blk_cnt))
			DMINFO("%s:%d, set tier analysis tierid(%d) UP blk_cnt(%llu) fail !!", __func__, __LINE__,
				i, blk_cnt);			
 	}
 }

int migrate_block_to_tier(struct pool_tier_private *pool_tier_data, dm_block_t b, uint8_t old_tierid, uint8_t new_tierid)
{
	struct dm_tier_new_mapping *m;
	unsigned long flags;
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;
	dm_block_t new_block;
	int r;
	struct dm_tier_lookup_result result;
	int retry_chance = 1;


	if (atomic_read(&pool_tier_data->migration_count) < atomic_read(&pool_tier_data->migration_num))
		atomic_inc(&pool_tier_data->migration_count);
	else 
		return  -EBUSY;

	build_tier_key(pool_tier_data, b, &key);
	if (bio_detain(pool_tier_data, &key, NULL, &cell)) {
		atomic_dec(&pool_tier_data->migration_count);
		return -EBUSY;
	}

	r = dm_tier_find_block(pool_tier_data->pmd, b, 1, &result);
	if (r) {
		cell_defer_no_holder_tier(pool_tier_data, cell);
		atomic_dec(&pool_tier_data->migration_count);

		inc_tier_move_data(pool_tier_data, (unsigned int)old_tierid, MOVE_WITHIN);
		if (r == -ENODATA)
			DMDEBUG("%s:%d, LBA[%llu] mapping is already removed !!", __func__, __LINE__, b);
		else
			DMINFO("%s:%d, find LBA[%llu] mapping with unexpected return r(%d) !!", __func__, __LINE__, b, r);
		return r;
	}

	if (result.tierid != old_tierid) {
		cell_defer_no_holder_tier(pool_tier_data, cell);
		atomic_dec(&pool_tier_data->migration_count);

		inc_tier_move_data(pool_tier_data, (unsigned int)old_tierid, MOVE_WITHIN);
		DMDEBUG("%s:%d, LBA[%llu] origin at tier%d but re-allocated at PBA [%d-%llu] !!", __func__, __LINE__, 
			b, old_tierid, result.tierid, result.block);
		return -ENODATA;

	}

retry_alloc_remove:
	r = dm_tier_alloc_blk_and_remove_swap(pool_tier_data->pmd, &new_block, (unsigned int)old_tierid, (unsigned int)new_tierid);
	if (r == -EBUSY) {
		cell_defer_no_holder_tier(pool_tier_data, cell);
		atomic_dec(&pool_tier_data->migration_count);
		return r;
	} else if (r == -ENOSPC && retry_chance) {
		retry_chance = 0;
		dm_pool_commit_metadata(pool_tier_data->pmd);
		goto retry_alloc_remove;
	} else if (r == -ENOSPC && !retry_chance) {	
		return migrate_block_swap_mode(pool_tier_data, b, old_tierid, new_tierid, cell, &result);
	} else if (r) {
		cell_defer_no_holder_tier(pool_tier_data, cell);
		atomic_dec(&pool_tier_data->migration_count);
		inc_tier_move_data(pool_tier_data, (unsigned int)old_tierid, MOVE_WITHIN);
		return r;
	}

	spin_lock_irqsave(&pool_tier_data->migr_data_lock, flags);
	bitmap_set(pool_tier_data->migr_data->bitmap_issued, b, 1);
	spin_unlock_irqrestore(&pool_tier_data->migr_data_lock, flags);

	m = mempool_alloc(pool_tier_data->migrate_mapping_pool, GFP_ATOMIC);

	INIT_LIST_HEAD(&m->list);
	m->pool_tier_data = pool_tier_data;
	m->virt_block = b;
	m->type = TASK_MIGR_NORMAL;
	m->new_tierid = new_tierid;
	m->cell = cell;
	m->new_block = pack_tier_block(new_tierid, new_block, 0);
	m->old_block = pack_tier_block(result.tierid, result.block, result.reserve);


	if (!dm_deferred_set_add_work(pool_tier_data->tier_io_ds, &m->list))
		tier_defer_task(pool_tier_data, m);

	DMDEBUG("%s:%d, migrate LBA[%llu] from PBA[%d-%llu] to PBA[%d-%llu] !!!", __func__, __LINE__, 
		b, result.tierid, result.block, new_tierid, new_block);

	return 0;

}

static int tier_migrate(struct pool_tier_private *pool_tier_data, unsigned long *cur_bitmap, unsigned long size, uint8_t tierid, uint8_t new_tierid)
{
	unsigned int index = 0;
	int r;

	while(1) {
		index = find_next_bit(cur_bitmap, size, index);

		if (index >= size) {
			if (bitmap_empty(cur_bitmap, size)) {
				return 0;
			} else {				
				msleep(100);
				index = 0;
				continue;
			}

		}

		if (cancel_tiering(pool_tier_data)) {
			DMINFO("%s:%d, stop bitmap scan due to stop_auto_tiering msg !!", __func__, __LINE__);
			return 0;
		}

		if (gate_lock(&pool_tier_data->gate))
			gate_unlock(&pool_tier_data->gate);
		else { 
			gate_sleep(&pool_tier_data->gate);
		}
			

		r = migrate_block_to_tier(pool_tier_data, index, tierid, new_tierid);
		switch (r) {
		case -ENOSPC:
		case -EBUSY:
			index++;
			break;
		case 0:	
		case -ENODATA:	
		default:
			progress_update(&pool_tier_data->progress);
			bitmap_clear(cur_bitmap, index, 1);
		}

	}
	return 0;
}

static int tier_migrate_down(struct pool_tier_private *pool_tier_data, unsigned long *cur_bitmap, unsigned long size, uint8_t tierid)
{
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	int new_tierid;

	if (bitmap_empty(cur_bitmap, size)) {
		DMDEBUG("%s:%d, tierid(%d) migrate down bitmap is empty !!", __func__, __LINE__, tierid);
		return -EINVAL;
	}

	if(!pool_tier_data->pool_features_tier_data.enable_map & (0x1 << tierid)) {
		DMINFO("%s:%d, Non-ative tierid(%d) cannot be migrate!!", __func__, __LINE__, tierid);
		return -EINVAL;
	}

	if (tierid == tf.tier_num - 1) {
		DMINFO("%s:%d, lowest tier cannot be migrate down!!", __func__, __LINE__);
		return -EINVAL;
	}

	for (new_tierid = (tierid + 1); new_tierid < tf.tier_num; new_tierid ++) {
		if(pool_tier_data->pool_features_tier_data.enable_map & (0x1 << new_tierid))
			break;
	}

	if (new_tierid >= (tf.tier_num)) {
		DMDEBUG("%s:%d, Corresponding tier for tier(%d) migrate down doesn't exist !!", __func__, __LINE__, tierid);
		return -EINVAL;
	}

	return tier_migrate(pool_tier_data, cur_bitmap, size, tierid, new_tierid);
}

static int tier_migrate_up(struct pool_tier_private *pool_tier_data, unsigned long *cur_bitmap, unsigned long size, uint8_t tierid)
{
	int new_tierid;

	if (bitmap_empty(cur_bitmap, size)) {
		DMDEBUG("%s:%d, tierid(%d) migrate up bitmap is empty !!", __func__, __LINE__, tierid);
		return -EINVAL;
	}

	if(!pool_tier_data->pool_features_tier_data.enable_map & (0x1 << tierid)) {
		DMINFO("%s:%d, Non-avtive tierid(%d) cannot be migrate!!", __func__, __LINE__, tierid);
		return -EINVAL;
	}

	if (tierid == 0) {
		DMINFO("%s:%d, highest tier cannot be migrate up!!", __func__, __LINE__);
		return -EINVAL;
	}

	for (new_tierid = (tierid - 1); new_tierid >= 0; new_tierid --) {
		if(pool_tier_data->pool_features_tier_data.enable_map & (0x1 << new_tierid))
			break;
	}

	if (new_tierid < 0) {
		DMDEBUG("%s:%d, Corresponding tier for tier(%d) migrate up doesn't exist !!", __func__, __LINE__, tierid);
		return -EINVAL;
	}


	return tier_migrate(pool_tier_data, cur_bitmap, size, tierid, new_tierid);
}

void free_migration_data(struct pool_tier_private *pool_tier_data)
{
	int i;
	struct migration_data *migr_data = pool_tier_data->migr_data;
	unsigned long flags;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	if (migr_data->bitmap)
		vfree(migr_data->bitmap);

	if(migr_data->bitmap_migr_down) {
		for (i = 0; i < tf.tier_num; i++) {
			if( migr_data->bitmap_migr_down[i]) {
				vfree(migr_data->bitmap_migr_down[i]);
			}
		}
		kfree(migr_data->bitmap_migr_down);
	}

	if (migr_data->bitmap_migr_up) {
		for (i = 0; i < tf.tier_num; i++) {
			if (migr_data->bitmap_migr_up[i]) {
				vfree(migr_data->bitmap_migr_up[i]);
			}
		}
		kfree(migr_data->bitmap_migr_up);
	}

	if (migr_data->bitmap_issued)
		vfree(migr_data->bitmap_issued);

	spin_lock_irqsave(&pool_tier_data->migr_data_lock, flags);
	migr_data->bitmap = NULL;
	migr_data->bitmap_migr_down = NULL;
	migr_data->bitmap_migr_up = NULL;
	migr_data->bitmap_issued = NULL;
	spin_unlock_irqrestore(&pool_tier_data->migr_data_lock, flags);
}

static int data_migration(struct work_struct *ws)
{
	int r = 0, i, start_time, blkcnt = 0;
	struct issue_work *iw = container_of(ws, struct issue_work, work);
	struct pool_tier_private *pool_tier_data = container_of(iw, struct pool_tier_private, issue_worker);
	unsigned long size = tier_get_bitmap_size(pool_tier_data->pmd);
	struct migration_data *migr_data = pool_tier_data->migr_data;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	progress_reset(&pool_tier_data->progress);
	r = create_tier_migration_data(pool_tier_data) ;
	if (r) {
		DMINFO("%s: Update migration statics by tier fail", __func__);
		goto free_migr_data;
	}

	init_move_data(pool_tier_data);
	r = profile_migr_direction(pool_tier_data, size, &blkcnt, true);
	if (r) 
		goto free_migr_data;

	progress_start(&pool_tier_data->progress, blkcnt);
	set_freezable();
	
	start_time = (int)get_seconds();
	// migrate down from the second-last tier to the highest tier
	for ( i = (tf.tier_num - 2) ; i >= 0 ; i --) {
		DMDEBUG("%s:%d, ---- Migrate down  for tierid(%d) ----", __func__, __LINE__, i);
		if (tier_migrate_down(pool_tier_data, migr_data->bitmap_migr_down[i], size, (uint8_t)i))
			continue;

 		try_to_freeze();
 		wait_event_freezable(data_migr_task_wait, bitmap_empty(migr_data->bitmap_issued, size));

		dm_pool_commit_metadata(pool_tier_data->pmd);
	}

	// migrate up from the second tier to the lowest tier
	for( i = 1; i < tf.tier_num; i++) {
		DMDEBUG("%s:%d, ---- Migrate up  for tierid(%d) ----", __func__, __LINE__, i);
		if (tier_migrate_up(pool_tier_data, migr_data->bitmap_migr_up[i], size, (uint8_t)i))
			continue;

 		try_to_freeze();
 		wait_event_freezable(data_migr_task_wait, bitmap_empty(migr_data->bitmap_issued, size));

 		dm_pool_commit_metadata(pool_tier_data->pmd);
	}
	DMDEBUG("%s:%d, Tiering Migration took %d seconds !!", __func__, __LINE__, (int)get_seconds() - start_time);

	free_migration_data(pool_tier_data);
	return 0;

free_migr_data:
	free_migration_data(pool_tier_data);
	DMINFO("%s: data migration fail and return", __func__);
	return r;
}

static int tiering_analysis(void *data)
{
	int r = 0;
	struct pool_tier_private *pool_tier_data = data;
	unsigned long size = tier_get_bitmap_size(pool_tier_data->pmd);

	r = create_tier_migration_data(pool_tier_data) ;
	if (r) {
		DMINFO("%s: Update migration statics by tier fail", __func__);
		goto free_migr_data_profile;
	}

	reset_analysis_data(&pool_tier_data->data_analysis);

	r =  store_sort_score(pool_tier_data, size);
	if (r) {
		DMINFO("%s: Sort sorted scores fail", __func__);
		goto free_migr_data_profile;
	}	

	r = profile_migr_direction(pool_tier_data, size, NULL, false);
	if (r)
		goto free_migr_data_profile;

	store_migr_down(pool_tier_data, size);
	store_migr_up(pool_tier_data, size);

free_migr_data_profile:
	free_migration_data(pool_tier_data);
	return r;
}

void  process_tier_prepared_migration(struct pool_tier_private *pool_tier_data)
{
	unsigned long flags;
	struct list_head maps;
	struct dm_tier_new_mapping *m, *tmp;
	int is_prepared_migrates_empty = 0;

	INIT_LIST_HEAD(&maps);
	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	list_splice_init(&pool_tier_data->prepared_migrates, &maps);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	list_for_each_entry_safe(m, tmp, &maps, list) {
		struct dm_io_region from, to;
		int r;
		dm_block_t new_block, old_block;
		uint32_t new_tier, old_tier;

		unpack_tier_block(m->new_block, &new_tier, &new_block, NULL);
		unpack_tier_block(m->old_block, &old_tier, &old_block, NULL);

		from.bdev = pool_tier_data->pool_features_tier_data.tier_dev[old_tier]->bdev;
		from.sector = old_block * pool_tier_data->tier_sec_per_blk;
		from.count = pool_tier_data->tier_sec_per_blk;

		to.bdev = pool_tier_data->pool_features_tier_data.tier_dev[new_tier]->bdev;
		to.sector = new_block * pool_tier_data->tier_sec_per_blk;
		to.count = pool_tier_data->tier_sec_per_blk;

		r = dm_kcopyd_copy(pool_tier_data->migrator, &from, 1, &to, 0, migrate_complete, m);
		if (r < 0) {
			clear_notify_bitmap_issued(pool_tier_data, m->virt_block);
			cell_defer_no_holder_tier(pool_tier_data, m->cell);
			mempool_free(m, pool_tier_data->migrate_mapping_pool);
			DMINFO("dm_kcopyd_copy() for migration failed");

			atomic_dec(&pool_tier_data->migration_count);
		}
	}

	spin_lock_irqsave(&pool_tier_data->tier_lock, flags);
	is_prepared_migrates_empty = list_empty(&pool_tier_data->prepared_migrates);
	spin_unlock_irqrestore(&pool_tier_data->tier_lock, flags);

	if(!is_prepared_migrates_empty)
		wake_migration_worker(pool_tier_data);
}

void clear_notify_bitmap_issued(struct pool_tier_private *pool_tier_data, dm_block_t b)
{
	struct migration_data *migr_data = pool_tier_data->migr_data;
	unsigned long flags;
	unsigned long size = tier_get_bitmap_size(pool_tier_data->pmd);

	spin_lock_irqsave(&pool_tier_data->migr_data_lock, flags);

	bitmap_clear(migr_data->bitmap_issued, (int)b, 1);
	if (bitmap_empty(migr_data->bitmap_issued, size))
		wake_up_interruptible(&data_migr_task_wait);

	spin_unlock_irqrestore(&pool_tier_data->migr_data_lock, flags);
}

static void cell_error(struct pool_tier_private *pool_tier_data,
		       struct dm_bio_prison_cell *cell)
{
	dm_cell_error(pool_tier_data->tier_prison, cell, -EIO);
	dm_bio_prison_free_cell(pool_tier_data->tier_prison, cell);
}

void migrate_complete(int read_err, unsigned long write_err, void *context)
{
	int r;
	struct dm_tier_new_mapping *m = context;
	struct pool_tier_private *pool_tier_data = m->pool_tier_data;
	dm_block_t new_block, old_block;
	uint32_t new_tier, old_tier;
	uint32_t old_res;

	m->err = read_err || write_err ? -EIO : 0;

	unpack_tier_block(m->new_block, &new_tier, &new_block, NULL);
	unpack_tier_block(m->old_block, &old_tier, &old_block, &old_res);	

	if (m->err) {
		DMERR("%s: migrate block %llu is error-out", __func__, m->virt_block);
		cell_error(pool_tier_data, m->cell);
		goto out;
	}

	if (old_res)
		DMDEBUG("%s:%d, Migrate LBA[%llu] from PBA[%d-%llu] to PBA[%d-%llu] finished, with res(0x%x)", __func__, __LINE__,
			m->virt_block, old_tier, old_block, new_tier, new_block, old_res);
	else
		DMDEBUG("%s:%d, Migrate LBA[%llu] from PBA[%u-%llu] to PBA[%u-%llu] finished", __func__, __LINE__, 
			m->virt_block, old_tier, old_block, new_tier, new_block);

	store_logic_block_tierid(pool_tier_data, m->virt_block, new_tier);
	update_timestamp(pool_tier_data, m->virt_block);
	r = dm_tier_insert_block_free_swap(pool_tier_data->pmd, m->virt_block, new_block, new_tier, old_res, old_tier);
	if (r) {
		cell_error(pool_tier_data, m->cell);
		DMINFO("%s:%d, insert block mapping LBA[%llu] PBA[%u-%llu] fail !!", __func__, __LINE__, 
			m->virt_block, new_tier, new_block);
	} else 
		cell_defer_no_holder_tier(pool_tier_data, m->cell);
out:
	clear_notify_bitmap_issued(pool_tier_data, m->virt_block);
	mempool_free(m, pool_tier_data->migrate_mapping_pool);

	atomic_dec(&pool_tier_data->migration_count);
	inc_tier_move_data(pool_tier_data, (unsigned int)old_tier, new_tier < old_tier ? MOVE_UP : MOVE_DOWN);
}

int stop_auto_tiering_thread(struct pool_tier_private *pool_tier_data)
{
	if (!pool_migrateable(pool_tier_data))
		return -EINVAL;

	atomic_set(&pool_tier_data->issue_worker.cancel, 1);
	cancel_work_sync(&pool_tier_data->issue_worker.work);
	cancel_work_sync(&pool_tier_data->migrate_worker);
	return 0;
}

int process_stop_auto_tiering_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = stop_auto_tiering_thread(pool_tier_data);
	if (r)
		DMINFO("stop auto tiering thread failed");

	return r;
}

int find_block(struct pool_tier_private *pool_tier_data, unsigned long *target_map, dm_block_t *b, struct dm_tier_lookup_result *result, struct dm_bio_prison_cell **new_cell, uint8_t new_tierid)
{
	unsigned int index = 0;
	unsigned long size = tier_get_bitmap_size(pool_tier_data->pmd);
	int r, retry = 0;
	struct dm_cell_key new_key;

	while (1) {
		index = find_next_bit(target_map, size, index);

		if (index >= size) {
			if (retry) {
				index = 0;
				retry = 0;
			} else
				return -ENODATA;
		} else {
			build_tier_key(pool_tier_data, (dm_block_t)index, &new_key);
			if (bio_detain(pool_tier_data, &new_key, NULL, new_cell)){
				DMDEBUG("%s:%d, swap LBA[%llu] cell is occupied !!", __func__, __LINE__, (dm_block_t)index);
				retry = 1;
				index += 1;
				continue;
			}

			r = dm_tier_find_block(pool_tier_data->pmd, (dm_block_t)index, 1, result);
			if (!r) {
				if (new_tierid != result->tierid) {
					retry = 1;
					index += 1;
					progress_update(&pool_tier_data->progress);
					bitmap_clear(target_map, index, 1);
					cell_defer_no_holder_tier(pool_tier_data, *new_cell);
					continue;
				}
				*b = (dm_block_t)index;
				return 0;
			} else {
				progress_update(&pool_tier_data->progress);
				bitmap_clear(target_map, index, 1);
				cell_defer_no_holder_tier(pool_tier_data, *new_cell);
				retry = 1;
				index += 1;
			}
		}
	}
}

int migrate_block_swap_mode(struct pool_tier_private *pool_tier_data, dm_block_t old_blk, uint8_t old_tierid, uint8_t new_tierid, struct dm_bio_prison_cell *old_cell,
	struct dm_tier_lookup_result *old_result)
{
	dm_block_t new_blk, new_swap, old_swap;
	struct migration_data *migr_data = pool_tier_data->migr_data;
	struct dm_bio_prison_cell *new_cell;
	int r = 0, retry_chance_new = 1, retry_chance_old = 1;
	unsigned long flags;
	struct dm_tier_new_mapping *m_old, *m_new;
	unsigned long *target_map;
	struct dm_tier_lookup_result new_result;

	if (atomic_read(&pool_tier_data->migration_count) < atomic_read(&pool_tier_data->migration_num))
		atomic_inc(&pool_tier_data->migration_count);
	else { 
		r = -EBUSY;
		goto release_old_cell;
	}
	
	if (old_tierid < new_tierid) {
		target_map = migr_data->bitmap_migr_up[new_tierid];
	} else 
		target_map = migr_data->bitmap_migr_down[new_tierid];

	r = find_block(pool_tier_data, target_map, &new_blk, &new_result, &new_cell, new_tierid);
	if (r) {
		inc_tier_move_data(pool_tier_data, (unsigned int)old_tierid, MOVE_WITHIN);
		DMDEBUG("%s:%d, no corresponding block found!! ", __func__, __LINE__);
		goto dec_new_cnt;
	}

retry_new_swap:
	r = dm_tier_alloc_swap_block(pool_tier_data->pmd, new_tierid, &new_swap);
	if (r == -ENOSPC && retry_chance_new) {
		retry_chance_new = 0;
		dm_pool_commit_metadata(pool_tier_data->pmd);
		goto retry_new_swap;
	} else if (r) 
		goto release_new_cell;	
	

retry_old_swap:
	r = dm_tier_alloc_swap_block(pool_tier_data->pmd, old_tierid, &old_swap);
	if (r == -ENOSPC && retry_chance_old) {
		retry_chance_old = 0;
		dm_pool_commit_metadata(pool_tier_data->pmd);
		goto retry_old_swap;	
	} else if (r) 
		goto free_new_swap;

	progress_update(&pool_tier_data->progress);	
	bitmap_clear(target_map,  new_blk, 1);

	spin_lock_irqsave(&pool_tier_data->migr_data_lock, flags);
	bitmap_set(pool_tier_data->migr_data->bitmap_issued, old_blk, 1);
	bitmap_set(pool_tier_data->migr_data->bitmap_issued, new_blk, 1);
	spin_unlock_irqrestore(&pool_tier_data->migr_data_lock, flags);

	m_old = mempool_alloc(pool_tier_data->migrate_mapping_pool, GFP_ATOMIC);
	INIT_LIST_HEAD(&m_old->list);
	m_old->pool_tier_data = pool_tier_data;
	m_old->virt_block = old_blk;
	m_old->type = TASK_MIGR_SWAP;
	m_old->new_tierid = new_tierid;
	m_old->cell = old_cell;
	m_old->new_block = pack_tier_block(new_tierid, new_swap, 0);
	m_old->old_block = pack_tier_block(old_result->tierid, old_result->block, old_result->reserve);

	if (!dm_deferred_set_add_work(pool_tier_data->tier_io_ds, &m_old->list))
		tier_defer_task(pool_tier_data, m_old);

	DMDEBUG("%s:%d, (swap) migrate LBA[%llu] from PBA[%d-%llu] to PBA[%d-%llu] !!!", __func__, __LINE__, 
		old_blk, old_result->tierid, old_result->block, new_tierid, new_swap);

	m_new = mempool_alloc(pool_tier_data->migrate_mapping_pool, GFP_ATOMIC);
	INIT_LIST_HEAD(&m_new->list);
	m_new->pool_tier_data = pool_tier_data;
	m_new->virt_block = new_blk;
	m_new->type = TASK_MIGR_SWAP;
	m_new->new_tierid = old_tierid;
	m_new->cell = new_cell;
	m_new->new_block = pack_tier_block(old_tierid, old_swap, 0);
	m_new->old_block = pack_tier_block(new_result.tierid, new_result.block, new_result.reserve);

	if (!dm_deferred_set_add_work(pool_tier_data->tier_io_ds, &m_new->list))
		tier_defer_task(pool_tier_data, m_new);

	DMDEBUG("%s:%d, (swap) migrate LBA[%llu] from PBA[%d-%llu] to PBA[%d-%llu] !!!", __func__, __LINE__, 
		new_blk, new_result.tierid, new_result.block, old_tierid, old_swap);

	return 0;

free_new_swap:
	dm_tier_free_swap_block(pool_tier_data->pmd, new_tierid, new_swap);
release_new_cell:
	cell_defer_no_holder_tier(pool_tier_data, new_cell);
dec_new_cnt:	
	atomic_dec(&pool_tier_data->migration_count);
release_old_cell:
	cell_defer_no_holder_tier(pool_tier_data, old_cell);
	atomic_dec(&pool_tier_data->migration_count);
	return r;
}

static int get_swap_space_size(struct pool_tier_private *pool_tier_data, unsigned int tierid, dm_block_t *swap_cnt)
{
	int r = 0;
	dm_block_t temp;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	*swap_cnt = 0;
	if (tf.enable_map & ( 0x1<< tierid )) {
		r = dm_pool_get_tier_data_dev_size(pool_tier_data->pmd, tierid, &temp);
		if (r) {
			DMINFO("%s:%d, failed to retrieve data device size for tier(%d)",  __func__, __LINE__, tierid);
			return r;
		}

		(void) sector_div(temp, SWAP_BLK_RATIO);
		temp = (temp > 0 ? temp : 1);
		//FIXME, should we synchronzie swap space with MIGRATION_NUM_HIGH
		*swap_cnt = (temp < SWAP_BLK_DEFAULT ? temp : SWAP_BLK_DEFAULT);
	}

	return r;
}

int build_bypass_tier_mapping(struct pool_tier_private *pool_tier_data, unsigned int tierid)
{
	dm_block_t device_size, free_size, swap_cnt, i, data_blcknr;
	int r = 0;

	r = dm_pool_get_tier_data_dev_free_size(pool_tier_data->pmd, tierid, &free_size);
	if (r) {
		DMINFO("%s:%d, failed to retrieve data device free size for tier(%u)",  __func__, __LINE__, tierid);
		return r;
	}

	r = dm_pool_get_tier_data_dev_size(pool_tier_data->pmd, tierid, &device_size);
	if (r) {
		DMINFO("%s:%d, failed to retrieve data device size for tier(%u)",  __func__, __LINE__, tierid);
		return r;
	}

	if (free_size != device_size) {
		DMINFO("%s:%d, tierid(%u) space map error !! device_size(%llu)  free_size(%llu) !!", __func__, __LINE__, 
			tierid, device_size, free_size);
		return -EINVAL;
	}

	r = get_swap_space_size(pool_tier_data, tierid, &swap_cnt);
	if (r) {
		DMINFO("%s:%d, Fail to get swap space size for tierid(%u) !!", __func__, __LINE__, tierid);
		return r;
	}

	for (i = 0; i < (device_size - swap_cnt); i++) {
		r = dm_tier_alloc_tier_data_block(pool_tier_data->pmd, &data_blcknr, tierid);
		if (r) {
			DMINFO("%s:%d, allocate data block for tier %u fail!!", __func__, __LINE__, tierid);
			return r;
		}

		r = dm_tier_insert_block(pool_tier_data->pmd, i, data_blcknr, tierid);
		if(r) {
			DMINFO("%s:%d, insert  mapping LBA[%llu] PBA[%u-%llu] fail!!", __func__, __LINE__, i, tierid, data_blcknr);
			return r;
		}

		store_logic_block_tierid(pool_tier_data,  i, (uint32_t )tierid);
		tier_bitmap_set(pool_tier_data->pmd, (int)i);
	}
	return r;
}

int maybe_resize_swap_space(struct pool_tier_private *pool_tier_data)
{
	int r;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
	dm_block_t swap_cnt;
	unsigned int i;

	for (i = 0; i < tf.tier_num; i++) {
		if (!(tf.enable_map & ( 0x1<< i )) ){
			DMDEBUG("%s:%d, Do not resize swap space fot tier %d !!", __func__, __LINE__, i);
			continue;
		}

		r = get_swap_space_size(pool_tier_data, i, &swap_cnt);
		if (r) {
			DMINFO("%s:%d, get swap space size faill fot tier %d !!", __func__, __LINE__, i);
			return r;
		}

		r = dm_tier_set_swap_block(pool_tier_data->pmd, i, swap_cnt);
		if (r == -ENOSPC)
			atomic_or(1, &pool_tier_data->swap_not_ready);
		else if (r)
			return r;
	}
	return 0;
}

void init_move_data(struct pool_tier_private *pool_tier_data)
{
	unsigned int i;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	for (i = 0; i < tf.tier_num; i++){
		atomic_set(pool_tier_data->move_up+i, 0);
		atomic_set(pool_tier_data->move_within+i, 0);
		atomic_set(pool_tier_data->move_down+i, 0);
	}
}

int get_tier_move_data(struct pool_tier_private *pool_tier_data, unsigned int tierid, int move_data_type)
{
	atomic_t *move_data = NULL;;

	switch (move_data_type)
	{
		case MOVE_UP:
			move_data = pool_tier_data->move_up+tierid;
			break;
		case MOVE_WITHIN:
			move_data = pool_tier_data->move_within+tierid;
			break;
		case MOVE_DOWN:
			move_data = pool_tier_data->move_down+tierid;
			break;
	}

	return atomic_read(move_data);
}

void inc_tier_move_data(struct pool_tier_private *pool_tier_data, unsigned int tierid, int move_data_type)
{
	atomic_t *move_data = NULL;;

	switch (move_data_type)
	{
		case MOVE_UP:
			move_data = pool_tier_data->move_up+tierid;
			break;
		case MOVE_WITHIN:
			move_data = pool_tier_data->move_within+tierid;
			break;
		case MOVE_DOWN:
			move_data = pool_tier_data->move_down+tierid;
			break;
	}

	 atomic_inc(move_data);
}


void get_tier_dev_size_info(struct pool_tier_private *pool_tier_data, unsigned int tierid, dm_block_t *free_blks, dm_block_t *alloc_blks, dm_block_t *total_blks, dm_block_t *swap_blks)
{
	int r = 0;

	r = dm_tier_get_swap_blkcnt(pool_tier_data->pmd, tierid, swap_blks);
	if (r) {
		DMERR("failed to retrieve data device size");
		return ;
	}	

	r = dm_pool_get_tier_data_dev_free_size(pool_tier_data->pmd, tierid, free_blks);
	if (r) {
		DMERR("failed to retrieve data device size");
		return ;
	}

	r = dm_pool_get_tier_data_dev_size(pool_tier_data->pmd, tierid, total_blks);
	if (r) {
		DMERR("failed to retrieve data device size");
		return ;
	}

	*alloc_blks = (*total_blks - *free_blks);
	*total_blks -= *swap_blks;
	if (*free_blks > *swap_blks)
		*free_blks -= *swap_blks;
	else
		*free_blks = 0;
}

void get_migration_progress(struct pool_tier_private *pool_tier_data, int *total, int *processed)
{
	get_progress(&pool_tier_data->progress, total, processed);
}

char* get_relocation_rate(struct pool_tier_private *pool_tier_data)
{
	return get_gate_sleep(&pool_tier_data->gate);
}

void set_relocation_rate(struct pool_tier_private *pool_tier_data, char *relocation_rate)
{
	set_gate_sleep(&pool_tier_data->gate, relocation_rate);
}

char* get_swap_ready(struct pool_tier_private *pool_tier_data)
{
	int swap_not_ready = atomic_read(&pool_tier_data->swap_not_ready);

	if (swap_not_ready)
		return "Swap space: not ready\n";
	else
		return "Swap space: ready\n";	
}

char* get_tier_bypass(struct pool_tier_private *pool_tier_data)
{
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	if (tf.bypass)
		return "Tier bypass: yes\n";
	else
		return "Tier bypass: no\n";
}

int process_set_alloc_tier_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r;
	unsigned long alloc_tier;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = kstrtoul(argv[1], 10, &alloc_tier);
	if (r || alloc_tier < 0 || alloc_tier >= tf.tier_num){
		DMINFO("set allocation tier failed");
		return r;
	}

	if (!pool_migrateable(pool_tier_data))
		return -EINVAL;		

	r = dm_tier_set_alloc_tier(pool_tier_data->pmd, alloc_tier);
	if (r)
		DMINFO("set allocation tier failed");
	DMINFO("%s:%d, set allocate tier as %lu success !! ", __func__, __LINE__, alloc_tier);

	return r;
}

 int display_swap_space_info(struct pool_tier_private *pool_tier_data)
 {
 	int r = 0;
 	uint32_t i;
 	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;
 	dm_block_t free_blks, total_blks, swap_blocks;

 	for (i = 0; i < tf.tier_num; i++) {
 		if (!(tf.enable_map & (0x1 << i)))
 			continue;

		r = dm_tier_get_swap_blkcnt(pool_tier_data->pmd, i, &swap_blocks);
		if (r) {
			DMERR("failed to retrieve data device size");
			return r;
		}	

		r = dm_pool_get_tier_data_dev_free_size(pool_tier_data->pmd, i, &free_blks);
		if (r) {
			DMERR("failed to retrieve data device size");
			return r;
		}

		r = dm_pool_get_tier_data_dev_size(pool_tier_data->pmd, i, &total_blks);
		if (r) {
			DMERR("failed to retrieve data device size");
			return r;
		}	
		DMINFO("%s:%d, Tierid(%d) total_blks(%llu) free_blks(%llu) swap_blocks(%llu) !!", __func__, __LINE__,
			i, total_blks, free_blks, swap_blocks);
 	}
 	return r;
 }

int process_display_swap_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	if (!pool_migrateable(pool_tier_data))
		return -EINVAL;	

	r = display_swap_space_info(pool_tier_data);
	if (r)
		DMINFO("%s:%d, display swap space fail !!", __func__, __LINE__);
	return r;
}

int remove_swap_space(struct pool_tier_private *pool_tier_data, int tierid)
{
	int r;

	r = dm_tier_set_swap_block(pool_tier_data->pmd, (uint32_t)tierid, 0);
	return r;
}

int process_remove_swap_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r, tierid;
	struct pool_features_tier_private tf = pool_tier_data->pool_features_tier_data;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = kstrtoint(argv[1], 10, &tierid);
	if (r || tierid < 0 || tierid >= tf.tier_num){
		DMINFO("%s:%d, remove swap space fail !!", __func__, __LINE__);
		return r;
	}

	if (!pool_migrateable(pool_tier_data))
		return -EINVAL;		

	r = remove_swap_space(pool_tier_data, tierid);
	if (r)
		DMINFO("%s:%d, remove swap space fail !!", __func__, __LINE__);

	return r;
}

int process_set_btier_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data)
{
	int r, value;

	r = check_arg_count(argc, 3);
	if (r)
		return r;

	r = kstrtoint(argv[2], 10, &value);
	if (r || value < 0) {
		DMINFO("%s:%d, invalid set btier parameter !!", __func__, __LINE__);
		return  -EINVAL;
	}

	if (!pool_migrateable(pool_tier_data))
		return -EINVAL;		

	r = btier_params_set(pool_tier_data, argv[1], value);
	if (r)
		DMINFO("%s:%d, set btier parameter fail !!", __func__, __LINE__);

	return r;
}

static void dump_tier_feature(struct pool_features_tier_private *tf)
{
	unsigned int i;

	DMINFO("%s:%d, ---- Dump Tier feature ----",  __func__, __LINE__);
	DMINFO("%s:%d, enable_tier(%d) tier_num(%u) alloc_tier(%lu) !!", __func__, __LINE__, tf->enable_tier, tf->tier_num, tf->alloc_tier);
	for (i = 0; i < tf->tier_num; i++)
		DMINFO("%s:%d, tier_dev[%u] %s !!", __func__, __LINE__, i, tf->tier_dev[i]->name);
	DMINFO("%s:%d, tier_blk_size(%llu) enable_map(%u) bypass(%d) !!", __func__, __LINE__, tf->tier_blk_size, tf->enable_map, tf->bypass);
}

int bind_tier_target(struct pool_features_tier_private *adjusted_tf, struct pool_tier_private *pool_tier_data)
{
	struct pool_features_tier_private *tf = &(pool_tier_data->pool_features_tier_data);

	if (!pool_tier_data->tier_created && adjusted_tf->bypass != tf->bypass) {
		DMINFO("%s:%d, bypass cannot be change once decided !!", __func__, __LINE__);
		return -EINVAL;
	}

	memcpy(tf, adjusted_tf, sizeof(struct pool_features_tier_private));
	return 0;	
}


