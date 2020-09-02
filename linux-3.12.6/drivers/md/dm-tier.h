#ifndef DM_TIER_H
#define DM_TIER_H

#include <linux/device-mapper.h>
#include <linux/dm-kcopyd.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/bitmap.h>
#include <linux/freezer.h> 

#include "persistent-data/dm-block-manager.h"
#include "dm-bio-prison.h"

#define MAX_TIER_LEVEL 3
#define ONE_HUNDRED 100

/*---- Move data type ----*/
#define MOVE_UP 0
#define MOVE_WITHIN 1
#define MOVE_DOWN 2

/*---- Migration status ----*/
#define MIGR_THRD_ABSENCE 0
#define MIGR_THRD_ACTIVE 1
#define MIGR_THRD_SLEEP 2

/*---- Btier parameters defualt value ----*/
#define COOL_DOWN_DEFAULT 86400
//#define COLLECT_TIME_DEFAULT 43200
#define DEGRADE_RATIO_DEFAULT 50
#define COLLECT_TIME_DEFAULT 10
#define RESERVE_RATIO_DEFAULT 40

/*---- Btier parameters type ----*/
#define COOL_DOWN 0
#define DEGRADE_RATIO 1
#define COLLECT_TIME 2
#define RESERVE_RATIO 3

/*---- Profile result operation type ----*/
#define PROFILE_DOWN 0
#define PROFILE_UP 1
#define PROFILE_FREE 2


struct pool_features_tier_private{
	bool enable_tier:1;
	unsigned int tier_num;
	unsigned long alloc_tier;
	struct dm_dev **tier_dev;
	dm_block_t tier_blk_size;
	unsigned int enable_map;
	bool bypass;
};

struct migration_data
{
	unsigned long *bitmap;	
	unsigned long *bitmap_issued;
	unsigned long **bitmap_migr_down;
	unsigned long **bitmap_migr_up;
};

struct migration_gate {
	struct rw_semaphore lock;
    	bool applied;
    	int sleep;
};

struct profile_result {
	dm_block_t down;
    	dm_block_t up;
    	dm_block_t free_blks;
    	dm_block_t total_blks;
    	dm_block_t res_blks;
};

struct score {
	uint64_t points;
	struct rb_node rb_node;
	unsigned int tierid;
};

struct score_list {
	struct rb_root head;
	unsigned long elements;
};

struct per_blk_analysis
{
	unsigned int tierid;
	uint64_t points;
};

struct per_tier_analysis
{
	dm_block_t down;
	dm_block_t up;
};

struct data_analysis
{
	unsigned long blk_idx;
	struct per_blk_analysis blk_analysis[MAX_TIER_LEVEL*ONE_HUNDRED];
	struct per_tier_analysis tier_analysis[MAX_TIER_LEVEL];
};

struct issue_work {
    	atomic_t cancel;
	struct work_struct work;
};

struct progress_data {
	atomic_t processed;
	atomic_t total;
};

struct btier_params {
	atomic_t cool_down;
	atomic_t degrad_ratio;
	atomic_t collect_time;
	atomic_t reserve_ratio;
};

struct pool_tier_private {
	dm_block_t tier_sec_per_blk;
	int tier_sec_per_blk_shift;

	struct dm_kcopyd_client *migrator;
	struct workqueue_struct *migration_wq;
	struct work_struct migrate_worker;
	struct migration_gate gate;

	rwlock_t migr_tiermap_rwlock;
	spinlock_t migr_data_lock;

	struct bio_list block_pm_bios;

	struct list_head prepared_migrates;
	struct list_head tier_prepared_discards;	

	struct dm_deferred_set *tier_io_ds;

	mempool_t *migrate_mapping_pool;

	//only for check if tier num related migration statistics need to be expanded
	unsigned int tier_num;

	atomic_t migration_num;
	atomic_t migration_count;
	dm_block_t migr_stats_size;
	atomic_t *readcount;
	atomic_t *writecount;
	atomic_t *lastused;
	uint64_t *total_reads;
	uint64_t *total_writes;

	//record LBA tier id, 2 bits for each LBA
	uint8_t *tier_map;

	uint64_t *average_reads; 
	uint64_t *average_writes; 	
	atomic_t *move_up;
	atomic_t *move_within;
	atomic_t *move_down;
	struct migration_data *migr_data;

	struct dm_bio_prison *tier_prison;
	spinlock_t tier_lock;
	struct pool_features_tier_private pool_features_tier_data;

	struct workqueue_struct *tier_wq;
	struct work_struct tier_worker;
	struct delayed_work tier_waker;

	struct dm_pool_metadata *pmd;
	uint8_t discard_passdown;

	atomic_t stats_switch;
	atomic_t swap_not_ready;

	int tier_created;

	//record target tierid when TIER_BYPASS_ON, -1 is invalid
	int bypass_tierid;

	unsigned int enable_map;
	struct workqueue_struct *issue_wq;
	struct issue_work issue_worker;

	struct progress_data progress;
	struct btier_params bparams;
	struct data_analysis data_analysis;
};

struct dm_tier_new_mapping {
	struct list_head list;

	struct pool_tier_private *pool_tier_data;
	dm_block_t virt_block;
	dm_block_t old_block;
	dm_block_t new_block;
	struct dm_bio_prison_cell *cell;
	int err;
	int type; // 0:auto-tiering 1:discard 2:swap
	uint8_t new_tierid;
	struct bio *bio;
};

struct pool_c_tier_private{
	unsigned int tier_num;
	struct dm_dev **tier_data_dev;
};

struct dm_tier_endio_hook {
	struct pool_tier_private *pool_tier_data;
	struct dm_deferred_entry *tier_io_entry;
	struct dm_tier_new_mapping *tier_mapping;
};

struct hitcount_info
{
	int index;
	int readcount;
	int writecount;
	struct list_head list;
};

void init_pool_features_tier_data(struct pool_features_tier_private *pool_features_tier_data);
int parse_tier_features(struct dm_arg_set *as, unsigned *argc, char *arg_name, struct dm_target *ti, struct pool_features_tier_private *pool_features_tier_data);
int parse_tier_enableMap(struct dm_arg_set *as, unsigned *argc, char *arg_name, struct dm_target *ti, struct pool_features_tier_private *pool_features_tier_data);
void set_bypass_off(struct pool_features_tier_private *pool_features_tier_data);
int is_tier_enable(char *arg, struct pool_features_tier_private *pool_features_tier_data);
void set_tier_blk_tier_disable(unsigned long block_size, struct pool_features_tier_private *pool_features_tier_data);
struct pool_tier_private *create_pool_tier_data(struct pool_features_tier_private *pool_features_tier_data);
void init_migration_stats(struct pool_tier_private *pool_tier_data);
void destroy_pool_tier_data(struct pool_tier_private *pool_tier_data, int destroy_migrator);
void free_migration_stats(struct pool_tier_private *pool_tier_data);
void init_pool_c_tier_data(struct pool_c_tier_private *pool_c_tier_data, struct pool_features_tier_private *pool_features_tier_data);
void destroy_tier_devices(struct dm_target *ti, unsigned int tier_num, struct dm_dev **tier_data_dev);
void tier_hook_bio(struct pool_tier_private *pool_tier_data, struct bio *bio);
int tier_bio_bypass_map(struct pool_tier_private *pool_tier_data, struct bio *bio);
int tier_bio_map(struct pool_tier_private *pool_tier_data, struct bio *bio);
void tier_defer_bio(struct pool_tier_private *pool_tier_data, struct bio *bio);
void do_tier_worker(struct work_struct *ws);
void wake_tier_worker(struct pool_tier_private *pool_tier_data);
void do_tier_waker(struct work_struct *ws);
void do_migration_worker(struct work_struct *ws);
void wake_migration_worker(struct pool_tier_private *pool_tier_data);
bool tier_blk_size_is_power_of_two(struct pool_tier_private *pool_tier_data);
sector_t convert_tier_address(struct pool_tier_private *pool_tier_data, dm_block_t b);
void remap_to_tier(struct pool_tier_private *pool_tier_data, struct bio *bio, dm_block_t block, uint32_t tierid, int issue);
void get_remain_sector(struct pool_tier_private *pool_tier_data, struct bio *bio, dm_block_t block, uint32_t tierid);
dm_block_t tier_get_bio_blk(struct pool_tier_private *pool_tier_data, struct bio *bio);
void build_tier_key(struct pool_tier_private *pool_tier_data, dm_block_t b, struct dm_cell_key *key);
void inc_tier_io_entry(struct pool_tier_private *pool_tier_data , struct bio *bio);
void cell_defer_nhnf_tier(struct pool_tier_private *pool_tier_data, struct dm_bio_prison_cell *cell);
void cell_defer_no_holder_tier(struct pool_tier_private *pool_tier_data, struct dm_bio_prison_cell *cell);
void process_block_bios(struct pool_tier_private *pool_tier_data);
int pool_new_block(struct pool_tier_private *pool_tier_data, struct bio *bio, 
					struct dm_tier_lookup_result *result, struct dm_bio_prison_cell *cell);
void process_tier_discard(struct pool_tier_private *pool_tier_data, struct bio *bio, struct dm_bio_prison_cell *cell);
int tier_io_overlaps_blk(struct pool_tier_private *pool_tier_data, struct bio *bio);
void process_tier_prepared_discard(struct pool_tier_private *pool_tier_data);
int tier_endio(struct dm_target *ti, struct bio *bio, int err);
int calculate_tier_data_total_size(struct pool_tier_private *pool_tier_data, dm_block_t *size);
dm_block_t get_data_dev_size_in_blocks(struct block_device *bdev, sector_t data_block_size);
int maybe_resize_tier_data_dev(struct dm_target *ti, struct pool_tier_private *pool_tier_data,  struct pool_c_tier_private *pool_c_tier_data, bool *need_commit);
void tier_passdown_check(struct pool_features_tier_private *tf, struct pool_tier_private *pool_tier_data);

void update_migration_stats(struct pool_tier_private *pool_tier_data, dm_block_t b, struct bio *bio);
void clear_migration_stats(struct pool_tier_private *pool_tier_data, dm_block_t b);
void update_timestamp(struct pool_tier_private *pool_tier_data, dm_block_t b);
void store_logic_block_tierid(struct pool_tier_private *pool_tier_data, dm_block_t block, uint32_t tierid);
void store_logic_block_tierid_nolock(struct pool_tier_private *pool_tier_data, dm_block_t block, uint32_t tierid);
uint8_t get_logic_block_tierid(struct pool_tier_private *pool_tier_data, dm_block_t block);
int process_display_mapping_msg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);
int display_tiering_hitcount(struct pool_tier_private *pool_tier_data);
int process_display_tiering_hitcount(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);

void update_migr_stats_mem(void **ptr_addr, void **new_addr, uint64_t size);
int maybe_resize_migr_stats(struct pool_tier_private *pool_tier_data, dm_block_t block_num);
int maybe_resize_swap_space(struct pool_tier_private *pool_tier_data);

int process_auto_tiering_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);
bool pool_migrateable(struct pool_tier_private *pool_tier_data);
int create_auto_tiering_thread(struct pool_tier_private *pool_tier_data);
int create_tier_migration_data(struct pool_tier_private *pool_tier_data);
unsigned int get_bit_num(unsigned int enable_map);
void set_bypass_tierid(struct pool_tier_private *pool_tier_data);
bool ifneed_build_tier_mapping(struct pool_tier_private *pool_tier_data, unsigned int *build_tierid);
void degrade_hitcount(struct pool_tier_private *pool_tier_data, dm_block_t b);
int migrate_block_to_tier(struct pool_tier_private *pool_tier_data, dm_block_t b, uint8_t old_tierid, uint8_t new_tierid);
void free_migration_data(struct pool_tier_private *pool_tier_data);
void  process_tier_prepared_migration(struct pool_tier_private *pool_tier_data);
int process_tiering_analysis_msg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);
void clear_notify_bitmap_issued(struct pool_tier_private *pool_tier_data, dm_block_t b);
void migrate_complete(int read_err, unsigned long write_err, void *context);
int stop_auto_tiering_thread(struct pool_tier_private *pool_tier_data);
int process_stop_auto_tiering_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);

int display_swap_space_info(struct pool_tier_private *pool_tier_data);
int remove_swap_space(struct pool_tier_private *pool_tier_data, int tierid);
int find_block(struct pool_tier_private *pool_tier_data, unsigned long *target_map, dm_block_t *b, struct dm_tier_lookup_result *result, struct dm_bio_prison_cell **new_cell, uint8_t new_tierid);
int build_bypass_tier_mapping(struct pool_tier_private *pool_tier_data, unsigned int tierid);
int migrate_block_swap_mode(struct pool_tier_private *pool_tier_data, dm_block_t old_blk, uint8_t old_tierid, uint8_t new_tierid, struct dm_bio_prison_cell *old_cell, struct dm_tier_lookup_result *old_result);

void init_move_data(struct pool_tier_private *pool_tier_data);
int get_tier_move_data(struct pool_tier_private *pool_tier_data, unsigned int tierid, int move_data_type);
void inc_tier_move_data(struct pool_tier_private *pool_tier_data, unsigned int tierid, int move_data_type);
void get_tier_dev_size_info(struct pool_tier_private *pool_tier_data, unsigned int tierid, dm_block_t *free_blks, dm_block_t *alloc_blks, dm_block_t *total_blks, dm_block_t *swap_blks);
void get_migration_progress(struct pool_tier_private *pool_tier_data, int *total, int *processed);

char* get_relocation_rate(struct pool_tier_private *pool_tier_data);
void set_relocation_rate(struct pool_tier_private *pool_tier_data, char *relocation_rate);

char* get_swap_ready(struct pool_tier_private *pool_tier_data);
char* get_tier_bypass(struct pool_tier_private *pool_tier_data);

int create_migrate_mapping_cache(void);
void destroy_migrate_mapping_cache(void);

int process_set_alloc_tier_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);
int process_display_swap_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);
int process_remove_swap_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);
int process_set_btier_mesg(unsigned argc, char **argv, struct pool_tier_private *pool_tier_data);

int bind_tier_target(struct pool_features_tier_private *adjusted_tf, struct pool_tier_private *pool_tier_data);

int btier_params_get(struct pool_tier_private *pool_tier_data, int type);
int btier_params_set(struct pool_tier_private *pool_tier_data, char *type, int value);

ssize_t  show_analysis_data(struct data_analysis *data_analysis, char *buf);

#endif

