/*
 * Copyright (C) 2001-2003 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "reverse"
#define SECTOR_SIZE 512
#define JOURNAL_BLOCK_SIZE 4096
#define NUM_OF_SECTOR ((int) (JOURNAL_BLOCK_SIZE) / (SECTOR_SIZE))

/*
 * reverse: maps a reverse range of a device.
 */
struct reverse_c {
	struct dm_dev *dev;
	sector_t start;
};

/*
 * Construct a reverse mapping: <dev_path> <offset>
 */
static int reverse_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct reverse_c *rc;
	unsigned long long tmp;
	char dummy;

	if (argc != 2) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	rc = kmalloc(sizeof(*rc), GFP_KERNEL);
	if (rc == NULL) {
		ti->error = "dm-reverse: Cannot allocate reverse context";
		return -ENOMEM;
	}

	if (sscanf(argv[1], "%llu%c", &tmp, &dummy) != 1) {
		ti->error = "dm-reverse: Invalid device sector";
		goto bad;
	}
	rc->start = tmp;

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &rc->dev)) {
		ti->error = "dm-reverse: Device lookup failed";
		goto bad;
	}

	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_write_same_bios = 1;
	ti->private = rc;
	return 0;

      bad:
	kfree(rc);
	return -EINVAL;
}

static void reverse_dtr(struct dm_target *ti)
{
	struct reverse_c *rc = (struct reverse_c *) ti->private;

	dm_put_device(ti, rc->dev);
	kfree(rc);
}

static sector_t reverse_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct reverse_c *rc = ti->private;
	sector_t position, offset;

	position = dm_target_offset(ti, bi_sector) / NUM_OF_SECTOR + 1;
	offset = dm_target_offset(ti, bi_sector) % NUM_OF_SECTOR;

	return rc->start + (ti->len - 1 - position * NUM_OF_SECTOR + offset);
}

static void reverse_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct reverse_c *rc = ti->private;

	bio->bi_bdev = rc->dev->bdev;
	if (bio_sectors(bio))
		bio->bi_sector = reverse_map_sector(ti, bio->bi_sector);
}

static int reverse_map(struct dm_target *ti, struct bio *bio)
{
	reverse_map_bio(ti, bio);

	return DM_MAPIO_REMAPPED;
}

static void reverse_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct reverse_c *rc = (struct reverse_c *) ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %llu", rc->dev->name,
				(unsigned long long)rc->start);
		break;
	}
}

static int reverse_ioctl(struct dm_target *ti, unsigned int cmd,
			unsigned long arg)
{
	struct reverse_c *rc = (struct reverse_c *) ti->private;
	struct dm_dev *dev = rc->dev;
	int r = 0;

	/*
	 * Only pass ioctls through if the device sizes match exactly.
	 */
	if (rc->start ||
	    ti->len != i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT)
		r = scsi_verify_blk_ioctl(NULL, cmd);

	return r ? : __blkdev_driver_ioctl(dev->bdev, dev->mode, cmd, arg);
}

static int reverse_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size)
{
	struct reverse_c *rc = ti->private;
	struct request_queue *q = bdev_get_queue(rc->dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = rc->dev->bdev;
	bvm->bi_sector = reverse_map_sector(ti, bvm->bi_sector);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int reverse_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct reverse_c *rc = ti->private;

	return fn(ti, rc->dev, rc->start, ti->len, data);
}

static struct target_type reverse_target = {
	.name   = "reverse",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr    = reverse_ctr,
	.dtr    = reverse_dtr,
	.map    = reverse_map,
	.status = reverse_status,
	.ioctl  = reverse_ioctl,
	.merge  = reverse_merge,
	.iterate_devices = reverse_iterate_devices,
};

int __init dm_reverse_init(void)
{
	int r = dm_register_target(&reverse_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

void dm_reverse_exit(void)
{
	dm_unregister_target(&reverse_target);
}
