#include <linux/jbd2.h>

int jbd2_shared_journal_init(journal_t *journal) {

	struct j_fs_dev_s *j_fs_dev;
	j_fs_dev = kzalloc(sizeof(*j_fs_dev), GFP_KERNEL);
	if (!j_fs_dev)
		return -ENOMEM;

	INIT_LIST_HEAD(&journal->j_fs_dev_list);
	INIT_LIST_HEAD(&journal->j_sb_list);
	INIT_LIST_HEAD(&j_fs_dev->list);
	j_fs_dev->fs_dev = journal->j_fs_dev;
	list_add(&j_fs_dev->list, &journal->j_fs_dev_list);
	journal->j_nr_loaded = 1;
	return 0;
}

int jbd2_is_journal_device(journal_t *journal) {

	/* internal journal */
	if (journal->j_dev == journal->j_fs_dev)
		return 0;
	else
		return 1;
}

EXPORT_SYMBOL(jbd2_shared_journal_init);
EXPORT_SYMBOL(jbd2_is_journal_device);
