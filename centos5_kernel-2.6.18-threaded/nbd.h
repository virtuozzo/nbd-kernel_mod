/*
 * 1999 Copyright (C) Pavel Machek, pavel@ucw.cz. This code is GPL.
 * 1999/11/04 Copyright (C) 1999 VMware, Inc. (Regis "HPReg" Duchesne)
 *            Made nbd_end_request() use the io_request_lock
 * 2001 Copyright (C) Steven Whitehouse
 *            New nbd_end_request() for compatibility with new linux block
 *            layer code.
 * 2003/06/24 Louis D. Langholtz <ldl@aros.net>
 *            Removed unneeded blksize_bits field from nbd_device struct.
 *            Cleanup PARANOIA usage & code.
 * 2004/02/19 Paul Clements
 *            Removed PARANOIA, plus various cleanup and comments
 * 2012/04/09 Michail Flouris <michail.flouris@onapp.com>
 *            Added query hash ioctl command
 */

#ifndef LINUX_NBD_H
#define LINUX_NBD_H

#define NBD_SET_SOCK	_IO( 0xab, 0 )
#define NBD_SET_BLKSIZE	_IO( 0xab, 1 )
#define NBD_SET_SIZE	_IO( 0xab, 2 )
#define NBD_DO_IT	_IO( 0xab, 3 )
#define NBD_CLEAR_SOCK	_IO( 0xab, 4 )
#define NBD_CLEAR_QUE	_IO( 0xab, 5 )
#define NBD_PRINT_DEBUG	_IO( 0xab, 6 )
#define NBD_SET_SIZE_BLOCKS	_IO( 0xab, 7 )
#define NBD_DISCONNECT  _IO( 0xab, 8 )
#define NBD_SET_TIMEOUT _IO( 0xab, 9 )
#define NBD_SET_FLAGS _IO( 0xab, 10 )
#define NBD_QUERY_HASH	_IOWR( 0xab, 12, nbd_query_blkhash_t )


/* define to enable counters (mostly for debugging & tracing...) */
#define ENABLE_REQ_DEBUG

/* enum {
	NBD_CMD_READ = 0,
	NBD_CMD_WRITE = 1,
	NBD_CMD_DISC = 2
};*/
enum nbd_command {
    NBD_CMD_READ = 0,
    NBD_CMD_WRITE = 1,
    NBD_CMD_DISC = 2,
    NBD_CMD_FLUSH = 3,
    NBD_CMD_TRIM = 4,
    NBD_CMD_QHASH = 5
};

#define nbd_cmd(req) ((req)->cmd[0])
#define MAX_NBD 128

/* userspace doesn't need the nbd_device structure */
#ifdef __KERNEL__

#include <linux/wait.h>
#include <linux/mutex.h>

/* values for flags field */
#define NBD_READ_ONLY 0x0001
#define NBD_WRITE_NOCHK 0x0002

/* max sectors (pages) for io requests in the nbd queues (i.e. req split limit) */
#define MAX_BIO_PAGES	128
#define PAGE_SECTORS	(PAGE_SIZE >> 9)

struct request;

struct nbd_device {
	int flags;
	int harderror;		/* Code of hard error			*/
	struct socket * sock;
	struct file * file; 	/* If == NULL, device is not ready, yet	*/
	int magic;

	spinlock_t queue_lock;
	struct list_head queue_head;	/* Requests waiting result */
	struct request *active_req;
	wait_queue_head_t active_wq;
	struct list_head waiting_queue;	/* Requests to be sent */
	wait_queue_head_t waiting_wq;

	struct mutex tx_lock;
	struct gendisk *disk;
	int blksize;
	pid_t client_pid;	/* pid of nbd-client process, if attached */
	u64 bytesize;
	spinlock_t timer_lock;
	volatile int reqs_in_progress;
	volatile int xmit_timeout;
	int errmsg_last_time;
	struct task_struct *client_task;
	struct timer_list ti;
#ifdef ENABLE_REQ_DEBUG
	atomic_t req_total;
	atomic_t req_total_rd;
	atomic_t req_total_wr;
	atomic_t req_inprogr;
	atomic_t req_inprogr_rd;
	atomic_t req_inprogr_wr;
#endif
};

#endif

#ifndef __UTILS__
/* These are sent over the network in the request/reply magic fields */

#define NBD_REQUEST_MAGIC 0x25609513
#define NBD_REPLY_MAGIC 0x67446698
/* Do *not* use magics: 0x12560953 0x96744668. */

/*
 * This is the packet used for communication between client and
 * server. All data are in network byte order.
 */
struct nbd_request {
	__be32 magic;
	__be32 type;	/* == READ || == WRITE 	*/
	char handle[8];
	__be64 from;
	__be32 len;
}
#ifdef __GNUC__
	__attribute__ ((packed))
#endif
;

/*
 * This is the reply packet that nbd-server sends back to the client after
 * it has completed an I/O request (or an error occurs).
 */
struct nbd_reply {
	__be32 magic;
	__be32 error;		/* 0 = ok, else error	*/
	char handle[8];		/* handle you got from request	*/
} __attribute__ ((packed)) ;
#endif

#define assert(x) if (unlikely(!(x))) { printk( KERN_ALERT "ASSERT: %s failed @ %s(): line %d\n", \
                                                #x, __FUNCTION__,__LINE__); }

/**
 * Maximum number of blocks in the hash query return values
 *
 * NOTE: setting this to >1 could return many block hashes with a single call...
 *    => HASH CACHING BUG: when there's active I/O on the master node (also sync written to the slaves),
 *       both master and slave hashes are updated continuously! Thus caching hashes on the master
 *       leads to comparison of stale hashes and incorrect resync of data blocks!
 *
 * CAUTION: this value MUST be defined identical to the one in nbd.h for the ioctl handler!
 */
#define	MAX_QUERY_BLKS	1	/* must be <= 64 */

/* CAUTION: this MUST be greater or equal to BLOCK_HASH_SIZE (in nbd_storage.h) */
#define	MAX_HASH_LEN	32	/* max byte length of hash values */

/* We need the definition of GChecksumType (already defined in user-space glib...) */
typedef enum {
  G_CHECKSUM_MD5,
  G_CHECKSUM_SHA1,
  G_CHECKSUM_SHA256
} GChecksumType;

/* CAUTION: this MUST match the nbd-server struct !! */
typedef struct nbd_qhash_request_t_ {
	uint64_t	blkaddr;	/* starting block address */
	uint32_t	blksize;	/* block size in bytes */
	uint16_t	blkcount;	/* number of block hashes returned (<= MAX_QUERY_BLKS) */
	uint16_t	hash_type;	/* type of hash algorithm (encoded value) */
	uint32_t	hash_len;	/* number of bytes per hash (<= MAX_HASH_LEN) */
} __attribute__((packed)) nbd_qhash_request_t;

/**
 * Type of argument and return data for block query hash ioctl (to NBD slave dev).
 * CAUTION: Total size of this struct should not exceed one memory page (4 KBytes)
 *          to be safe for ioctl(). */
typedef struct nbd_query_blkhash_t_ {
	uint64_t	blkaddr;	/* starting block address */
	uint32_t	blksize;	/* block size in bytes */
	uint16_t	blkcount;	/* number of block hashes returned (<= MAX_QUERY_BLKS) */
	uint16_t	hash_type;	/* type of hash algorithm (encoded value) */
	uint32_t	hash_len;	/* number of bytes per hash (<= MAX_HASH_LEN) */
	uint32_t	error;		/* error code for request */
	uint64_t	blkmap;		/* bitmap with 1s for valid data blocks */
	char		blkhash[MAX_QUERY_BLKS][MAX_HASH_LEN];	/* byte array with block hash */
} __attribute__((packed)) nbd_query_blkhash_t;

#endif
