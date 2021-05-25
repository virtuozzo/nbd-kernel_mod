/* SPDX-License-Identifier: GPL-1.0+ WITH Linux-syscall-note */
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
 */

#ifndef _UAPILINUX_NBD_H
#define _UAPILINUX_NBD_H

#include <linux/types.h>

/* ATTENTION: this includes a comma-separated list of 2 chars per feature supported by this nbd... */
#define NBD_FEATURE_SET "TO,TR,FL,QH,QH,SC,"
/* LIST OF FEATURES SUPPORTED AND MEANINGS:
 * TO: NBD Timeouts
 * TR: TRIM feature
 * PD: PRINT_DEBUG ioctl
 * QH: QUERY_HASH ioctl using nbd_query_blkhash_t transport struct
 * QB: QUERY_HASHB ioctl using nbd_query_blkhashbat_t for batched hashing
 * SC: NBD_SERVER_CMD ioctl for sending short custom server commands
 * FL: FLUSH buffers via BLKFLSBUF ioctl
 * Example:
 * #define NBD_FEATURE_SET "TO,TR,PD,QH,QB,SC,FL,"
 */

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
#define NBD_SET_FLAGS   _IO( 0xab, 10)

enum {
	NBD_CMD_READ = 0,
	NBD_CMD_WRITE = 1,
	NBD_CMD_DISC = 2,
	NBD_CMD_FLUSH = 3,
	NBD_CMD_TRIM = 4,
	NBD_CMD_QHASH = 5,
    NBD_CMD_SRVCMD = 6,
    NBD_CMD_QHASHB = 7
};

/* values for flags field, these are server interaction specific. */
#define NBD_FLAG_HAS_FLAGS	(1 << 0) /* nbd-server supports flags */
#define NBD_FLAG_READ_ONLY	(1 << 1) /* device is read-only */
#define NBD_FLAG_SEND_FLUSH	(1 << 2) /* can flush writeback cache */
#define NBD_FLAG_SEND_FUA	(1 << 3) /* send FUA (forced unit access) */
/* there is a gap here to match userspace */
#define NBD_FLAG_SEND_TRIM	(1 << 5) /* send trim/discard */
#define NBD_FLAG_CAN_MULTI_CONN	(1 << 8)	/* Server supports multiple connections per export. */

/* values for cmd flags in the upper 16 bits of request type */
#define NBD_CMD_FLAG_FUA	(1 << 16) /* FUA (forced unit access) op */

/* These are client behavior specific flags. */
#define NBD_CFLAG_DESTROY_ON_DISCONNECT	(1 << 0) /* delete the nbd device on
						    disconnect. */
#define NBD_CFLAG_DISCONNECT_ON_CLOSE (1 << 1) /* disconnect the nbd device on
						*  close by last opener.
						*/

/* userspace doesn't need the nbd_device structure */

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
} __attribute__((packed));

/*
 * This is the reply packet that nbd-server sends back to the client after
 * it has completed an I/O request (or an error occurs).
 */
struct nbd_reply {
	__be32 magic;
	__be32 error;		/* 0 = ok, else error	*/
	char handle[8];		/* handle you got from request	*/
};

#define CONN_INFO_LEN		512

typedef struct nbd_conn_info_t_ {
	uint16_t	set_info;	/* get (0) or set (1) info ? */
	uint16_t	connected;	/* is nbd connection live? */
	uint32_t	sock;		/* nbd socket ptr */
	uint32_t	pid;		/* nbd client pid */
	char		cidata[CONN_INFO_LEN];	/* byte array with connection info */
} __attribute__((packed)) nbd_conn_info_t;

#define SERVER_CMD_MAX_LEN	128

typedef struct nbd_server_cmd_ {
	uint16_t	connected;	/* is nbd connection live? */
	char		cmdbytes[SERVER_CMD_MAX_LEN];	/* byte array with server cmd string */
	uint16_t	err_code;	/* error code for cmd. OK = 0 */
} __attribute__((packed)) nbd_server_cmd_t;

/**
 * Maximum number of blocks in the hash query return values
 *
 * NOTE: setting this to >1 could return many block hashes with a single call...
 *    => HASH CACHING BUG: when there's active I/O on the master node (also sync written to the slaves),
 *       both master and slave hashes are updated continuously! Thus caching hashes on the master
 *       leads to comparison of stale hashes and incorrect resync of data blocks!
 *
 * CAUTION: these values MUST be defined identical to the ones in nbd.h for the ioctl handler!
 */
#define	MAX_QUERY_BLKS			1	/* must be 1 for backwards compatibility!! */
#define	MAX_QUERY_BLKS_BATCH	64	/* must be 64 */

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
	uint16_t	blkcount;	/* number of block hashes returned (<= MAX_QUERY_BLKS_BATCH) */
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

/* Clone of nbd_query_blkhash_t to maintain backwards compatibility with older nbds
 * that support only single-hash ioctl and message type */
typedef struct nbd_query_blkhashbat_t_ {
	uint64_t	blkaddr;	/* starting block address */
	uint32_t	blksize;	/* block size in bytes */
	uint16_t	blkcount;	/* number of block hashes returned (<= MAX_QUERY_BLKS_BATCH) */
	uint16_t	hash_type;	/* type of hash algorithm (encoded value) */
	uint32_t	hash_len;	/* number of bytes per hash (<= MAX_HASH_LEN) */
	uint32_t	error;		/* error code for request */
	uint64_t	blkmap;		/* bitmap with 1s for valid data blocks */
	char		blkhash[MAX_QUERY_BLKS_BATCH][MAX_HASH_LEN];	/* byte array with block hash */
} __attribute__((packed)) nbd_query_blkhashbat_t;

#define NBD_QUERY_HASH	_IOWR( 0xab, 12, nbd_query_blkhash_t )
#define NBD_CONN_INFO	_IOWR( 0xab, 13, nbd_conn_info_t )
#define NBD_SERVER_CMD	_IOWR( 0xab, 14, nbd_server_cmd_t )
#define NBD_QUERY_HASHB	_IOWR( 0xab, 15, nbd_query_blkhashbat_t )

#endif /* _UAPILINUX_NBD_H */
