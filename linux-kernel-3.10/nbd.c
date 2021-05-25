/*
 * Network block device - make block devices work over TCP
 *
 * Note that you can not swap over this thing, yet. Seems to work but
 * deadlocks sometimes - you can not swap over TCP in general.
 * 
 * Copyright 1997-2000, 2008 Pavel Machek <pavel@ucw.cz>
 * Parts copyright 2001 Steven Whitehouse <steve@chygwyn.com>
 *
 * This file is released under GPLv2 or later.
 *
 * (part of code stolen from loop.c)
 *
 * 2013/02/12 Michail Flouris <michail.flouris@onapp.com>
 *            Added query hash ioctl command and several bug fixes
 * 2013/02/25 Michail Flouris <michail.flouris@onapp.com>
 *            Added conn_info ioctl command code
 * 2013/10/10 Michail Flouris <michail.flouris@onapp.com>
 *            Added server_cmd ioctl command code
 */

#include <linux/major.h>

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>
#include <asm/types.h>
#include <linux/debugfs.h>

/* IMPORTANT: we use the LOCAL version of the nbd.h file, not <linux/nbd.h> */
#include "nbd.h"

#define NBD_MAGIC 0x68797548

#ifdef NDEBUG
#define dprintk(flags, fmt...)
#else /* NDEBUG */
#define dprintk(flags, fmt...) do { \
	if (debugflags & (flags)) printk(KERN_ALERT fmt); \
} while (0)
#define DBG_IOCTL       0x0004
#define DBG_INIT        0x0010
#define DBG_EXIT        0x0020
#define DBG_QHASH       0x0040
#define DBG_IOCMDS      0x0080
#define DBG_BLKDEV      0x0100
#define DBG_RX          0x0200
#define DBG_TX          0x0400
static unsigned int debugflags = 0;
#endif /* NDEBUG */

#if IS_ENABLED(CONFIG_DEBUG_FS)
static struct dentry *nbd_dbg_dir;
#endif

static unsigned int nbds_max = 16;
static struct nbd_device *nbd_dev;
static int max_part;

#define NBD_BUILD_ID	"nbd_OA_380"
#define NBD_BUILD_STR_MAXLEN	42
static char __nbd_build_date_id[NBD_BUILD_STR_MAXLEN] = NBD_BUILD_ID";"__DATE__"-"__TIME__;
static char __nbd_build_date[NBD_BUILD_STR_MAXLEN] = __DATE__" "__TIME__; // store the nbd build date here

#define nbd_name(nbd) ((nbd)->disk->disk_name)

#ifndef INIT_COMPLETION
#define INIT_COMPLETION(x) reinit_completion(&x)
#endif

#ifdef EL7_VER_328
#define DEP_REQ_TYPE_SPECIAL	REQ_TYPE_DRV_PRIV
#else
#define DEP_REQ_TYPE_SPECIAL	REQ_TYPE_SPECIAL
#endif

/* this is for debugging the cmd headers sent & replies received... */
//#define NBD_DEBUG_CMDS
#undef NBD_DEBUG_CMDS

#ifdef NBD_DEBUG_CMDS
#define MAX_LAST_ITEMS	32
int   last_req_cnt = 0, last_rep_cnt = 0;
struct nbd_request last_requests[MAX_LAST_ITEMS];
struct nbd_reply last_replies[MAX_LAST_ITEMS];
#endif

#ifndef NDEBUG
static const char *ioctl_cmd_to_ascii(int cmd)
{
	switch (cmd) {
	case NBD_SET_SOCK: return "set-sock";
	case NBD_SET_BLKSIZE: return "set-blksize";
	case NBD_SET_SIZE: return "set-size";
	case NBD_SET_TIMEOUT: return "set-timeout";
	case NBD_SET_FLAGS: return "set-flags";
	case NBD_DO_IT: return "do-it";
	case NBD_CLEAR_SOCK: return "clear-sock";
	case NBD_CLEAR_QUE: return "clear-que";
	case NBD_PRINT_DEBUG: return "print-debug";
	case NBD_SET_SIZE_BLOCKS: return "set-size-blocks";
	case NBD_DISCONNECT: return "disconnect";
	case NBD_QUERY_HASH: return "query-blk-hash";
	case NBD_QUERY_HASHB: return "query-blk-hash-batch";
	case NBD_CONN_INFO: return "connection-info";
	case NBD_SERVER_CMD: return "server-command";
	case BLKROSET: return "set-read-only";
	case BLKFLSBUF: return "flush-buffer-cache";
	}
	return "unknown";
}

static const char *nbdcmd_to_ascii(int cmd)
{
	switch (cmd) {
	case  NBD_CMD_READ: return "read";
	case  NBD_CMD_WRITE: return "write";
	case  NBD_CMD_DISC: return "disconnect";
	case  NBD_CMD_FLUSH: return "flush";
	case  NBD_CMD_TRIM: return "trim/discard";
	case  NBD_CMD_QHASH: return "query_hash";
	case  NBD_CMD_QHASHB: return "query_hash_bat";
	case  NBD_CMD_SRVCMD: return "server_cmd";
	}
	return "invalid";
}



static void
print_queue_info( struct nbd_device *nbd )
{
	if (list_empty(&nbd->queue_head)) {

		printk( KERN_ALERT "%s: Request Queue is EMPTY\n", nbd->disk->disk_name);

	} else {
		struct request *req;
		struct list_head *tmp;
		unsigned long flags;
		int rcount = 0;

		printk( KERN_ALERT "%s: Printing Request Queue Info:\n", nbd->disk->disk_name);

		spin_lock_irqsave(&nbd->queue_lock, flags);
		list_for_each(tmp, &nbd->queue_head) {
			req = list_entry(tmp, struct request, queuelist);

			printk( KERN_ALERT "%s: [%d] REQ %p: %s [ERR: %d, cmd_type: 0x%x]\n",
					nbd->disk->disk_name, rcount++, req, nbdcmd_to_ascii(nbd_cmd(req)),
					req->errors, req->cmd_type);
		}
		spin_unlock_irqrestore(&nbd->queue_lock, flags);
	}
}
#endif /* NDEBUG */

static void
dump_last_requests( struct nbd_device *nbd )
{
#ifdef NBD_DEBUG_CMDS
	struct nbd_request *rq;
	struct nbd_reply *rp;
	int i;

	if ( nbd ) { /* if nbd arg provided... */
		printk(KERN_ALERT "\n%s: REQUEST DEBUG INFO\n========================\n", nbd->disk->disk_name );

		printk(KERN_ALERT "%s: RESP TIMEOUT = %d sec, reqs_in_progress=%d, sock= 0x%p \n", nbd->disk->disk_name,
						nbd->xmit_timeout/HZ, atomic_read(&nbd->reqs_in_progress), nbd->sock );
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ALERT "%s: IO Reqs Total: %d (RD: %d, WR: %d) -> In Progress: %d (RD: %d, WR: %d)\n",
			nbd->disk->disk_name,
			atomic_read( &nbd->req_total ), atomic_read( &nbd->req_total_rd ),
			atomic_read( &nbd->req_total_wr ), atomic_read( &nbd->req_inprogr ),
			atomic_read( &nbd->req_inprogr_rd ), atomic_read( &nbd->req_inprogr_wr )
			);
#endif

		print_queue_info( nbd );
	}

	printk( KERN_ALERT "=> last_req_cnt: %d, last_rep_cnt: %d [MAX: %d]\n",
				last_req_cnt, last_rep_cnt, MAX_LAST_ITEMS );
	assert( last_req_cnt >= 0 && last_req_cnt <= MAX_LAST_ITEMS );
	assert( last_rep_cnt >= 0 && last_rep_cnt <= MAX_LAST_ITEMS );

	if ( last_req_cnt == 0 ) {
		printk( KERN_ALERT "====> REQUEST LIST EMPTY\n");
	} else {
		for (i = 0; i < last_req_cnt; i++ ) {
			rq = &last_requests[i];
			printk( KERN_ALERT " REQ[%d] magic: 0x%x type: %d handle: 0x%llx from: %llu len: %d\n", i,
				ntohl (rq->magic), ntohl (rq->type), *((unsigned long long *)rq->handle), be64_to_cpu(rq->from),
				ntohl (rq->len) );
		}

		printk( KERN_ALERT "====> OLDER REQ LIST ============\n");
		for (i = last_req_cnt; i < MAX_LAST_ITEMS; i++ ) {
			rq = &last_requests[i];
			if ( ntohl (rq->magic) != 0 || ntohl (*(unsigned long*)rq->handle) != 0 ) {
				printk( KERN_ALERT " REQ[%d] magic: 0x%x type: %d handle: 0x%llx from: %llu len: %d\n", i,
					ntohl (rq->magic), ntohl (rq->type), *((unsigned long long *)rq->handle), be64_to_cpu(rq->from),
					ntohl (rq->len) );
			}
		}
		printk( KERN_ALERT "====> ENDOF REQ LIST  ============\n");
	}

	if ( last_rep_cnt == 0 ) {
		printk( KERN_ALERT "====> REPLY LIST EMPTY\n");
	} else {
		for (i = 0; i < last_rep_cnt; i++ ) {
			rp = &last_replies[i];
			printk( KERN_ALERT " REPLY[%d] magic: 0x%x error: %d handle: 0x%llx\n", i,
				ntohl (rp->magic), ntohl (rp->error), *((unsigned long long *)rp->handle) );
		}

		printk( KERN_ALERT "====> OLDER REPLY LIST ============\n");
		for (i = last_rep_cnt; i < MAX_LAST_ITEMS; i++ ) {
			rp = &last_replies[i];
			if ( ntohl (rp->magic) != 0 || ntohl (*(unsigned long*)rp->handle) != 0 ) {
				printk( KERN_ALERT " REPLY[%d] magic: 0x%x error: %d handle: 0x%llx\n", i,
					ntohl (rp->magic), ntohl (rp->error), *((unsigned long long *)rp->handle) );
			}
		}
		printk( KERN_ALERT "====> ENDOF REPLY LIST  ============\n");
	}
#endif
}

static void
print_debug_info( struct nbd_device *nbd )
{
	printk(KERN_ALERT "\n%s: REQUEST DEBUG INFO\n========================\n", nbd->disk->disk_name );

	printk(KERN_ALERT "%s: RESP TIMEOUT = %d sec, reqs_in_progress=%d, sock= 0x%p \n", nbd->disk->disk_name,
					nbd->xmit_timeout/HZ, atomic_read(&nbd->reqs_in_progress), nbd->sock );

#ifdef ENABLE_REQ_DEBUG
	printk(KERN_ALERT "%s: IO Reqs Total: %d (RD: %d, WR: %d) -> In Progress: %d (RD: %d, WR: %d)\n",
		nbd->disk->disk_name,
		atomic_read( &nbd->req_total ), atomic_read( &nbd->req_total_rd ),
		atomic_read( &nbd->req_total_wr ), atomic_read( &nbd->req_inprogr ),
		atomic_read( &nbd->req_inprogr_rd ), atomic_read( &nbd->req_inprogr_wr )
		);

	printk(KERN_ALERT "%s: Bytesize= %lld, Blksize= %d\n",
						nbd->disk->disk_name, nbd->bytesize, nbd->blksize);

	if ( !nbd->sock)
		printk(KERN_ALERT "%s: Socket is CLOSED!\n", nbd->disk->disk_name);
	else
		printk(KERN_ALERT "%s: Socket is OPEN & CONNECTED!\n", nbd->disk->disk_name);

#ifndef NBD_DEBUG_CMDS
	/* Ok, now dump info about all pending requests in the queue... */
	print_queue_info( nbd );
#endif
#endif

	dump_last_requests(nbd);
}

#if IS_ENABLED(CONFIG_DEBUG_FS)

static int nbd_dbg_init(void)
{
	struct dentry *dbg_dir;

	dbg_dir = debugfs_create_dir("nbd", NULL);
	if (!dbg_dir)
		return -EIO;

	debugfs_create_u32("nbds_max", 0444, dbg_dir, &nbds_max);
	debugfs_create_u32("max_part", 0444, dbg_dir, &max_part);
	nbd_dbg_dir = dbg_dir;

	return 0;
}

static void nbd_dbg_close(void)
{
	debugfs_remove_recursive(nbd_dbg_dir);
}

static int nbd_dbg_flags_show(struct seq_file *s, void *unused)
{
	struct nbd_device *nbd = s->private;
	u32 flags = nbd->flags;

	seq_printf(s, "Hex: 0x%08x\n\n", flags);

	seq_puts(s, "Known flags:\n");

	if (flags & NBD_FLAG_HAS_FLAGS)
		seq_puts(s, "NBD_FLAG_HAS_FLAGS\n");
	if (flags & NBD_FLAG_READ_ONLY)
		seq_puts(s, "NBD_FLAG_READ_ONLY\n");
	if (flags & NBD_FLAG_SEND_FLUSH)
		seq_puts(s, "NBD_FLAG_SEND_FLUSH\n");
	if (flags & NBD_FLAG_SEND_FUA)
		seq_puts(s, "NBD_FLAG_SEND_FUA\n");
	if (flags & NBD_FLAG_SEND_TRIM)
		seq_puts(s, "NBD_FLAG_SEND_TRIM\n");

	return 0;
}

static int nbd_dbg_flags_open(struct inode *inode, struct file *file)
{
	return single_open(file, nbd_dbg_flags_show, inode->i_private);
}

static const struct file_operations nbd_dbg_flags_ops = {
	.open = nbd_dbg_flags_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int nbd_dbg_queues_show(struct seq_file *s, void *unused)
{
	struct nbd_device *nbd = s->private;
	struct request *req;
	unsigned long queue_len = 0;
	unsigned long flags;

	seq_puts(s, "Send waiting queue:\n");
	spin_lock_irqsave(&nbd->lock, flags);
	list_for_each_entry(req, &nbd->waiting_queue, queuelist) {
		queue_len++;
		seq_printf(s, "%lu: handle %p \n", queue_len, req);
	}
	spin_unlock_irqrestore(&nbd->lock, flags);
	seq_printf(s, "\n Total len:%lu\n", queue_len);
	queue_len = 0;

	seq_puts(s, "Response waiting queue:\n");
	spin_lock_irqsave(&nbd->queue_lock, flags);
	list_for_each_entry(req, &nbd->queue_head, queuelist) {
		queue_len++;
		seq_printf(s, "%lu: handle %p \n", queue_len, req);
	}
	spin_unlock_irqrestore(&nbd->queue_lock, flags);
	seq_printf(s, "\n Total len:%lu\n", queue_len);

	return 0;
}

static int nbd_dbg_queues_open(struct inode *inode, struct file *file)
{
	return single_open(file, nbd_dbg_queues_show, inode->i_private);
}

static const struct file_operations nbd_dbg_queues_ops = {
	.open = nbd_dbg_queues_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int nbd_dbg_add_device(struct nbd_device *nbd)
{
	struct dentry *dir;

	if (!nbd_dbg_dir)
		return -EIO;

	dir = debugfs_create_dir(nbd_name(nbd), nbd_dbg_dir);
	if (!dir) {
		dev_err(disk_to_dev(nbd->disk), "Failed to create debugfs dir for '%s'\n",	nbd_name(nbd));
		return -EIO;
	}
	nbd->dbg_dir = dir;

	debugfs_create_u64("size_bytes", 0444, dir, &nbd->bytesize);
	debugfs_create_u32("timeout", 0444, dir, (u32 *)&nbd->xmit_timeout);
	debugfs_create_u32("client_pid", 0444, dir, &nbd->pid);
	debugfs_create_u32("blocksize", 0444, dir, &nbd->blksize);
	debugfs_create_file("flags", 0444, dir, nbd, &nbd_dbg_flags_ops);
	debugfs_create_atomic_t("reqs_in_progress", 0444, dir, &nbd->reqs_in_progress);
	debugfs_create_atomic_t("qhash_pending", 0444, dir, &nbd->qhash_pending);
	debugfs_create_atomic_t("srvcmd_pending", 0444, dir, &nbd->srvcmd_pending);
	debugfs_create_file("queues", 0444, dir, nbd, &nbd_dbg_queues_ops);

	return 0;
}

static void nbd_dbg_del_device(struct nbd_device *nbd)
{
	debugfs_remove_recursive(nbd->dbg_dir);
}

#else  /* IS_ENABLED(CONFIG_DEBUG_FS) */

static int nbd_dbg_init(void)
{
	return 0;
}

static void nbd_dbg_close(void) {}
static int nbd_dbg_add_device(struct nbd_device *nbd)
{
	return 0;
}

static void nbd_dbg_del_device(struct nbd_device *nbd) {}

#endif

void disarm_response_timer( struct nbd_device *nbd )
{
	unsigned long flags;

	/* only if timeout is set and timer is armed... */
	if (nbd->xmit_timeout) {

		spin_lock_irqsave(&nbd->timer_lock, flags);

		del_timer(&nbd->ti); /* this works in inactive timers too... */

		/* Don't need this: del_timer_sync(&nbd->ti); */

		spin_unlock_irqrestore(&nbd->timer_lock, flags);

		atomic_set( &nbd->reqs_in_progress, 0 );

		//printk(KERN_ALERT "%s: response timeout deactivated\n", nbd->disk->disk_name);
	}
}

static void nbd_end_request(struct request *req)
{
	int error = req->errors ? -EIO : 0;
	struct request_queue *q = req->q;
	unsigned long flags;

	dprintk(DBG_BLKDEV, "%s: request %p: %s\n", req->rq_disk->disk_name,
			req, error ? "failed" : "done");

	spin_lock_irqsave(q->queue_lock, flags);
	__blk_end_request_all(req, error);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void sock_shutdown(struct nbd_device *nbd)
{
	if (nbd->sock) {
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ALERT "%s: shutting down socket [pendRQ:%d R:%d W:%d]\n",
			nbd->disk->disk_name, atomic_read(&nbd->req_inprogr),
			atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
		dev_warn(disk_to_dev(nbd->disk), "shutting down socket\n");
#endif
		kernel_sock_shutdown(nbd->sock, SHUT_RDWR);
		nbd->sock = NULL;
		disarm_response_timer( nbd );
	}

	memset( &nbd->conn_info, 0, sizeof(nbd_conn_info_t) ); /* clear stored connection info */
}

void nbd_xmit_timeout(unsigned long arg)
{
	struct task_struct *task = (struct task_struct *)arg;

	printk(KERN_ALERT "nbd: killing hung xmit (%s, pid: %d)\n",
		task->comm, task->pid);
	dump_last_requests(NULL);
	force_sig(SIGKILL, task);
}

void nbd_resp_timeout(unsigned long arg)
{
	struct nbd_device *nbd = (struct nbd_device *)arg;

	/* CAUTION: directly shutting down the socket causes a mini kernel panic...
	 *          -> so try to kill the client process with SIGKILL... */
	if ( nbd->client_task ) {
		unsigned long flags;

		printk(KERN_ALERT "%s: Server not responding after %d seconds - killing client (pid:%d %s)\n",
							nbd->disk->disk_name, nbd->xmit_timeout/HZ, nbd->pid, nbd->conn_info.cidata );
		dump_last_requests(nbd);

		/* Must avoid races to kill or we can get a crash... */
		spin_lock_irqsave(&nbd->timer_lock, flags);

		if ( nbd->client_task ) {
			force_sig(SIGKILL, nbd->client_task);
			nbd->client_task = NULL;
			spin_unlock_irqrestore(&nbd->timer_lock, flags);

		} else {
			spin_unlock_irqrestore(&nbd->timer_lock, flags);
			printk(KERN_ALERT "%s: Too slow to kill, client is already dead (pid:%d)\n",
							nbd->disk->disk_name, nbd->pid );
		}

	} else {
		// FIXME: this is dangerous from an interrupt context! use execute_in_process_context() ?
		printk(KERN_ALERT "%s: Server not responding after %d seconds - NULL task, cannot kill client!!\n",
							nbd->disk->disk_name, nbd->xmit_timeout/HZ );
		dump_last_requests(nbd);
		//sock_shutdown(nbd, 1); // BAD IDEA: this causes a crash...
	}
	/* NOTE: socket cleanup will be taken care or by the client task exit...*/
}

/* Increases the pending request count and sets the response
 * deadline timer accordingly */
void set_req_response_deadline( struct nbd_device *nbd )
{
	unsigned long flags;

	/* only if timeout is set and socket exists... */
	if (nbd->xmit_timeout && nbd->sock) {

		int rip;

		spin_lock_irqsave(&nbd->timer_lock, flags);

		/* first pending req? arm timer */
		if ( (rip = atomic_inc_return( &nbd->reqs_in_progress )) == 1 ) {

			init_timer(&nbd->ti);
			nbd->ti.function = nbd_resp_timeout;
			nbd->ti.data = (unsigned long)nbd;
			nbd->ti.expires = jiffies + nbd->xmit_timeout;
			add_timer(&nbd->ti);

		} else { /* timer already armed, reset timeout value... */
			assert( rip > 0 );

			/* CAUTION: if the timer is not pending, mod_timer() will RE-ACTIVATE it ! */
			if ( timer_pending(&nbd->ti) ) /* test it timer pending... */
				mod_timer(&nbd->ti, jiffies + nbd->xmit_timeout);
		}

		spin_unlock_irqrestore(&nbd->timer_lock, flags);
	}
}

/* Decreases the pending request count and resets the response
 * deadline timer accordingly - if more requests pending, the timer
 * is not reset... */
void reset_req_response_deadline( struct nbd_device *nbd )
{
	unsigned long flags;

	/* only if timeout is set and socket exists... */
	if (nbd->xmit_timeout && nbd->sock) {

		int rip;

		spin_lock_irqsave(&nbd->timer_lock, flags);

		/* last pending req? disarm timer */
		if ( (rip = atomic_dec_return( &nbd->reqs_in_progress )) == 0 ) {

			del_timer(&nbd->ti); /* this works in inactive timers too... */

			/* Don't need this: del_timer_sync(&nbd->ti); */

		} else { /* many reqs pending, reset timeout value... */
			assert( rip >= 0 );

			/* CAUTION: if the timer is not pending, mod_timer() will RE-ACTIVATE it ! */
			if ( timer_pending(&nbd->ti) ) /* test it timer pending... */
				mod_timer(&nbd->ti, jiffies + nbd->xmit_timeout);
		}

		spin_unlock_irqrestore(&nbd->timer_lock, flags);
	}
}

/*
 * Send packet
 */

static int sock_send(struct nbd_device *nbd, void *buf, int size, int msg_flags)
{
	int result, curr_timeout = nbd->xmit_timeout;
	struct socket *sock = nbd->sock;
	struct msghdr msg;
	struct kvec iov;
	struct timer_list ti;
	unsigned long pflags = current->flags;

	if (unlikely(!sock)) {
		dev_err_ratelimited(disk_to_dev(nbd->disk), "Attempted send on closed socket in sock_send\n");
		return -EINVAL;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = msg_flags | MSG_NOSIGNAL;
	if (curr_timeout) {
		init_timer(&ti);
		ti.function = nbd_xmit_timeout;
		ti.data = (unsigned long)current;
		ti.expires = jiffies + curr_timeout;
		add_timer(&ti);
	}

	current->flags |= PF_MEMALLOC;
	do {
		iov.iov_base = buf;
		iov.iov_len = size;
		result = kernel_sendmsg(sock, &msg, &iov, 1, size);
		if (result <= 0) {
			if (result == 0)
				result = -EPIPE; /* short read */
			break;
		}
		size -= result;
		buf += result;
	} while (size > 0);

	tsk_restore_flags(current, pflags, PF_MEMALLOC);
	if (curr_timeout)
		del_timer_sync(&ti);

	return result;
}

static int sock_recv(struct nbd_device *nbd, void *buf, int size)
{
	struct msghdr msg;
	struct kvec iov;
	int result;
	struct socket *sock = nbd->sock;
	unsigned long pflags = current->flags;

	if (unlikely(!sock)) {
		dev_err_ratelimited(disk_to_dev(nbd->disk), "Attempted recv on closed socket in sock_recv\n");
		return -EINVAL;
	}
	current->flags |= PF_MEMALLOC;
		do {
		iov.iov_base = buf;
		iov.iov_len = size;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;
		
		result = kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
		if (result <= 0) {
			if (result == 0)
				result = -EPIPE; /* short read */
			break;
		}
		size -= result;
		buf += result;
	} while (size > 0);

	tsk_restore_flags(current, pflags, PF_MEMALLOC);
	return result;
}

static int send_write_cmd(struct nbd_device *nbd, struct request *req, struct nbd_request *request)
{
	struct req_iterator iter;
	struct bio_vec *bvec;
	struct socket *sock = nbd->sock;
	struct msghdr msg;
	struct kvec iov;
	struct timer_list ti;
	void *kaddr;
	int result = 0, size = 0, curr_timeout = nbd->xmit_timeout;


	result = sock_send(nbd, request, sizeof(*request), MSG_MORE);
	if (result <= 0) {
		dev_err_ratelimited(disk_to_dev(nbd->disk), "Send write cmd control message failed (result %d)\n", result);
		return -EIO;
	}

	if (unlikely(!sock)) {
		dev_err_ratelimited(disk_to_dev(nbd->disk), "Attempted send on closed socket in send_write_cmd\n");
		return -EIO;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	if (curr_timeout) {
		init_timer(&ti);
		ti.function = nbd_xmit_timeout;
		ti.data = (unsigned long)current;
		ti.expires = jiffies + curr_timeout;
		add_timer(&ti);
	}

	rq_for_each_segment(bvec, req, iter) {
		if (rq_iter_last(req, iter))
			msg.msg_flags = MSG_NOSIGNAL;
		else
			msg.msg_flags = MSG_MORE | MSG_NOSIGNAL;

		size = bvec->bv_len;
		kaddr = kmap(bvec->bv_page) + bvec->bv_offset;
		do {
			iov.iov_base = kaddr;
			iov.iov_len = size;
			result = kernel_sendmsg(sock, &msg, &iov, 1, size);
			if (result <= 0) {
				if (result == 0)
					result = -EPIPE;
				break;
			}
			size -= result;
			kaddr += result;
		} while (size > 0);
		kunmap(bvec->bv_page);
		if (result <= 0) {
			dev_err_ratelimited(disk_to_dev(nbd->disk),	"Send data failed (result %d)\n", result);
			if (curr_timeout)
				del_timer_sync(&ti);

			return -EIO;
		}
	}
	if (curr_timeout)
		del_timer_sync(&ti);

	return 0;
}

static int nbd_send_req(struct nbd_device *nbd, struct request *req)
{
	int result, flags = 0;
	struct nbd_request request;

	memset(&request, 0, sizeof(request));
	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(nbd_cmd(req));

	if (unlikely(req->cmd_type == DEP_REQ_TYPE_SPECIAL &&
		(nbd_cmd(req) == NBD_CMD_FLUSH || nbd_cmd(req) == NBD_CMD_DISC)))
	{
		request.from = 0;
		request.len = 0;
	} else {
		request.from = cpu_to_be64((u64)blk_rq_pos(req) << 9);
		request.len = htonl(blk_rq_bytes(req));
	}
	
	memcpy(request.handle, &req, sizeof(req));
	if (nbd_cmd(req) == NBD_CMD_WRITE) {
		mutex_lock(&nbd->tx_lock);
		result = send_write_cmd(nbd, req, &request);
		mutex_unlock(&nbd->tx_lock);
		return result;
	}

	if (( req->cmd_type == DEP_REQ_TYPE_SPECIAL && nbd_cmd(req) == NBD_CMD_QHASH ) ||
		( req->cmd_type == DEP_REQ_TYPE_SPECIAL && nbd_cmd(req) == NBD_CMD_QHASHB ) )
		flags = MSG_MORE;
#ifdef NBD_DEBUG_CMDS
	assert( last_req_cnt >= 0 && last_req_cnt <= MAX_LAST_ITEMS );
	memcpy( &last_requests[last_req_cnt], &request, sizeof (request) );
	if ( last_req_cnt++ >= MAX_LAST_ITEMS )
		last_req_cnt = 0;
#endif

	// lock tx_lock so no one send between requeast header and body
	mutex_lock(&nbd->tx_lock);
	result = sock_send(nbd, &request, sizeof(request), flags );
	if (result <= 0) {
		mutex_unlock(&nbd->tx_lock);
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ERR "%s: Send control failed (result %d) [pendRQ:%d R:%d W:%d]\n",
				nbd->disk->disk_name, result,atomic_read(&nbd->req_inprogr),
				atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
		dev_err_ratelimited(disk_to_dev(nbd->disk), "Send control failed (result %d)\n", result);
#endif
		goto error_out;
	}

	if ( nbd_cmd(req) == NBD_CMD_READ) {
		mutex_unlock(&nbd->tx_lock);
		return 0;
	} else if ( req->cmd_type == DEP_REQ_TYPE_SPECIAL &&
		( nbd_cmd(req) == NBD_CMD_QHASH || nbd_cmd(req) == NBD_CMD_QHASHB ) ){
		/* special processing for qhash requests... */
		nbd_query_blkhash_t * nbd_qhash = req->special;
		/* NOTE: using same pointer for nbd_query_blkhashbat_t reqs !! */
		nbd_qhash_request_t qhreq;

		/* FYI: new nr_sectors is now blk_rq_bytes(req) bytes
		 *      and req->__sector is now blk_rq_pos(req) sectors */
		dprintk( DBG_QHASH, "QHASH REQ: sending EXTRA req data\n"); // michail
		BUG_ON( req->__sector != (nbd_qhash->blkaddr * (uint64_t)nbd_qhash->blksize) >> 9 );
		/* the following fields have been removed from the struct request in kernel v. 3.x
		BUG_ON( req->hard_nr_sectors != nbd_qhash->blksize >> 9 );
		BUG_ON( req->nr_sectors != nbd_qhash->blkcount ); */
		qhreq.blkaddr = htonl( nbd_qhash->blkaddr );
		qhreq.blksize = htonl( nbd_qhash->blksize );
		qhreq.blkcount = htons( nbd_qhash->blkcount );
		qhreq.hash_type = htons( nbd_qhash->hash_type );
		qhreq.hash_len = htonl( nbd_qhash->hash_len );
		dprintk( DBG_QHASH, "QHASH REQ Send: blkaddr= %u size= %d, count=%d - %d\n",
							ntohl(qhreq.blkaddr), ntohl(qhreq.blksize), ntohs(qhreq.blkcount),
							nbd_qhash->blkcount ); // michail

		dprintk( DBG_QHASH, "QHASH REQ Sending %d bytes\n", (int)sizeof(nbd_qhash_request_t) );
		result = sock_send(nbd, &qhreq, sizeof(nbd_qhash_request_t), 0 /* last */);
		mutex_unlock(&nbd->tx_lock);
		if (result <= 0) {
#ifdef ENABLE_REQ_DEBUG
			printk(KERN_ERR "%s: Send data failed (result %d) [pendRQ:%d R:%d W:%d]\n",
					nbd->disk->disk_name, result,atomic_read(&nbd->req_inprogr),
					atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
			printk(KERN_ERR "%s: Send data failed (result %d)\n",
					nbd->disk->disk_name, result);
#endif
			goto error_out;
		}

	} else if ( req->cmd_type == DEP_REQ_TYPE_SPECIAL && nbd_cmd(req) == NBD_CMD_SRVCMD ) {
		/* special processing for srvcmd requests... */
		nbd_server_cmd_t * nbd_srvcmd = req->special;

		/* should translate to network order for nbd server... */
		nbd_srvcmd->connected =  htons( nbd_srvcmd->connected );
		nbd_srvcmd->err_code = htons( nbd_srvcmd->err_code );

		dprintk( DBG_IOCMDS, "SRVCMD REQ Sending %d bytes\n", (int)sizeof(nbd_server_cmd_t));

		result = sock_send(nbd, nbd_srvcmd, sizeof(nbd_server_cmd_t), 0 /* last */);
		mutex_unlock(&nbd->tx_lock);
		if (result <= 0) {
#ifdef ENABLE_REQ_DEBUG
			printk(KERN_ERR "%s: Send data failed (result %d) [pendRQ:%d R:%d W:%d]\n",
					nbd->disk->disk_name, result,atomic_read(&nbd->req_inprogr),
					atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
			printk(KERN_ERR "%s: Send data failed (result %d)\n",
					nbd->disk->disk_name, result);
#endif
			goto error_out;
		}
	} else {
		mutex_unlock(&nbd->tx_lock);
		if (nbd_cmd(req) > NBD_CMD_QHASHB) {
			printk(KERN_ERR "%s: Unknown request type %d\n", nbd->disk->disk_name, nbd_cmd(req));
			goto error_out;
		}
	}
	return 0;

error_out:
	return -EIO;
}

static struct request *nbd_find_request(struct nbd_device *nbd, struct request *xreq)
{
	struct request *req, *tmp;
	unsigned long flags;
	// Consider using hash table here size 100 elements default and configurable
	// or completely rewite to lockless list so we can add to tail while cycling through list
	spin_lock_irqsave(&nbd->queue_lock, flags);
	list_for_each_entry_safe(req, tmp, &nbd->queue_head, queuelist) {
		if (req != xreq)
			continue;
		list_del_init(&req->queuelist);
		spin_unlock_irqrestore(&nbd->queue_lock, flags);
		return req;
	}
	spin_unlock_irqrestore(&nbd->queue_lock, flags);
	return ERR_PTR(-ENOENT);
}

static inline int sock_recv_bvec(struct nbd_device *nbd, struct bio_vec *bvec)
{
	int result;
	void *kaddr = kmap(bvec->bv_page);
	result = sock_recv(nbd, kaddr + bvec->bv_offset, bvec->bv_len);
	kunmap(bvec->bv_page);
	return result;
}

/* NULL returned = something went wrong, inform userspace */
static int nbd_handle_special_reply(struct nbd_device *nbd, struct nbd_reply *reply)
{
	int result = 0;

	if ( atomic_read(&nbd->qhash_pending) > 0 ) { /* pending qhash reqs? */
		struct request *qreq;

		memcpy( &qreq, (char *) reply->handle, sizeof(qreq) );

		dprintk(DBG_QHASH, "%s RESP: Checking for Query Hash reply! (%d pending reqs, qreq= %p)\n",
						nbd->disk->disk_name, atomic_read(&nbd->qhash_pending), qreq );

	   	if ( qreq->cmd_type == DEP_REQ_TYPE_SPECIAL && nbd_cmd(qreq) == NBD_CMD_QHASH) {

			/* NOTE: we don't recv the response directly into the ioctl buffer, because
			 *       we will need to check & convert the values received... */
			nbd_query_blkhash_t *nbd_qhash = qreq->special; /* get the ioctl-waiting struct... */
			nbd_query_blkhash_t *recv_qh = kzalloc( sizeof(nbd_query_blkhash_t), GFP_NOIO );
			if (!recv_qh)
				return -ENOMEM;

			dprintk(DBG_QHASH, "%s RESP: Received Query Hash reply! (req %p)\n",
							nbd->disk->disk_name, qreq);
			
			if (ntohl(reply->error)) {
				dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: QHash: Other side returned error (%d)\n",
					nbd->disk->disk_name, (int)ntohl(reply->error));

				qreq->errors++;
			} else { /* Handle successful request... read the hash data (only if NOT error) */

				dprintk(DBG_QHASH, "%s RESP: Receiving Query Hash reply: %d bytes\n",
				   		nbd->disk->disk_name, (int)sizeof(nbd_query_blkhash_t) );

				/* receive the hash data (i.e. nbd_query_blkhash_t) */
				result = sock_recv(nbd, recv_qh, sizeof(nbd_query_blkhash_t));
				if (result < 0) {
					printk(KERN_ERR "%s: Receiveing hash data failed (result %d)\n",
							nbd->disk->disk_name, result);
					kfree( recv_qh );
					return result;
				}

				dprintk(DBG_QHASH, "%s RESP: QHash: SUCCESS!\n", nbd->disk->disk_name );

				assert( nbd_qhash->blkaddr == ntohl( recv_qh->blkaddr ) );
				assert( nbd_qhash->blksize == ntohl( recv_qh->blksize ) );
				assert( nbd_qhash->blkcount == ntohs( recv_qh->blkcount ) );
				assert( nbd_qhash->hash_type == ntohs( recv_qh->hash_type ) );
				assert( nbd_qhash->hash_len == ntohl( recv_qh->hash_len ) );

				nbd_qhash->error = ntohl( recv_qh->error );

				if ( nbd_qhash->blkaddr != ntohl( recv_qh->blkaddr ) ||
					 nbd_qhash->blksize != ntohl( recv_qh->blksize ) ||
					 nbd_qhash->blkcount != ntohs( recv_qh->blkcount ) ||
					 nbd_qhash->hash_type != ntohs( recv_qh->hash_type ) ||
					 nbd_qhash->hash_len != ntohl( recv_qh->hash_len ) )
					nbd_qhash->error++;

				nbd_qhash->blkmap = recv_qh->blkmap;
				memcpy( nbd_qhash->blkhash, recv_qh->blkhash, MAX_QUERY_BLKS * MAX_HASH_LEN );

				dprintk(DBG_QHASH, "%s RESP: QHash: blkaddr= %llu, blksize= %u, blkcount= %u!\n",
								nbd->disk->disk_name, nbd_qhash->blkaddr, nbd_qhash->blksize,
								nbd_qhash->blkcount );
				dprintk(DBG_QHASH, "%s RESP: QHash: blkmap= 0x%llx!\n", nbd->disk->disk_name, nbd_qhash->blkmap );
			}

			atomic_dec( &nbd->qhash_pending );
			kfree( recv_qh );
			complete( (struct completion *)qreq->completion_data );
			dprintk(DBG_QHASH, "%s RESP: ===== EXIT == QHASH =============\n", nbd->disk->disk_name );
			return 0;
		}
		
		if ( qreq->cmd_type == DEP_REQ_TYPE_SPECIAL && nbd_cmd(qreq) == NBD_CMD_QHASHB ) {

			/* NOTE: we don't recv the response directly into the ioctl buffer, because
			 *       we will need to check & convert the values received... */
			nbd_query_blkhashbat_t *nbd_qhash = qreq->special; /* get the ioctl-waiting struct... */
			nbd_query_blkhashbat_t *recv_qh = kzalloc( sizeof(nbd_query_blkhashbat_t), GFP_NOIO );
			if (!recv_qh)
				return -ENOMEM;

			dprintk(DBG_QHASH, "%s RESP: Received Query Hash Bat reply! (req %p)\n",
							nbd->disk->disk_name, qreq);
			
			if (ntohl(reply->error)) {
				dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: QHashB: Other side returned error (%d)\n",
					nbd->disk->disk_name, (int)ntohl(reply->error));

				qreq->errors++;
			} else { /* Handle successful request... read the hash data (only if NOT error) */

				dprintk(DBG_QHASH, "%s RESP: Receiving Query Hash Bat reply: %d bytes\n",
				   		nbd->disk->disk_name, (int)sizeof(nbd_query_blkhashbat_t) );

				/* receive the hash data (i.e. nbd_query_blkhashbat_t) */
				result = sock_recv(nbd, recv_qh, sizeof(nbd_query_blkhashbat_t));
				if (result < 0) {
					printk(KERN_ERR "%s: Receiving hash batch data failed (result %d)\n",
							nbd->disk->disk_name, result);
					kfree( recv_qh );
					return result;
				}

				dprintk(DBG_QHASH, "%s RESP: QHashB: SUCCESS!\n", nbd->disk->disk_name );

				assert( nbd_qhash->blkaddr == ntohl( recv_qh->blkaddr ) );
				assert( nbd_qhash->blksize == ntohl( recv_qh->blksize ) );
				assert( nbd_qhash->blkcount == ntohs( recv_qh->blkcount ) );
				assert( nbd_qhash->hash_type == ntohs( recv_qh->hash_type ) );
				assert( nbd_qhash->hash_len == ntohl( recv_qh->hash_len ) );

				nbd_qhash->error = ntohl( recv_qh->error );

				if ( nbd_qhash->blkaddr != ntohl( recv_qh->blkaddr ) ||
					 nbd_qhash->blksize != ntohl( recv_qh->blksize ) ||
					 nbd_qhash->blkcount != ntohs( recv_qh->blkcount ) ||
					 nbd_qhash->hash_type != ntohs( recv_qh->hash_type ) ||
					 nbd_qhash->hash_len != ntohl( recv_qh->hash_len ) )
					nbd_qhash->error++;

				nbd_qhash->blkmap = recv_qh->blkmap;
				memcpy( nbd_qhash->blkhash, recv_qh->blkhash, MAX_QUERY_BLKS_BATCH * MAX_HASH_LEN );

				dprintk(DBG_QHASH, "%s RESP: QHashB: blkaddr= %llu, blksize= %u, blkcount= %u!\n",
								nbd->disk->disk_name, nbd_qhash->blkaddr, nbd_qhash->blksize,
								nbd_qhash->blkcount );
				dprintk(DBG_QHASH, "%s RESP: QHashB: blkmap= 0x%llx!\n", nbd->disk->disk_name, nbd_qhash->blkmap );
			}

			atomic_dec( &nbd->qhash_pending );
			kfree( recv_qh );
			complete( (struct completion *)qreq->completion_data );
			dprintk(DBG_QHASH, "%s RESP: ===== EXIT == QHASHB =============\n", nbd->disk->disk_name );
			return 0;
		}
	}
	
	if ( atomic_read(&nbd->srvcmd_pending) > 0 ) { /* pending srvcmd reqs? */
		struct request *creq;

		memcpy( &creq, (char *) reply->handle, sizeof(creq) );
		dprintk(DBG_IOCMDS, "%s RESP: Checking for Server CMD reply! (%d pending reqs, creq= %p)\n",
						nbd->disk->disk_name, atomic_read(&nbd->srvcmd_pending), creq );

		if ( creq->cmd_type == DEP_REQ_TYPE_SPECIAL && nbd_cmd(creq) == NBD_CMD_SRVCMD) {

			/* NOTE: we don't recv the response directly into the ioctl buffer, because
			 *       we will need to check & convert the values received... */
			nbd_server_cmd_t *nbd_srvcmd = creq->special; /* get the ioctl-waiting struct... */
			nbd_server_cmd_t *recv_sc = kzalloc( sizeof(nbd_server_cmd_t), GFP_NOIO );
			if (!recv_sc)
				return -ENOMEM;

			dprintk(DBG_IOCMDS, "%s RESP: Received Server CMD reply! (req %p)\n",
							nbd->disk->disk_name, creq);
			
			memset( nbd_srvcmd, 0, sizeof(nbd_server_cmd_t)); /* clean up the response buffer... */

			if (ntohl(reply->error)) {
				dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: SrvCmd: Other side returned error (%d)\n",
					nbd->disk->disk_name, (int)ntohl(reply->error));

				creq->errors++;
			} else { /* Handle successful request... read the cmd response data (only if NOT error) */

				dprintk(DBG_IOCMDS, "%s RESP: Receiving Server CMD reply: %d bytes\n",
				   		nbd->disk->disk_name, (int)sizeof(nbd_server_cmd_t) );

				/* receive the cmd response data (i.e. nbd_server_cmd_t) */
				result = sock_recv(nbd, recv_sc, sizeof(nbd_server_cmd_t));
				if (result < 0) {
					printk(KERN_ERR "%s: Receiveing cmd response data failed (result %d)\n",
							nbd->disk->disk_name, result);
					kfree( recv_sc );
					return result;
				}

				dprintk(DBG_IOCMDS, "%s RESP: SrvCmd: SUCCESS!\n", nbd->disk->disk_name );

				nbd_srvcmd->connected = htons( recv_sc->connected );
				nbd_srvcmd->err_code = htons( recv_sc->err_code );

				if ( !nbd_srvcmd->err_code && !nbd_srvcmd->connected )
					nbd_srvcmd->err_code = 1;

				memcpy( nbd_srvcmd->cmdbytes, recv_sc->cmdbytes, SERVER_CMD_MAX_LEN );

				dprintk(DBG_IOCMDS, "%s RESP: SrvCmd: connected= %d, err_code= %d, cmdbytes= %s!\n",
								nbd->disk->disk_name, nbd_srvcmd->connected, nbd_srvcmd->err_code,
								nbd_srvcmd->cmdbytes );
			}

			atomic_dec( &nbd->srvcmd_pending );
			kfree( recv_sc );
			complete( (struct completion *)creq->completion_data );
			dprintk(DBG_IOCMDS, "%s RESP: ===== EXIT == SERVER CMD =============\n", nbd->disk->disk_name );
			return 0;
		}
		if ( creq->cmd_type == DEP_REQ_TYPE_SPECIAL && nbd_cmd(creq) == NBD_CMD_FLUSH) { // Is this a FLUSH request?
			dprintk(DBG_IOCMDS, "%s RESP: Received FLUSH reply! (req %p)\n",nbd->disk->disk_name, creq);
			if (ntohl(reply->error)) {
				dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: FLUSH: Other side returned error (%d)\n",
					nbd->disk->disk_name, (int)ntohl(reply->error));

				creq->errors++;
			} else { /* Handle successful request, completing the ioctl... */
				dprintk(DBG_IOCMDS, "%s RESP: FLUSH: SUCCESS!\n", nbd->disk->disk_name );
			}
			atomic_dec( &nbd->srvcmd_pending );
			complete( (struct completion *)creq->completion_data );
			dprintk(DBG_IOCMDS, "%s RESP: ===== EXIT == FLUSH CMD =============\n", nbd->disk->disk_name );
			return 0;
		}
	}

	return 0;
}

static ssize_t pid_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);

	return sprintf(buf, "%ld\n",
		(long) ((struct nbd_device *)disk->private_data)->pid);
}

static struct device_attribute pid_attr = {
	.attr = { .name = "pid", .mode = S_IRUGO},
	.show = pid_show,
};

static int nbd_do_it(struct nbd_device *nbd)
{
	struct request *req;

	if ( !nbd->xmit_timeout )
		printk(KERN_ALERT "%s INIT: xmit timeout: DISABLED\n", nbd->disk->disk_name );
	else
		printk(KERN_ALERT "%s INIT: Using xmit timeout: %d seconds\n", nbd->disk->disk_name, nbd->xmit_timeout/HZ );

	if (atomic_read(&nbd->qhash_pending) || !list_empty(&nbd->waiting_queue) || !list_empty(&nbd->queue_head) )
		printk(KERN_ALERT "%s INIT: WARNING! qhash_pending: %d, EMPTY: waiting_queue= %d, queue_head= %d\n",
				nbd->disk->disk_name, atomic_read(&nbd->qhash_pending),
				list_empty(&nbd->waiting_queue), list_empty(&nbd->queue_head) );

	while (1) {
		int result;
		struct nbd_reply reply;

		reply.magic = 0;
		result = sock_recv(nbd, &reply, sizeof(struct nbd_reply));
		if (result < 0) {
			dev_err(disk_to_dev(nbd->disk), "Receive control failed (result %d)\n", result);
			dump_last_requests(nbd);
			nbd->harderror = result;
			break;
		}

		if (ntohl(reply.magic) != NBD_REPLY_MAGIC) {
			// Consider not exiting here just continue with warning
			dev_warn(disk_to_dev(nbd->disk), "Wrong magic (0x%lx)\n", (unsigned long)ntohl(reply.magic));
			dump_last_requests(nbd);
			continue;
		}

		req = nbd_find_request(nbd, *(struct request **)reply.handle);
		if (IS_ERR(req)) {
			if (PTR_ERR(req) == -ENOENT) {
				// Request not found in queue try to handle special commands
				result = nbd_handle_special_reply(nbd, &reply);
				if (result == 0) { // request handled
					continue;
				}
				// we got error during handling special request
				dev_err(disk_to_dev(nbd->disk), "Error handling special command (result %d)\n", result);
				dump_last_requests(nbd);
				nbd->harderror = result;
				break;
			} else {
				nbd->harderror = -EBADR;
				dev_err(disk_to_dev(nbd->disk), "Unexpected reply (%p) req error (%ld)\n", reply.handle, PTR_ERR(req));
				break;
			}
		}

		if (ntohl(reply.error)) {
			dev_err_ratelimited(disk_to_dev(nbd->disk), "Other side returned error (%d)\n", ntohl(reply.error));
			dump_last_requests(nbd);
			req->errors++;
			reset_req_response_deadline(nbd); /* reset response deadlines appropriately */
			nbd_end_request(req);
			continue;
		}

		if (nbd_cmd(req) == NBD_CMD_READ) {
			struct req_iterator iter;
			struct bio_vec *bvec;

			rq_for_each_segment(bvec, req, iter) {
				result = sock_recv_bvec(nbd, bvec);
				if (result < 0) {
					dev_err_ratelimited(disk_to_dev(nbd->disk), "Receive data failed (result %d)\n", result);
					dump_last_requests(nbd);
					req->errors++;
					break;
				}
			}
		}
		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */
		nbd_end_request(req);
	}

	/* IMPORTANT: complete any qhash request blocked in waiting! */
	if ( atomic_read( &nbd->qhash_pending ) != 0 ) {
		/* NOTE: there is only one such request pending, so complete it */
		if ( nbd->qhash_req ) {
			nbd->qhash_req->errors++;
			complete( (struct completion *)nbd->qhash_req->completion_data );
			msleep(1); /* wait 1 msec for completion */
		}
		if ( atomic_read( &nbd->qhash_pending ) > 0 )
			atomic_dec( &nbd->qhash_pending );
		printk( KERN_INFO "%s: cleared pending qhash req\n",
			nbd->disk->disk_name );
	}

	/* IMPORTANT: complete any server cmd request blocked in waiting! */
	if ( atomic_read( &nbd->srvcmd_pending ) != 0 ) {
		/* NOTE: there is only one such request pending, so complete it */
		if ( nbd->srvcmd_req ) {
			nbd->srvcmd_req->errors++;
			complete( (struct completion *)nbd->srvcmd_req->completion_data );
			msleep(1); /* wait 1 msec for completion */
		}
		if ( atomic_read( &nbd->srvcmd_pending ) > 0 )
			atomic_dec( &nbd->srvcmd_pending );
		printk( KERN_INFO "%s: cleared pending server cmd req\n",
			nbd->disk->disk_name );
	}
	device_remove_file(disk_to_dev(nbd->disk), &pid_attr);
	nbd->pid = 0;
	return 0;
}

static void nbd_clear_que(struct nbd_device *nbd)
{
	struct request *req;
#ifdef ENABLE_REQ_DEBUG
	int req_inprogr = atomic_read(&nbd->req_inprogr);
	int req_inprogr_rd = atomic_read(&nbd->req_inprogr_rd);
	int req_inprogr_wr = atomic_read(&nbd->req_inprogr_wr);
#endif

	while (!list_empty(&nbd->queue_head)) {
		req = list_entry(nbd->queue_head.next, struct request, queuelist);
		list_del_init(&req->queuelist);
		req->errors++;

		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */

		if (req->cmd_type == DEP_REQ_TYPE_SPECIAL ) {
			if ( nbd_cmd(req) == NBD_CMD_QHASH || nbd_cmd(req) == NBD_CMD_QHASHB ) { /* qhash req? */
				complete( (struct completion *)req->completion_data );
				atomic_dec( &nbd->qhash_pending );
				continue;

			} else if ( nbd_cmd(req) == NBD_CMD_SRVCMD || nbd_cmd(req) == NBD_CMD_FLUSH ) { /* srvcmd req? */
				complete( (struct completion *)req->completion_data );
				atomic_dec( &nbd->srvcmd_pending );
				continue;
			}
		}
#ifdef ENABLE_REQ_DEBUG
		atomic_dec( &nbd->req_inprogr );
		if (rq_data_dir(req) == WRITE)
			atomic_dec( &nbd->req_inprogr_wr );
		else
			atomic_dec( &nbd->req_inprogr_rd );
#endif
		nbd_end_request(req);
	}

	while (!list_empty(&nbd->waiting_queue)) {
		req = list_entry(nbd->waiting_queue.next, struct request, queuelist);
		list_del_init(&req->queuelist);
		req->errors++;

		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */

		if (req->cmd_type == DEP_REQ_TYPE_SPECIAL ) {
			if ( nbd_cmd(req) == NBD_CMD_QHASH || nbd_cmd(req) == NBD_CMD_QHASHB ) { /* qhash req? */
				complete( (struct completion *)req->completion_data );
				atomic_dec( &nbd->qhash_pending );
				continue;

			} else if ( nbd_cmd(req) == NBD_CMD_SRVCMD || nbd_cmd(req) == NBD_CMD_FLUSH ) { /* srvcmd req? */
				complete( (struct completion *)req->completion_data );
				atomic_dec( &nbd->srvcmd_pending );
				continue;
			}
		}
		nbd_end_request(req);
	}

	/* IMPORTANT: complete any qhash request blocked in waiting! */
	if ( atomic_read( &nbd->qhash_pending ) != 0 ) {
		printk( KERN_INFO "%s CLEAR_QUEUE: Completed waiting qhash request\n",
			nbd->disk->disk_name );
		/* NOTE: there is only one such request pending, so complete it */
		if ( nbd->qhash_req ) {
			nbd->qhash_req->errors++;
			complete( (struct completion *)nbd->qhash_req->completion_data );
			msleep(1); /* wait 1 msec for completion */
		}
		if ( atomic_read( &nbd->qhash_pending ) > 0 )
			atomic_dec( &nbd->qhash_pending );
	}

	/* IMPORTANT: complete any server cmd request blocked in waiting! */
	if ( atomic_read( &nbd->srvcmd_pending ) != 0 ) {
		printk( KERN_INFO "%s CLEAR_QUEUE: Completed waiting server cmd request\n",
			nbd->disk->disk_name );
		/* NOTE: there is only one such request pending, so complete it */
		if ( nbd->srvcmd_req ) {
			nbd->srvcmd_req->errors++;
			complete( (struct completion *)nbd->srvcmd_req->completion_data );
			msleep(1); /* wait 1 msec for completion */
		}
		if ( atomic_read( &nbd->srvcmd_pending ) > 0 )
			atomic_dec( &nbd->srvcmd_pending );
	}

	disarm_response_timer( nbd ); /* cleanup any timer leftovers */
	nbd->flags = 0;

#ifdef ENABLE_REQ_DEBUG
	printk(KERN_WARNING "%s: queue cleared [pendRQ:%d/%d R:%d/%d W:%d/%d L:%d]\n",
		nbd->disk->disk_name, req_inprogr, atomic_read(&nbd->req_inprogr),
		req_inprogr_rd, atomic_read(&nbd->req_inprogr_rd),
		req_inprogr_wr, atomic_read(&nbd->req_inprogr_wr),
		mutex_is_locked(&nbd->tx_lock) );
#else
	dev_warn(disk_to_dev(nbd->disk), "queue cleared (lock: %d)\n", mutex_is_locked(&nbd->tx_lock) );
#endif
}


static void nbd_handle_req(struct nbd_device *nbd, struct request *req)
{
	unsigned long flags;

	if (req->cmd_type != REQ_TYPE_FS)
		goto error_out;

#ifdef ENABLE_REQ_DEBUG
	atomic_inc( &nbd->req_total );

	nbd_cmd(req) = NBD_CMD_READ;
	if (rq_data_dir(req) == WRITE) {
		if ((req->cmd_flags & REQ_DISCARD)) {
			WARN_ON(!(nbd->flags & NBD_FLAG_SEND_TRIM));
			nbd_cmd(req) = NBD_CMD_TRIM;
		} else
			nbd_cmd(req) = NBD_CMD_WRITE;
		if (nbd->flags & NBD_FLAG_READ_ONLY) {
			printk(KERN_ERR "%s: Write on read-only\n",
					nbd->disk->disk_name);
			goto error_out;
		}
		atomic_inc( &nbd->req_total_wr );
		atomic_inc( &nbd->req_inprogr_wr );
	} else {
		atomic_inc( &nbd->req_total_rd );
		atomic_inc( &nbd->req_inprogr_rd );
	}
#else
	nbd_cmd(req) = NBD_CMD_READ;
	if (rq_data_dir(req) == WRITE) {
		if ((req->cmd_flags & REQ_DISCARD)) {
			WARN_ON(!(nbd->flags & NBD_FLAG_SEND_TRIM));
			nbd_cmd(req) = NBD_CMD_TRIM;
		} else
			nbd_cmd(req) = NBD_CMD_WRITE;
		if (nbd->flags & NBD_FLAG_READ_ONLY) {
			dev_err(disk_to_dev(nbd->disk),
				"Write on read-only\n");
			goto error_out;
		}
	}
#endif

	req->errors = 0;
	if (unlikely(!nbd->sock)) {
		dev_err_ratelimited(disk_to_dev(nbd->disk), "Attempted send on closed socket nbd_handle_req\n");
		goto error_out;
	}
	set_req_response_deadline(nbd); /* set response deadlines for new request */
	spin_lock_irqsave(&nbd->queue_lock, flags);
	list_add_tail(&req->queuelist, &nbd->queue_head); // add request to queue before send so we can handle responce 
	spin_unlock_irqrestore(&nbd->queue_lock, flags);
#ifdef ENABLE_REQ_DEBUG
	atomic_inc( &nbd->req_inprogr );
#endif
	if (nbd_send_req(nbd, req) != 0) {
		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */
		dump_last_requests(nbd);
		nbd_find_request(nbd, req); // this will delete  req->queuelist
		req->errors++;
		nbd_end_request(req);	
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ERR "%s: Request send failed [pendRQ:%d R:%d W:%d]\n",
				nbd->disk->disk_name, atomic_read(&nbd->req_inprogr),
				atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
		
		if (rq_data_dir(req) == WRITE)
			atomic_dec( &nbd->req_inprogr_wr );
		else
			atomic_dec( &nbd->req_inprogr_rd );
#else
		dev_err(disk_to_dev(nbd->disk), "Request send failed\n");
#endif
	}
	return;

error_out:
	disarm_response_timer( nbd );
	req->errors++;
	nbd_end_request(req);
}

static int nbd_thread(void *data)
{
	struct nbd_device *nbd = data;
	struct request *req;
	unsigned long flags;

	set_user_nice(current, -20);
	while (!kthread_should_stop() || !list_empty(&nbd->waiting_queue)) {
		/* wait for something to do */
		wait_event_interruptible(nbd->waiting_wq, kthread_should_stop() || !list_empty(&nbd->waiting_queue));

		/* extract request */
		if (list_empty(&nbd->waiting_queue))
			continue;

		spin_lock_irqsave(&nbd->lock, flags);
		req = list_entry(nbd->waiting_queue.next, struct request, queuelist);
		list_del_init(&req->queuelist);
		spin_unlock_irqrestore(&nbd->lock, flags);

		/* handle request */
		nbd_handle_req(nbd, req);
	}
	return 0;
}

static void do_nbd_request(struct request_queue *q)
{
	struct request *req;
	unsigned long flags;
	
	while ((req = blk_fetch_request(q)) != NULL) {
		struct nbd_device *nbd = req->rq_disk->private_data;

		if (unlikely(!nbd->sock)) {
			__blk_end_request_all(req, -EIO);
			dev_err_ratelimited(disk_to_dev(nbd->disk), "Attempted send on closed socket in sock_send\n");
			return;
		}

		spin_lock_irqsave(&nbd->lock, flags);
		list_add_tail(&req->queuelist, &nbd->waiting_queue);
		spin_unlock_irqrestore(&nbd->lock, flags);

		wake_up(&nbd->waiting_wq);
	}
}

static int do_disconnect_ioctl(struct nbd_device *nbd, struct block_device *bdev)
{
	struct request sreq;

	dev_info(disk_to_dev(nbd->disk), "NBD_DISCONNECT\n");
	if (!nbd->sock)
		return -EINVAL;

	fsync_bdev(bdev);
	blk_rq_init(NULL, &sreq);
	sreq.cmd_type = DEP_REQ_TYPE_SPECIAL;
	nbd_cmd(&sreq) = NBD_CMD_DISC;

	/* Check again after getting mutex back.  */
	if (!nbd->sock)
		return -EINVAL;

	if (nbd_send_req(nbd, &sreq) != 0)
		printk(KERN_ERR "%s: Error sending NBD_DISCONNECT\n", nbd->disk->disk_name);

	return 0;
}

static int do_query_hash_ioctl(struct nbd_device *nbd, struct block_device *bdev, unsigned long arg)
{
	nbd_query_blkhash_t * nbd_qhash = NULL;
	struct request *qreq; /* use our own locally allocated struct... */
	int retval = 0, err;

	dprintk( DBG_QHASH, "%s: NBD_QUERY_HASH\n", nbd->disk->disk_name);
	nbd_qhash = kzalloc( sizeof(nbd_query_blkhash_t), GFP_NOIO );
	if (!nbd_qhash)
		return -ENOMEM;

	qreq = kzalloc( sizeof(struct request), GFP_NOIO );
	blk_rq_init(NULL, qreq);

	/* Copy cmd arguments from user space */
	if (copy_from_user( (char *)nbd_qhash, (nbd_query_blkhash_t *)arg, sizeof(nbd_query_blkhash_t))) {
		printk( KERN_ERR "ERROR: Copying query_hash ioctl() user-space arg\n");
		retval = -EINVAL;
		goto qhash_exit;
	}

	dprintk( DBG_QHASH, "INFO: query_hash() blkaddr= %llu, blksize=%d, blkcount= %d\n",
		nbd_qhash->blkaddr, nbd_qhash->blksize, nbd_qhash->blkcount );

	/* if socket is not connected, exit... */
	if (!nbd->sock) {
		printk( KERN_ERR "ERROR: Socket not connected! query_hash() failed!\n");
		retval = -EPIPE;
		goto qhash_exit;
	}

	mutex_lock(&nbd->qhash_lock); /* only ONE query hash req in flight (synchronous req) */

	/* _____________________________________
	 * setup the command request header... */
	qreq->cmd_type = DEP_REQ_TYPE_SPECIAL;
	nbd_cmd(qreq) = NBD_CMD_QHASH;

	/* NOTE: assuming a sector size= 512 bytes! */
	qreq->__sector = (nbd_qhash->blkaddr * (uint64_t)nbd_qhash->blksize) >> 9;
	/* the following fields have been removed from the struct request in kernel v. 3.x
	qreq->hard_nr_sectors = nbd_qhash->blksize >> 9; // == blocksize
	qreq->nr_sectors = nbd_qhash->blkcount; // == blkcount
	*/
	qreq->special = nbd_qhash; /* pass the pointer along */

	{	/* Debug block */
		int qp = atomic_inc_return(&nbd->qhash_pending);
			
		if ( qp != 1 )
			printk( KERN_ALERT "%s ERROR: qhash_pending: %d != 1\n", nbd->disk->disk_name, qp );

		BUG_ON( qp != 1 ); /* ONLY ONE SHOULD BE IN PROGRESS */
	}

	INIT_COMPLETION(nbd->qhash_wait);
	qreq->completion_data = (void *) &nbd->qhash_wait;
	nbd->qhash_req = qreq;
	set_req_response_deadline(nbd); /* set response deadlines for new request */
	if ( nbd_send_req(nbd, qreq) == 0 ) {
		dprintk( DBG_QHASH, "SENT QHASH REQ: qreq= 0x%p\n", qreq );
		/* ______________________________________________________________________________________________
		 * OK, query_hash() request was sent... let the async handler wake us on completion... */

		dprintk( DBG_QHASH, "WAITING FOR QHASH REQ COMPLETION!\n");
qcompl_wait:
		// IMPORTANT: NO NEED to unlock the tx while waiting to prevent deadlocks,
		//            but it limits async I/O running while the cmd has not completed!! (FIXME?)
		err = wait_for_completion_interruptible( (struct completion *)qreq->completion_data);
		if (unlikely(err)) {
			printk( KERN_ERR "ERROR: query_hash ioctl() interrupted with %d !\n", err);
			if (err == -ERESTARTSYS)
				goto qcompl_wait;
		}
	} else { /* send req error, don't wait... */
		dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: Error sending QHash... exiting\n", nbd->disk->disk_name);
		if ( atomic_read(&nbd->qhash_pending) > 0 ) /* pending qhash reqs? */
			atomic_dec( &nbd->qhash_pending );
		qreq->errors++;
	}

	nbd->qhash_req = NULL;
	reset_req_response_deadline(nbd); /* reset response deadlines appropriately */
	mutex_unlock(&nbd->qhash_lock); /* only ONE query hash req in flight (synchronous req) */
	dprintk(DBG_QHASH, "%s QHash COMPLETED: blkmap= 0x%llx!\n", nbd->disk->disk_name, nbd_qhash->blkmap );
	/* Flag error, if not set already */
	if (qreq->errors) {
		retval = -EINVAL;
	} else if (copy_to_user( (nbd_query_blkhash_t *)arg, (char *)nbd_qhash, sizeof(nbd_query_blkhash_t))) {
		/* Return hash data back to user... */
		printk( KERN_ERR "ERROR: Copying query_hash ioctl() data to user space\n");
		retval = -EINVAL;
	}

	dprintk( DBG_QHASH, "------ QHASH CMD Exiting -------\n");
qhash_exit:
	kfree( nbd_qhash );
	kfree( qreq );
	return retval;
}

static int do_query_hashbat_ioctl(struct nbd_device *nbd, struct block_device *bdev, unsigned long arg)
{
	nbd_query_blkhashbat_t * nbd_qhashb = NULL;
	struct request *qreq; /* use our own locally allocated struct... */
	int retval = 0, err;

	dprintk( DBG_QHASH, "%s: NBD_QUERY_HASH_BAT\n", nbd->disk->disk_name);
	nbd_qhashb = kzalloc( sizeof(nbd_query_blkhashbat_t), GFP_NOIO );
	if (!nbd_qhashb)
		return -ENOMEM;

	qreq = kzalloc( sizeof(struct request), GFP_NOIO );
	blk_rq_init(NULL, qreq);

	/* Copy cmd arguments from user space */
	if (copy_from_user( (char *)nbd_qhashb, (nbd_query_blkhashbat_t *)arg, sizeof(nbd_query_blkhashbat_t))) {
		printk( KERN_ERR "ERROR: Copying query_hashb ioctl() user-space arg\n");
		retval = -EINVAL;
		goto qhashb_exit;
	}

	dprintk( DBG_QHASH, "INFO: query_hashb() blkaddr= %llu, blksize=%d, blkcount= %d\n",
		nbd_qhashb->blkaddr, nbd_qhashb->blksize, nbd_qhashb->blkcount );

	/* if socket is not connected, exit... */
	if (!nbd->sock) {
		printk( KERN_ERR "ERROR: Socket not connected! query_hashb() failed!\n");
		retval = -EPIPE;
		goto qhashb_exit;
	}

	mutex_lock(&nbd->qhash_lock); /* only ONE query hash req in flight (synchronous req) */
	/* _____________________________________
	 * setup the command request header... */
	qreq->cmd_type = DEP_REQ_TYPE_SPECIAL;
	nbd_cmd(qreq) = NBD_CMD_QHASHB;
	/* NOTE: assuming a sector size= 512 bytes! */
	qreq->__sector = (nbd_qhashb->blkaddr * (uint64_t)nbd_qhashb->blksize) >> 9;
	qreq->special = nbd_qhashb; /* pass the pointer along */
	{	/* Debug block */
		int qp = atomic_inc_return(&nbd->qhash_pending);
		if ( qp != 1 )
			printk( KERN_ALERT "%s ERROR: qhash_pending: %d != 1\n", nbd->disk->disk_name, qp );

		BUG_ON( qp != 1 ); /* ONLY ONE SHOULD BE IN PROGRESS */
	}

	INIT_COMPLETION(nbd->qhash_wait);
	qreq->completion_data = (void *) &nbd->qhash_wait;
	nbd->qhash_req = qreq;
	set_req_response_deadline(nbd); /* set response deadlines for new request */
	if ( nbd_send_req(nbd, qreq) == 0 ) {
		dprintk( DBG_QHASH, "SENT QHASH_BAT REQ: qreq= 0x%p\n", qreq );
		/* ______________________________________________________________________________________________
		 * OK, query_hashb() request was sent... let the async handler wake us on completion... */
		dprintk( DBG_QHASH, "WAITING FOR QHASH_BAT REQ COMPLETION!\n");
qbcompl_wait:
		// IMPORTANT: NO NEED to unlock the tx while waiting to prevent deadlocks,
		//            but it limits async I/O running while the cmd has not completed!! (FIXME?)
		err = wait_for_completion_interruptible( (struct completion *)qreq->completion_data);
		if (unlikely(err)) {
			printk( KERN_ERR "ERROR: query_hashb ioctl() interrupted with %d !\n", err);
			if (err == -ERESTARTSYS)
				goto qbcompl_wait;
		}
	} else { /* send req error, don't wait... */
		dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: Error sending QHash_Bat... exiting\n", nbd->disk->disk_name);
		if ( atomic_read(&nbd->qhash_pending) > 0 ) /* pending qhash reqs? */
			atomic_dec( &nbd->qhash_pending );
		qreq->errors++;
	}

	nbd->qhash_req = NULL;
	reset_req_response_deadline(nbd); /* reset response deadlines appropriately */
	mutex_unlock(&nbd->qhash_lock); /* only ONE query hash req in flight (synchronous req) */
	dprintk(DBG_QHASH, "%s QHash_Bat COMPLETED: blkmap= 0x%llx!\n", nbd->disk->disk_name, nbd_qhashb->blkmap );
	/* Flag error, if not set already */
	if (qreq->errors) {
		retval = -EINVAL;
	} else if (copy_to_user( (nbd_query_blkhashbat_t *)arg, (char *)nbd_qhashb, sizeof(nbd_query_blkhashbat_t))) {
		/* Return hash data back to user... */
		printk( KERN_ERR "ERROR: Copying query_hashb ioctl() data to user space\n");
		retval = -EINVAL;
	}

	dprintk( DBG_QHASH, "------ QHASH_BAT CMD Exiting -------\n");
qhashb_exit:
	kfree( nbd_qhashb );
	kfree( qreq );
	return retval;
}

static int do_conn_info_ioctl(struct nbd_device *nbd, struct block_device *bdev, unsigned long arg)
{
	nbd_conn_info_t * nbd_cinfo = NULL;
	int retval = 0;

	dprintk(DBG_IOCMDS, "%s: NBD_CONN_INFO\n", nbd->disk->disk_name);
	nbd_cinfo = kzalloc( sizeof(nbd_conn_info_t), GFP_KERNEL );
	if (!nbd_cinfo)
		return -ENOMEM;

	/* Copy cmd arguments from user space */
	if (copy_from_user( (char *)nbd_cinfo, (nbd_conn_info_t *)arg, sizeof(nbd_conn_info_t))) {
		printk( KERN_ERR "ERROR: Copying conn_info ioctl() user-space arg\n");
		retval = -EINVAL;
		goto cinfo_exit;
	}

	if ( nbd_cinfo->set_info ) { /* SET INFO */
		dprintk(DBG_IOCMDS, "INFO: conn_info() set_info=%u SET INFO\nconnected=%u, cidata=%s\n",
			nbd_cinfo->set_info, nbd_cinfo->connected, nbd_cinfo->cidata );

		/* Ignore connected info, just store the info details into the nbd struct field */
		if ( !nbd->file || !nbd->sock || /* NOT CONNECTED, IGNORE SET INFO CALL! */
			nbd_cinfo->pid != current->pid || /* Allow only same pid (i.e. nbd-client process) */
			nbd->conn_info.pid != current->pid) { /* with pid that called the NBD_SET_SOCK ioctl */
			printk( KERN_ERR "conn_info() ERROR: not connected, or different PID from client!\n");
			retval = -EINVAL;
			goto cinfo_exit;
		}

		memcpy( (char *)&nbd->conn_info, nbd_cinfo, sizeof(nbd_conn_info_t) ); /* copy connection info */
		nbd->conn_info.pid = current->pid;
		nbd->conn_info.connected = 1;
		/* add nbd feature info and nbd build info in cidata, if there is space available */
		if ( strlen(nbd->conn_info.cidata) <
			CONN_INFO_LEN - strlen(NBD_FEATURE_SET) - strlen(__nbd_build_date_id) - 20 ) {

			memset( nbd->conn_info.cidata, 0, CONN_INFO_LEN); /* clean cidata */
			sprintf(nbd->conn_info.cidata, "%s nbdfeat=%s build=%s", nbd_cinfo->cidata, NBD_FEATURE_SET, __nbd_build_date_id );
		/* add nbd feature info in cidata */
		} else if ( strlen(nbd->conn_info.cidata) < CONN_INFO_LEN - strlen(NBD_FEATURE_SET) - 12 ) {
			memset( nbd->conn_info.cidata, 0, CONN_INFO_LEN); /* clean cidata */
			sprintf(nbd->conn_info.cidata, "%s nbdfeat=%s", nbd_cinfo->cidata, NBD_FEATURE_SET );
		} else {
			printk( KERN_ERR "NBD_CONN_INFO ERROR: Not enough space %d for nbd feature set data in cidata field!\n",
				(int)CONN_INFO_LEN - (int)strlen(NBD_FEATURE_SET) - 12);
		}
		dprintk(DBG_IOCMDS, "INFO: conn_info() set_info=%u SET INFO\nconnected=%u, cidata=%s\n",
			nbd->conn_info.set_info, nbd->conn_info.connected, nbd->conn_info.cidata );
	} else { /* GET INFO */
		if (!nbd->file || !nbd->sock) { /* NOT CONNECTED */
			nbd_cinfo->connected = 0;
			memset( nbd_cinfo, 0, sizeof(nbd_conn_info_t) ); /* clear connection info */
			memset( &nbd->conn_info, 0, sizeof(nbd_conn_info_t) ); /* clear stored connection info */
		} else { /* CONNECTED */
			memset( nbd_cinfo, 0, sizeof(nbd_conn_info_t) ); /* clear connection info */
			nbd_cinfo->connected = 1;
			nbd_cinfo->pid = nbd->pid;
			if ( strlen(nbd->conn_info.cidata) > 0 ) {
				memcpy( nbd_cinfo->cidata, nbd->conn_info.cidata, CONN_INFO_LEN-1);
			}
		}
		dprintk(DBG_IOCMDS, "INFO: conn_info() set_info=%u GET INFO\nconnected=%u, pid=%u, cidata=%s\n",
			nbd_cinfo->set_info, nbd_cinfo->connected, nbd_cinfo->pid, nbd_cinfo->cidata );

	}

	/* Flag error, if not set already */
	if (copy_to_user( (nbd_conn_info_t *)arg, (char *)nbd_cinfo, sizeof(nbd_conn_info_t))) {
		/* Return connection info data back to user... */
		printk( KERN_ERR "ERROR: Copying conn_info ioctl() data to user space\n");
		retval = -EINVAL;
		goto cinfo_exit;
	}

cinfo_exit:
	kfree( nbd_cinfo );
	return retval;
}

static int do_server_cmd_ioctl(struct nbd_device *nbd, struct block_device *bdev, unsigned long arg)
{
	nbd_server_cmd_t * nbd_srvcmd = NULL;
	struct request *creq; /* use our own locally allocated struct... */
	int retval = 0, err;

	dprintk(DBG_IOCMDS, "%s: NBD_SERVER_CMD\n", nbd->disk->disk_name);
	nbd_srvcmd = kzalloc( sizeof(nbd_server_cmd_t), GFP_NOIO );
	if (!nbd_srvcmd)
		return -ENOMEM;

	creq = kzalloc( sizeof(struct request), GFP_NOIO );
	blk_rq_init(NULL, creq);

	/* Copy cmd arguments from user space */
	if (copy_from_user( (char *)nbd_srvcmd, (nbd_server_cmd_t *)arg, sizeof(nbd_server_cmd_t))) {
		printk( KERN_ERR "ERROR: Copying srv_cmd ioctl() user-space arg\n");
		retval = -EINVAL;
		goto srvcmd_exit;
	}

	if (!nbd->file || !nbd->sock) { /* NOT CONNECTED */
		memset( nbd_srvcmd, 0, sizeof(nbd_server_cmd_t)); /* clean up the response buffer... */
		nbd_srvcmd->err_code = 1;
		nbd_srvcmd->connected = 0;
		sprintf( nbd_srvcmd->cmdbytes, "ERROR: Not connected");
		retval = -EPIPE;
		goto srvcmd_ioctl_resp;
	} else { /* CONNECTED */
		nbd_srvcmd->connected = 1;
		nbd_srvcmd->err_code = 0;
		mutex_lock(&nbd->srvcmd_lock); /* only ONE server cmd or server cmd req in flight (synchronous req) */
		/* _____________________________________
		 * setup the command request header... */
		creq->cmd_type = DEP_REQ_TYPE_SPECIAL;
		nbd_cmd(creq) = NBD_CMD_SRVCMD;
		/* NOTE: assuming a sector size= 512 bytes! */
		creq->__sector = 0;
		/* the following fields have been removed from the struct request in kernel v. 2.6.3x
		creq->hard_nr_sectors = nbd_qhash->blksize >> 9; // == blocksize
		creq->nr_sectors = nbd_qhash->blkcount; // == blkcount
		*/
		creq->special = nbd_srvcmd; /* pass the pointer along */
		{	/* Debug block */
			int cp = atomic_inc_return(&nbd->srvcmd_pending);
			if ( cp != 1 )
				printk( KERN_ALERT "%s ERROR: srvcmd_pending: %d != 1\n", nbd->disk->disk_name, cp );

			BUG_ON( cp != 1 ); /* ONLY ONE SHOULD BE IN PROGRESS */
		}

		INIT_COMPLETION(nbd->srvcmd_wait);
		creq->completion_data = (void *) &nbd->srvcmd_wait;
		nbd->srvcmd_req = creq;
		set_req_response_deadline(nbd); /* set response deadlines for new request */
		if ( nbd_send_req(nbd, creq) == 0 ) {
			dprintk( DBG_IOCMDS, "SENT SERVER_CMD REQ: creq= 0x%p\n", creq );
			/* ______________________________________________________________________________________________
			 * OK, server_cmd() request was sent... let the async handler wake us on completion... */
			dprintk( DBG_IOCMDS, "WAITING FOR SERVER CMD REQ COMPLETION!\n");
scompl_wait:
			// IMPORTANT: NO NEED to unlock the tx while waiting to prevent deadlocks,
			//            but it limits async I/O running while the cmd has not completed!! (FIXME?)
			err = wait_for_completion_interruptible( (struct completion *)creq->completion_data);
			if (unlikely(err)) {
				printk( KERN_ERR "ERROR: server_cmd ioctl() interrupted with %d !\n", err);
				if (err == -ERESTARTSYS)
					goto scompl_wait;
			}
		} else { /* send req error, don't wait... */
			dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: Error sending server cmd... exiting\n", nbd->disk->disk_name);
			if ( atomic_read(&nbd->srvcmd_pending) > 0 ) /* pending srvcmd reqs? */
				atomic_dec( &nbd->srvcmd_pending );
			creq->errors++;
		}

		nbd->srvcmd_req = NULL;
		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */
		mutex_unlock(&nbd->srvcmd_lock); /* only ONE server cmd or server cmd req in flight (synchronous req) */
		dprintk(DBG_IOCMDS, "%s SERVER_CMD COMPLETED!\n", nbd->disk->disk_name );
		/* Flag error, if not set already */
		if (creq->errors) {
			memset( nbd_srvcmd, 0, sizeof(nbd_server_cmd_t)); /* clean up the response buffer... */
			nbd_srvcmd->err_code = 1;
			sprintf( nbd_srvcmd->cmdbytes, "ERROR: nbd connection error");
			retval = -EINVAL;
		}

		nbd_srvcmd->connected = (nbd->file && nbd->sock) ? 1 : 0; /* still connected? */

	}

srvcmd_ioctl_resp:
	dprintk(DBG_IOCMDS, "srv_cmd() INFO: connected=%u, err_code=%u, cmdbytes=\"%s\"\n",
		nbd_srvcmd->connected, nbd_srvcmd->err_code, nbd_srvcmd->cmdbytes );

	/* Flag error, if not set already */
	if (copy_to_user( (nbd_server_cmd_t *)arg, (char *)nbd_srvcmd, sizeof(nbd_server_cmd_t))) {
		/* Return connection info data back to user... */
		printk( KERN_ERR "ERROR: Copying srv_cmd ioctl() data to user space\n");
		retval = -EINVAL;
	}

	dprintk( DBG_IOCMDS, "------ SERVER CMD IOCTL Exiting -------\n");
srvcmd_exit:
	kfree( nbd_srvcmd );
	kfree( creq );
	return retval;
}

static int do_do_it_ioctl(struct nbd_device *nbd, struct block_device *bdev)
{
	struct task_struct *thread;
	struct file *file;
	int error;

	if (nbd->pid)
		return -EBUSY;
	if (!nbd->file)
		return -EINVAL;

	if (nbd->flags & NBD_FLAG_SEND_TRIM)
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, nbd->disk->queue);

	disarm_response_timer( nbd ); /* cleanup any timer leftovers from a previous instance */
	/* ATTENTION: Initialize any instance-specific values HERE, because the nbd device may be re-used, e.g. after an error! */
	atomic_set( &nbd->qhash_pending, 0 );
	atomic_set( &nbd->srvcmd_pending, 0 );
#ifdef ENABLE_REQ_DEBUG
	atomic_set( &nbd->req_total, 0 );
	atomic_set( &nbd->req_total_rd, 0 );
	atomic_set( &nbd->req_total_wr, 0 );
	atomic_set( &nbd->req_inprogr, 0 );
	atomic_set( &nbd->req_inprogr_rd, 0 );
	atomic_set( &nbd->req_inprogr_wr, 0 );
#endif

	sk_set_memalloc(nbd->sock->sk);
	nbd->pid = task_pid_nr(current);
	nbd->client_task = current; /* ready for a kill */

	error = device_create_file(disk_to_dev(nbd->disk), &pid_attr);
	if (error) {
		dev_err(disk_to_dev(nbd->disk), "device_create_file failed!\n");
		nbd->pid = 0;
		return error;
	}

	thread = kthread_create(nbd_thread, nbd, nbd->disk->disk_name);
	if (IS_ERR(thread)) {
		return PTR_ERR(thread);
	}
	wake_up_process(thread);
	error = nbd_do_it(nbd);
	kthread_stop(thread);
	printk(KERN_ERR "%s: EXITING: stopped kthread, got error %d...\n", nbd->disk->disk_name, error );
	if (error)
		return error;
	sock_shutdown(nbd);
	file = nbd->file;
	nbd->file = NULL;
	nbd_clear_que(nbd);
	BUG_ON(!list_empty(&nbd->queue_head));
	BUG_ON(!list_empty(&nbd->waiting_queue));
	kill_bdev(bdev);
	queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD, nbd->disk->queue);
	if (file)
		fput(file);
	nbd->bytesize = 0;
	bdev->bd_inode->i_size = 0;
	set_capacity(nbd->disk, 0);
	nbd->pid = 0;
	nbd->flags = 0;
	nbd->client_task = NULL;
	if (max_part > 0)
		ioctl_by_bdev(bdev, BLKRRPART, 0);
	return nbd->harderror;
}

static int do_blkflsbuff_ioctls(struct nbd_device *nbd)
{
	struct request *creq; /* use our own locally allocated struct... */
	int retval = 0, err;

	if ( !(nbd->flags & NBD_FLAG_SEND_FLUSH) ) { /* ignore FLUSH, not supported? */
		dprintk(DBG_IOCMDS, "%s: IGNORING flush-buffer-cache\n", nbd->disk->disk_name);
		return 0;
	}

	dprintk(DBG_IOCMDS, "%s: GOT flush-buffer-cache\n", nbd->disk->disk_name);
	creq = kzalloc( sizeof(struct request), GFP_NOIO );
	if (!creq)
		return -ENOMEM;
	
	blk_rq_init(NULL, creq);
	if (!nbd->file || !nbd->sock) { /* NOT CONNECTED, IGNORE */
		retval = -EPIPE;

	} else { /* CONNECTED */
		mutex_lock(&nbd->srvcmd_lock); // only ONE server cmd or server cmd req in flight (synchronous req)
		// setup the command request header...
		creq->cmd_type = DEP_REQ_TYPE_SPECIAL;
		nbd_cmd(creq) = NBD_CMD_FLUSH;
		{	// Debug block 
			int cp = atomic_inc_return(&nbd->srvcmd_pending);
			if ( cp != 1 )
				printk( KERN_ALERT "%s ERROR: flush srvcmd_pending: %d != 1\n", nbd->disk->disk_name, cp );

			BUG_ON( cp != 1 ); // ONLY ONE SHOULD BE IN PROGRESS
		}

		INIT_COMPLETION(nbd->srvcmd_wait);
		creq->completion_data = (void *) &nbd->srvcmd_wait;
		nbd->srvcmd_req = creq;
		set_req_response_deadline(nbd); // set response deadlines for new request
		if ( nbd_send_req(nbd, creq) == 0 ) {
			dprintk( DBG_IOCMDS, "SENT FLUSH REQ: creq= 0x%p\n", creq );
			// OK, FLUSH request was sent... let the async handler wake us on completion...
			dprintk( DBG_IOCMDS, "WAITING FOR FLUSH REQ COMPLETION!\n");
fcompl_wait:
			// IMPORTANT: NO NEED to unlock the tx while waiting to prevent deadlocks,
			//            but it limits async I/O running while the cmd has not completed!! (FIXME?)
			err = wait_for_completion_interruptible( (struct completion *)creq->completion_data);
			if (unlikely(err)) {
				printk( KERN_ERR "ERROR: BLKFLSBUF ioctl() interrupted with %d !\n", err);
				if (err == -ERESTARTSYS)
					goto fcompl_wait;
			}
		} else { // send req error, don't wait... 
			dev_err_ratelimited(disk_to_dev(nbd->disk), "%s: Error sending FLUSH cmd... aborting\n", nbd->disk->disk_name);
			if ( atomic_read(&nbd->srvcmd_pending) > 0 ) // pending srvcmd reqs? 
				atomic_dec( &nbd->srvcmd_pending );
			creq->errors++;
		}
		nbd->srvcmd_req = NULL;
		reset_req_response_deadline(nbd); // reset response deadlines appropriately 
		mutex_unlock(&nbd->srvcmd_lock); // only ONE server cmd or server cmd req in flight (synchronous req)
		dprintk(DBG_IOCMDS, "%s FLUSH COMPLETED!\n", nbd->disk->disk_name );
		// Check and return any error 
		if (creq->errors)
			retval = -EIO;
	}

	dprintk( DBG_IOCMDS, "------ FLUSH IOCTL Exiting -------\n");
	kfree( creq );
	return retval;
}

static int nbd_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	struct nbd_device *nbd = bdev->bd_disk->private_data;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	// Anyone capable of this syscall can do *real bad* things 
	dprintk(DBG_IOCTL, "%s: nbd_ioctl cmd=%s(0x%x) arg=%lu\n",
		nbd->disk->disk_name, ioctl_cmd_to_ascii(cmd), cmd, arg);

	switch (cmd) {
	case NBD_DISCONNECT:
		return do_disconnect_ioctl(nbd, bdev);

	case NBD_QUERY_HASH:
		return do_query_hash_ioctl(nbd, bdev, arg);

	case NBD_QUERY_HASHB:
		return do_query_hashbat_ioctl(nbd, bdev, arg);

	case NBD_SET_FLAGS: /* flags sent by the user-level nbd-client -> received from nbd-server */
		nbd->flags = (unsigned)arg;
		printk(KERN_ALERT "%s: set flags to 0x%x\n", nbd->disk->disk_name, nbd->flags );
		return 0;

	case NBD_CONN_INFO:
		return do_conn_info_ioctl(nbd, bdev, arg);

	case NBD_SERVER_CMD:
		return do_server_cmd_ioctl(nbd, bdev, arg);

	case NBD_CLEAR_SOCK: {
		struct file *file;

		nbd->sock = NULL;
		file = nbd->file;
		nbd->file = NULL;
		nbd_clear_que(nbd);
		BUG_ON(!list_empty(&nbd->queue_head));
		BUG_ON(!list_empty(&nbd->waiting_queue));
		kill_bdev(bdev);
		if (file)
			fput(file);

		return 0;
	}

	case NBD_SET_SOCK: {
		struct file *file;
		//printk(KERN_ALERT "%s: NBD_SET_SOCK CALL\n", nbd->disk->disk_name );
		if (nbd->file)
			return -EBUSY;
		file = fget(arg);
		if (file) {
			struct inode *inode = file->f_path.dentry->d_inode;
			if (S_ISSOCK(inode->i_mode)) {
				nbd->file = file;
				nbd->sock = SOCKET_I(inode);
				nbd->sock->sk->sk_allocation = GFP_NOIO | __GFP_MEMALLOC;
				if (max_part > 0)
					bdev->bd_invalidated = 1;
				memset( &nbd->conn_info, 0, sizeof(nbd_conn_info_t) ); /* clear stored connection info */
				nbd->conn_info.pid = current->pid; /* Store this to check pid that may call set NBD_CONN_INFO */
				return 0;
			} else {
				fput(file);
			}
		}
		return -EINVAL;
	}

	case NBD_SET_BLKSIZE:
		nbd->blksize = arg;
		nbd->bytesize &= ~(nbd->blksize-1);
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		return 0;

	case NBD_SET_SIZE:
		nbd->bytesize = arg & ~(nbd->blksize-1);
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		return 0;

	case NBD_SET_TIMEOUT:
	{
		int old_xmit_timeout = nbd->xmit_timeout;

		if ( arg >= 0 && arg <= 1000 ) {
			nbd->xmit_timeout = arg * HZ;

			printk(KERN_ALERT "%s: NBD_SET_TIMEOUT: timeout changed from %d -> %d seconds\n",
					nbd->disk->disk_name, old_xmit_timeout/HZ, nbd->xmit_timeout/HZ );
		} else {
			printk(KERN_ALERT "%s: NBD_SET_TIMEOUT: timeout remains %d seconds (0 <= t <= 1000)\n",
					nbd->disk->disk_name, nbd->xmit_timeout/HZ );
		}
		return 0;
	}
	case NBD_SET_SIZE_BLOCKS:
		nbd->bytesize = ((u64) arg) * nbd->blksize;
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		return 0;

	case NBD_DO_IT:
		return do_do_it_ioctl(nbd, bdev);

	case NBD_CLEAR_QUE:
		/*
		 * This is for compatibility only.  The queue is always cleared
		 * by NBD_DO_IT or NBD_CLEAR_SOCK.
		 */
		BUG_ON(!nbd->sock && !list_empty(&nbd->queue_head));
		return 0;

	case NBD_PRINT_DEBUG:
		dev_info(disk_to_dev(nbd->disk),
			"next = %p, prev = %p, head = %p\n",
			nbd->queue_head.next, nbd->queue_head.prev,
			&nbd->queue_head);
		print_debug_info( nbd );
		return 0;

	case BLKFLSBUF: // Flush buffers command -> sent to server as server cmd... 
	// NOTE: this is invoked via cli as: "/sbin/blockdev --flushbufs /dev/nbdX" 
		return do_blkflsbuff_ioctls(nbd);
	} // switch(cmd) 

	return -ENOTTY;
}

static const struct block_device_operations nbd_fops =
{
	.owner =	THIS_MODULE,
	.ioctl =	nbd_ioctl,
	.compat_ioctl = nbd_ioctl,
};

/*
 * And here should be modules and kernel interface 
 *  (Just smiley confuses emacs :-)
 */

static int __init nbd_init(void)
{
	int err = -ENOMEM;
	int i = 0;
	int part_shift;

	BUILD_BUG_ON(sizeof(struct nbd_request) != 28);

	if (max_part < 0) {
		printk(KERN_ERR "nbd: max_part must be >= 0\n");
		return -EINVAL;
	}
	if (nbds_max > 4096) {
		printk(KERN_ERR "nbd: supported nbds_max is <= 4096\n");
		return -EINVAL;
	}

	part_shift = 0;
	if (max_part > 0) {
		part_shift = fls(max_part);

		/*
		 * Adjust max_part according to part_shift as it is exported
		 * to user space so that user can know the max number of
		 * partition kernel should be able to manage.
		 *
		 * Note that -1 is required because partition 0 is reserved
		 * for the whole disk.
		 */
		max_part = (1UL << part_shift) - 1;
	}

	if ((1UL << part_shift) > DISK_MAX_PARTS)
		return -EINVAL;

	if (nbds_max > 1UL << (MINORBITS - part_shift))
		return -EINVAL;

	nbd_dev = kcalloc(nbds_max, sizeof(*nbd_dev), GFP_KERNEL);
	if (!nbd_dev)
		return -ENOMEM;

	if (register_blkdev(NBD_MAJOR, "nbd")) {
		err = -EIO;
		goto out;
	}

	for (i = 0; i < NBD_BUILD_STR_MAXLEN; i++ )
		__nbd_build_date_id[i] = __nbd_build_date_id[i] != ' ' ? __nbd_build_date_id[i] : '_';

	printk(KERN_INFO "%s [Build: %s]: registered device at major %d - nbds max: %d\n",
				NBD_BUILD_ID, __nbd_build_date, NBD_MAJOR, nbds_max);
	dprintk(DBG_INIT, "nbd: debugflags=0x%x\n", debugflags);
	nbd_dbg_init();

	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = NULL;
		nbd_dev[i].file = NULL;
		nbd_dev[i].magic = NBD_MAGIC;
		nbd_dev[i].flags = 0;
		spin_lock_init(&nbd_dev[i].lock);
		INIT_LIST_HEAD(&nbd_dev[i].waiting_queue);
		spin_lock_init(&nbd_dev[i].queue_lock);
		INIT_LIST_HEAD(&nbd_dev[i].queue_head);
		mutex_init(&nbd_dev[i].tx_lock);
		init_waitqueue_head(&nbd_dev[i].waiting_wq);
		nbd_dev[i].blksize = 1024;
		nbd_dev[i].bytesize = 0;
		nbd_dev[i].xmit_timeout = 60 * HZ; /* default timeout: 60 secs */
		//nbd_dev[i].xmit_timeout = 0; /* DISABLED timeout: 0 */
		spin_lock_init(&nbd_dev[i].timer_lock);
		atomic_set( &nbd_dev[i].reqs_in_progress, 0 );
		nbd_dev[i].pid = 0;
		nbd_dev[i].client_task = NULL;

		mutex_init( &nbd_dev[i].qhash_lock );
		mutex_init( &nbd_dev[i].srvcmd_lock );
		atomic_set( &nbd_dev[i].qhash_pending, 0 );
		atomic_set( &nbd_dev[i].srvcmd_pending, 0 );
		init_completion( &nbd_dev[i].qhash_wait );
		init_completion( &nbd_dev[i].srvcmd_wait );
		nbd_dev[i].qhash_req = NULL;
		nbd_dev[i].srvcmd_req = NULL;
#ifdef ENABLE_REQ_DEBUG
		atomic_set( &nbd_dev[i].req_total, 0 );
		atomic_set( &nbd_dev[i].req_total_rd, 0 );
		atomic_set( &nbd_dev[i].req_total_wr, 0 );
		atomic_set( &nbd_dev[i].req_inprogr, 0 );
		atomic_set( &nbd_dev[i].req_inprogr_rd, 0 );
		atomic_set( &nbd_dev[i].req_inprogr_wr, 0 );
#endif

		memset( &nbd_dev[i].conn_info, 0, sizeof(nbd_conn_info_t) ); /* clear connection info */
		disk = alloc_disk(1 << part_shift);
		if (!disk)
			goto out;
		nbd_dev[i].disk = disk;
		/*
		 * The new linux 2.5 block layer implementation requires
		 * every gendisk to have its very own request_queue struct.
		 * These structs are big so we dynamically allocate them.
		 */
		spin_lock_init(&nbd_dev[i].blk_queue_lock);
		disk->queue = blk_init_queue(do_nbd_request, &nbd_dev[i].blk_queue_lock);
		if (!disk->queue) {
			put_disk(disk);
			goto out;
		}
		/*
		 * Tell the block layer that we are not a rotational device
		 */
		queue_flag_set_unlocked(QUEUE_FLAG_NONROT, disk->queue);
		/* set max sectors for io requests in this queue (i.e. req split limit) */
		disk->queue->limits.discard_granularity = 512;
		disk->queue->limits.max_discard_sectors = UINT_MAX;
		disk->queue->limits.discard_zeroes_data = 0;
		blk_queue_max_hw_sectors(disk->queue, 65535);
		disk->major = NBD_MAJOR;
		disk->first_minor = i << part_shift;
		disk->fops = &nbd_fops;
		disk->private_data = &nbd_dev[i];
		sprintf(disk->disk_name, "nbd%d", i);
		set_capacity(disk, 0);
		add_disk(disk);
		nbd_dbg_add_device(&nbd_dev[i]);
	}

#ifdef NBD_DEBUG_CMDS
	memset( last_requests, 0, MAX_LAST_ITEMS*sizeof(struct nbd_request) );
	memset( last_replies, 0, MAX_LAST_ITEMS*sizeof(struct nbd_reply) );
#endif

	return 0;
out:
	while (i--) {
		blk_cleanup_queue(nbd_dev[i].disk->queue);
		put_disk(nbd_dev[i].disk);
		nbd_dbg_del_device(&nbd_dev[i]);
	}
	kfree(nbd_dev);
	return err;
}

static void __exit nbd_cleanup(void)
{
	int i;
	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = nbd_dev[i].disk;
		nbd_dev[i].magic = 0;
		if (disk) {
			del_gendisk(disk);
			blk_cleanup_queue(disk->queue);
			put_disk(disk);
			nbd_dbg_del_device(&nbd_dev[i]);
		}
	}
	nbd_dbg_close();
	unregister_blkdev(NBD_MAJOR, "nbd");
	kfree(nbd_dev);
	printk(KERN_INFO "nbd: unregistered device at major %d\n", NBD_MAJOR);
}

module_init(nbd_init);
module_exit(nbd_cleanup);

MODULE_DESCRIPTION("Network Block Device");
MODULE_LICENSE("GPL");

module_param(nbds_max, int, 0444);
MODULE_PARM_DESC(nbds_max, "number of network block devices to initialize (default: 16, max: 4096)");
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "number of partitions per device (default: 0)");
#ifndef NDEBUG
module_param(debugflags, int, 0644);
MODULE_PARM_DESC(debugflags, "flags for controlling debug output");
#endif
