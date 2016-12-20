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
 * 2012/04/09 Michail Flouris <michail.flouris@onapp.com>
 *            Added query hash ioctl command and several bug fixes
 * 2012/06/27 Michail Flouris <michail.flouris@onapp.com>
 *            Added rolling timeout of requests killing hanging connections
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
#include <linux/compat.h>
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

static unsigned int nbds_max = 16;
static struct nbd_device *nbd_dev;
static int max_part;

#define NBD_BUILD_ID	"nbd_OA_346"
#define NBD_BUILD_STR_MAXLEN	42
static char __nbd_build_date_id[NBD_BUILD_STR_MAXLEN] = NBD_BUILD_ID";"__DATE__"-"__TIME__;
static char __nbd_build_date[NBD_BUILD_STR_MAXLEN] = __DATE__" "__TIME__; // store the nbd build date here

#ifndef INIT_COMPLETION
#define INIT_COMPLETION(x) reinit_completion(&x)
#endif

/*
 * Use just one lock (or at most 1 per NIC). Two arguments for this:
 * 1. Each NIC is essentially a synchronization point for all servers
 *    accessed through that NIC so there's no need to have more locks
 *    than NICs anyway.
 * 2. More locks lead to more "Dirty cache line bouncing" which will slow
 *    down each lock to the point where they're actually slower than just
 *    a single lock.
 * Thanks go to Jens Axboe and Al Viro for their LKML emails explaining this!
 */
static DEFINE_SPINLOCK(nbd_lock);

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
#endif /* NDEBUG */


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

			printk( KERN_ALERT "%s: [%d] REQ %p: %s @ Addr: %llu Size: %u (Bytes) [ERR: %d, cmd_type: 0x%x]\n",
					nbd->disk->disk_name, rcount++, req, nbdcmd_to_ascii(nbd_cmd(req)),
					(unsigned long long)blk_rq_pos(req) << 9, blk_rq_bytes(req),
					req->errors, req->cmd_type);
		}
		spin_unlock_irqrestore(&nbd->queue_lock, flags);
	}
}


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

#define SHUTDOWN_UNLOCK_TIMEOUT_SEC	20

static void nbd_unlock_timeout(unsigned long arg)
{
	struct nbd_device *nbd = (struct nbd_device *)arg;

	if ( mutex_is_locked(&nbd->tx_lock) ) {
		printk(KERN_ERR "%s: nbd_unlock_timeout() UNLOCKING tx_lock after %d seconds!\n",
					nbd->disk->disk_name, SHUTDOWN_UNLOCK_TIMEOUT_SEC );
		mutex_unlock(&nbd->tx_lock);
	}
}

static void
lock_auto_unlockable_mutex(struct nbd_device *nbd, const char *funcname)
{
	struct timer_list uti;
	int unlock_timer_enabled = 0;

	/* if lock is already locked, WARN of the upcoming deadlock and
	 * unlock it by force within SHUTDOWN_UNLOCK_TIMEOUT_SEC seconds! */
	if ( mutex_is_locked(&nbd->tx_lock) ) {

		printk(KERN_ERR "%s: %s() WARNING: LOCKED tx_lock, will auto unlock in %d sec!\n",
				nbd->disk->disk_name, funcname, SHUTDOWN_UNLOCK_TIMEOUT_SEC );

		init_timer(&uti);
		uti.function = nbd_unlock_timeout;
		uti.data = (unsigned long)nbd;
		uti.expires = jiffies + (SHUTDOWN_UNLOCK_TIMEOUT_SEC * HZ);
		add_timer(&uti);

		unlock_timer_enabled = 1; /* timer enabled */
	}

	mutex_lock(&nbd->tx_lock); /* ok, now lock it... */

	if ( unlock_timer_enabled ) { /* did we have to set the timer? if yes, then disable it! */

		del_timer(&uti); /* this works in inactive timers too... */
	}
}

static void sock_shutdown(struct nbd_device *nbd, int lock)
{
	/* Forcibly shutdown the socket causing all listeners
	 * to error
	 *
	 * FIXME: This code is duplicated from sys_shutdown, but
	 * there should be a more generic interface rather than
	 * calling socket ops directly here */
	if (lock)
		lock_auto_unlockable_mutex(nbd, "sock_shutdown");

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
	if (lock)
		mutex_unlock(&nbd->tx_lock);
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
 *  Send or receive packet.
 */
static int sock_xmit(struct nbd_device *nbd, int send, void *buf, int size,
		int msg_flags)
{
	int result, curr_timeout = nbd->xmit_timeout;
	struct socket *sock = nbd->sock;
	struct msghdr msg;
	struct kvec iov;
	sigset_t blocked, oldset;

	if (unlikely(!sock)) {
		if ( ! nbd->errmsg_last_time || jiffies >= nbd->errmsg_last_time + (3*HZ) ) {
#ifdef ENABLE_REQ_DEBUG
			printk(KERN_ERR "%s: Attempted %s on closed socket in sock_xmit [pendRQ:%d R:%d W:%d]\n",
			       nbd->disk->disk_name, (send ? "send" : "recv"),atomic_read(&nbd->req_inprogr),
				   atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
			dev_err(disk_to_dev(nbd->disk),
				"Attempted %s on closed socket in sock_xmit\n",
				(send ? "send" : "recv"));
#endif
			nbd->errmsg_last_time = jiffies;
		}
		return -EINVAL;
	}

	/* Allow interception of SIGKILL only
	 * Don't allow other signals to interrupt the transmission */
	siginitsetinv(&blocked, sigmask(SIGKILL));
	sigprocmask(SIG_SETMASK, &blocked, &oldset);

	do {
		sock->sk->sk_allocation = GFP_NOIO;
		iov.iov_base = buf;
		iov.iov_len = size;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = msg_flags | MSG_NOSIGNAL;

		if (send) {
			struct timer_list ti;

			if (curr_timeout) {
				init_timer(&ti);
				ti.function = nbd_xmit_timeout;
				ti.data = (unsigned long)current;
				ti.expires = jiffies + curr_timeout;
				add_timer(&ti);
			}
			result = kernel_sendmsg(sock, &msg, &iov, 1, size);
			if (curr_timeout)
				del_timer_sync(&ti);
		} else
			result = kernel_recvmsg(sock, &msg, &iov, 1, size,
						msg.msg_flags);

		if (signal_pending(current)) {
			siginfo_t info;
			printk(KERN_WARNING "%s: (pid %d: %s) got signal %d (locked: %d, send: %d)\n",
				nbd->disk->disk_name, task_pid_nr(current), current->comm,
				dequeue_signal_lock(current, &current->blocked, &info),
				mutex_is_locked(&nbd->tx_lock), send );
			result = -EINTR;
			/* NOTE: sock_shutdown has auto-unlockable tx_lock (via timeout) */
			sock_shutdown(nbd, !send);
			printk(KERN_WARNING "%s: (pid %d: %s) socket shut down OK... lock: %d\n",
				nbd->disk->disk_name, task_pid_nr(current), current->comm,
				mutex_is_locked(&nbd->tx_lock) );
			break;
		}

		if (result <= 0) {
			if (result == 0)
				result = -EPIPE; /* short read */
			break;
		}
		size -= result;
		buf += result;
	} while (size > 0);

	sigprocmask(SIG_SETMASK, &oldset, NULL);

	return result;
}

static inline int sock_send_bvec(struct nbd_device *nbd, struct bio_vec *bvec,
		int flags)
{
	int result;
	void *kaddr = kmap(bvec->bv_page);
	result = sock_xmit(nbd, 1, kaddr + bvec->bv_offset, bvec->bv_len, flags);
	kunmap(bvec->bv_page);
	return result;
}

/* always call with the tx_lock held */
static int nbd_send_req(struct nbd_device *nbd, struct request *req)
{
	int result, flags = 0, bcount = 0;
	struct nbd_request request;
	unsigned long size = blk_rq_bytes(req);

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(nbd_cmd(req));
	request.from = cpu_to_be64((u64)blk_rq_pos(req) << 9);
	request.len = htonl(size);
	memcpy(request.handle, &req, sizeof(req));

	dprintk(DBG_TX, "%s: request %p: sending control (%s@%llu,%uB)\n",
			nbd->disk->disk_name, req,
			nbdcmd_to_ascii(nbd_cmd(req)),
			(unsigned long long)blk_rq_pos(req) << 9,
			blk_rq_bytes(req));
	if ( nbd_cmd(req) == NBD_CMD_WRITE ||
		( req->cmd_type == REQ_TYPE_SPECIAL && nbd_cmd(req) == NBD_CMD_QHASH ) ||
		( req->cmd_type == REQ_TYPE_SPECIAL && nbd_cmd(req) == NBD_CMD_QHASHB ) )
		flags = MSG_MORE;
#ifdef NBD_DEBUG_CMDS
	assert( last_req_cnt >= 0 && last_req_cnt <= MAX_LAST_ITEMS );
	memcpy( &last_requests[last_req_cnt], &request, sizeof (request) );
	if ( last_req_cnt++ >= MAX_LAST_ITEMS )
		last_req_cnt = 0;
#endif

	result = sock_xmit(nbd, 1, &request, sizeof(request), flags );
	if (result <= 0) {
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ERR "%s: Send control failed (result %d) [pendRQ:%d R:%d W:%d]\n",
				nbd->disk->disk_name, result,atomic_read(&nbd->req_inprogr),
				atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
		dev_err(disk_to_dev(nbd->disk),
			"Send control failed (result %d)\n", result);
#endif
		goto error_out;
	}

	bcount += sizeof(request);
	dprintk(DBG_TX, "%s: WRITE request %p: CONTROL SENT: %d bytes [flags= %d]\n",
					nbd->disk->disk_name, req, bcount, flags);

	if (nbd_cmd(req) == NBD_CMD_WRITE) {
		struct req_iterator iter;
		struct bio_vec *bvec;
		/*
		 * we are really probing at internals to determine
		 * whether to set MSG_MORE or not...
		 */
		rq_for_each_segment(bvec, req, iter) {
			flags = 0;
			if (!rq_iter_last(req, iter))
				flags = MSG_MORE;
			dprintk(DBG_TX, "%s: request %p: sending %d bytes data [flags= %d]\n",
					nbd->disk->disk_name, req, bvec->bv_len, flags);
			result = sock_send_bvec(nbd, bvec, flags);
			bcount += bvec->bv_len;
			if (result <= 0) {
#ifdef ENABLE_REQ_DEBUG
				printk(KERN_ERR "%s: Send data failed (result %d) [pendRQ:%d R:%d W:%d]\n",
						nbd->disk->disk_name, result,atomic_read(&nbd->req_inprogr),
						atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
				dev_err(disk_to_dev(nbd->disk),
					"Send data failed (result %d)\n", result);
#endif
				goto error_out;
			}
		}

		dprintk(DBG_TX, "%s: WRITE request %p: DONE - SENT: %d bytes [flags= %d]\n",
						nbd->disk->disk_name, req, bcount, flags);

	} else if ( req->cmd_type == REQ_TYPE_SPECIAL &&
			  ( nbd_cmd(req) == NBD_CMD_QHASH || nbd_cmd(req) == NBD_CMD_QHASHB ) ) {
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
		result = sock_xmit(nbd, 1, &qhreq, sizeof(nbd_qhash_request_t), 0 /* last */);
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

	} else if ( req->cmd_type == REQ_TYPE_SPECIAL && nbd_cmd(req) == NBD_CMD_SRVCMD ) {
		/* special processing for srvcmd requests... */
		nbd_server_cmd_t * nbd_srvcmd = req->special;

		/* should translate to network order for nbd server... */
		nbd_srvcmd->connected =  htons( nbd_srvcmd->connected );
		nbd_srvcmd->err_code = htons( nbd_srvcmd->err_code );

		dprintk( DBG_IOCMDS, "SRVCMD REQ Sending %d bytes\n", (int)sizeof(nbd_server_cmd_t));

		result = sock_xmit(nbd, 1, nbd_srvcmd, sizeof(nbd_server_cmd_t), 0 /* last */);
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
	}
	return 0;

error_out:
	return -EIO;
}

static struct request *nbd_find_request(struct nbd_device *nbd,
					struct request *xreq)
{
	struct request *req, *tmp;
	unsigned long flags;
	int err;

wait:
	err = wait_event_interruptible(nbd->active_wq, nbd->active_req != xreq);
	if (unlikely(err)) {
		if (err == -ERESTARTSYS)
			goto wait;
		goto out;
	}

	spin_lock_irqsave(&nbd->queue_lock, flags);
	list_for_each_entry_safe(req, tmp, &nbd->queue_head, queuelist) {
		if (req != xreq)
			continue;
		list_del_init(&req->queuelist);
		spin_unlock_irqrestore(&nbd->queue_lock, flags);
		return req;
	}
	spin_unlock_irqrestore(&nbd->queue_lock, flags);

	err = -ENOENT;

out:
	return ERR_PTR(err);
}

static inline int sock_recv_bvec(struct nbd_device *nbd, struct bio_vec *bvec)
{
	int result;
	void *kaddr = kmap(bvec->bv_page);
	result = sock_xmit(nbd, 0, kaddr + bvec->bv_offset, bvec->bv_len,
			MSG_WAITALL);
	kunmap(bvec->bv_page);
	return result;
}

/* NULL returned = something went wrong, inform userspace */
static struct request *nbd_read_stat(struct nbd_device *nbd)
{
	int result;
	struct nbd_reply reply;
	struct request *req;

	reply.magic = 0;
	result = sock_xmit(nbd, 0, &reply, sizeof(struct nbd_reply), MSG_WAITALL);
	if (result <= 0) {
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ERR "%s: Receive control failed (result %d) [pendRQ:%d R:%d W:%d]\n",
				nbd->disk->disk_name, result, atomic_read(&nbd->req_inprogr),
				atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
		dev_err(disk_to_dev(nbd->disk),
			"Receive control failed (result %d)\n", result);
#endif
		goto harderror;
	}
	dprintk(DBG_QHASH|DBG_IOCMDS, "%s RESP: == ENTER == GOT REPLY ==========\n", nbd->disk->disk_name );
	dprintk(DBG_QHASH|DBG_IOCMDS, "%s RESP: Received nbd_reply: %u bytes\n", nbd->disk->disk_name, (unsigned)sizeof(struct nbd_reply));

#ifdef NBD_DEBUG_CMDS
	assert( last_rep_cnt >= 0 && last_rep_cnt <= MAX_LAST_ITEMS );
	memcpy( &last_replies[last_rep_cnt], &reply, sizeof (struct nbd_reply) );
	if ( last_rep_cnt++ >= MAX_LAST_ITEMS )
		last_rep_cnt = 0;
#endif

	if (ntohl(reply.magic) != NBD_REPLY_MAGIC) {
		dev_err(disk_to_dev(nbd->disk), "Wrong magic (0x%lx)\n",
				(unsigned long)ntohl(reply.magic));
		result = -EPROTO;
		goto harderror;
	}

	if ( atomic_read(&nbd->qhash_pending) > 0 ) { /* pending qhash reqs? */
		struct request *qreq;

		memcpy( &qreq, (char *) reply.handle, sizeof(qreq) );

		dprintk(DBG_QHASH, "%s RESP: Checking for Query Hash reply! (%d pending reqs, qreq= %p)\n",
						nbd->disk->disk_name, atomic_read(&nbd->qhash_pending), qreq );

	   	if ( qreq->cmd_type == REQ_TYPE_SPECIAL && nbd_cmd(qreq) == NBD_CMD_QHASH) {

			/* NOTE: we don't recv the response directly into the ioctl buffer, because
			 *       we will need to check & convert the values received... */
			nbd_query_blkhash_t *recv_qh = kzalloc( sizeof(nbd_query_blkhash_t), GFP_NOIO );
			nbd_query_blkhash_t *nbd_qhash = qreq->special; /* get the ioctl-waiting struct... */

			dprintk(DBG_QHASH, "%s RESP: Received Query Hash reply! (req %p)\n",
							nbd->disk->disk_name, qreq);
			
			if (ntohl(reply.error)) {

				qreq->errors++;

				if ( ! nbd->errmsg_last_time || jiffies >= nbd->errmsg_last_time + (3*HZ) ) {
					printk(KERN_ERR "%s: QHash: Other side returned error (%d)\n",
							nbd->disk->disk_name, (int)ntohl(reply.error));
					nbd->errmsg_last_time = jiffies;
				}

			} else { /* Handle successful request... read the hash data (only if NOT error) */

				dprintk(DBG_QHASH, "%s RESP: Receiving Query Hash reply: %d bytes\n",
				   		nbd->disk->disk_name, (int)sizeof(nbd_query_blkhash_t) );

				/* receive the hash data (i.e. nbd_query_blkhash_t) */
				result = sock_xmit(nbd, 0, recv_qh, sizeof(nbd_query_blkhash_t), MSG_WAITALL);
				if (result <= 0) {
					printk(KERN_ERR "%s: Receiveing hash data failed (result %d)\n",
							nbd->disk->disk_name, result);
					kfree( recv_qh );
					goto harderror;
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

			dprintk(DBG_QHASH, "%s RESP: ===== EXIT == QHASH =============\n", nbd->disk->disk_name );
			return qreq;

		} else if ( qreq->cmd_type == REQ_TYPE_SPECIAL && nbd_cmd(qreq) == NBD_CMD_QHASHB ) {

			/* NOTE: we don't recv the response directly into the ioctl buffer, because
			 *       we will need to check & convert the values received... */
			nbd_query_blkhashbat_t *recv_qh = kzalloc( sizeof(nbd_query_blkhashbat_t), GFP_NOIO );
			nbd_query_blkhashbat_t *nbd_qhash = qreq->special; /* get the ioctl-waiting struct... */

			dprintk(DBG_QHASH, "%s RESP: Received Query Hash Bat reply! (req %p)\n",
							nbd->disk->disk_name, qreq);
			
			if (ntohl(reply.error)) {

				qreq->errors++;

				if ( ! nbd->errmsg_last_time || jiffies >= nbd->errmsg_last_time + (3*HZ) ) {
					printk(KERN_ERR "%s: QHashB: Other side returned error (%d)\n",
							nbd->disk->disk_name, (int)ntohl(reply.error));
					nbd->errmsg_last_time = jiffies;
				}

			} else { /* Handle successful request... read the hash data (only if NOT error) */

				dprintk(DBG_QHASH, "%s RESP: Receiving Query Hash Bat reply: %d bytes\n",
				   		nbd->disk->disk_name, (int)sizeof(nbd_query_blkhashbat_t) );

				/* receive the hash data (i.e. nbd_query_blkhashbat_t) */
				result = sock_xmit(nbd, 0, recv_qh, sizeof(nbd_query_blkhashbat_t), MSG_WAITALL);
				if (result <= 0) {
					printk(KERN_ERR "%s: Receiving hash batch data failed (result %d)\n",
							nbd->disk->disk_name, result);
					kfree( recv_qh );
					goto harderror;
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

			dprintk(DBG_QHASH, "%s RESP: ===== EXIT == QHASHB =============\n", nbd->disk->disk_name );
			return qreq;
		}
	}

	if ( atomic_read(&nbd->srvcmd_pending) > 0 ) { /* pending srvcmd reqs? */
		struct request *creq;

		memcpy( &creq, (char *) reply.handle, sizeof(creq) );

		dprintk(DBG_IOCMDS, "%s RESP: Checking for Server CMD reply! (%d pending reqs, creq= %p)\n",
						nbd->disk->disk_name, atomic_read(&nbd->srvcmd_pending), creq );

	   	if ( creq->cmd_type == REQ_TYPE_SPECIAL && nbd_cmd(creq) == NBD_CMD_SRVCMD) {

			/* NOTE: we don't recv the response directly into the ioctl buffer, because
			 *       we will need to check & convert the values received... */
			nbd_server_cmd_t *recv_sc = kzalloc( sizeof(nbd_server_cmd_t), GFP_NOIO );
			nbd_server_cmd_t *nbd_srvcmd = creq->special; /* get the ioctl-waiting struct... */

			dprintk(DBG_IOCMDS, "%s RESP: Received Server CMD reply! (req %p)\n",
							nbd->disk->disk_name, creq);
			
			memset( nbd_srvcmd, 0, sizeof(nbd_server_cmd_t)); /* clean up the response buffer... */

			if (ntohl(reply.error)) {

				creq->errors++;

				if ( ! nbd->errmsg_last_time || jiffies >= nbd->errmsg_last_time + (3*HZ) ) {
					printk(KERN_ERR "%s: SrvCmd: Other side returned error (%d)\n",
							nbd->disk->disk_name, (int)ntohl(reply.error));
					nbd->errmsg_last_time = jiffies;
				}

			} else { /* Handle successful request... read the cmd response data (only if NOT error) */

				dprintk(DBG_IOCMDS, "%s RESP: Receiving Server CMD reply: %d bytes\n",
				   		nbd->disk->disk_name, (int)sizeof(nbd_server_cmd_t) );

				/* receive the cmd response data (i.e. nbd_server_cmd_t) */
				result = sock_xmit(nbd, 0, recv_sc, sizeof(nbd_server_cmd_t), MSG_WAITALL);
				if (result <= 0) {
					printk(KERN_ERR "%s: Receiveing cmd response data failed (result %d)\n",
							nbd->disk->disk_name, result);
					kfree( recv_sc );
					goto harderror;
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

			dprintk(DBG_IOCMDS, "%s RESP: ===== EXIT == SERVER CMD =============\n", nbd->disk->disk_name );
			return creq;
		}

		/* Is this a FLUSH request? */
		else if ( creq->cmd_type == REQ_TYPE_SPECIAL && nbd_cmd(creq) == NBD_CMD_FLUSH) {

			dprintk(DBG_IOCMDS, "%s RESP: Received FLUSH reply! (req %p)\n",
							nbd->disk->disk_name, creq);
			
			if (ntohl(reply.error)) {

				creq->errors++;

				if ( ! nbd->errmsg_last_time || jiffies >= nbd->errmsg_last_time + (3*HZ) ) {
					printk(KERN_ERR "%s: FLUSH: Other side returned error (%d)\n",
							nbd->disk->disk_name, (int)ntohl(reply.error));
					nbd->errmsg_last_time = jiffies;
				}

			} else { /* Handle successful request, completing the ioctl... */

				dprintk(DBG_IOCMDS, "%s RESP: FLUSH: SUCCESS!\n", nbd->disk->disk_name );
			}

			atomic_dec( &nbd->srvcmd_pending );

			dprintk(DBG_IOCMDS, "%s RESP: ===== EXIT == FLUSH CMD =============\n", nbd->disk->disk_name );
			return creq;
		}
	}

	req = nbd_find_request(nbd, *(struct request **)reply.handle);
	if (IS_ERR(req)) {
		result = PTR_ERR(req);
		if (result != -ENOENT)
			goto harderror;

		dev_err(disk_to_dev(nbd->disk), "Unexpected reply (%p)\n",
			reply.handle);
		result = -EBADR;
		goto harderror;
	}

	if (ntohl(reply.error)) {
		dev_err(disk_to_dev(nbd->disk), "Other side returned error (%d)\n",
			ntohl(reply.error));
		dump_last_requests(nbd);
		req->errors++;
		return req;
	}

	dprintk(DBG_RX, "%s: request %p: got reply\n",
			nbd->disk->disk_name, req);
	if (nbd_cmd(req) == NBD_CMD_READ) {
		struct req_iterator iter;
		struct bio_vec *bvec;

		rq_for_each_segment(bvec, req, iter) {
			result = sock_recv_bvec(nbd, bvec);
			if (result <= 0) {
#ifdef ENABLE_REQ_DEBUG
				printk(KERN_ERR "%s: Receive data failed (result %d) [pendRQ:%d R:%d W:%d]\n",
						nbd->disk->disk_name, result, atomic_read(&nbd->req_inprogr),
						atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
				dev_err(disk_to_dev(nbd->disk), "Receive data failed (result %d)\n",
					result);
#endif
				dump_last_requests(nbd);
				req->errors++;
				return req;
			}
			dprintk(DBG_RX, "%s: request %p: got %d bytes data\n",
				nbd->disk->disk_name, req, bvec->bv_len);
		}
	}
	return req;

harderror:
	dump_last_requests(nbd);
	nbd->harderror = result;
	return NULL;
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
	int ret;

	BUG_ON(nbd->magic != NBD_MAGIC);
	disarm_response_timer( nbd ); /* cleanup any timer leftovers from a previous instance */

	if ( !nbd->xmit_timeout )
		printk(KERN_ALERT "%s INIT: xmit timeout: DISABLED\n", nbd->disk->disk_name );
	else
		printk(KERN_ALERT "%s INIT: Using xmit timeout: %d seconds\n", nbd->disk->disk_name, nbd->xmit_timeout/HZ );

	if (nbd->active_req != NULL || atomic_read(&nbd->qhash_pending) || !list_empty(&nbd->waiting_queue) || !list_empty(&nbd->queue_head) )
		printk(KERN_ALERT "%s INIT: WARNING! active_req: %p, qhash_pending: %d, EMPTY: waiting_queue= %d, queue_head= %d\n",
				nbd->disk->disk_name, nbd->active_req, atomic_read(&nbd->qhash_pending),
				list_empty(&nbd->waiting_queue), list_empty(&nbd->queue_head) );

	/* ATTENTION: Initialize any instance-specific values HERE, because the nbd device may be re-used, e.g. after an error! */
	nbd->errmsg_last_time = 0;
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

	nbd->pid = task_pid_nr(current);
	nbd->client_task = current; /* ready for a kill */

	ret = device_create_file(disk_to_dev(nbd->disk), &pid_attr);
	if (ret) {
		dev_err(disk_to_dev(nbd->disk), "device_create_file failed!\n");
		nbd->pid = 0;
		return ret;
	}

	while ((req = nbd_read_stat(nbd)) != NULL) {
		if (req->cmd_type == REQ_TYPE_SPECIAL &&
			( nbd_cmd(req) == NBD_CMD_QHASH || nbd_cmd(req) == NBD_CMD_SRVCMD ||
			  nbd_cmd(req) == NBD_CMD_FLUSH || nbd_cmd(req) == NBD_CMD_QHASHB ) ) { /* qhash or srvcmd req? */
			complete( (struct completion *)req->completion_data );
		} else {

			reset_req_response_deadline(nbd); /* reset response deadlines appropriately */

#ifdef ENABLE_REQ_DEBUG
			atomic_dec( &nbd->req_inprogr );
			if (rq_data_dir(req) == WRITE)
				atomic_dec( &nbd->req_inprogr_wr );
			else
				atomic_dec( &nbd->req_inprogr_rd );
#endif
			nbd_end_request(req);
		}
	}
	//printk(KERN_ALERT "%s : NBD thread exiting...\n", nbd->disk->disk_name );

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

	BUG_ON(nbd->magic != NBD_MAGIC);

	/*
	 * Because we have set nbd->sock to NULL under the tx_lock, all
	 * modifications to the list must have completed by now.  For
	 * the same reason, the active_req must be NULL.
	 *
	 * As a consequence, we don't need to take the spin lock while
	 * purging the list here.
	 */
	BUG_ON(nbd->sock);
	BUG_ON(nbd->active_req);

	while (!list_empty(&nbd->queue_head)) {
		req = list_entry(nbd->queue_head.next, struct request,
				 queuelist);
		list_del_init(&req->queuelist);
		req->errors++;

		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */

		if (req->cmd_type == REQ_TYPE_SPECIAL ) {
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
		req = list_entry(nbd->waiting_queue.next, struct request,
			queuelist);
		list_del_init(&req->queuelist);
		req->errors++;

		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */

		if (req->cmd_type == REQ_TYPE_SPECIAL ) {
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
	if (req->cmd_type != REQ_TYPE_FS)
		goto error_out;

#ifdef ENABLE_REQ_DEBUG
	atomic_inc( &nbd->req_total );

	nbd_cmd(req) = NBD_CMD_READ;
	if (rq_data_dir(req) == WRITE) {
		nbd_cmd(req) = NBD_CMD_WRITE;
		if (nbd->flags & NBD_READ_ONLY) {
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
		nbd_cmd(req) = NBD_CMD_WRITE;
		if (nbd->flags & NBD_READ_ONLY) {
			dev_err(disk_to_dev(nbd->disk),
				"Write on read-only\n");
			goto error_out;
		}
	}
#endif

	req->errors = 0;

	mutex_lock(&nbd->tx_lock);
	if (unlikely(!nbd->sock)) {
		mutex_unlock(&nbd->tx_lock);

		if ( ! nbd->errmsg_last_time || jiffies >= nbd->errmsg_last_time + (3*HZ) ) {
#ifdef ENABLE_REQ_DEBUG
			printk(KERN_ERR "%s: Attempted send on closed socket [pendRQ:%d R:%d W:%d]\n",
			       nbd->disk->disk_name, atomic_read(&nbd->req_inprogr),
				   atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
			dev_err(disk_to_dev(nbd->disk),
				"Attempted send on closed socket\n");
#endif
			nbd->errmsg_last_time = jiffies;
		}
		goto error_out;
	}

	set_req_response_deadline(nbd); /* set response deadlines for new request */

	nbd->active_req = req;

	if (nbd_send_req(nbd, req) != 0) {

		reset_req_response_deadline(nbd); /* reset response deadlines appropriately */

#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ERR "%s: Request send failed [pendRQ:%d R:%d W:%d]\n",
				nbd->disk->disk_name, atomic_read(&nbd->req_inprogr),
				atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
		dev_err(disk_to_dev(nbd->disk), "Request send failed\n");
#endif
		dump_last_requests(nbd);
		req->errors++;
		nbd_end_request(req);
#ifdef ENABLE_REQ_DEBUG
		if (rq_data_dir(req) == WRITE)
			atomic_dec( &nbd->req_inprogr_wr );
		else
			atomic_dec( &nbd->req_inprogr_rd );
#endif
	} else {
		unsigned long flags;

		spin_lock_irqsave(&nbd->queue_lock, flags);
		list_add_tail(&req->queuelist, &nbd->queue_head);
		spin_unlock_irqrestore(&nbd->queue_lock, flags);
#ifdef ENABLE_REQ_DEBUG
		atomic_inc( &nbd->req_inprogr );
#endif
	}

	nbd->active_req = NULL;
	mutex_unlock(&nbd->tx_lock);
	wake_up_all(&nbd->active_wq);

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
		wait_event_interruptible(nbd->waiting_wq,
					 kthread_should_stop() ||
					 !list_empty(&nbd->waiting_queue));

		/* extract request */
		if (list_empty(&nbd->waiting_queue))
			continue;

		spin_lock_irqsave(&nbd->queue_lock, flags);
		req = list_entry(nbd->waiting_queue.next, struct request,
				 queuelist);
		list_del_init(&req->queuelist);
		spin_unlock_irqrestore(&nbd->queue_lock, flags);

		/* handle request */
		nbd_handle_req(nbd, req);

		//dprintk(DBG_BLKDEV, "%s: request %p: DONE, get next one\n",
		//		req->rq_disk->disk_name, req );
	}
	return 0;
}

/*
 * We always wait for result of write, for now. It would be nice to make it optional
 * in future
 * if ((rq_data_dir(req) == WRITE) && (nbd->flags & NBD_WRITE_NOCHK))
 *   { printk( "Warning: Ignoring result!\n"); nbd_end_request( req ); }
 */

static void do_nbd_request(struct request_queue *q)
{
	struct request *req;
	
	while ((req = blk_fetch_request(q)) != NULL) {
		struct nbd_device *nbd;

		spin_unlock_irq(q->queue_lock);

		/* RUNTIME DEBUG: Printing out all I/O requests... */
		dprintk(DBG_BLKDEV, "%s: request %p: dequeued (cmd_type=%ux) [%s@%llu, %uB]\n",
				req->rq_disk->disk_name, req, req->cmd_type,
				nbdcmd_to_ascii(nbd_cmd(req)),
				(unsigned long long)blk_rq_pos(req) << 9, blk_rq_bytes(req) );

		nbd = req->rq_disk->private_data;

		BUG_ON(nbd->magic != NBD_MAGIC);

		if (unlikely(!nbd->sock)) {

			if ( ! nbd->errmsg_last_time || jiffies >= nbd->errmsg_last_time + (3*HZ) ) {
#ifdef ENABLE_REQ_DEBUG
				printk(KERN_ERR "%s: Attempted send on closed socket [pendRQ:%d R:%d W:%d]\n",
				       nbd->disk->disk_name, atomic_read(&nbd->req_inprogr),
					   atomic_read(&nbd->req_inprogr_rd), atomic_read(&nbd->req_inprogr_wr) );
#else
				dev_err(disk_to_dev(nbd->disk),
					"Attempted send on closed socket\n");
#endif
				nbd->errmsg_last_time = jiffies;
			}
			req->errors++;
			nbd_end_request(req);

			spin_lock_irq(q->queue_lock);
			disarm_response_timer( nbd );
			continue;
		}

		spin_lock_irq(&nbd->queue_lock);
		list_add_tail(&req->queuelist, &nbd->waiting_queue);
		spin_unlock_irq(&nbd->queue_lock);

		wake_up(&nbd->waiting_wq);

		spin_lock_irq(q->queue_lock);
	}
}

/* Must be called with tx_lock held */

static int __nbd_ioctl(struct block_device *bdev, struct nbd_device *nbd,
		     unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NBD_DISCONNECT: {
		struct request sreq;

		dev_info(disk_to_dev(nbd->disk), "NBD_DISCONNECT\n");
		if (!nbd->sock)
			return -EINVAL;

		mutex_unlock(&nbd->tx_lock);
		fsync_bdev(bdev);
		mutex_lock(&nbd->tx_lock);
		blk_rq_init(NULL, &sreq);
		sreq.cmd_type = REQ_TYPE_SPECIAL;
		nbd_cmd(&sreq) = NBD_CMD_DISC;

		/* Check again after getting mutex back.  */
		if (!nbd->sock)
			return -EINVAL;
		if (nbd_send_req(nbd, &sreq) != 0)
			printk(KERN_ERR "%s: Error sending NBD_DISCONNECT\n", nbd->disk->disk_name);
		return 0;
	}
 
	case NBD_QUERY_HASH:
	{
		nbd_query_blkhash_t * nbd_qhash = NULL;
		struct request *qreq; /* use our own locally allocated struct... */
		int retval = 0, err;

		dprintk( DBG_QHASH, "%s: NBD_QUERY_HASH\n", nbd->disk->disk_name);
   		nbd_qhash = kzalloc( sizeof(nbd_query_blkhash_t), GFP_NOIO );
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
		qreq->cmd_type = REQ_TYPE_SPECIAL;
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

		dprintk( DBG_QHASH, "------------\nSENDING QHASH REQ: sector= %llu, req_size=%u bytes\n",
				(unsigned long long)blk_rq_pos(qreq), blk_rq_bytes(qreq) );
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

			printk(KERN_ERR "%s: Error sending QHash... exiting\n", nbd->disk->disk_name);
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

	/* ATTENTION: added NEW batched version of query_hash cmd to allow backward compatibility
	 * with older nbds and/or nbd servers. */
	case NBD_QUERY_HASHB:
	{
		nbd_query_blkhashbat_t * nbd_qhashb = NULL;
		struct request *qreq; /* use our own locally allocated struct... */
		int retval = 0, err;

		dprintk( DBG_QHASH, "%s: NBD_QUERY_HASH_BAT\n", nbd->disk->disk_name);
   		nbd_qhashb = kzalloc( sizeof(nbd_query_blkhashbat_t), GFP_NOIO );
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
		qreq->cmd_type = REQ_TYPE_SPECIAL;
		nbd_cmd(qreq) = NBD_CMD_QHASHB;

		/* NOTE: assuming a sector size= 512 bytes! */
		qreq->__sector = (nbd_qhashb->blkaddr * (uint64_t)nbd_qhashb->blksize) >> 9;
		/* the following fields have been removed from the struct request in kernel v. 3.x
		qreq->hard_nr_sectors = nbd_qhashb->blksize >> 9; // == blocksize
		qreq->nr_sectors = nbd_qhashb->blkcount; // == blkcount
		*/
		qreq->special = nbd_qhashb; /* pass the pointer along */

		{	/* Debug block */
			int qp = atomic_inc_return(&nbd->qhash_pending);
			
			if ( qp != 1 )
				printk( KERN_ALERT "%s ERROR: qhash_pending: %d != 1\n", nbd->disk->disk_name, qp );

			BUG_ON( qp != 1 ); /* ONLY ONE SHOULD BE IN PROGRESS */
		}

		dprintk( DBG_QHASH, "------------\nSENDING QHASH_BAT REQ: sector= %llu, req_size=%u bytes\n",
				(unsigned long long)blk_rq_pos(qreq), blk_rq_bytes(qreq) );
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

			printk(KERN_ERR "%s: Error sending QHash_Bat... exiting\n", nbd->disk->disk_name);
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

	case NBD_SET_FLAGS: /* flags sent by the user-level nbd-client -> received from nbd-server */
		nbd->flags = (unsigned)arg;
		printk(KERN_ALERT "%s: set flags to 0x%x\n", nbd->disk->disk_name, nbd->flags );
		return 0;

	case NBD_CONN_INFO:
	{
		nbd_conn_info_t * nbd_cinfo = NULL;
		int retval = 0;

		dprintk(DBG_IOCMDS, "%s: NBD_CONN_INFO\n", nbd->disk->disk_name);
   		nbd_cinfo = kzalloc( sizeof(nbd_conn_info_t), GFP_KERNEL );

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
#if 0
			if ( nbd_cinfo->connected )
				printk( KERN_DEBUG "%s : GET CONN INFO connected=%u, pid=%u, %s\n",
						nbd->disk->disk_name, nbd_cinfo->connected, nbd_cinfo->pid, nbd_cinfo->cidata );
#endif
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

	case NBD_SERVER_CMD:
	{
		nbd_server_cmd_t * nbd_srvcmd = NULL;
		struct request *creq; /* use our own locally allocated struct... */
		int retval = 0, err;

		dprintk(DBG_IOCMDS, "%s: NBD_SERVER_CMD\n", nbd->disk->disk_name);
   		nbd_srvcmd = kzalloc( sizeof(nbd_server_cmd_t), GFP_NOIO );
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
			creq->cmd_type = REQ_TYPE_SPECIAL;
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

			dprintk( DBG_IOCMDS, "------------\nSENDING SERVER_CMD REQ: sector= %llu, req_size=%u bytes\n",
					(unsigned long long)blk_rq_pos(creq), blk_rq_bytes(creq) );
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

				printk(KERN_ERR "%s: Error sending server cmd... exiting\n", nbd->disk->disk_name);
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

	case NBD_CLEAR_SOCK: {
		struct file *file;

		sock_shutdown(nbd, 0);
		nbd->sock = NULL;
		file = nbd->file;
		nbd->file = NULL;
		nbd_clear_que(nbd);
		BUG_ON(!list_empty(&nbd->queue_head));
		BUG_ON(!list_empty(&nbd->waiting_queue));
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

	case NBD_DO_IT: {
		struct task_struct *thread;
		struct file *file;
		int error;

		if (nbd->pid)
			return -EBUSY;
		if (!nbd->file)
			return -EINVAL;

		mutex_unlock(&nbd->tx_lock);

		thread = kthread_create(nbd_thread, nbd, nbd->disk->disk_name);
		if (IS_ERR(thread)) {
			mutex_lock(&nbd->tx_lock);
			return PTR_ERR(thread);
		}
		wake_up_process(thread);
		error = nbd_do_it(nbd);
		kthread_stop(thread);

		if ( mutex_is_locked(&nbd->tx_lock) ) /* WARN of the upcoming deadlock! */
			printk(KERN_ERR "%s: WARNING: LOCKED tx_lock! deadlock coming up?\n", nbd->disk->disk_name );

		mutex_lock(&nbd->tx_lock);
		printk(KERN_ERR "%s: EXITING: stopped kthread, got tx_lock...\n", nbd->disk->disk_name );
		if (error)
			return error;
		sock_shutdown(nbd, 0);
		file = nbd->file;
		nbd->file = NULL;
		nbd_clear_que(nbd);
		BUG_ON(!list_empty(&nbd->queue_head));
		BUG_ON(!list_empty(&nbd->waiting_queue));
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

	case NBD_CLEAR_QUE:
		/*
		 * This is for compatibility only.  The queue is always cleared
		 * by NBD_DO_IT or NBD_CLEAR_SOCK.
		 */
		BUG_ON(!nbd->sock && !list_empty(&nbd->queue_head));
		return 0;

	case NBD_PRINT_DEBUG:
		printk(KERN_ALERT "%s: next = %p, prev = %p, head = %p\n\n",
			nbd->disk->disk_name,
			nbd->queue_head.next, nbd->queue_head.prev,
			&nbd->queue_head);
		print_debug_info( nbd );
		return 0;

	case BLKFLSBUF: /* Flush buffers command -> sent to server as server cmd... */
	/* NOTE: this is invoked via cli as: "/sbin/blockdev --flushbufs /dev/nbdX" */
	{
		struct request *creq; /* use our own locally allocated struct... */
		int retval = 0, err;

		if ( !(nbd->flags & NBD_FLAG_SEND_FLUSH) ) { /* ignore FLUSH, not supported? */
			dprintk(DBG_IOCMDS, "%s: IGNORING %s\n", nbd->disk->disk_name, ioctl_cmd_to_ascii(cmd));
			return 0;
		}

		dprintk(DBG_IOCMDS, "%s: GOT %s\n", nbd->disk->disk_name, ioctl_cmd_to_ascii(cmd));

   		creq = kzalloc( sizeof(struct request), GFP_NOIO );
		blk_rq_init(NULL, creq);

		if (!nbd->file || !nbd->sock) { /* NOT CONNECTED, IGNORE */

			retval = -EPIPE;

		} else { /* CONNECTED */

			mutex_lock(&nbd->srvcmd_lock); /* only ONE server cmd or server cmd req in flight (synchronous req) */

			/* _____________________________________
			 * setup the command request header... */
			creq->cmd_type = REQ_TYPE_SPECIAL;
			nbd_cmd(creq) = NBD_CMD_FLUSH;

			{	/* Debug block */
				int cp = atomic_inc_return(&nbd->srvcmd_pending);
			
				if ( cp != 1 )
					printk( KERN_ALERT "%s ERROR: flush srvcmd_pending: %d != 1\n", nbd->disk->disk_name, cp );

				BUG_ON( cp != 1 ); /* ONLY ONE SHOULD BE IN PROGRESS */
			}

			dprintk( DBG_IOCMDS, "------------\nSENDING FLUSH REQ: sector= %llu, req_size=%u bytes\n",
					(unsigned long long)blk_rq_pos(creq), blk_rq_bytes(creq) );
			INIT_COMPLETION(nbd->srvcmd_wait);
			creq->completion_data = (void *) &nbd->srvcmd_wait;

			nbd->srvcmd_req = creq;

			set_req_response_deadline(nbd); /* set response deadlines for new request */

			if ( nbd_send_req(nbd, creq) == 0 ) {

				dprintk( DBG_IOCMDS, "SENT FLUSH REQ: creq= 0x%p\n", creq );

				/* ______________________________________________________________________________________________
				 * OK, FLUSH request was sent... let the async handler wake us on completion... */

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

			} else { /* send req error, don't wait... */

				printk(KERN_ERR "%s: Error sending FLUSH cmd... aborting\n", nbd->disk->disk_name);
				if ( atomic_read(&nbd->srvcmd_pending) > 0 ) /* pending srvcmd reqs? */
					atomic_dec( &nbd->srvcmd_pending );
				creq->errors++;
			}

			nbd->srvcmd_req = NULL;

			reset_req_response_deadline(nbd); /* reset response deadlines appropriately */

			mutex_unlock(&nbd->srvcmd_lock); /* only ONE server cmd or server cmd req in flight (synchronous req) */

			dprintk(DBG_IOCMDS, "%s FLUSH COMPLETED!\n", nbd->disk->disk_name );

			/* Check and return any error */
			if (creq->errors)
				retval = -EIO;
		}

		dprintk( DBG_IOCMDS, "------ FLUSH IOCTL Exiting -------\n");
		kfree( creq );
		return retval;
	}

	} /* switch(cmd) */

	return -ENOTTY;
}

static int nbd_ioctl(struct block_device *bdev, fmode_t mode,
		     unsigned int cmd, unsigned long arg)
{
	struct nbd_device *nbd = bdev->bd_disk->private_data;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	BUG_ON(nbd->magic != NBD_MAGIC);

	/* Anyone capable of this syscall can do *real bad* things */
	dprintk(DBG_IOCTL, "%s: nbd_ioctl cmd=%s(0x%x) arg=%lu\n",
		nbd->disk->disk_name, ioctl_cmd_to_ascii(cmd), cmd, arg);

	switch (cmd) { /* on some cmds we auto-unlock... */
	case NBD_DISCONNECT:
	case NBD_CLEAR_SOCK:
	case NBD_CLEAR_QUE:
		lock_auto_unlockable_mutex(nbd, "nbd_ioctl");
	break;
	default:
		mutex_lock(&nbd->tx_lock);
	break;
	}

	error = __nbd_ioctl(bdev, nbd, cmd, arg);
	mutex_unlock(&nbd->tx_lock);

	return error;
}

/* 32-bits of pain on a 64-bit system... */
static int nbd_compat_ioctl(struct block_device *bdev, fmode_t mode,
                           unsigned int cmd, unsigned long arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dprintk(DBG_IOCTL, "COMPAT IOCTL(): cmd=%s(0x%x) arg=%lu\n",
						ioctl_cmd_to_ascii(cmd), cmd, arg);

	switch (cmd) {

	case NBD_QUERY_HASH: /* just make these two compatible... the rest should be native */
	case NBD_QUERY_HASHB:
	case NBD_PRINT_DEBUG:
	case NBD_SET_TIMEOUT:
	case NBD_SET_FLAGS:
	case NBD_CONN_INFO:
	case NBD_SERVER_CMD:
	case NBD_SET_SOCK:
		return nbd_ioctl( bdev, mode, cmd, arg);

	default:
		return -ENOIOCTLCMD;
	}
}

static const struct block_device_operations nbd_fops =
{
	.owner =	THIS_MODULE,
	.ioctl =	nbd_ioctl,
	.compat_ioctl = nbd_compat_ioctl,
};

/*
 * And here should be modules and kernel interface 
 *  (Just smiley confuses emacs :-)
 */

static int __init nbd_init(void)
{
	int err = -ENOMEM;
	int i;
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

	nbd_dev = kcalloc(nbds_max, sizeof(*nbd_dev), GFP_KERNEL);
	if (!nbd_dev)
		return -ENOMEM;

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

	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = alloc_disk(1 << part_shift);
		if (!disk)
			goto out;
		nbd_dev[i].disk = disk;
		/*
		 * The new linux 2.5 block layer implementation requires
		 * every gendisk to have its very own request_queue struct.
		 * These structs are big so we dynamically allocate them.
		 */
		disk->queue = blk_init_queue(do_nbd_request, &nbd_lock);
		if (!disk->queue) {
			put_disk(disk);
			goto out;
		}
		/*
		 * Tell the block layer that we are not a rotational device
		 */
		queue_flag_set_unlocked(QUEUE_FLAG_NONROT, disk->queue);
#if 0
		/* set max sectors for io requests in this queue (i.e. req split limit) */
		//blk_queue_max_sectors( disk->queue, MAX_BIO_PAGES*PAGE_SECTORS );
		// FIXME: use correct calls as in linux-2.6.32-220.el6.x86_64/include/linux/blkdev.h 
		blk_queue_physical_block_size( disk->queue, MAX_BIO_PAGES*PAGE_SECTORS );
		blk_queue_max_segment_size( disk->queue, MAX_BIO_PAGES*PAGE_SIZE );
		blk_queue_segment_boundary( disk->queue, ((MAX_BIO_PAGES*PAGE_SIZE)>>1) - 1);
#endif
		blk_queue_max_hw_sectors(disk->queue, 65536);
#if 0
		blk_queue_logical_block_size(disk->queue, 4096);
		blk_queue_io_opt(disk->queue, 65536);
#endif
	}

	if (register_blkdev(NBD_MAJOR, "nbd")) {
		err = -EIO;
		goto out;
	}

	for (i = 0; i < NBD_BUILD_STR_MAXLEN; i++ )
		__nbd_build_date_id[i] = __nbd_build_date_id[i] != ' ' ? __nbd_build_date_id[i] : '_';

	printk(KERN_INFO "%s [Build: %s]: registered device at major %d - nbds max: %d\n",
				NBD_BUILD_ID, __nbd_build_date, NBD_MAJOR, nbds_max);
	dprintk(DBG_INIT, "nbd: debugflags=0x%x\n", debugflags);

	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = nbd_dev[i].disk;
		nbd_dev[i].file = NULL;
		nbd_dev[i].magic = NBD_MAGIC;
		nbd_dev[i].flags = 0;
		INIT_LIST_HEAD(&nbd_dev[i].waiting_queue);
		spin_lock_init(&nbd_dev[i].queue_lock);
		INIT_LIST_HEAD(&nbd_dev[i].queue_head);
		mutex_init(&nbd_dev[i].tx_lock);
		init_waitqueue_head(&nbd_dev[i].active_wq);
		init_waitqueue_head(&nbd_dev[i].waiting_wq);
		nbd_dev[i].blksize = 1024;
		nbd_dev[i].bytesize = 0;
		nbd_dev[i].xmit_timeout = 60 * HZ; /* default timeout: 60 secs */
		//nbd_dev[i].xmit_timeout = 0; /* DISABLED timeout: 0 */
		spin_lock_init(&nbd_dev[i].timer_lock);
		atomic_set( &nbd_dev[i].reqs_in_progress, 0 );
		nbd_dev[i].pid = 0;
		nbd_dev[i].errmsg_last_time = 0;
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

		disk->major = NBD_MAJOR;
		disk->first_minor = i << part_shift;
		disk->fops = &nbd_fops;
		disk->private_data = &nbd_dev[i];
		sprintf(disk->disk_name, "nbd%d", i);
		set_capacity(disk, 0);
		add_disk(disk);
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
		}
	}
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
