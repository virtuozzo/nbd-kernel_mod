/*
 * Network block device - make block devices work over TCP
 *
 * Note that you can not swap over this thing, yet. Seems to work but
 * deadlocks sometimes - you can not swap over TCP in general.
 * 
 * Copyright 1997-2000 Pavel Machek <pavel@ucw.cz>
 * Parts copyright 2001 Steven Whitehouse <steve@chygwyn.com>
 *
 * This file is released under GPLv2 or later.
 *
 * (part of code stolen from loop.c)
 *
 * 2012/04/09 Michail Flouris <michail.flouris@onapp.com>
 *            Added query hash ioctl command
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
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/types.h>

/* IMPORTANT: we use the LOCAL version of the nbd.h file, not <linux/nbd.h> */
#include "nbd.h"

#define LO_MAGIC 0x68797548

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
#define DBG_BLKDEV      0x0100
#define DBG_RX          0x0200
#define DBG_TX          0x0400
static unsigned int debugflags = 0;
#endif /* NDEBUG */

static unsigned int nbds_max = 16;
static struct nbd_device nbd_dev[MAX_NBD];

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

/* Lock to allow only ONE query hash req in flight (synchronous req) */
static DEFINE_MUTEX(qhash_lock);

atomic_t qhash_pending = ATOMIC_INIT(0); /* how many qhash reqs pending... */

/* global completion (assumes ONE qhash req in flight) */
DECLARE_COMPLETION(qhash_wait);

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
	case NBD_DO_IT: return "do-it";
	case NBD_CLEAR_SOCK: return "clear-sock";
	case NBD_CLEAR_QUE: return "clear-que";
	case NBD_PRINT_DEBUG: return "print-debug";
	case NBD_SET_SIZE_BLOCKS: return "set-size-blocks";
	case NBD_SET_TIMEOUT: return "set-timeout";
	case NBD_DISCONNECT: return "disconnect";
	case NBD_QUERY_HASH: return "query-blk-hash";
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
	case  NBD_CMD_QHASH: return "query_hash";
	}
	return "invalid";
}
#endif /* NDEBUG */


static void
print_queue_info( struct nbd_device *lo )
{
	if (list_empty(&lo->queue_head)) {

		printk( KERN_ALERT "%s: Request Queue is EMPTY\n", lo->disk->disk_name);

	} else {
		struct request *req;
		struct list_head *tmp;
		int rcount = 0;

		printk( KERN_ALERT "%s: Printing Request Queue Info:\n", lo->disk->disk_name);

		spin_lock(&lo->queue_lock);
		list_for_each(tmp, &lo->queue_head) {
			req = list_entry(tmp, struct request, queuelist);

			printk( KERN_ALERT "%s: [%d] REQ %p: %s @ Addr: %llu Size: %lu (Bytes) [ERR: %d, Flags: 0x%lx]\n",
					lo->disk->disk_name, rcount++, req, nbdcmd_to_ascii(nbd_cmd(req)),
					(unsigned long long)req->sector << 9, req->nr_sectors << 9,
					req->errors, req->flags);
		}
		spin_unlock(&lo->queue_lock);
	}
}


static void
dump_last_requests( struct nbd_device *lo )
{
#ifdef NBD_DEBUG_CMDS
	struct nbd_request *rq;
	struct nbd_reply *rp;
	int i;

	if ( lo ) { /* if lo arg provided... */
		printk(KERN_ALERT "\n%s: REQUEST DEBUG INFO\n========================\n", lo->disk->disk_name );

		printk(KERN_ALERT "%s: RESP TIMEOUT = %d sec, reqs_in_progress=%d, sock= 0x%p \n", lo->disk->disk_name,
						lo->xmit_timeout/HZ, lo->reqs_in_progress, lo->sock );
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ALERT "%s: IO Reqs Total: %d (RD: %d, WR: %d) -> In Progress: %d (RD: %d, WR: %d)\n",
			lo->disk->disk_name,
			atomic_read( &lo->req_total ), atomic_read( &lo->req_total_rd ),
			atomic_read( &lo->req_total_wr ), atomic_read( &lo->req_inprogr ),
			atomic_read( &lo->req_inprogr_rd ), atomic_read( &lo->req_inprogr_wr )
			);
#endif

		print_queue_info( lo );
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

static void disarm_response_timer( struct nbd_device *lo )
{
	/* only if timeout is set and timer is armed... */
	if (lo->xmit_timeout) {

		spin_lock(&lo->timer_lock);

		del_timer(&lo->ti); /* this works in inactive timers too... */

		/* Don't need this: del_timer_sync(&lo->ti); */

		spin_unlock(&lo->timer_lock);
	}
}

static void nbd_end_request(struct request *req)
{
	int uptodate = (req->errors == 0) ? 1 : 0;
	request_queue_t *q = req->q;
	unsigned long flags;

	dprintk(DBG_BLKDEV, "%s: request %p: %s\n", req->rq_disk->disk_name,
			req, uptodate? "done": "failed");

	spin_lock_irqsave(q->queue_lock, flags);
	if (!end_that_request_first(req, uptodate, req->nr_sectors)) {
		end_that_request_last(req, uptodate);
	}
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void sock_shutdown(struct nbd_device *lo, int lock)
{
	/* Forcibly shutdown the socket causing all listeners
	 * to error
	 *
	 * FIXME: This code is duplicated from sys_shutdown, but
	 * there should be a more generic interface rather than
	 * calling socket ops directly here */
	if (lock)
		mutex_lock(&lo->tx_lock);

	if (lo->sock) {
		printk(KERN_ALERT "%s: shutting down socket\n",
			lo->disk->disk_name);
		lo->sock->ops->shutdown(lo->sock, SEND_SHUTDOWN);
		/* CAUTION: This is a BUG! Do NOT add the RCV_SHUTDOWN flag !!
		lo->sock->ops->shutdown(lo->sock,
			SEND_SHUTDOWN|RCV_SHUTDOWN); */
		lo->sock = NULL;
		disarm_response_timer( lo );
	}
	if (lock)
		mutex_unlock(&lo->tx_lock);
}

static void nbd_xmit_timeout(unsigned long arg)
{
	struct task_struct *task = (struct task_struct *)arg;

	printk(KERN_ALERT "nbd: killing hung xmit (%s, pid: %d)\n",
		task->comm, task->pid);
	dump_last_requests(NULL);
	force_sig(SIGKILL, task);
}

static void nbd_resp_timeout(unsigned long arg)
{
	struct nbd_device *lo = (struct nbd_device *)arg;

	/* CAUTION: directly shutting down the socket causes a mini kernel panic...
	 *          -> so try to kill the client process with SIGKILL... */
	if ( lo->client_task ) {
		printk(KERN_ALERT "%s: Server not responding after %d seconds - killing client (pid: %d)\n",
							lo->disk->disk_name, lo->xmit_timeout/HZ, lo->client_pid );
		dump_last_requests(lo);
		force_sig(SIGKILL, lo->client_task);
	} else {
		// FIXME: this is dangerous from an interrupt context! use execute_in_process_context() ?
		printk(KERN_ALERT "%s: Server not responding after %d seconds - NULL task, cannot kill client!!\n",
							lo->disk->disk_name, lo->xmit_timeout/HZ );
		dump_last_requests(lo);
		//sock_shutdown(lo, 1); // BAD IDEA: this causes a crash...
	}
	/* NOTE: socket cleanup will be taken care or by the client task exit...*/
}

/* Increases the pending request count and sets the response
 * deadline timer accordingly */
static void set_req_response_deadline( struct nbd_device *lo )
{
	/* only if timeout is set and socket exists... */
	if (lo->xmit_timeout && lo->sock) {

		spin_lock(&lo->timer_lock);

		lo->reqs_in_progress++;

		/* first pending req? arm timer */
		if ( lo->reqs_in_progress == 1 ) {

			init_timer(&lo->ti);
			lo->ti.function = nbd_resp_timeout;
			lo->ti.data = (unsigned long)lo;
			lo->ti.expires = jiffies + lo->xmit_timeout;
			add_timer(&lo->ti);

		} else { /* timer already armed, reset timeout value... */
			assert( lo->reqs_in_progress > 0 );

			/* CAUTION: if the timer is not pending, mod_timer() will RE-ACTIVATE it ! */
			if ( timer_pending(&lo->ti) ) /* test it timer pending... */
				mod_timer(&lo->ti, jiffies + lo->xmit_timeout);
		}

		spin_unlock(&lo->timer_lock);
	}
}

/* Decreases the pending request count and resets the response
 * deadline timer accordingly - if more requests pending, the timer
 * is not reset... */
static void reset_req_response_deadline( struct nbd_device *lo )
{
	/* only if timeout is set and socket exists... */
	if (lo->xmit_timeout && lo->sock) {

		spin_lock(&lo->timer_lock);

		lo->reqs_in_progress--;

		/* last pending req? disarm timer */
		if ( lo->reqs_in_progress == 0 ) {

			del_timer(&lo->ti); /* this works in inactive timers too... */

			/* Don't need this: del_timer_sync(&lo->ti); */

		} else { /* many reqs pending, reset timeout value... */
			assert( lo->reqs_in_progress >= 0 );

			/* CAUTION: if the timer is not pending, mod_timer() will RE-ACTIVATE it ! */
			if ( timer_pending(&lo->ti) ) /* test it timer pending... */
				mod_timer(&lo->ti, jiffies + lo->xmit_timeout);
		}

		spin_unlock(&lo->timer_lock);
	}
}

/*
 *  Send or receive packet.
 */
static int sock_xmit(struct nbd_device *lo, int send, void *buf, int size,
		int msg_flags)
{
	int result;
	struct socket *sock = lo->sock;
	struct msghdr msg;
	struct kvec iov;
	unsigned long flags;
	sigset_t oldset;

	if (unlikely(!sock)) {
		if ( ! lo->errmsg_last_time || jiffies >= lo->errmsg_last_time + (2*HZ) ) {
			printk(KERN_ERR "%s: Attempted %s on closed socket in sock_xmit\n",
			       lo->disk->disk_name, (send ? "send" : "recv"));
			lo->errmsg_last_time = jiffies;
		}
		return -EINVAL;
	}

	/* Allow interception of SIGKILL only
	 * Don't allow other signals to interrupt the transmission */
	spin_lock_irqsave(&current->sighand->siglock, flags);
	oldset = current->blocked;
	sigfillset(&current->blocked);
	sigdelsetmask(&current->blocked, sigmask(SIGKILL));
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);

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

			if (lo->xmit_timeout) {
				init_timer(&ti);
				ti.function = nbd_xmit_timeout;
				ti.data = (unsigned long)current;
				ti.expires = jiffies + lo->xmit_timeout;
				add_timer(&ti);
			}
			result = kernel_sendmsg(sock, &msg, &iov, 1, size);
			if (lo->xmit_timeout)
				del_timer_sync(&ti);
		} else
			result = kernel_recvmsg(sock, &msg, &iov, 1, size, 0);

		if (signal_pending(current)) {
			siginfo_t info;
			spin_lock_irqsave(&current->sighand->siglock, flags);
			printk(KERN_ALERT "nbd (pid %d: %s) got signal %d\n",
				current->pid, current->comm, 
				dequeue_signal(current, &current->blocked, &info));
			spin_unlock_irqrestore(&current->sighand->siglock, flags);
			result = -EINTR;
			sock_shutdown(lo, !send);
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

	spin_lock_irqsave(&current->sighand->siglock, flags);
	current->blocked = oldset;
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);

	return result;
}

static inline int sock_send_bvec(struct nbd_device *lo, struct bio_vec *bvec,
		int flags)
{
	int result;
	void *kaddr = kmap(bvec->bv_page);
	result = sock_xmit(lo, 1, kaddr + bvec->bv_offset, bvec->bv_len, flags);
	kunmap(bvec->bv_page);
	return result;
}

/* always call with the tx_lock held */
static int nbd_send_req(struct nbd_device *lo, struct request *req)
{
	int result, flags = 0, bcount = 0;
	struct nbd_request request;
	unsigned long size = req->nr_sectors << 9;

	request.magic = htonl(NBD_REQUEST_MAGIC);
	request.type = htonl(nbd_cmd(req));
	request.from = cpu_to_be64((u64) req->sector << 9);
	request.len = htonl(size);
	memcpy(request.handle, &req, sizeof(req));

	dprintk(DBG_TX, "%s: request %p: sending control (%s@%llu,%luB)\n",
			lo->disk->disk_name, req,
			nbdcmd_to_ascii(nbd_cmd(req)),
			(unsigned long long)req->sector << 9,
			req->nr_sectors << 9);
	if ( nbd_cmd(req) == NBD_CMD_WRITE ||
		( req->flags == REQ_SPECIAL && nbd_cmd(req) == NBD_CMD_QHASH ) )
		flags = MSG_MORE;
#ifdef NBD_DEBUG_CMDS
	assert( last_req_cnt >= 0 && last_req_cnt <= MAX_LAST_ITEMS );
	memcpy( &last_requests[last_req_cnt], &request, sizeof (request) );
	if ( last_req_cnt++ >= MAX_LAST_ITEMS )
		last_req_cnt = 0;
#endif

	result = sock_xmit(lo, 1, &request, sizeof(request), flags );
	if (result <= 0) {
		printk(KERN_ERR "%s: Send control failed (result %d)\n",
				lo->disk->disk_name, result);
		goto error_out;
	}

	bcount += sizeof(request);
	dprintk(DBG_TX, "%s: WRITE request %p: CONTROL SENT: %d bytes [flags= %d]\n",
					lo->disk->disk_name, req, bcount, flags);

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
					lo->disk->disk_name, req, bvec->bv_len, flags);
			result = sock_send_bvec(lo, bvec, flags);
			bcount += bvec->bv_len;
			if (result <= 0) {
				printk(KERN_ERR "%s: Send data failed (result %d)\n",
						lo->disk->disk_name, result);
				goto error_out;
			}
		}

		dprintk(DBG_TX, "%s: WRITE request %p: DONE - SENT: %d bytes [flags= %d]\n",
						lo->disk->disk_name, req, bcount, flags);

	} else if ( req->flags == REQ_SPECIAL && nbd_cmd(req) == NBD_CMD_QHASH ) {
		/* special processing for qhash requests... */
		nbd_query_blkhash_t * nbd_qhash = req->special;
		nbd_qhash_request_t qhreq;

		dprintk( DBG_QHASH, "QHASH REQ: sending EXTRA req data\n"); // michail
		BUG_ON( req->sector != (nbd_qhash->blkaddr * (uint64_t)nbd_qhash->blksize) >> 9 );
		BUG_ON( req->hard_nr_sectors != nbd_qhash->blksize >> 9 );
		BUG_ON( req->nr_sectors != nbd_qhash->blkcount );
		qhreq.blkaddr = htonl( nbd_qhash->blkaddr );
		qhreq.blksize = htonl( nbd_qhash->blksize );
		qhreq.blkcount = htons( nbd_qhash->blkcount );
		qhreq.hash_type = htons( nbd_qhash->hash_type );
		qhreq.hash_len = htonl( nbd_qhash->hash_len );
		dprintk( DBG_QHASH, "QHASH REQ Send: blkaddr= %u size= %d, count=%d - %d\n",
							ntohl(qhreq.blkaddr), ntohl(qhreq.blksize), ntohs(qhreq.blkcount),
							nbd_qhash->blkcount ); // michail

		dprintk( DBG_QHASH, "QHASH REQ Sending %d bytes\n", (int)sizeof(nbd_qhash_request_t) );
		result = sock_xmit(lo, 1, &qhreq, sizeof(nbd_qhash_request_t), 0 /* last */);
		if (result <= 0) {
			printk(KERN_ERR "%s: Send data failed (result %d)\n",
					lo->disk->disk_name, result);
			goto error_out;
		}
	}

	/* OK, arm (or re-arm) a global response timer... we need a max timeout from the last req sent */

	return 0;

error_out:
	return 1;
}

static struct request *nbd_find_request(struct nbd_device *lo, char *handle)
{
	struct request *req;
	struct list_head *tmp;
	struct request *xreq;
	int err;

	memcpy(&xreq, handle, sizeof(xreq));

	err = wait_event_interruptible(lo->active_wq, lo->active_req != xreq);
	if (unlikely(err))
		goto out;

	spin_lock(&lo->queue_lock);
	list_for_each(tmp, &lo->queue_head) {
		req = list_entry(tmp, struct request, queuelist);
		if (req != xreq)
			continue;
		list_del_init(&req->queuelist);
		spin_unlock(&lo->queue_lock);
		return req;
	}
	spin_unlock(&lo->queue_lock);

	err = -ENOENT;

out:
	return ERR_PTR(err);
}

static inline int sock_recv_bvec(struct nbd_device *lo, struct bio_vec *bvec)
{
	int result;
	void *kaddr = kmap(bvec->bv_page);
	result = sock_xmit(lo, 0, kaddr + bvec->bv_offset, bvec->bv_len,
			MSG_WAITALL);
	kunmap(bvec->bv_page);
	return result;
}

/* NULL returned = something went wrong, inform userspace */
static struct request *nbd_read_stat(struct nbd_device *lo)
{
	int result;
	struct nbd_reply reply;
	struct request *req;

	reply.magic = 0;
	result = sock_xmit(lo, 0, &reply, sizeof(struct nbd_reply), MSG_WAITALL);
	if (result <= 0) {
		printk(KERN_ERR "%s: Receive control failed (result %d)\n",
				lo->disk->disk_name, result);
		goto harderror;
	}
	dprintk(DBG_QHASH, "%s RESP: == ENTER == GOT REPLY ==========\n", lo->disk->disk_name );
	dprintk(DBG_QHASH, "%s RESP: Received nbd_reply: %lu bytes\n", lo->disk->disk_name, sizeof(struct nbd_reply));

#ifdef NBD_DEBUG_CMDS
	assert( last_rep_cnt >= 0 && last_rep_cnt <= MAX_LAST_ITEMS );
	memcpy( &last_replies[last_rep_cnt], &reply, sizeof (struct nbd_reply) );
	if ( last_rep_cnt++ >= MAX_LAST_ITEMS )
		last_rep_cnt = 0;
#endif

	if (ntohl(reply.magic) != NBD_REPLY_MAGIC) {
		printk(KERN_ERR "%s: Wrong magic (0x%lx)\n",
				lo->disk->disk_name,
				(unsigned long)ntohl(reply.magic));
		result = -EPROTO;
		goto harderror;
	}

	if ( atomic_read(&qhash_pending) > 0 ) { /* pending qhash reqs? */
		struct request *qreq;

		memcpy( &qreq, (char *) reply.handle, sizeof(qreq) );

		dprintk(DBG_QHASH, "%s RESP: Checking for Query Hash reply! (%d pending reqs, qreq= %p)\n",
						lo->disk->disk_name, atomic_read(&qhash_pending), qreq );

	   	if ( qreq->flags == REQ_SPECIAL && nbd_cmd(qreq) == NBD_CMD_QHASH) {

			/* NOTE: we don't recv the response directly into the ioctl buffer, because
			 *       we will need to check & convert the values received... */
			nbd_query_blkhash_t *recv_qh = kzalloc( sizeof(nbd_query_blkhash_t), GFP_NOIO );
			nbd_query_blkhash_t *nbd_qhash = qreq->special; /* get the ioctl-waiting struct... */

			dprintk(DBG_QHASH, "%s RESP: Received Query Hash reply! (req %p)\n",
							lo->disk->disk_name, qreq);
			
			if (ntohl(reply.error)) {
				printk(KERN_ERR "%s: QHash: Other side returned error (%d)\n",
						lo->disk->disk_name, ntohl(reply.error));
				qreq->errors++;

			} else { /* Handle successful request... read the hash data (only if NOT error) */

				dprintk(DBG_QHASH, "%s RESP: Receiving Query Hash reply: %d bytes\n",
				   		lo->disk->disk_name, (int)sizeof(nbd_query_blkhash_t) );

				/* receive the hash data (i.e. nbd_query_blkhash_t) */
				result = sock_xmit(lo, 0, recv_qh, sizeof(nbd_query_blkhash_t), MSG_WAITALL);
				if (result <= 0) {
					printk(KERN_ERR "%s: Receiveing hash data failed (result %d)\n",
							lo->disk->disk_name, result);
					kfree( recv_qh );
					goto harderror;
				}

				dprintk(DBG_QHASH, "%s RESP: QHash: SUCCESS!\n", lo->disk->disk_name );

				assert( nbd_qhash->blkaddr == ntohl( recv_qh->blkaddr ) );
				assert( nbd_qhash->blksize == ntohl( recv_qh->blksize ) );
				assert( nbd_qhash->blkcount == ntohs( recv_qh->blkcount ) );
				assert( nbd_qhash->hash_type == ntohs( recv_qh->hash_type ) );
				assert( nbd_qhash->hash_len == ntohl( recv_qh->hash_len ) );
				nbd_qhash->error = ntohl( recv_qh->error );
				nbd_qhash->blkmap = recv_qh->blkmap;
				memcpy( nbd_qhash->blkhash, recv_qh->blkhash, MAX_QUERY_BLKS * MAX_HASH_LEN );

				dprintk(DBG_QHASH, "%s RESP: QHash: blkaddr= %llu, blksize= %u, blkcount= %u!\n",
								lo->disk->disk_name, nbd_qhash->blkaddr, nbd_qhash->blksize,
								nbd_qhash->blkcount );
				dprintk(DBG_QHASH, "%s RESP: QHash: blkmap= 0x%llx!\n", lo->disk->disk_name, nbd_qhash->blkmap );
			}

			atomic_dec( &qhash_pending );

			kfree( recv_qh );

			dprintk(DBG_QHASH, "%s RESP: ===== EXIT == QHASH =============\n", lo->disk->disk_name );
			return qreq;
		}
	}

	req = nbd_find_request(lo, reply.handle);
	if (unlikely(IS_ERR(req))) {
		result = PTR_ERR(req);
		if (result != -ENOENT)
			goto harderror;

		printk(KERN_ERR "%s: Unexpected reply (%p)\n",
				lo->disk->disk_name, reply.handle);
		result = -EBADR;
		goto harderror;
	}

	if (ntohl(reply.error)) {
		printk(KERN_ERR "%s: Other side returned error (%d)\n",
				lo->disk->disk_name, ntohl(reply.error));
		dump_last_requests(lo);
		req->errors++;
		return req;
	}

	dprintk(DBG_RX, "%s: request %p: got reply\n",
			lo->disk->disk_name, req);
	if (nbd_cmd(req) == NBD_CMD_READ) {
		struct req_iterator iter;
		struct bio_vec *bvec;

		rq_for_each_segment(bvec, req, iter) {
			result = sock_recv_bvec(lo, bvec);
			if (result <= 0) {
				printk(KERN_ERR "%s: Receive data failed (result %d)\n",
						lo->disk->disk_name, result);
				dump_last_requests(lo);
				req->errors++;
				return req;
			}
			dprintk(DBG_RX, "%s: request %p: got %d bytes data\n",
				lo->disk->disk_name, req, bvec->bv_len);
		}
	}
	return req;

harderror:
	dump_last_requests(lo);
	lo->harderror = result;
	return NULL;
}

static int nbd_do_it(struct nbd_device *lo)
{
	struct request *req;

	BUG_ON(lo->magic != LO_MAGIC);
	if ( !lo->xmit_timeout )
		printk(KERN_ALERT "%s INIT: xmit timeout: DISABLED\n", lo->disk->disk_name );
	else
		printk(KERN_ALERT "%s INIT: Using xmit timeout: %d seconds\n", lo->disk->disk_name, lo->xmit_timeout/HZ );

	lo->client_pid = current->pid;
	lo->client_task = current; /* ready for a kill */

	while ((req = nbd_read_stat(lo)) != NULL) {
		if (req->flags == REQ_SPECIAL && nbd_cmd(req) == NBD_CMD_QHASH) /* qhash req? */
			complete( req->waiting );
		else {

			reset_req_response_deadline(lo); /* reset response deadlines appropriately */

#ifdef ENABLE_REQ_DEBUG
			atomic_dec( &lo->req_inprogr );
			if (rq_data_dir(req) == WRITE)
				atomic_dec( &lo->req_inprogr_wr );
			else
				atomic_dec( &lo->req_inprogr_rd );
#endif
			nbd_end_request(req);
		}
	}

	lo->client_pid = 0;
	return 0;
}

static void nbd_clear_que(struct nbd_device *lo)
{
	struct request *req;

	BUG_ON(lo->magic != LO_MAGIC);

	/*
	 * Because we have set lo->sock to NULL under the tx_lock, all
	 * modifications to the list must have completed by now.  For
	 * the same reason, the active_req must be NULL.
	 *
	 * As a consequence, we don't need to take the spin lock while
	 * purging the list here.
	 */
	BUG_ON(lo->sock);
	BUG_ON(lo->active_req);

	while (!list_empty(&lo->queue_head)) {
		req = list_entry(lo->queue_head.next, struct request,
				 queuelist);
		list_del_init(&req->queuelist);
		req->errors++;

		reset_req_response_deadline(lo); /* reset response deadlines appropriately */

#ifdef ENABLE_REQ_DEBUG
		atomic_dec( &lo->req_inprogr );
		if (rq_data_dir(req) == WRITE)
			atomic_dec( &lo->req_inprogr_wr );
		else
			atomic_dec( &lo->req_inprogr_rd );
#endif
		nbd_end_request(req);
	}

	while (!list_empty(&lo->waiting_queue)) {
		req = list_entry(lo->waiting_queue.next, struct request,
			queuelist);
		list_del_init(&req->queuelist);
		req->errors++;

		reset_req_response_deadline(lo); /* reset response deadlines appropriately */
		nbd_end_request(req);
	}
}

static void nbd_handle_req(struct nbd_device *lo, struct request *req)
{
	if (!(req->flags & REQ_CMD))
		goto error_out;

#ifdef ENABLE_REQ_DEBUG
	atomic_inc( &lo->req_total );
	atomic_inc( &lo->req_inprogr );

	nbd_cmd(req) = NBD_CMD_READ;
	if (rq_data_dir(req) == WRITE) {
		nbd_cmd(req) = NBD_CMD_WRITE;
		if (lo->flags & NBD_READ_ONLY) {
			printk(KERN_ERR "%s: Write on read-only\n",
					lo->disk->disk_name);
			atomic_dec( &lo->req_inprogr );
			goto error_out;
		}
		atomic_inc( &lo->req_total_wr );
		atomic_inc( &lo->req_inprogr_wr );
	} else {
		atomic_inc( &lo->req_total_rd );
		atomic_inc( &lo->req_inprogr_rd );
	}
#else
	nbd_cmd(req) = NBD_CMD_READ;
	if (rq_data_dir(req) == WRITE) {
		nbd_cmd(req) = NBD_CMD_WRITE;
		if (lo->flags & NBD_READ_ONLY) {
			printk(KERN_ERR "%s: Write on read-only\n",
					lo->disk->disk_name);
			goto error_out;
		}
	}
#endif

	req->errors = 0;

	mutex_lock(&lo->tx_lock);
	if (unlikely(!lo->sock)) {
		mutex_unlock(&lo->tx_lock);

		if ( ! lo->errmsg_last_time || jiffies >= lo->errmsg_last_time + (2*HZ) ) {
			printk(KERN_ERR "%s: Attempted send on closed socket\n",
			       lo->disk->disk_name);
			lo->errmsg_last_time = jiffies;
		}
		goto error_out;
	}

	set_req_response_deadline(lo); /* set response deadlines for new request */

	lo->active_req = req;

	if (nbd_send_req(lo, req) != 0) {

		reset_req_response_deadline(lo); /* reset response deadlines appropriately */

		printk(KERN_ERR "%s: Request send failed\n",
				lo->disk->disk_name);
		dump_last_requests(lo);
		req->errors++;
		nbd_end_request(req);
#ifdef ENABLE_REQ_DEBUG
		atomic_dec( &lo->req_inprogr );

		if (rq_data_dir(req) == WRITE)
			atomic_dec( &lo->req_inprogr_wr );
		else
			atomic_dec( &lo->req_inprogr_rd );
#endif
	} else {
		spin_lock(&lo->queue_lock);
		list_add_tail(&req->queuelist, &lo->queue_head);
		spin_unlock(&lo->queue_lock);
	}

	lo->active_req = NULL;
	mutex_unlock(&lo->tx_lock);
	wake_up_all(&lo->active_wq);

	dprintk(DBG_BLKDEV, "%s: request %p: DONE, get next one\n",
			req->rq_disk->disk_name, req );
	return;

error_out:
	disarm_response_timer( lo );
	req->errors++;
	nbd_end_request(req);
}

static int nbd_thread(void *data)
{
	struct nbd_device *lo = data;
	struct request *req;

	set_user_nice(current, -20);
	while (!kthread_should_stop() || !list_empty(&lo->waiting_queue)) {
		/* wait for something to do */
		wait_event_interruptible(lo->waiting_wq,
					 kthread_should_stop() ||
					 !list_empty(&lo->waiting_queue));

		/* extract request */
		if (list_empty(&lo->waiting_queue))
			continue;

		spin_lock_irq(&lo->queue_lock);
		req = list_entry(lo->waiting_queue.next, struct request,
				 queuelist);
		list_del_init(&req->queuelist);
		spin_unlock_irq(&lo->queue_lock);

		/* handle request */
		nbd_handle_req(lo, req);

		dprintk(DBG_BLKDEV, "%s: request %p: DONE, get next one\n",
				req->rq_disk->disk_name, req );
	}
	return 0;
}

/*
 * We always wait for result of write, for now. It would be nice to make it optional
 * in future
 * if ((req->cmd == WRITE) && (lo->flags & NBD_WRITE_NOCHK)) 
 *   { printk( "Warning: Ignoring result!\n"); nbd_end_request( req ); }
 */

static void do_nbd_request(request_queue_t * q)
{
	struct request *req;
	
	while ((req = elv_next_request(q)) != NULL) {
		struct nbd_device *lo;

		spin_unlock_irq(q->queue_lock);

		blkdev_dequeue_request(req);
		dprintk(DBG_BLKDEV, "%s: request %p: dequeued (flags=%lx) [%s@%llu, %luB]\n",
				req->rq_disk->disk_name, req, req->flags,
				nbdcmd_to_ascii(nbd_cmd(req)),
				(unsigned long long)req->sector << 9, req->nr_sectors << 9);

		lo = req->rq_disk->private_data;

		BUG_ON(lo->magic != LO_MAGIC);

		if (unlikely(!lo->sock)) {

			if ( ! lo->errmsg_last_time || jiffies >= lo->errmsg_last_time + (2*HZ) ) {
				printk(KERN_ERR "%s: Attempted send on closed socket\n",
				       lo->disk->disk_name);
				lo->errmsg_last_time = jiffies;
			}
			disarm_response_timer( lo );
			req->errors++;
			nbd_end_request(req);

			spin_lock_irq(q->queue_lock);
			continue;
		}

		spin_lock_irq(&lo->queue_lock);
		list_add_tail(&req->queuelist, &lo->waiting_queue);
		spin_unlock_irq(&lo->queue_lock);

		wake_up(&lo->waiting_wq);

		spin_lock_irq(q->queue_lock);
	}
}

static int nbd_ioctl(struct inode *inode, struct file *file,
		     unsigned int cmd, unsigned long arg)
{
	struct nbd_device *lo = inode->i_bdev->bd_disk->private_data;
	int error;
	struct request sreq ;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	BUG_ON(lo->magic != LO_MAGIC);

	/* Anyone capable of this syscall can do *real bad* things */
	dprintk(DBG_IOCTL, "%s: nbd_ioctl cmd=%s(0x%x) arg=%lu\n",
			lo->disk->disk_name, ioctl_cmd_to_ascii(cmd), cmd, arg);

	switch (cmd) {
	case NBD_DISCONNECT:
		printk(KERN_INFO "%s: NBD_DISCONNECT\n", lo->disk->disk_name);
		sreq.flags = REQ_SPECIAL;
		nbd_cmd(&sreq) = NBD_CMD_DISC;
		/*
		 * Set these to sane values in case server implementation
		 * fails to check the request type first and also to keep
		 * debugging output cleaner.
		 */
		sreq.sector = 0;
		sreq.nr_sectors = 0;
		if (!lo->sock)
			return -EINVAL;

		mutex_lock(&lo->tx_lock);

		nbd_send_req(lo, &sreq);

		mutex_unlock(&lo->tx_lock);
		return 0;
 
	case NBD_QUERY_HASH:
	{
		nbd_query_blkhash_t * nbd_qhash = NULL;
		struct request *qreq; /* use our own locally allocated struct... */
		int retval = 0;

		dprintk( DBG_QHASH, "%s: NBD_QUERY_HASH\n", lo->disk->disk_name);
   		nbd_qhash = kzalloc( sizeof(nbd_query_blkhash_t), GFP_NOIO );
   		qreq = kzalloc( sizeof(struct request), GFP_NOIO );

		/* Copy cmd arguments from user space */
		if (copy_from_user( (char *)nbd_qhash, (nbd_query_blkhash_t *)arg, sizeof(nbd_query_blkhash_t))) {
			printk( KERN_ERR "ERROR: Copying query_hash ioctl() user-space arg\n");
			retval = -EINVAL;
			goto qhash_exit;
		}

		dprintk( DBG_QHASH, "INFO: query_hash() blkaddr= %llu, blksize=%d, blkcount= %d\n",
					nbd_qhash->blkaddr, nbd_qhash->blksize, nbd_qhash->blkcount );

		/* if socket is not connected, exit... */
		if (!lo->sock) {
			printk( KERN_ERR "ERROR: Socket not connected! query_hash() failed!\n");
			retval = -EINVAL;
			goto qhash_exit;
		}

		mutex_lock(&qhash_lock); /* only ONE query hash req in flight (synchronous req) */

		/* _____________________________________
		 * setup the command request header... */
		qreq->flags = REQ_SPECIAL;
		nbd_cmd(qreq) = NBD_CMD_QHASH;

		/* NOTE: assuming a sector size= 512 bytes! */
		qreq->sector = (nbd_qhash->blkaddr * (uint64_t)nbd_qhash->blksize) >> 9;
		qreq->hard_nr_sectors = nbd_qhash->blksize >> 9; /* == blocksize */
		qreq->nr_sectors = nbd_qhash->blkcount; /* == blkcount */
		qreq->special = nbd_qhash; /* pass the pointer along */

		dprintk( DBG_QHASH, "------------\nSENDING QHASH REQ: sector= %llu, nr_sectors=%lu\n", qreq->sector, qreq->nr_sectors );
		INIT_COMPLETION(qhash_wait);
		qreq->waiting = &qhash_wait;

		BUG_ON( atomic_inc_return(&qhash_pending) != 1 ); /* ONLY ONE SHOULD BE IN PROGRESS */

		mutex_lock(&lo->tx_lock);

		set_req_response_deadline(lo); /* set response deadlines for new request */

		nbd_send_req(lo, qreq);

		mutex_unlock(&lo->tx_lock);

		dprintk( DBG_QHASH, "SENT QHASH REQ: qreq= 0x%p\n", qreq );

		/* ______________________________________________________________________________________________
		 * OK, query_hash() request was sent... let the async handler wake us on completion... */

		dprintk( DBG_QHASH, "WAITING FOR QHASH REQ COMPLETION!\n");
		wait_for_completion_interruptible(qreq->waiting);

		reset_req_response_deadline(lo); /* reset response deadlines appropriately */

		mutex_unlock(&qhash_lock); /* only ONE query hash req in flight (synchronous req) */

		dprintk(DBG_QHASH, "%s QHash COMPLETED: blkmap= 0x%llx!\n", lo->disk->disk_name, nbd_qhash->blkmap );

		/* Return hash data back to user... */
		if (copy_to_user( (nbd_query_blkhash_t *)arg, (char *)nbd_qhash, sizeof(nbd_query_blkhash_t))) {
			printk( KERN_ERR "ERROR: Copying query_hash ioctl() data to user space\n");
			retval = -EINVAL;
		}

		dprintk( DBG_QHASH, "------ QHASH CMD Exiting -------\n");
qhash_exit:
		kfree( nbd_qhash );
		kfree( qreq );
		return retval;
	}

	case NBD_SET_FLAGS: /* FIXME: unsupported ioctl() sent by the user-level nbd-client */
		printk(KERN_ALERT "%s: IGNORED NBD_SET_FLAGS CALL\n", lo->disk->disk_name );
		return -EINVAL;

	case NBD_CLEAR_SOCK:
		lo->harderror = 0;
		goto shutdown_socket;

	case NBD_SET_SOCK:
		//printk(KERN_ALERT "%s: NBD_SET_SOCK CALL\n", lo->disk->disk_name );
		if (lo->file)
			return -EBUSY;
		error = -EINVAL;
		file = fget(arg);
		if (file) {
			inode = file->f_dentry->d_inode;
			if (S_ISSOCK(inode->i_mode)) {
				lo->file = file;
				lo->sock = SOCKET_I(inode);
				error = 0;
			} else {
				fput(file);
			}
		}
		return error;
	case NBD_SET_BLKSIZE:
		lo->blksize = arg;
		lo->bytesize &= ~(lo->blksize-1);
		inode->i_bdev->bd_inode->i_size = lo->bytesize;
		set_blocksize(inode->i_bdev, lo->blksize);
		set_capacity(lo->disk, lo->bytesize >> 9);
		return 0;

	case NBD_SET_SIZE:
		lo->bytesize = arg & ~(lo->blksize-1);
		inode->i_bdev->bd_inode->i_size = lo->bytesize;
		set_blocksize(inode->i_bdev, lo->blksize);
		set_capacity(lo->disk, lo->bytesize >> 9);
		return 0;

	case NBD_SET_TIMEOUT:
	{
		int old_xmit_timeout = lo->xmit_timeout;

		if ( arg >= 0 && arg <= 900 )
			lo->xmit_timeout = arg * HZ;

		printk(KERN_ALERT "%s: NBD_SET_TIMEOUT: timeout changed from %d -> %d seconds\n",
				lo->disk->disk_name, old_xmit_timeout/HZ, lo->xmit_timeout/HZ );
		return 0;
	}
	case NBD_SET_SIZE_BLOCKS:
		lo->bytesize = ((u64) arg) * lo->blksize;
		inode->i_bdev->bd_inode->i_size = lo->bytesize;
		set_blocksize(inode->i_bdev, lo->blksize);
		set_capacity(lo->disk, lo->bytesize >> 9);
		return 0;

	case NBD_DO_IT: {
		struct task_struct *thread;
		struct file *file;
		int error;
		if (lo->client_pid)
			return -EBUSY;
		if (!lo->file)
			return -EINVAL;

		thread = kthread_create(nbd_thread, lo, lo->disk->disk_name);
		if (IS_ERR(thread)) {
			return PTR_ERR(thread);
		}
		wake_up_process(thread);
		error = nbd_do_it(lo);
		kthread_stop(thread);

		if (error)
			return error;

		/* on return tidy up in case we have a signal */
		/* Forcibly shutdown the socket causing all listeners
		 * to error
		 *
		 * FIXME: This code is duplicated from sys_shutdown, but
		 * there should be a more generic interface rather than
		 * calling socket ops directly here */
shutdown_socket:
		sock_shutdown(lo, 1);

		file = lo->file;
		lo->file = NULL;
		nbd_clear_que(lo);
		BUG_ON(!list_empty(&lo->queue_head));
		BUG_ON(!list_empty(&lo->waiting_queue));
		printk(KERN_WARNING "%s: queue cleared\n", lo->disk->disk_name);
		if (file)
			fput(file);
		//lo->bytesize = 0;
		//inode->i_bdev->bd_inode->i_size = 0;
		//set_capacity(lo->disk, 0);
		lo->client_pid = 0;
		lo->client_task = NULL;
		return lo->harderror;
	}

	case NBD_CLEAR_QUE:
		/*
		 * This is for compatibility only.  The queue is always cleared
		 * by NBD_DO_IT or NBD_CLEAR_SOCK.
		 */
		BUG_ON(!lo->sock && !list_empty(&lo->queue_head));
		return 0;

	case NBD_PRINT_DEBUG:
		printk(KERN_ALERT "\n%s: REQUEST DEBUG INFO\n========================\n", lo->disk->disk_name );

		printk(KERN_ALERT "%s: RESP TIMEOUT = %d sec, reqs_in_progress=%d, sock= 0x%p \n", lo->disk->disk_name,
						lo->xmit_timeout/HZ, lo->reqs_in_progress, lo->sock );
#ifdef ENABLE_REQ_DEBUG
		printk(KERN_ALERT "%s: IO Reqs Total: %d (RD: %d, WR: %d) -> In Progress: %d (RD: %d, WR: %d)\n",
			inode->i_bdev->bd_disk->disk_name,
			atomic_read( &lo->req_total ), atomic_read( &lo->req_total_rd ),
			atomic_read( &lo->req_total_wr ), atomic_read( &lo->req_inprogr ),
			atomic_read( &lo->req_inprogr_rd ), atomic_read( &lo->req_inprogr_wr )
			);

		printk(KERN_ALERT "%s: Bytesize= %lld, Blksize= %d\n",
							lo->disk->disk_name, lo->bytesize, lo->blksize);

		mutex_lock(&lo->tx_lock);
		if ( !lo->sock)
			printk(KERN_ALERT "%s: Socket is CLOSED!\n", lo->disk->disk_name);
		else
			printk(KERN_ALERT "%s: Socket is OPEN & CONNECTED!\n", lo->disk->disk_name);
		mutex_unlock(&lo->tx_lock);

		/* Ok, now dump info about all pending requests in the queue... */
		print_queue_info( lo );
#endif

		printk(KERN_ALERT "%s: next = %p, prev = %p, head = %p\n\n",
			inode->i_bdev->bd_disk->disk_name,
			lo->queue_head.next, lo->queue_head.prev, &lo->queue_head);

		dump_last_requests(lo);
		return 0;
	}
	return -EINVAL;
}

/* 32-bits of pain on a 64-bit system... */
static long
nbd_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dprintk(DBG_IOCTL, "COMPAT IOCTL(): cmd=%s(0x%x) arg=%lu\n",
						ioctl_cmd_to_ascii(cmd), cmd, arg);

	switch (cmd) {

	case NBD_QUERY_HASH: /* just make these two compatible... the rest should be native */
	case NBD_PRINT_DEBUG:
	case NBD_SET_TIMEOUT:
	case NBD_SET_FLAGS:
	case NBD_SET_SOCK:
		return nbd_ioctl(f->f_dentry->d_inode, f, cmd, arg);

	default:
		return -ENOIOCTLCMD;
	}
}


static struct block_device_operations nbd_fops =
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

	BUILD_BUG_ON(sizeof(struct nbd_request) != 28);

	if (nbds_max > MAX_NBD) {
		printk(KERN_CRIT "nbd: cannot allocate more than %u nbds; %u requested.\n", MAX_NBD,
				nbds_max);
		return -EINVAL;
	}

	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = alloc_disk(1);
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

		/* set max sectors for io requests in this queue (i.e. req split limit) */
		blk_queue_max_sectors( disk->queue, MAX_BIO_PAGES*PAGE_SECTORS );
		blk_queue_max_segment_size( disk->queue, MAX_BIO_PAGES*PAGE_SIZE );
		blk_queue_segment_boundary( disk->queue, ((MAX_BIO_PAGES*PAGE_SIZE)>>1) - 1);
#if 0
		/* set physical sector size */
		blk_queue_hardsect_size(disk->queue, 4096);
#endif
	}

	if (register_blkdev(NBD_MAJOR, "nbd")) {
		err = -EIO;
		goto out;
	}

	printk(KERN_INFO "nbd_OA_C5T: registered device at major %d\n", NBD_MAJOR);
	dprintk(DBG_INIT, "nbd: debugflags=0x%x\n", debugflags);

	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = nbd_dev[i].disk;
		nbd_dev[i].file = NULL;
		nbd_dev[i].magic = LO_MAGIC;
		nbd_dev[i].flags = 0;
		INIT_LIST_HEAD(&nbd_dev[i].waiting_queue);
		spin_lock_init(&nbd_dev[i].queue_lock);
		INIT_LIST_HEAD(&nbd_dev[i].queue_head);
		mutex_init(&nbd_dev[i].tx_lock);
		init_waitqueue_head(&nbd_dev[i].active_wq);
		init_waitqueue_head(&nbd_dev[i].waiting_wq);
		nbd_dev[i].blksize = 1024;
		nbd_dev[i].bytesize = 0x7ffffc00ULL << 10; /* 2TB */
		nbd_dev[i].xmit_timeout = 30 * HZ; /* default timeout: 30 secs */
		//nbd_dev[i].xmit_timeout = 0; /* DISABLED timeout: 0 */
		spin_lock_init(&nbd_dev[i].timer_lock);
		nbd_dev[i].reqs_in_progress = 0;
		nbd_dev[i].client_pid = 0;
		nbd_dev[i].errmsg_last_time = 0;
		nbd_dev[i].client_task = NULL;
#ifdef ENABLE_REQ_DEBUG
		atomic_set( &nbd_dev[i].req_total, 0 );
		atomic_set( &nbd_dev[i].req_total_rd, 0 );
		atomic_set( &nbd_dev[i].req_total_wr, 0 );
		atomic_set( &nbd_dev[i].req_inprogr, 0 );
		atomic_set( &nbd_dev[i].req_inprogr_rd, 0 );
		atomic_set( &nbd_dev[i].req_inprogr_wr, 0 );
#endif

		disk->major = NBD_MAJOR;
		disk->first_minor = i;
		disk->fops = &nbd_fops;
		disk->private_data = &nbd_dev[i];
		disk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
		sprintf(disk->disk_name, "nbd%d", i);
		set_capacity(disk, 0x7ffffc00ULL << 1); /* 2 TB */
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
	printk(KERN_INFO "nbd: unregistered device at major %d\n", NBD_MAJOR);
}

module_init(nbd_init);
module_exit(nbd_cleanup);

MODULE_DESCRIPTION("Network Block Device");
MODULE_LICENSE("GPL");

module_param(nbds_max, int, 0444);
MODULE_PARM_DESC(nbds_max, "How many network block devices to initialize.");
#ifndef NDEBUG
module_param(debugflags, int, 0644);
MODULE_PARM_DESC(debugflags, "flags for controlling debug output");
#endif
