/*
 * Copyright (c) 2011-2012, Michail Flouris <michail.flouris@onapp.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h> 
#include <errno.h>
#include <signal.h>
#include <linux/ioctl.h>
#include <stdint.h>

#define __UTILS__

#include "nbd.h"

static const char hexdigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/* ____________________________________________________________________________
 * Sends the hash_query ioctl to the NBD device (already opened)...
 * @param blkaddr:  starting block address requested
 * @param blksize:  block size in bytes requested
 * @param blkcount: number of block hashes requested (<= MAX_QUERY_BLKS)
 *
 * @return nbd_query_blkhash_t with the requested bitmap & hashes
 */

int
nbd_query_hash_ioctl( int devfd, uint64_t blkaddr, int blksize,
						uint16_t blkcount, nbd_query_blkhash_t *nqb )
{
	/* prepare the request values for the ioctl... */
	memset( nqb, 0, sizeof(nbd_query_blkhash_t) );
	nqb->blkaddr = blkaddr;
	nqb->blksize = blksize;
	nqb->blkcount = blkcount;

	nqb->hash_type = G_CHECKSUM_SHA256;
	nqb->hash_len = 32;

	printf("Sending IOCTL: fd=%d, ioctl: %lx nqb: %lx\n", devfd, (unsigned long)NBD_QUERY_HASH, (unsigned long)nqb );

	if ( ioctl(devfd, NBD_QUERY_HASH, nqb ) < 0 ) {
		perror("Sending NBD_QUERY_HASH ioctl():");
		return 0;
	} 

	printf("QUERY_HASH successful!");
	return 1;
}


int
main(int argc, char ** argv)
{
	uint64_t blkaddr = 0;
	nbd_query_blkhash_t nqb;
	unsigned char t;
	int devfd, i;

	if (argc != 3) {
		fprintf( stderr, "\"%s\": Send a query_hash cmd to nbd\n", argv[0]);
		fprintf( stderr, "Usage: %s <nbd device> <block number>\n", argv[0]);
		exit(1);
	}

	blkaddr = atoi(argv[2]);
	if (blkaddr < 0 || blkaddr > 1024*1024*1024 ) {
        fprintf( stderr, "Error: Invalid block address: %llu\n", blkaddr);
        return 0;
	}

        /* Open the device driver descriptor ... */
    if ( (devfd = open( argv[1], O_RDWR, S_IRWXU)) == -1) {
        fprintf( stderr, "Error Opening NBD device %s : %s\n", argv[1], strerror(errno));
        return 0;
    }

	if ( nbd_query_hash_ioctl( devfd, blkaddr, 64*1024 /* blksize */, 1 /*blkcount*/, &nqb ) ) {

		printf("VALID BITMAP: 0x%llx HASH= ", nqb.blkmap );
		for (i = 0; i < nqb.hash_len; i++) {
			t = nqb.blkhash[0][i];
			printf( "%c%c",	hexdigits[(t >> 4) & 0xf], hexdigits[t & 0xf] );
		}
		printf("\n");

		printf("Query Hash [Blk: %llu]: Successful.\n", blkaddr );
	} else
		printf("Query Hash [Blk: %llu]: Failed.\n", blkaddr );

	return 0;

}

