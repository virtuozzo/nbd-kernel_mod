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

/* ____________________________________________________________________________
 * Sends the NBD_CONN_INFO ioctl to the NBD device (already opened)...
 */
int
nbd_conn_info_ioctl( int devfd, nbd_conn_info_t *cinfo )
{
	//cinfo->set_info = 0;
	memset( cinfo, 0, sizeof(nbd_conn_info_t) );

	if ( ioctl(devfd, NBD_CONN_INFO, cinfo ) < 0 ) {
		//perror("Sending NBD_CONN_INFO ioctl():");
		return 0;
	} 

	return 1;
}


int
main(int argc, char ** argv)
{
	int devfd;
	nbd_conn_info_t cinfo;

	if (argc != 2) {
		fprintf( stderr, "\"%s\": Get the NBD connection info for a specific nbd device\n", argv[0]);
		fprintf( stderr, "Usage: %s <nbd device>\n", argv[0]);
		exit(1);
	}

	/* Open the device driver descriptor ... */
	if ( (devfd = open( argv[1], O_RDWR, S_IRWXU)) == -1) {
		fprintf( stderr, "nbd_conn_info=failed error=\"failed to open NBD device %s: %s\"\n", argv[1], strerror(errno));
		return 0;
	}

	if ( nbd_conn_info_ioctl( devfd, &cinfo ) ) {

		if ( cinfo.connected )
			printf("nbd_conn_info=ok connected=%d pid=%d %s\n",
				cinfo.connected, cinfo.pid, cinfo.cidata );
		else
			printf("nbd_conn_info=ok connected=%d pid=0 hostname=NULL port=0\n", cinfo.connected );

	} else
		printf("nbd_conn_info=failed error=\"ioctl failed for NBD device %s: %s\"\n", argv[1], strerror(errno));

	return 0;
}

