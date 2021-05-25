/*
 * Copyright (c) 2013, Michail Flouris <michail.flouris@onapp.com>
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
#include <assert.h>

#define __UTILS__

#include "nbd.h"


int
main(int argc, char ** argv)
{
	int devfd;
	nbd_server_cmd_t srvcmd;
	char cmdstr[SERVER_CMD_MAX_LEN];

	if (argc != 3) {
		fprintf( stderr, "\"%s\": Send a cmd to the NBD server of a specific nbd device\n", argv[0]);
		fprintf( stderr, "Usage: %s <nbd device> <cmd string (max %d chars)>\n", argv[0], SERVER_CMD_MAX_LEN );
		exit(1);
	}

	if ( !argv[2] || strlen(argv[2]) >= SERVER_CMD_MAX_LEN ) {
		fprintf( stderr, "\"%s\": ERROR: Invalid cmd string! (too short or long, max %d chars)\n", argv[0], SERVER_CMD_MAX_LEN );
		exit(1);
	}

	/* Open the device driver descriptor ... */
	if ( (devfd = open( argv[1], O_RDWR, S_IRWXU)) == -1) {
		fprintf( stderr, "nbd_server_cmd=failed error=\"failed to open NBD device %s: %s\"\n", argv[1], strerror(errno));
		return 0;
	}

	/* Build the cmd struct for the cmd */
	memset( cmdstr, 0, SERVER_CMD_MAX_LEN);
	sprintf( cmdstr, "%s", argv[2] );
	assert( strlen(cmdstr) < SERVER_CMD_MAX_LEN );

	memset( &srvcmd, 0, sizeof(nbd_server_cmd_t) );
	memcpy( srvcmd.cmdbytes, cmdstr, SERVER_CMD_MAX_LEN );

	if ( ioctl(devfd, NBD_SERVER_CMD, &srvcmd ) < 0 ) {

		printf("nbd_server_cmd=failed error=\"ioctl failed for NBD device %s: %s\"\n", argv[1], strerror(errno));

	} else {

		/* OK, ioctl success... */
		printf("nbd_server_cmd=ok connected=%d err_code=%d response=\"%s\"\n",
				srvcmd.connected, srvcmd.err_code, srvcmd.cmdbytes );
	}

	return 0;
}

