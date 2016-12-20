/**
 * Extended / modified Network Block Device driver for the Linux kernel.
 *
 * Copyright (C) 2011-2016 OnApp Ltd.
 *
 * Author: Michail Flouris <michail.flouris@onapp.com>
 *
 * This file is part of the extended nbd (network block device) driver.
 * 
 * The extended nbd driver is free software: you can redistribute 
 * it and/or modify it under the terms of the GNU General Public 
 * License as published by the Free Software Foundation, either 
 * version 2 of the License, or (at your option) any later version.
 * 
 * Some open source application is distributed in the hope that it will 
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty 
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
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

