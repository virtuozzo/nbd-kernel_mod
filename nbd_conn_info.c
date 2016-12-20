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

