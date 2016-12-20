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
 * Sends the NBD_PRINT_DEBUG ioctl to the NBD device (already opened)...
 */
int
nbd_print_debug_ioctl( int devfd )
{
	if ( ioctl(devfd, NBD_PRINT_DEBUG ) < 0 ) {
		perror("Sending NBD_PRINT_DEBUG ioctl():");
		return 0;
	} 

	printf("NBD_PRINT_DEBUG successful!");
	return 1;
}


int
main(int argc, char ** argv)
{
	int devfd;

	if (argc != 2) {
		fprintf( stderr, "\"%s\": Send a print_debug cmd to nbd\n", argv[0]);
		fprintf( stderr, "Usage: %s <nbd device>\n", argv[0]);
		exit(1);
	}

        /* Open the device driver descriptor ... */
    if ( (devfd = open( argv[1], O_RDWR, S_IRWXU)) == -1) {
        fprintf( stderr, "Error Opening NBD device %s : %s\n", argv[1], strerror(errno));
        return 0;
    }

	if ( nbd_print_debug_ioctl( devfd ) ) {
		printf("NBD_PRINT_DEBUG: Successful.\n");
	} else
		printf("NBD_PRINT_DEBUG: Failed.\n");

	return 0;

}

