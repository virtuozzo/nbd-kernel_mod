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
 * Sends the NBD_SET_TIMEOUT ioctl to the NBD device (already opened)...
 */
int
nbd_set_timeout_ioctl( int devfd, int timeout )
{
	if ( ioctl(devfd, NBD_SET_TIMEOUT, (unsigned long)timeout ) < 0 ) {
		perror("Sending NBD_SET_TIMEOUT ioctl():");
		return 0;
	} 

	//printf("NBD_SET_TIMEOUT successful!");
	return 1;
}


int
main(int argc, char ** argv)
{
	int devfd, timeout = -1;

	if (argc != 3) {
		fprintf( stderr, "\"%s\": Set the NBD timeout value in seconds [0 = disable timeout]\n", argv[0]);
		fprintf( stderr, "Usage: %s <nbd device> <timeout seconds>\n", argv[0]);
		exit(1);
	}

	timeout = strtol(argv[2], NULL, 0);
	if ( timeout < 0 || timeout > 10000 ) {
		fprintf( stderr, "ERROR: Invalid timeout value!\n");
		exit(1);
	}

	/* Open the device driver descriptor ... */
	if ( (devfd = open( argv[1], O_RDWR, S_IRWXU)) == -1) {
		fprintf( stderr, "Error Opening NBD device %s : %s\n", argv[1], strerror(errno));
		return 0;
	}

	if ( nbd_set_timeout_ioctl( devfd, timeout ) ) {
		printf("NBD_SET_TIMEOUT -> %d seconds: Successful.\n", timeout);
	} else
		printf("NBD_SET_TIMEOUT -> %d seconds: Failed.\n", timeout);

	return 0;
}

