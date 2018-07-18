// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file server.c
 * Userd server main.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @author Benjamin Morin <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * Copyright (C) 2013-2014 SGDSN/ANSSI
 *
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <clip/clip.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "cmd.h"
#include "userd_priv.h"

#define ADMIN_SOCKNUM	0
#define USER_SOCKNUM	1
#define SOCKNUM_MAX	2

/*************************************************************/
/*                     Global options                        */
/*************************************************************/

extern int conn_handler(int, struct clip_sock_t *);

static clip_sock_t g_socks[SOCKNUM_MAX] = {
	{
	  .sock = -1,
	  .name = "admin",
	  .path = NULL,
	  .handler = admin_conn_handler,
	},
	{
	  .sock = -1,
	  .name = "user",
	  .path = NULL,
	  .handler = user_conn_handler,
	},
};

static int g_foreground = 0;
int g_verbose = 0;
int g_daemonized = 0;
int g_with_rmb = 0;
int g_with_rmh = 0;

// PKCS11 library to use
char *module_lib_path = "/usr/lib/p11proxy.so";
// user authentication certificate label on card
char *auth_cert_label="clip_auth";
// master key disk encryption certificate label on card
char *enc_cert_label="clip_disk";

/*************************************************************/
/*                     Options parsing                       */
/*************************************************************/

#define OPTS	"BHFhre:a:m:s:v"

static void
print_help(const char *exe)
{
	printf("%s -s <admin sock path> -s <user sock path> "
	       "[-v [-v]] [-F] [-H] [-B] [-r] "
	       "[-m <module path>]"
	       "[-a <auth cert label>] [-e <disk encryption cert label>]\n", exe);
}

#define _set_if_not_set(arg, var, msg) do {				\
	if (var) {							\
		ERROR(msg"already set to %s, can't set "		\
				"it to %s", var, optarg);		\
		return -1;						\
	}								\
	var = arg;							\
} while (0)

#define set_if_not_set(var, msg) _set_if_not_set(optarg, var, msg)

static int
set_sock(char *arg)
{
	char *ptr;

	ptr = strchr(arg, ':');
	if (!ptr || !*(ptr+1)) { /* OK, null terminated */
		ERROR("Invalid socket specification: %s", arg);
		return -1;
	}

	if (!strncmp("admin", arg, ptr - arg)) {
		_set_if_not_set(ptr + 1, g_socks[ADMIN_SOCKNUM].path, 
							"admin socket path");
		return 0;
	} else if (!strncmp("user", arg, ptr - arg)) {
		_set_if_not_set(ptr + 1, g_socks[USER_SOCKNUM].path, 
							"user socket path");
		return 0;
	} else {
		ERROR("Unknown socket type : %.*s", ptr - arg, arg);
		return -1;
	}
}

static int
set_module(char* arg)
{
	if (!arg || !*(arg+1)) { /* OK, null terminated */
		ERROR("Missing module name");
		return -1;
	}
	module_lib_path=arg;
	return 0;
}

static int
set_auth_cert_label(char* arg)
{
	if (!arg || !*(arg+1)) { /* OK, null terminated */
		ERROR("Missing authentication certificate label");
		return -1;
	}
	auth_cert_label=arg;
	return 0;
}

static int
set_enc_cert_label(char* arg)
{
	if (!arg || !*(arg+1)) { /* OK, null terminated */
		ERROR("Missing disk encryption certificate label");
		return -1;
	}
	enc_cert_label=arg;
	return 0;
}

static int
get_options(int argc, char *argv[])
{
	int c;
	unsigned int i;
	while ((c = getopt(argc, argv, OPTS)) != -1) {
		switch (c) {
			case 's':
				if (set_sock(optarg)) 
					return -1;
				break;
			case 'F':
				g_foreground = 1;
				break;
			case 'h':
				print_help((argc > 0) ? basename(argv[0])
						: "userd");
				exit(0);
				break;
			case 'v':
				g_verbose++;
				break;
			case 'B':
				g_with_rmb = 1;
				break;
			case 'H':
				g_with_rmh = 1;
				break;
			case 'r':
				/* Not used anymore - kept for compatibility */
				break;
			case 'm':
				if (set_module(optarg)) 
					return -1;
				break;
			case 'a':
				if (set_auth_cert_label(optarg)) 
					return -1;
				break;
			case 'e':
				if (set_enc_cert_label(optarg)) 
					return -1;
				break;
			default:
				ERROR("Unsupported option %c", c);
				return -1;
				break;
		}
	}

	for (i = 0; i < SOCKNUM_MAX; i++) {
		if (!g_socks[i].path) {
			ERROR("Missing path for socket %s", g_socks[i].name);
			print_help(basename(argv[0]));
			return -1;
		}
	}

	return 0;
}

/*************************************************************/
/*                     Main loop                             */
/*************************************************************/

static int
server_loop(void)
{
	int sock;
	unsigned int i;
	clip_sock_t *iter;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		ERROR_ERRNO("signal");
		return -1;
	}


	for (i = 0; i < SOCKNUM_MAX; i++) {
		iter = g_socks + i;
		memset(&(iter->sau), 0, sizeof(iter->sau));
		sock = clip_sock_listen(iter->path, &(iter->sau), 0);
		if (sock < 0) {
			ERROR("Failure binding socket %s", iter->name);
			/* We're not closing any already bound sockets 
			 * here, but we'll die soon anyway...
			 */
			return -1;
		}
		iter->sock = sock;
	}

	for (;;) {
	  if (clip_accept_one(g_socks, SOCKNUM_MAX, 0))
	    ERROR("Connection failed");
	}

	return -1;
}


/*************************************************************/
/*                     Main                                  */
/*************************************************************/

int 
main (int argc, char *argv[])
{
	if (get_options(argc, argv))
		return EXIT_FAILURE;
	
	if (!g_foreground) {
		if (clip_daemonize()) {
			ERROR("Failed to daemonize");
			return EXIT_FAILURE;
		}
		g_daemonized = 1;
		openlog("userd", LOG_CONS|LOG_PID, LOG_DAEMON);
	}
	
	(void)server_loop();
	return EXIT_FAILURE;
}
// vim:sw=2:ts=2:et:
