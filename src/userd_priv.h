// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file userd_priv.h
 * Userd private header.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * @n
 * All rights reserved.
 */

#ifndef USERD_PRIV_H
#define USERD_PRIV_H

#include "userd.h"
#include <clip/clip.h>
#include <syslog.h>


#define __U __attribute__((unused))

#define _LOG(lev, slev, fmt, args...) do {\
	if (g_verbose >= lev) { \
		if (!g_daemonized) { \
		  printf("%s(%s:%d): "fmt"\n", __FUNCTION__,		\
			 __FILE__, __LINE__, ##args);			\
		} else {						\
		  syslog(LOG_DAEMON|slev,				\
			 "%s(%s:%d): "fmt"\n", __FUNCTION__,		\
			 __FILE__, __LINE__, ##args);			\
		} \
	} \
} while (0)

#define LOG(fmt, args...) _LOG(0, LOG_NOTICE, fmt, ##args);
#define LOG2(fmt, args...) _LOG(1, LOG_NOTICE, fmt, ##args);
#define DEBUG(fmt, args...) _LOG(0, LOG_DEBUG, fmt, ##args);
		
#define ERROR(fmt, args...) do {\
	if (!g_daemonized) { \
	  fprintf(stderr, "%s(%s:%d): "fmt"\n", __FUNCTION__,		\
		  __FILE__, __LINE__, ##args);				\
	} else { \
	  syslog(LOG_DAEMON|LOG_ERR, "%s(%s:%d): "fmt"\n",    \
		 __FUNCTION__,						\
		 __FILE__, __LINE__, ##args);				\
	} \
} while (0)


#define CMD_ERROR(cmd, fmt, args...) \
	ERROR(fmt" : %s", ##args, cmderr(cmd))


#define ERROR_ERRNO(fmt, args...) \
	ERROR(fmt": %s", ##args, strerror(errno))



int admin_conn_handler(int s, struct clip_sock_t *__s __attribute__((unused)));
int user_conn_handler(int s, struct clip_sock_t *__s __attribute__((unused)));

#endif // USERD_PRIV_H
// vim:sw=2:ts=2:et:
