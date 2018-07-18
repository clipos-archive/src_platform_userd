// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file cmd.h
 * Userd client/server dialog header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef _USERD_CMD_H
#define _USERD_CMD_H

#include <stdint.h>

/* Socket commands */

typedef struct cmd {
	uint32_t cmd;
	uint32_t data;
} cmd_t;

/* Server / client commands */
#define CMD_NAME	0x0100	/* Send data: account name */
#define CMD_PASSWD	0x0200	/* Send data: password */
#define CMD_TYPE	0x0300	/* Send data: account type */
#define CMD_SIZE	0x0400	/* Send data: partition size / available space disk */
#define CMD_ENDLIST     0x0500	/* End of a sent list */
#define CMD_AUTHTYPE	0x0600  /* Send data: authentication type */

/* Client commands */
/* ADMIN socket */
#define CMD_DISKINFO		0x010000	/* Ask for the disk informations */
#define CMD_LISTUSERS		0x020000	/* Get the list of existing accounts */
#define CMD_ADDUSER		0x030000	/* Adds a new account */
#define CMD_DELUSER		0x040000	/* Deletes an existing account */
#define CMD_LOCKUSER		0x050000	/* Locks an existing account */
#define CMD_UNLOCKUSER		0x060000	/* Unlocks an existing account */
#define CMD_MIGRATETOCARD	0x080000	/* Migrate user from password to smartdard */
/* USER socket */
#define CMD_CHPASSWD		0x070000	/* Change password for current account */

extern uint32_t get_cmd(int, cmd_t *);
extern uint32_t get_cmd_notimeout(int, cmd_t *);
extern uint32_t put_cmd(int, uint32_t, uint32_t);
extern uint32_t get_field(int, uint32_t, char **, uint32_t *, cmd_t *);
extern uint32_t get_field_notimeout(int, uint32_t, char **, 
						uint32_t *, cmd_t *);
extern uint32_t put_field(int, uint32_t, char *, uint32_t);
extern uint32_t put_field_notimeout(int, uint32_t, char *, uint32_t);
extern int set_nonblock(int);

extern const char *cmderr(uint32_t cmd);
extern uint32_t errno2cmd(int err);



#endif /* _USERD_CMD_H */
// vim:sw=2:ts=2:et:
