// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file cmd.c
 * Userd client/server dialog functions.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * @n
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <clip/clip.h>

#include "cmd.h"
#include "userd.h"
#include "userd_priv.h"

#define READ_TIMEOUT 10000
#define WRITE_TIMEOUT 10000

#define CHUNK_SIZE 	(1<<12)
#define CHUNK_DELAY 	1000

uint32_t 
get_cmd(int s, cmd_t *cmd)
{
	ssize_t ret;

	ret = clip_sock_read(s, (char *)cmd, sizeof(*cmd), READ_TIMEOUT, 1);
	if (ret < 0)
		return CMD_FAULT;
	if (ret != sizeof(*cmd)) {
		ERROR("timed-out getting command");
		return CMD_TIMOUT;
	}
	return CMD_OK;
}

uint32_t 
get_cmd_notimeout(int s, cmd_t *cmd)
{
	ssize_t ret;

	ret = clip_sock_read(s, (char *)cmd, sizeof(*cmd), -1, 0);
	if (ret < 0)
		return CMD_FAULT;
	if (ret != sizeof(*cmd)) {
		ERROR("timed-out getting command");
		return CMD_TIMOUT;
	}
	return CMD_OK;
}

uint32_t
put_cmd(int s, uint32_t ret, uint32_t data)
{
	ssize_t sret;
	cmd_t cmd = {
		.cmd = ret,
		.data = data,
	};

	sret = clip_sock_write(s, (char *)&cmd, sizeof(cmd), WRITE_TIMEOUT, 1);
	if (sret < 0)
		return CMD_FAULT;
	if (sret != sizeof(cmd)) {
		ERROR("timed-out sending ack");
		return CMD_TIMOUT;
	}
	return CMD_OK;
}


static uint32_t
_get_field(int s,  uint32_t command, char **datap, uint32_t *lenp, 
		cmd_t *recv_cmd, int timeout_p)
{
	uint32_t ret;
	uint32_t len;
	ssize_t rret;
	char *data;
	cmd_t cmd;

	/* First mode : we read the command from the socket */
	if (command) {
		ret = get_cmd(s, &cmd);
		if (ret != CMD_OK) {
			CMD_ERROR(ret, "Failed to get initial syn");
			return ret;
		}
		if (cmd.cmd != command) {
			if (recv_cmd)
				memcpy(recv_cmd, &cmd, sizeof(*recv_cmd));
			else
				CMD_ERROR(cmd.cmd, 
					"Unexpected answer 0x%x != 0x%x", 
					cmd.cmd, command);
			return CMD_ORDER;
		}
		len = cmd.data;
		if (!len) {
			return CMD_EMPTY;
		}
	} else {
		/* Second mode : we get the initial command as argument */
		if (!recv_cmd)
			return CMD_FAULT;
		len = recv_cmd->data;
	}

	ret = put_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		return ret;

	data = malloc(len);
	if (!data)
		return CMD_NOMEM;

	if (timeout_p) 
		rret = clip_sock_read(s, data, len, 
			READ_TIMEOUT + (len / CHUNK_SIZE) * CHUNK_DELAY, 
			5 + len / CHUNK_SIZE );
	else 
		rret = clip_sock_read(s, data, len, -1, 5 + len / CHUNK_SIZE);

	if (rret < 0) {
		ret = CMD_FAULT;
		goto err;
	}
	if ((size_t)rret != len) {
		ERROR("timed-out getting data (delay: %i)",
			READ_TIMEOUT + (len / CHUNK_SIZE) * CHUNK_DELAY);
		ret = CMD_TIMOUT;
		goto err;
	}

	ret = put_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get final ack");
		goto err;
	}

	*datap = data;
	*lenp = len;

	return CMD_OK;

err:
	free(data);
	return ret;
}

uint32_t
get_field(int s,  uint32_t command, char **datap, uint32_t *lenp, 
		cmd_t *recv_cmd)
{
	return _get_field(s, command, datap, lenp, recv_cmd, 1);
}

uint32_t
get_field_notimeout(int s,  uint32_t command, char **datap, uint32_t *lenp, 
		cmd_t *recv_cmd)
{
	return _get_field(s, command, datap, lenp, recv_cmd, 0);
}

static uint32_t
_put_field(int s, uint32_t command, char *data, uint32_t len, int timeout_p)
{
	uint32_t ret;
	ssize_t wret;
	cmd_t cmd;

	ret = put_cmd(s, command, len);
	if (ret != CMD_OK)
		return ret;

	ret = get_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get initial ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Unexpected initial ack value");
		return cmd.cmd;
	}

	if (timeout_p) 
		wret = clip_sock_write(s, data, len, 
			WRITE_TIMEOUT + (len / CHUNK_SIZE) * CHUNK_DELAY, 
			5 + len / CHUNK_SIZE);
	else
		wret = clip_sock_write(s, data, len, -1, 5 + len / CHUNK_SIZE);

	if (wret < 0) 
		return CMD_FAULT;
	if ((size_t)wret != len) {
		ERROR("timed-out writting data (%d, %zd != %u)", timeout_p, wret, len);
		return CMD_TIMOUT;
	}

	ret = get_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "failed to get final ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK)
		return cmd.cmd;
	
	return CMD_OK;
}

uint32_t
put_field(int s, uint32_t command, char *data, uint32_t len)
{
	return _put_field(s, command, data, len, 1);
}

uint32_t
put_field_notimeout(int s, uint32_t command, char *data, uint32_t len)
{
	return _put_field(s, command, data, len, 0);
}

int
set_nonblock(int s)
{
        int opts;
        opts = fcntl(s, F_GETFL);
        if (opts < 0) {
                ERROR_ERRNO("fcntl(F_GETFL)");
                return -1;
        }
        opts |= O_NONBLOCK;
        if (fcntl(s, F_SETFL, opts) < 0) {
                ERROR_ERRNO("fcntl(F_SETFL)");
                return -1;
        }
        return 0;
}

const char *
cmderr(uint32_t err)
{
  switch (err) {
  case CMD_OK:
    return "success ?";
  case CMD_ORDER:
    return "wrong command order";
  case CMD_FAULT:
    return "internal error";
  case CMD_INVAL:
    return "invalid parameter";
  case CMD_NOMEM:
    return "not enough memory";
  case CMD_TIMOUT:
    return "command time out";
  case CMD_NOENT:
    return "no such entry";
  case CMD_PERM:
    return "permission denied";
  case CMD_EXIST:
    return "entry already exists";
  case CMD_EMPTY:
    return "empty result";
  case CMD_UNKNOWNUSER:
    return "unknown user";
  case CMD_CURRENTUSER:
    return "unable to perform an operation on the current user";
  case CMD_UNDET_USER:
    return "Unable to determine current user";
  case CMD_USEREXISTS:
    return "User already exists";
  case CMD_INVALID_LOGIN:
    return "Invalid login";
  case CMD_WEAK_PASSWD:
    return "Weak password";
  case CMD_DISKSPACE:
    return "Not enough disk space available";
  case CMD_INVALID_AUTHTYPE:
    return "Unexpected user authentication type";
  case CMD_INVALID_CARD:
    return "Invalid or missing smartcard";
  case CMD_INVALID_CA_CHAIN:
    return "Invalid or missing CA chain for certificate validation";
  default:
    return "<unknown>";
  }
}

uint32_t 
errno2cmd(int err) 
{
  switch (err) {
		case EPERM	:
			return CMD_PERM;
		case ENOENT	:
			return CMD_NOENT;
		case ESRCH	:
			return CMD_NOENT;
		case ENOMEM	:
			return CMD_NOMEM;
		case EACCES	:
			return CMD_PERM;
		case EFAULT	:
			return CMD_FAULT;
		case EEXIST	:
			return CMD_EXIST;
		default:
			return CMD_INVAL;
	}
}
// vim:sw=2:ts=2:et:
