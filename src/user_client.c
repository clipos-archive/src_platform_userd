// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file user_client.c
 * userd client functions.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * Copyright (C) 2010-2013 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include <clip/clip.h>

#include "cmd.h"
#include "userd_priv.h"


const char *g_prefix = "user_client";


int sock_connect(const char* sockpath) {
  int s;
  struct sockaddr_un sau;

  sau.sun_family = AF_UNIX;
  snprintf(sau.sun_path, sizeof(sau.sun_path), "%s", sockpath);
  
  s = socket(PF_UNIX, SOCK_STREAM, 0);
  if (s < 0) {
    ERROR_ERRNO("socket (%s)", sockpath);
    return s;
  }
  if (connect(s, (struct sockaddr *)&sau, sizeof(struct sockaddr_un)) < 0)	{
    ERROR_ERRNO("connect %s", sockpath);
    close(s);
    return -1;
  }
  
  if (set_nonblock(s)) {
    close(s);
    return -1;
  }
  
  return s;
}




static uint32_t try_send_cmd (int s, uint32_t cmd_num) {
  uint32_t ret;
  cmd_t cmd;
  
  ret = put_cmd(s, cmd_num, 0);
  if (ret != CMD_OK) {
    CMD_ERROR(ret, "Rejected by server");
    return ret;
  }
  
  ret = get_cmd(s, &cmd);
  if (ret != CMD_OK) {
    CMD_ERROR(ret, "Failed to get handshake ack");
    return ret;
  }
  if (cmd.cmd != CMD_OK) {
    CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
    return cmd.cmd;
  }

  return CMD_OK;
}



uint32_t client_list_users(int s, userlist_t** res)
{
  uint32_t ret;
  cmd_t cmd;
  char* name;
  uint32_t len;
  userinfo_t* info;
  char* buf;
  
  ret = try_send_cmd(s, CMD_LISTUSERS);
  if (ret) return ret;
  
  *res = userlist_alloc();
  if (!res) {
    ERROR ("Not enough memory");
    return CMD_NOMEM;
  }
  
  while ((ret = get_field(s, CMD_NAME, &name, &len, &cmd)) == CMD_OK) {
    info = userinfo_alloc ();
    if (!info)
      goto clu_mem_err;
    
    info->name=name;
    info->nlen=len; 

    ret = get_field(s, CMD_TYPE, &buf, &len, NULL);
    if (len != sizeof (usertype_t) || ret != CMD_OK)
      goto clu_error;
    memcpy (&info->type, buf, sizeof (usertype_t));
    free (buf);

    ret = get_field(s, CMD_AUTHTYPE, &buf, &len, NULL);
    if (len != sizeof (authtype_t) || ret != CMD_OK)
      goto clu_error;
    memcpy (&info->auth, buf, sizeof (authtype_t));
    free (buf);

    if (g_with_rmh) {
      ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
      if (len != disksize_size || ret != CMD_OK)
        goto clu_error;
      memcpy (&info->rmh_size, buf, disksize_size);
      free (buf);
    }

    if (g_with_rmb) {
      ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
      if (len != disksize_size || ret != CMD_OK)
        goto clu_error;
      memcpy (&info->rmb_size, buf, disksize_size);
      free (buf);
    }

    if (add_userinfo (*res, info))
      goto clu_mem_err;
  }
  
  if (ret != CMD_ORDER || cmd.cmd != CMD_ENDLIST)
    goto clu_error;
  
  return CMD_OK;

 clu_mem_err:
  ERROR ("Not enough memory");
  ret = CMD_NOMEM;
 
 clu_error:
  CMD_ERROR (ret, "Error retrieving user list");
  userlist_free_all (*res);
  return ret;
}



uint32_t client_disk_info(int s, diskinfo_t** res)
{
  uint32_t ret;
  uint32_t len;
  char* buf;

  ret = try_send_cmd(s, CMD_DISKINFO);
  if (ret != CMD_OK) 
  	return ret;
  
  *res = diskinfo_alloc();
  if (!res) {
    ERROR ("Not enough memory");
    return CMD_NOMEM;
  }
  
  ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
  if (len != sizeof ((*res)->space_available) || ret != CMD_OK)
    goto cdi_error;
  memcpy (&(*res)->space_available, buf, sizeof ((*res)->space_available));
  free (buf);

  ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
  if (len != disksize_size || ret != CMD_OK)
    goto cdi_error;
  memcpy (&(*res)->clip_partition_minsize, buf, disksize_size);
  free (buf);

  if (g_with_rmh || g_with_rmb) {
    ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
    if (len != disksize_size || ret != CMD_OK)
      goto cdi_error;
    memcpy (&(*res)->rm_partition_minsize, buf, disksize_size);
    free (buf);

    ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
    if (len != disksize_size || ret != CMD_OK)
      goto cdi_error;
    memcpy (&(*res)->default_partsize, buf, disksize_size);
    free (buf);
  }

  return CMD_OK;

 cdi_error:
  CMD_ERROR (ret, "Error retrieving disk information");
  diskinfo_free (*res);
  return ret;
}



static uint32_t client_lock_unlock (int s, const char* constname, int lock) {
  uint32_t ret;
  cmd_t cmd;
  char* name;

  if (asprintf (&name, "%s", constname) <= 0) {
    ret = CMD_NOMEM;
    goto clu_error;
  }

  ret = try_send_cmd(s, lock ? CMD_LOCKUSER : CMD_UNLOCKUSER);
  if (ret != CMD_OK) goto clu_free;
  
  ret = put_field(s, CMD_NAME, name, strlen (name));
  if (ret != CMD_OK) goto clu_free;

  ret = get_cmd_notimeout(s, &cmd);
  if (ret != CMD_OK) goto clu_free;
  if (cmd.cmd != CMD_OK) {
    ret = cmd.cmd;
    goto clu_free;
  }

  return CMD_OK;

 clu_free:
  free (name);

 clu_error:
  if (ret != CMD_OK)
    CMD_ERROR (ret, "Error while locking / unlocking user %s", constname);
  return ret;
}


uint32_t client_lock_user(int s, const char* name) {
  return (client_lock_unlock (s, name, 1));
}

uint32_t client_unlock_user(int s, const char* name) {
  return (client_lock_unlock (s, name, 0));
}



uint32_t client_delete_user (int s, const char* constname) {
  uint32_t ret;
  cmd_t cmd;
  char* name;

  if (asprintf (&name, "%s", constname) <= 0) {
    ret = CMD_NOMEM;
    goto cdu_error;
  }

  ret = try_send_cmd(s, CMD_DELUSER);
  if (ret != CMD_OK) goto cdu_free;
  
  ret = put_field(s, CMD_NAME, name, strlen (name));
  if (ret != CMD_OK) goto cdu_free;

  ret = get_cmd_notimeout(s, &cmd);
  if (ret != CMD_OK) goto cdu_free;
  if (cmd.cmd != CMD_OK) {
    ret = cmd.cmd;
    goto cdu_free;
  }

 cdu_free:
  free (name);

 cdu_error:
  if (ret != CMD_OK)
    CMD_ERROR(ret, "Error while deleting user %s", constname);
  return ret;
}


uint32_t client_create_user (int s, userinfo_t* newuser) {
  uint32_t ret;
  cmd_t cmd;

  ret = try_send_cmd(s, CMD_ADDUSER);
  if (ret != CMD_OK) goto ccu_error;
  
  ret = put_field(s, CMD_NAME, newuser->name, newuser->nlen);
  if (ret != CMD_OK) goto ccu_error;

  ret = put_field(s, CMD_PASSWD, newuser->passwd, newuser->plen);
  if (ret != CMD_OK) goto ccu_error;

  ret = put_field(s, CMD_TYPE, (char*) &newuser->type, sizeof (usertype_t));
  if (ret != CMD_OK) goto ccu_error;

  ret = put_field(s, CMD_AUTHTYPE, (char*) &newuser->auth, sizeof (authtype_t));
  if (ret != CMD_OK) goto ccu_error;

  if (g_with_rmh) {
    ret = put_field(s, CMD_SIZE, (char*) &newuser->rmh_size, disksize_size);
    if (ret != CMD_OK) goto ccu_error;
  }

  if (g_with_rmb) {
    ret = put_field(s, CMD_SIZE, (char*) &newuser->rmb_size, disksize_size);
    if (ret != CMD_OK) goto ccu_error;
  }

  ret = get_cmd_notimeout(s, &cmd);
  if (ret != CMD_OK) goto ccu_error;
  if (cmd.cmd != CMD_OK) {
    ret = cmd.cmd;
    goto ccu_error;
  }

  return CMD_OK;

 ccu_error:
  CMD_ERROR (ret, "Error while creating user %.*s", 
                          newuser->nlen, newuser->name);
  return ret;
 
}

uint32_t client_chpw_self(int s, const char *oldpw, const char *newpw) {
  uint32_t ret;
  cmd_t cmd;
  char *opw, *npw;
  opw = strdup(oldpw);
  npw = strdup(newpw);
  if (!opw || !npw) {
    ERROR("out of memory duplicating passwords");
    ret = CMD_NOMEM;
    goto out_free;
  }

  ret = try_send_cmd(s, CMD_CHPASSWD);
  if (ret != CMD_OK)
    goto err;

  ret = put_field(s, CMD_PASSWD, opw, strlen(opw));
  if (ret != CMD_OK)
    goto err;

  ret = put_field(s, CMD_PASSWD, npw, strlen(npw));
  if (ret != CMD_OK)
    goto err;

  ret = get_cmd_notimeout(s, &cmd);
  if (ret != CMD_OK)
    goto err;
  if (cmd.cmd != CMD_OK) {
    ret = cmd.cmd;
    goto err;
  }
	
  ret = CMD_OK;
  /* Fall through */
out_free:
  if (opw) {
    memset(opw, 0, strlen(opw));
    free(opw);
  }
  if (npw) {
    memset(npw, 0, strlen(npw));
    free(npw);
  }
  return ret;
 
err:
  CMD_ERROR(ret, "failed to change password");
  goto out_free;
}






uint32_t client_migrate_user(int s, const char *user, const char *password, const char *pincode) {
  uint32_t ret;
  cmd_t cmd;
  char *opw, *npin, *name;

  name = strdup(user);
  opw = strdup(password);
  npin = strdup(pincode);

  if (!opw || !npin || !name) {
    ERROR("out of memory duplicating passwords and/or name");
    ret = CMD_NOMEM;
    goto out_free;
  }

  ret = try_send_cmd(s, CMD_MIGRATETOCARD);
  if (ret != CMD_OK)
    goto err;

  ret = put_field(s, CMD_NAME, name, strlen(name));
  if (ret != CMD_OK)
    goto err;

  ret = put_field(s, CMD_PASSWD, opw, strlen(opw));
  if (ret != CMD_OK)
    goto err;

  ret = put_field(s, CMD_PASSWD, npin, strlen(npin));
  if (ret != CMD_OK)
    goto err;

  ret = get_cmd_notimeout(s, &cmd);
  if (ret != CMD_OK)
    goto err;
  if (cmd.cmd != CMD_OK) {
    ret = cmd.cmd;
    goto err;
  }
	
  ret = CMD_OK;
  /* Fall through */
out_free:
  if (opw) {
    memset(opw, 0, strlen(opw));
    free(opw);
  }
  if (npin) {
    memset(npin, 0, strlen(npin));
    free(npin);
  }
  if (name) {
    free(name);
  }
  return ret;
 
err:
  CMD_ERROR(ret, "failed to migrate user");
  goto out_free;
}
// vim:sw=2:ts=2:et:
