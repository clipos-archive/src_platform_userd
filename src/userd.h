// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file userd.h
 * Userd main header.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * @n
 * All rights reserved.
 */

#ifndef USERD_H
#define USERD_H


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif



/* Error codes */
#define CMD_OK		0x0000	/* Success */
#define CMD_ORDER	0x0001	/* Unexpected command at this point */
#define CMD_FAULT	0x0002	/* Failure executing command */
#define CMD_INVAL	0x0003	/* Invalid command */
#define CMD_NOMEM	0x0004	/* Out of memory */
#define CMD_TIMOUT	0x0005	/* Timed-out waiting for command completion */
#define CMD_NOENT	0x0006	/* No such element */
#define CMD_PERM	0x0007	/* Permission denied */
#define CMD_EXIST	0x0008	/* Object already exists */
#define CMD_EMPTY	0x0009	/* Empty answer */

#define CMD_UNKNOWNUSER 0x000A  /* Unknown user */
#define CMD_CURRENTUSER 0x000B  /* Unable to perform operations on the current user */
#define CMD_UNDET_USER  0x000C  /* Impossible to determine current user */
#define CMD_USEREXISTS  0x000D  /* User already exists */
#define CMD_INVALID_LOGIN 0x000E  /* Invalid login (>8cars, or invalid cars) */
#define CMD_WEAK_PASSWD 0x000F  /* Weak password */
#define CMD_DISKSPACE   0x0010  /* No space left */
#define CMD_INVALID_PWD 0x0011  /* Invalid password/pin */
#define CMD_INVALID_AUTHTYPE 0x0012  /* Invalid AUTH type */
#define CMD_INVALID_CARD 0x0013  /* Invalid or missing PKCS11 token */
#define CMD_INVALID_CA_CHAIN 0x0014  /* Invalid/missing CA chain for PKCS11 authentication */



/*****************/
/*  logging      */
/*****************/
extern int g_verbose;
extern int g_daemonized;

/******************/
/* error handling */
/******************/
extern int g_relaxed;

/*****************/
/*  RM jails     */
/*****************/
extern int g_with_rmh;
extern int g_with_rmb;

/************/
/* usertype */
/************/

typedef enum usertype {
  T_UNKNOWN = -1,
  T_ADMIN = 0,
  T_AUDIT = 1,
  T_USER = 2,
  T_PRIV_USER = 3,
  T_NOMAD_USER = 4,
  T_USERTYPE_MAX = 4,
  T_USERTYPE_MASK = 7,
  T_CURRENT_USER = 0x10
} usertype_t;

/*************/
/* auth type */
/*************/

typedef enum authtype {
  AUTH_UNKNOWN = -1,
  AUTH_PW = 0,
  AUTH_PKCS,
  AUTH_MAX
} authtype_t;

#define AUTH_TYPE_MASK	0x1

/********************/
/* freedisk message */
/********************/

static const unsigned long disksize_size = sizeof (long);

typedef struct diskinfo {
  long space_available;
  long clip_partition_minsize;
  long rm_partition_minsize;
  long default_partsize;
} diskinfo_t;

static inline diskinfo_t *
diskinfo_alloc(void)
{
  diskinfo_t* _new = (diskinfo_t*) calloc(1, sizeof(*_new));
  return _new;
}

static inline void
diskinfo_free(diskinfo_t * fdsk)
{
  free(fdsk);
}


/*******************/
/* userinfo struct */
/*******************/

typedef struct userinfo_s {
  char* name;
  uint32_t nlen;
  char* passwd;
  uint32_t plen;
  usertype_t type;
  authtype_t auth;
  long rmh_size;
  long rmb_size;
} userinfo_t;

static inline userinfo_t *
userinfo_alloc(void)
{
  userinfo_t* _new = (userinfo_t*) calloc(1, sizeof(*_new));
  if (_new) {
    _new->name = NULL;
    _new->nlen = 0;
    _new->passwd = NULL;
    _new->plen = 0;
    _new->type = T_UNKNOWN;
    _new->auth = AUTH_UNKNOWN;
  }
  return _new;
}

static inline void
userinfo_free(userinfo_t *userinfo)
{
  if (userinfo->name) {
    memset(userinfo->name, 0, userinfo->nlen);
    free(userinfo->name);
  }
  if (userinfo->passwd) {
    memset(userinfo->passwd, 0, userinfo->plen);
    free(userinfo->passwd);
  }
  free(userinfo);
}


/**********************/
/* account name list  */
/**********************/

typedef struct userlist_s {
  userinfo_t* userinfo;
  struct userlist_s *prev, *next;
} userlist_t;

#define list_for_each(iter, head) \
	for (iter = (head)->next; iter != (head); iter = iter->next)

static inline userlist_t * userlist_alloc(void)
{
  userlist_t *_new = (userlist_t*) malloc(sizeof(*_new));

  if (_new) {
    _new->userinfo = NULL;
    _new->prev = _new->next = _new;
  }
  
  return _new;
}

static inline int add_userinfo (userlist_t* head, userinfo_t* userinfo) {
  userlist_t *_new = (userlist_t*) userlist_alloc();
  if (_new) {
    (_new)->userinfo = userinfo;
    (_new)->prev = (head)->prev;
    (_new)->next = (head);
    (head)->prev->next = _new;
    (head)->prev = _new;
    
    return 0;
  }
  return -1;
}

static inline void userlist_free_all (userlist_t* head) {
  userlist_t* _iter = head->prev;
  while (_iter != head) {
    (_iter)->prev->next = (_iter)->next;
    (_iter)->next->prev = (_iter)->prev;

    if (_iter->userinfo)
      free (_iter->userinfo);
    free (_iter);

    _iter = head->prev;
  }
  
  free (head);
}



extern int sock_connect(const char* sockpath);

extern uint32_t client_list_users(int s, userlist_t** res);
extern uint32_t client_disk_info(int s, diskinfo_t** res);
extern uint32_t client_lock_user(int s, const char* name);
extern uint32_t client_unlock_user(int s, const char* name);
extern uint32_t client_delete_user (int s, const char* name);
extern uint32_t client_create_user (int s, userinfo_t* newuser);
extern uint32_t client_chpw_self(int s, const char *oldpw, const char *newpw);
extern uint32_t client_migrate_user(int s, const char *user, const char *password, const char *pincode);

#ifdef __cplusplus
}
#endif

#endif /* USERD_H */
// vim:sw=2:ts=2:et:
