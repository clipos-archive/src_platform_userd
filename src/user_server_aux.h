// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file user_server_aux.h
 * Prototypes of helper functions for the userd server.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * Copyright (C) 2013-2014 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#ifndef USER_SERVER_AUX_H
#define USER_SERVER_AUX_H

#include "userd_priv.h"

extern const char clip_users_grp[];
extern const char clip_admin_grp[];
extern const char clip_audit_grp[];
extern const char clip_priv_users_grp[];
extern const char clip_nomad_users_grp[];
extern const char clip_pkauth_grp[];
extern const char admins_supp_grps[];
extern const char clip_base[];
extern const char part_rootpath[];
extern const char rmh_base[];
extern const char rmb_base[];

extern long minCLIPPartSize;
extern long minRMPartSize;
extern long defaultSize;
extern const long reservedSpace;
extern const long _1MB;

extern char CP[];
extern char DD[];
extern char TR[];
extern char MKE2FS[];
extern char MKFS_EXT4[];
extern char CRYPTSETUP[];
extern char DMSETUP[];
extern char LOSETUP[];
extern char USERMOD[];
extern char USERDEL[];
extern char USERADD[];
extern char GPASSWD[];
extern char CREATE_SSH[];
extern char DELETE_SSH[];

extern char SUB_HELPER[];
extern char HASH_PASS[];
extern char CREATE_SETTINGS[];
extern char ENCRYPT_STAGE2_KEY[];
extern char OUTPUT_STAGE2_KEY[];

extern char CRACK_CHECK[];

extern const int ENCPASSWD_MAXLEN;
extern const int STAGE2KEY_MAXLEN;

extern uint32_t get_gids (gid_t gids[]);
extern usertype_t get_type_from_gid (gid_t gid, gid_t gids[]);
extern usertype_t get_type_from_name (const char* user, gid_t gids[]);
extern const char * get_type_name(usertype_t);

extern authtype_t get_authtype_from_name (const char* user);

extern int fork_exec (char *arg, ...);
extern pid_t fork_exec_fin_fout (int fd_input, int fd_output, char *arg, ...);
extern uint32_t fork_exec_sin_env (const char* input, const char* env_var, const char* env_val, char *arg, ...);
extern char* fork_exec_fin_sout (const char* filename, int maxOutput, int* status, char *arg, ...);
extern char* fork_exec_sout (int maxOutput, int* status, char *arg, ...);
extern char* fork_exec_sout_env (int maxOutput, int* status, const char* env_var, const char* env_val, char *arg, ...);

extern uint32_t get_current_user (uid_t* res);
extern uint32_t check_uid (const char* const username);

extern uint32_t remove_file (const char *fmt, ...);

extern uint32_t get_free_space (long* space);

#endif // USER_SERVER_AUX_H

// vim:sw=2:ts=2:et:
