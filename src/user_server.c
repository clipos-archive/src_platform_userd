// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright Â© 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file user_server.c
 * Main functions for the userd server.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * Copyright (C) 2013-2014 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <errno.h>

#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/stat.h>
#include <clip/clip.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <libp11.h>
#include <inttypes.h>

#include "cmd.h"
#include "userd_priv.h"
#include "user_server_aux.h"
#include "pkcs11_ops.h"
#include "pam_check.h"


static inline void FREE_IF_NOT_NULL (void* x) {
  if (x != NULL) free (x);
  x = NULL;
}




static uint32_t list_users(int s) {
  gid_t gids[T_USERTYPE_MAX + 1];
  struct passwd * pw;
  uid_t current_user = 0;
  char* name;

  usertype_t t;
  authtype_t a;
  struct stat64 fileinfo;
  long rmh = 0, rmb = 0;
  char* filename;

  uint32_t ret;

  ret = put_cmd(s, CMD_OK, 0);
  if (ret != CMD_OK)
    return ret;

  ret = get_gids (gids);
  if (ret != CMD_OK) goto lu_end;

  ret = get_current_user (&current_user);
  if (ret != CMD_OK) {
    if (ret == CMD_UNDET_USER) {
    	ret = CMD_OK; /* Needed to avoid returning an error when 
	                 there are no user accounts on the system */
    } else {
      CMD_ERROR (ret, "Unable to find out who the current user is");
      return ret;
    }
  }

  while ((pw = getpwent()) != NULL) {
    name = pw->pw_name;
    t = get_type_from_gid (pw->pw_gid , gids);
    if (t == T_UNKNOWN) continue;

    a = get_authtype_from_name (name);
    if (a == AUTH_UNKNOWN) continue;

    rmh = 0;
    rmb = 0;

    if (pw->pw_uid == current_user)
      t |= T_CURRENT_USER;

    if ((t & T_USERTYPE_MASK) == T_PRIV_USER || (t & T_USERTYPE_MASK) == T_USER 
            || (t & T_USERTYPE_MASK) == T_NOMAD_USER) {
      if (g_with_rmh) {
        if (asprintf (&filename, "%s/parts/%s.part", rmh_base, name) <= 0) {
          ret = CMD_NOMEM;
          goto lu_endpwent;
        }
        if (stat64 (filename, &fileinfo) == 0)
          rmh = (fileinfo.st_size >> 20); // Result is in mega bytes
        free (filename);
      }
      if (g_with_rmb) {
        if (asprintf (&filename, "%s/parts/%s.part", rmb_base, name) <= 0) {
          ret = CMD_NOMEM;
          goto lu_endpwent;
        }
        if (stat64 (filename, &fileinfo) == 0)
          rmb = (fileinfo.st_size >> 20); // Result is in mega bytes
        free (filename);
      }
    }

    ret = put_field (s, CMD_NAME, name, strlen (name));
    if (ret != CMD_OK) break;
    ret = put_field (s, CMD_TYPE, (char*) &t, sizeof (usertype_t));
    if (ret != CMD_OK) break;
    ret = put_field (s, CMD_AUTHTYPE, (char*) &a, sizeof (authtype_t));
    if (ret != CMD_OK) break;
    if (g_with_rmh) {
      ret = put_field (s, CMD_SIZE, (char*) &rmh, sizeof (rmh));
      if (ret != CMD_OK) break;
    }
    if (g_with_rmb) {
      ret = put_field (s, CMD_SIZE, (char*) &rmb, sizeof (rmb));
      if (ret != CMD_OK) break;
    }
  }

lu_endpwent:
  endpwent();

lu_end:
  if (ret == CMD_OK)
    ret = put_cmd(s, CMD_ENDLIST, 0);

  if (ret != CMD_OK)
    CMD_ERROR(ret, "Failed to send user list");

  return ret;
}



static uint32_t disk_info (int s) {
  uint32_t ret;
  long space;

  ret = put_cmd(s, CMD_OK, 0);
  if (ret != CMD_OK)
    return ret;

  if (get_free_space (&space) != CMD_OK)
    goto gd_end;

  ret = put_field (s, CMD_SIZE, (char*) &space, disksize_size);
  if (ret != CMD_OK) goto gd_end;
  ret = put_field (s, CMD_SIZE, (char*) &minCLIPPartSize, disksize_size);
  if (ret != CMD_OK) goto gd_end;
  if (g_with_rmh || g_with_rmb) {
    ret = put_field (s, CMD_SIZE, (char*) &minRMPartSize, disksize_size);
    if (ret != CMD_OK) goto gd_end;
    ret = put_field (s, CMD_SIZE, (char*) &defaultSize, disksize_size);
    if (ret != CMD_OK) goto gd_end;
  }

 gd_end:
  if (ret != CMD_OK)
    CMD_ERROR(ret, "Failed to send disk information");

  return ret;
}



static uint32_t lock_user (int s, int lock) {
  uint32_t ret;
  char* name;
  char* buf;
  uint32_t len;

  ret = put_cmd(s, CMD_OK, 0);
  if (ret != CMD_OK)
    return ret;

  ret = get_field(s, CMD_NAME, &buf, &len, NULL);
  if (ret != CMD_OK)
    return ret;

  if (asprintf (&name, "%.*s", len, buf) <= 0) {
    ret = CMD_NOMEM;
    goto lu_buffree;
  }

  ret = check_uid (name);
  switch (ret) {
  case CMD_OK: break;
  case CMD_CURRENTUSER:
    CMD_ERROR (ret, "lock_user");
    goto lu_namefree;
  case CMD_UNKNOWNUSER:
    CMD_ERROR (ret, "lock_user");
    goto lu_namefree;
  default:
    CMD_ERROR (ret, "Unexpected return value from check_uid");
    goto lu_namefree;
  }

  if (ret != CMD_OK) {
    put_cmd(s, CMD_CURRENTUSER, 0);
    goto lu_namefree;
  }

  if (fork_exec (USERMOD, lock ? "-L" : "-U", name, NULL) != 0) {
    ret = CMD_FAULT;
    goto lu_namefree;
  }

  ret = put_cmd(s, CMD_OK, 0);
  
 lu_namefree:
  free (name);

 lu_buffree:
  free (buf);
  
  return ret;
}



static uint32_t remove_home (const char* base, const char* login, authtype_t auth) {
  uint32_t ret = CMD_OK;

  ret = remove_file ("%s/parts/%s.part", base, login);
  if (ret != CMD_OK) return ret;

  if (auth == AUTH_PKCS) {
    ret = remove_file ("%s/keys/%s.key.enc", base, login);
    if (ret != CMD_OK) return ret;
  } else if(auth == AUTH_PW) {
    ret = remove_file ("%s/keys/%s.settings", base, login);
    if (ret != CMD_OK) return ret;
    ret = remove_file ("%s/keys/%s.key", base, login);
    if (ret != CMD_OK) return ret;
  } else {
    ERROR("Unknown authentication type");
    return CMD_FAULT;
  }

  return CMD_OK;
}

static uint32_t 
clean_ssh_keys(const char *name, usertype_t type)
{   
  const char *tname = get_type_name(type);
  if (!tname) {
    CMD_ERROR(CMD_INVAL, "Unsupported user type");
    return CMD_INVAL;
  }

  if (fork_exec(DELETE_SSH, name, tname, NULL)) { 
    CMD_ERROR(CMD_FAULT, "Error deleting user SSH keys");
    return CMD_FAULT;
  }

  return CMD_OK;
}

static uint32_t delete_user (int s) {
  uint32_t ret;
  char* name;
  char* buf;
  uint32_t len;
  gid_t gids[T_USERTYPE_MAX + 1];
  usertype_t type;
  authtype_t auth;

  ret = put_cmd(s, CMD_OK, 0);
  if (ret != CMD_OK)
    return ret;

  ret = get_field(s, CMD_NAME, &buf, &len, NULL);
  if (ret != CMD_OK)
    return ret;

  if (asprintf (&name, "%.*s", len, buf) <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "delete_user");
    (void)put_cmd(s, CMD_NOMEM, 0);
    goto du_buffree;
  }

  // Checking whether the user to delete is the one connected
  ret = check_uid (name);
  switch (ret) {
  case CMD_OK: break;
  case CMD_CURRENTUSER:
    CMD_ERROR (ret, "Cannot operate on the user currently logged.");
    (void)put_cmd(s, ret, 0);
    goto du_name_free;
  case CMD_UNKNOWNUSER:
    CMD_ERROR (ret, "Invalid username given.");
    (void)put_cmd(s, ret, 0);
    goto du_name_free;
  default:
    CMD_ERROR (ret, "Unexpected return value from check_uid");
    (void)put_cmd(s, ret, 0);
    goto du_name_free;
  }

  // Checking whether the user to delete is a valid CLIP account
  ret = get_gids (gids);
  if (ret != CMD_OK) {
    (void)put_cmd(s, ret, 0);
    goto du_name_free;
  }

  type = get_type_from_name (name, gids);
  if (type == T_UNKNOWN) {
     CMD_ERROR (ret = CMD_NOENT,
          "The account %s is not a valid CLIP account, and thus cannot be deleted",
          name);
     (void)put_cmd(s, ret, 0);
     goto du_name_free;
  }

  auth = get_authtype_from_name (name);
  switch(auth) {
  case AUTH_PKCS:
  case AUTH_PW:
    break;
  default:
     CMD_ERROR (ret = CMD_NOENT,
          "The account %s is not a valid CLIP account, and thus cannot be deleted",
          name);
     (void)put_cmd(s, ret, 0);
     goto du_name_free;
  }

  // Removing ssh key
  ret = clean_ssh_keys(name, type);
  if (ret != CMD_OK) {
    put_cmd(s, ret, 0);
    goto du_name_free;
  }

  ret = remove_home (clip_base, name, auth);
  if (ret != CMD_OK) {
    put_cmd(s, ret, 0);
    goto du_name_free;
  }

  if(auth == AUTH_PKCS) {
    ret = remove_file ("%s/keys/%s.masterkey", clip_base, name);
    if (ret != CMD_OK) goto du_name_free;

    // remove pam_pkcs11 cert -> user mapping
    ret = pkauth_del_user(name);
    if (ret != CMD_OK) goto du_name_free;
  }

  if (type == T_USER || type == T_PRIV_USER || type == T_NOMAD_USER) {
    if (g_with_rmh) {
      ret = remove_home (rmh_base, name, auth);
      if (ret != CMD_OK) {
        put_cmd(s, ret, 0);
        goto du_name_free;
      }
    }

    if (g_with_rmb) {
      ret = remove_home (rmb_base, name, auth);
      if (ret != CMD_OK) {
        put_cmd(s, ret, 0);
        goto du_name_free;
      }
    }
  }

  if (fork_exec (USERDEL, name, NULL) != 0) {
    ret = CMD_FAULT;
    goto du_name_free;
  }

  ret = put_cmd(s, CMD_OK, 0);

 du_name_free:
  free (name);

 du_buffree:
  free (buf);
  
  return ret;
}


static uint32_t check_login (char* login) {
  int i;
  int l = strlen (login);

  if (l > 32) {
    CMD_ERROR (CMD_INVALID_LOGIN, "Login too long");
    return CMD_INVALID_LOGIN;
  }

  if (l == 0) {
    CMD_ERROR (CMD_INVALID_LOGIN, "Empty login");
    return CMD_INVALID_LOGIN;
  }

  for (i=0; i<l; i++) {
    if (login[i] >= 'a' && login[i] <= 'z') continue;
    if (login[i] == '_') continue;
    if (i != 0) {
      if (login[i] >= '0' && login[i] <= '9') continue;
      if (login[i] == '-') continue;
    }     
    CMD_ERROR (CMD_INVALID_LOGIN, "Login should be in [a-z_][a-z0-9_-]*{0,31}");
    return CMD_INVALID_LOGIN;
  }

  return CMD_OK;
}

static uint32_t encrypt_password (const char* passwd, char** enc_passwd) {
  char* result;
  int n;
  int status;

  result = fork_exec_sout_env (ENCPASSWD_MAXLEN, &status, "PASS", passwd, SUB_HELPER, HASH_PASS, "PASS", NULL);
  if ( (result == NULL) || (! WIFEXITED (status)) || (WEXITSTATUS (status) != 0) ) {
    CMD_ERROR (CMD_FAULT, "Error while deriving passphrase (exec)");
    return CMD_FAULT;
  }

  n = strlen(result);
  if (result[n] == '\n')
    result[n] = 0;

  *enc_passwd = result;
  return CMD_OK;
}






static uint32_t do_useradd (char* name, char* enc_passwd, usertype_t type, authtype_t auth) {
  int res;
  char *grps = NULL;
  const char *default_grp = NULL;
  char* auth_grp = "";

  DEBUG ("Adding user %s to the system", name);

  if(auth == AUTH_PKCS) {
    if (asprintf(&auth_grp, ",%s", clip_pkauth_grp) < 0) {
      CMD_ERROR (CMD_NOMEM, "Out of memory");
      return CMD_NOMEM;
    }
  }

  switch (type) {
  case T_USER:
    default_grp = clip_users_grp;
    if (asprintf(&grps, "%s%s", clip_users_grp, auth_grp) < 0) {
      CMD_ERROR (CMD_NOMEM, "Out of memory");
      return CMD_NOMEM;
    }
    break;
  case T_ADMIN:
    default_grp = clip_admin_grp;
    if (asprintf(&grps, "%s%s", admins_supp_grps, auth_grp) < 0) {
      CMD_ERROR (CMD_NOMEM, "Out of memory");
      return CMD_NOMEM;
    }
    break;
  case T_AUDIT:
    default_grp = clip_audit_grp;
    if (asprintf(&grps, "%s%s", clip_users_grp, auth_grp) < 0) {
      CMD_ERROR (CMD_NOMEM, "Out of memory");
      return CMD_NOMEM;
    }
    break;
  case T_PRIV_USER:
    default_grp = clip_priv_users_grp;
    if (asprintf(&grps, "%s%s", admins_supp_grps, auth_grp) < 0) {
      CMD_ERROR (CMD_NOMEM, "Out of memory");
      return CMD_NOMEM;
    }
    break;
  case T_NOMAD_USER:
    default_grp = clip_nomad_users_grp;
    if (asprintf(&grps, "%s,%s%s", admins_supp_grps, clip_priv_users_grp, auth_grp) < 0) {
      CMD_ERROR (CMD_NOMEM, "Out of memory");
      return CMD_NOMEM;
    }
    break;
  default:
    // This case cannot happen since we have already checked the type
    return CMD_FAULT;
  }

  res = fork_exec (USERADD, 
		   "-g", default_grp,
		   "-G", grps,
		   "-d", "/home/user",
		   "-p", enc_passwd,
		   name, NULL);

  if (res != 0) {
    CMD_ERROR (CMD_FAULT, "Impossible to add user %s (fork_exec returned %d)", name, res);
    res = CMD_FAULT;
  } else {
    res = CMD_OK;
  }

  if(grps != NULL)
    free(grps);
  if(auth == AUTH_PKCS && auth_grp != NULL)
    free(auth_grp);
  
  return res;
}

static inline uint32_t read_key(const char *base, const char *name,
                                     const char *pwd, char **key, uint32_t *len)
{
  uint32_t ret;
  char *key_fn = NULL;
  char *settings_fn = NULL;
  char *key_str = NULL;
  uint32_t key_len = 0;
  int status;

  ret = CMD_NOMEM;
  if (asprintf(&key_fn, "%s/keys/%s.key", base, name) <= 0)
    return ret;
  if (asprintf(&settings_fn, "%s/keys/%s.settings", base, name) <= 0)
    goto out_free;

  ret = CMD_FAULT;
  key_str = fork_exec_sout_env(STAGE2KEY_MAXLEN, &status, "PASS", pwd, 
                                     SUB_HELPER, OUTPUT_STAGE2_KEY, 
                                     settings_fn, "PASS", key_fn, NULL);
  if (!key_str || (!WIFEXITED (status)) || WEXITSTATUS (status)) {
    ERROR("failed to read key for %s in %s based on old password", name, base);
    goto out_free;
  }

  key_len = strlen(key_str);
  if (key_str[key_len - 1] == '\n') {
    key_str[key_len - 1] = 0;
    key_len--;
  }

  *key = key_str;
  *len = key_len;
  free(settings_fn);
  free(key_fn);
  return CMD_OK;

out_free:
  if (key_fn)
    free(key_fn);

  if (settings_fn)
    free(settings_fn);

  if (key_str && key_len) {
    memset(key_str, 0, key_len);
    free(key_str);
  }
  return ret;
}

static uint32_t chpw_home_prepare(const char *base, const char *name,
                             const char *oldpw, const char *newpw)
{
  uint32_t ret;
  char *key_fn = NULL;
  char *settings_fn = NULL;
  char *key_str = NULL;
  uint32_t key_len = 0;
  mode_t saved_umask;

  DEBUG("Modifying partition password for %s in %s", name, base);

  ret = read_key(base, name, oldpw, &key_str, &key_len);
  if (ret != CMD_OK)
    return ret;


  saved_umask = umask(S_IRWXG | S_IRWXO);

  ret = CMD_NOMEM;
  if (asprintf(&key_fn, "%s/keys/%s.key.new", base, name) <= 0)
    goto out_free;
  if (asprintf(&settings_fn, "%s/keys/%s.settings.new", base, name) <= 0)
    goto out_free;

  ret = CMD_FAULT;
  if (fork_exec(SUB_HELPER, CREATE_SETTINGS, name, settings_fn, NULL) != 0) {
    CMD_ERROR (ret, "Error while creating new settings "
                                  "for %s in %s", name, base);
    goto out_settings;
  }

  if (fork_exec_sin_env(key_str, "PASS", newpw, SUB_HELPER, 
                        ENCRYPT_STAGE2_KEY, settings_fn, "PASS", key_fn, "pw", NULL) != 0) {
    CMD_ERROR (ret, "Error while encrypting the key with the password");
    goto out_key;
  }

  ret = CMD_OK;
  goto out_free;
 
out_key:
  remove_file("%s", key_fn);

out_settings:
  remove_file("%s", settings_fn);

out_free:
  if (key_fn)
    free(key_fn);

  if (settings_fn)
    free(settings_fn);

  if (key_str) {
    memset(key_str, 0, key_len);
    free(key_str);
  }

  (void)umask(saved_umask);
  return ret;
}

static uint32_t chpw_home_abort(const char *base, const char *name) {
  uint32_t ret1, ret2;

  ret1 = remove_file("%s/keys/%s.key.new", base, name);
  ret2 = remove_file("%s/keys/%.settings.new", base, name);

  if (ret1 != CMD_OK)
    return ret1;
  return ret2;
}

static uint32_t chpw_home_finish(const char *base, const char *name) {
  char *from, *to;
  int ret;

  if (asprintf(&from, "%s/keys/%s.key.new", base, name) <= 0)
    return CMD_NOMEM;
  if (asprintf(&to, "%s/keys/%s.key", base, name) <= 0) {
    free(from);
    return CMD_NOMEM;
  }
  ret = rename(from, to);
  if (ret)
    ERROR_ERRNO("failed to move %s to %s", from, to);

  free(from);
  free(to);
  if (ret)
    return errno2cmd(errno);

  if (asprintf(&from, "%s/keys/%s.settings.new", base, name) <= 0)
    return CMD_NOMEM;
  if (asprintf(&to, "%s/keys/%s.settings", base, name) <= 0) {
    free(from);
    return CMD_NOMEM;
  }
  ret = rename(from, to);
  if (ret)
    ERROR_ERRNO("failed to move %s to %s", from, to);

  free(from);
  free(to);
  if (ret)
    return errno2cmd(errno);
  else 
    return CMD_OK;
}

static uint32_t chpw_homes(const char *name, const char *oldpw, 
                          const char *newpw, usertype_t type) {
  uint32_t ret;
  	
  ret = chpw_home_prepare(clip_base, name, oldpw, newpw);
  if (ret != CMD_OK)
    return ret;

  if (type == T_USER || type == T_PRIV_USER || type == T_NOMAD_USER) {
    if (g_with_rmh) {
      ret = chpw_home_prepare(rmh_base, name, oldpw, newpw);
      if (ret != CMD_OK)
        goto abort;
    }
    if (g_with_rmb) {
      ret = chpw_home_prepare(rmb_base, name, oldpw, newpw);
      if (ret != CMD_OK)
        goto abort;
    }
  }

  ret = chpw_home_finish(clip_base, name);
  if (ret != CMD_OK)
    goto abort;

  /* Note : we don't really handle the case where one move
   * works but not the next. In that case, the user is screwed
   * as far as logging in is concerned, but we should still be able to 
   * read her data with a little work.
   */
  if (type == T_USER || type == T_PRIV_USER || type == T_NOMAD_USER) {
    if (g_with_rmh) {
      ret = chpw_home_finish(rmh_base, name);
      if (ret != CMD_OK)
        goto abort;
    }
    if (g_with_rmb) {
      ret = chpw_home_finish(rmb_base, name);
      if (ret != CMD_OK)
        goto abort;
    }
  }

  return CMD_OK;

abort:
  (void)chpw_home_abort(clip_base, name);
  if (type == T_USER || type == T_PRIV_USER || type == T_NOMAD_USER) {
    if (g_with_rmh)
      (void)chpw_home_abort(rmh_base, name);
    if (g_with_rmb)
      (void)chpw_home_abort(rmb_base, name);
  }

  return ret;
}

static uint32_t 
make_home(const char* base, uid_t uid, const char* name, const char* password, 
          long size, int gen_key, int auth, usertype_t type) 
{
  uint32_t ret;
  char* part_fn = NULL;
  int   part_fd = 0;
  off_t len = 0;
  char* key_fn = NULL;
  char* settings_fn = NULL;
  char* login_at_clip = NULL;

  char* key_str = NULL;
  struct stat stats;
  mode_t saved_umask;

  DEBUG ("Creating home partition for %s", name);

  // Should not happen since the size are tested before
  if (size <= 0)
    return CMD_INVAL;

  ret = CMD_NOMEM;
  if (asprintf (&part_fn, "%s/parts/%s.part", base, name) <= 0)
    goto mh_free;

  if (asprintf (&key_fn, "%s/keys/%s.key%s", base, name, auth==AUTH_PKCS ? ".enc" : "") <= 0)
    goto mh_free;
  if (asprintf (&login_at_clip, "%s@clip", name) <= 0)
    goto mh_free;

  if(auth == AUTH_PW) {
    if (asprintf (&settings_fn, "%s/keys/%s.settings", base, name) <= 0)
      goto mh_free;
    if (fork_exec (SUB_HELPER, CREATE_SETTINGS, name, settings_fn, NULL) != 0) {
      CMD_ERROR (ret = CMD_FAULT, "Error while creating user settings");
      goto mh_err_settings;
    }
  }

  DEBUG("Initializing user partition");

  part_fd = open(part_fn, O_WRONLY|O_CREAT, 0600);
  if (part_fd < 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while opening user partition for creation");
    goto mh_err_part;
  }

  // size is given in Mibibytes and is a long int, so beware of overflows
  len = size;
  len *= 1024*1024;
  if (posix_fallocate(part_fd, 0, len) < 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error during posix_fallocate()");
    if (close(part_fd) < 0)
      DEBUG("Error when closing partition file descriptor, ignoring");
    goto mh_err_part;
  }
  if (close(part_fd) < 0)
    DEBUG("Error when closing partition file descriptor, ignoring");


  DEBUG("Creating loop device");

  if (fork_exec (LOSETUP, "/dev/loop7", part_fn, NULL) < 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while creating loop device");
    goto mh_err_part;
  }

  key_str = fork_exec_fin_sout ("/dev/urandom", 119, NULL, TR, "-cd", "[:graph:]", NULL);
  if (key_str == NULL || strlen (key_str) < 119) {
    CMD_ERROR (ret = CMD_FAULT, "Error while generating the key");
    goto mh_err_unloop;
  }

  saved_umask = umask (S_IRWXG | S_IRWXO);
  if (fork_exec_sin_env (key_str, "PASS", password, SUB_HELPER, ENCRYPT_STAGE2_KEY, auth==AUTH_PKCS ? "NOTHIN" : settings_fn, "PASS", key_fn, auth==AUTH_PKCS ? "key" : "pw", NULL) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while encrypting the key with the password");
    (void) umask (saved_umask);
    goto mh_err_forget_key;
  }

  if (fork_exec_sin_env (key_str, "NOTHIN", "", CRYPTSETUP, "-c", "aes-lrw-benbi", "-s", "384", "-h", "sha256", "create", "newuser", "/dev/loop7", NULL) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while creating the mapped device");
    (void) umask (saved_umask);
    goto mh_err_keyfile;
  }
  (void) umask (saved_umask);  

  if (chown (key_fn, 0, 0) != 0 || chown (part_fn, uid, -1) != 0 ||
      chmod (key_fn, S_IRUSR | S_IWUSR) != 0 || chmod (part_fn, S_IRUSR | S_IWUSR) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while changing key and part files' owner");
    goto mh_err_keyfile;
  }

  if (stat ("/dev/mapper/newuser", &stats) != 0 || (stats.st_mode & S_IFBLK) == 0) {
    CMD_ERROR (ret = CMD_FAULT, "The block device was mysteriously not found");
    goto mh_err_keyfile;
  }

  DEBUG("running mkfs.ext4 on %s", part_fn);
  if (fork_exec (MKFS_EXT4, "/dev/mapper/newuser", NULL) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while creating the filesystem");
    goto mh_err_unmap_device;
  }
  DEBUG("done running mkfs.ext4");

  if (mkdir ("/var/tmp/newuser", S_IRWXU) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "mkdir failed");
    goto mh_err_unmap_device;
  }

  if (mount ("/dev/mapper/newuser", "/var/tmp/newuser", "ext4", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while mounting the new partition");
    goto mh_err_rmdir;
  }

  if (chown ("/var/tmp/newuser", uid, -1) != 0 || chmod ("/var/tmp/newuser", S_IRWXU) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while changing the partition's owner");
    goto mh_err_umount;
  }


  // Traitement des clés SSH

  if (gen_key) {
    const char *tname = get_type_name(type);
    if (!tname) {
      CMD_ERROR(ret = CMD_INVAL, "Unsupported user type");
      goto mh_err_umount;
    }
    if (fork_exec(CREATE_SSH, name, tname, "/var/tmp/newuser")) { 
      CMD_ERROR(ret = CMD_FAULT, "Error setting up user SSH keys");
      goto mh_err_umount;
    }
  }

  // Nettoyage

  if (umount ("/var/tmp/newuser"))
    ERROR ("Could not unmount properly /var/tmp/newuser");
  if (rmdir ("/var/tmp/newuser"))
    ERROR ("Could not remove /var/tmp/newuser");
  if (fork_exec (DMSETUP, "remove", "newuser", NULL) != 0)
    ERROR ("Error while unmapping /dev/mapper/newuser");

  memset(key_str, 0, strlen (key_str));
  free (key_str);
  key_str = NULL;

  if (fork_exec (LOSETUP, "-d", "/dev/loop7", NULL != 0))
    ERROR ("Error while unlooping /dev/loop7");

  ret = CMD_OK;

  goto mh_free;

 mh_err_umount:
  if (umount ("/var/tmp/newuser"))
    ERROR ("Could not unmount properly /var/tmp/newuser");

 mh_err_rmdir:
  if (rmdir ("/var/tmp/newuser"))
    ERROR ("Could not remove /var/tmp/newuser");

 mh_err_unmap_device:
  if (fork_exec (DMSETUP, "remove", "newuser", NULL) != 0)
    ERROR ("Error while unmapping /dev/mapper/newuser");

 mh_err_keyfile:
  remove_file ("%s", key_fn);

 mh_err_forget_key:
  memset(key_str, 0, strlen (key_str));
  free (key_str);
  key_str = NULL;

 mh_err_unloop:
  if (fork_exec (LOSETUP, "-d", "/dev/loop7", NULL != 0))
    ERROR ("Error while unlooping /dev/loop7");

 mh_err_part:
  remove_file ("%s", part_fn);

 mh_err_settings:
  if(settings_fn != NULL)
    remove_file ("%s", settings_fn);

 mh_free:
  FREE_IF_NOT_NULL (login_at_clip);
  FREE_IF_NOT_NULL (settings_fn);
  FREE_IF_NOT_NULL (key_fn);
  FREE_IF_NOT_NULL (part_fn);

  return ret;
}





static uint32_t create_user (int s) {
  uint32_t ret;
  char* name;
  char* passwd = NULL;
  usertype_t type;
  authtype_t auth;
  long rmb_size = 0, rmh_size = 0;
  char* buf;
  uint32_t len;
  long space;
  int n;
  struct passwd* pw;
  uid_t uid;
  char* secret = NULL;
  char* enc_secret = NULL;
  char* masterkey = NULL;
  char* enc_masterkey = NULL;
  unsigned int enc_masterkey_size;

  PKCS11_CTX *ctx = NULL;
  PKCS11_SLOT *slots, *slot;
  unsigned int nslots;
  PKCS11_CERT *auth_cert, *enc_cert;

  ret = put_cmd(s, CMD_OK, 0);
  if (ret != CMD_OK)
    return ret;


  // Arguments retrieval
  //--------------------

  ret = get_field(s, CMD_NAME, &buf, &len, NULL);
  if (ret != CMD_OK)
    return ret;
  n = asprintf (&name, "%.*s", len, buf);
  free (buf);
  if (n <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");
    goto cu_end;
  }

  ret = get_field(s, CMD_PASSWD, &buf, &len, NULL);
  if (ret != CMD_OK)
    return ret;
  n = asprintf (&passwd, "%.*s", len, buf);
  memset(buf, 0, len);
  free (buf);
  if (n <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");
    goto cu_namefree;
  }

  ret = get_field(s, CMD_TYPE, &buf, &len, NULL);
  if (len != sizeof (usertype_t) || ret != CMD_OK)
    goto cu_pass_free;
  memcpy (&type, buf, sizeof (usertype_t));
  free (buf);

  ret = get_field(s, CMD_AUTHTYPE, &buf, &len, NULL);
  if (len != sizeof (authtype_t) || ret != CMD_OK)
    goto cu_pass_free;
  memcpy (&auth, buf, sizeof (authtype_t));
  free (buf);

  if (g_with_rmh) {
    ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
    if (len != disksize_size || ret != CMD_OK)
      goto cu_pass_free;
    memcpy ((char*) &rmh_size, buf, disksize_size);
    free (buf);
  }
  if (g_with_rmb) {
    ret = get_field(s, CMD_SIZE, &buf, &len, NULL);
    if (len != disksize_size || ret != CMD_OK)
      goto cu_pass_free;
    memcpy ((char*) &rmb_size, buf, disksize_size);
    free (buf);
  }

  

  // Arguments checks
  //-----------------

  // Check login
  ret = check_login (name);
  if (ret != CMD_OK)
    goto cu_return_ret;


  // Check user type
  switch (type) {
  case T_USER: case T_PRIV_USER:
  case T_ADMIN: case T_AUDIT:
  case T_NOMAD_USER:
    break;
  default:
    CMD_ERROR (ret = CMD_INVAL, "type");
    goto cu_return_ret;
  }

  // Check auth type and test passwd/pin quality
  switch (auth) {
  case AUTH_PW: 
    if (check_password(AUTH_PW, name, passwd)) {
      ret = CMD_WEAK_PASSWD;
      goto cu_return_ret;
    }
    break;
  case AUTH_PKCS:
    /* We should not check the pin because the user/admin cannot
       choose it at this point
    if (bad_pin(passwd)) {
      CMD_ERROR(ret = CMD_WEAK_PASSWD,"Bad PIN");
      goto cu_return_ret;
      }
    */

    // Initialize the smart card comm.
    ret = pkauth_init(&ctx, &slots, &nslots, &slot);
    if (ret != CMD_OK) {
      goto cu_return_ret;
    }

    // Check and retrieve the disk encrypption and authentication certs.
    ret = pkauth_list_certificates(slot, &auth_cert, &enc_cert);
    if (ret != CMD_OK) {
      goto cu_return_ret;
    }

    break;
  default:
    CMD_ERROR (ret = CMD_INVAL, "auth");
    goto cu_return_ret;
  }

  // Check partitions sizes
  ret = get_free_space (&space);
  if (ret != CMD_OK)
    goto cu_return_ret;

  if (space < minCLIPPartSize + rmh_size + rmb_size) {
    CMD_ERROR (ret = CMD_DISKSPACE, "Not enough disk space");
    goto cu_return_ret;
  }

  if (((type == T_USER) || (type == T_PRIV_USER) || (type == T_NOMAD_USER))) {
    if ((g_with_rmh && (rmh_size < minRMPartSize)) 
          || (g_with_rmb && (rmb_size < minRMPartSize))) {
      CMD_ERROR (ret = CMD_INVAL, "The minimum RM partition size was not respected");
      goto cu_return_ret;
    }
  }

  // Check whether the user already exist
  ret = (getpwnam (name) != NULL) ? CMD_USEREXISTS : CMD_OK;
  endpwent();
  if (ret != CMD_OK) {
    CMD_ERROR (ret = CMD_USEREXISTS, "The user already exists.");
    goto cu_return_ret;
  }


  // Prepare the encrypted password
  //--------------------------------

  switch (auth) {
  case AUTH_PW: 
    secret = passwd;
    ret = encrypt_password (secret, &enc_secret);
    if (ret != CMD_OK) {
      ERROR ("The password could not be encrypted.");
      goto cu_return_ret;
    }
    break;
  case AUTH_PKCS:
    // Generate master key
    ret = pkauth_gen_secret(&masterkey);
    if(ret != CMD_OK) {
      ERROR("Error generating master secret");
      goto cu_return_ret;
    }
    secret = masterkey;

    // Encrypt master key
    ret = pkauth_encrypt_secret(slot, enc_cert, passwd, masterkey, &enc_masterkey, &enc_masterkey_size);
    if(ret != CMD_OK) {
      ERROR("Error encrypting master secret");
      goto cu_return_ret;
    }

    // only defined for the next do_useradd call
    if(asprintf(&enc_secret, "*") < 0) {
      ret=CMD_NOMEM;
      ERROR("No memory left");
      goto cu_return_ret;
    }

    break;
  default:
    CMD_ERROR (ret = CMD_INVAL, "auth");
    goto cu_return_ret;
  }

  // From now on, secret == passwd (if AUTH_PW) 
  // or secret == masterkey (if AUTH_PKCS)

  // Add the user
  //-------------

  DEBUG("Adding user to the system");

  ret = do_useradd (name, enc_secret, type, auth);
  if (ret != CMD_OK) {
    ERROR("Could not add user...");
    goto cu_return_ret;
  }

  // Get the user uid
  pw = getpwnam (name);
  if (pw == NULL) {
    ERROR ("The user was not correctly created after all...");
    goto cu_return_ret;
  }
  uid = pw->pw_uid;
  endpwent();

  // Write encrypted master key to disk and record user mapping
  if(auth == AUTH_PKCS) {

    ret = pkauth_add_user(name, auth_cert);
    if(ret != CMD_OK) {
      ERROR ("Could add pam user mapping");
      goto cu_rollback_useradd;
    }

    ret = pkauth_record_secret(name, enc_masterkey, enc_masterkey_size);
    if(ret != CMD_OK) {
      ERROR ("Could not write encrypted master key to disk");
      goto cu_rollback_useradd;
    }

    (void)pkauth_logout(slot);

    ret = pkauth_finish(ctx, slots, nslots);
    ctx = NULL;
    if(ret != CMD_OK) {
      ERROR ("Could not terminate pkcs session");
      // should not fail, but if it does, cancel user creation
      goto cu_rollback_useradd;
    }

    // Checking certificate validity with a pam authentication request 
    if(try_user_authenticate(auth, name, passwd)) {
      CMD_ERROR (ret = CMD_INVALID_CA_CHAIN, "Failed to check certificate through authentication request");
      goto cu_rollback_useradd;
    }

  }


  DEBUG("Creating home directory");

  ret = make_home(clip_base, uid, name, secret, minCLIPPartSize, 1, auth, type);
  if (ret != CMD_OK) {
    ERROR ("The CLIP home partition could not be created.");
    goto cu_rollback_ssh;
  }

  if (type == T_USER || type == T_PRIV_USER || type == T_NOMAD_USER) {
    if (g_with_rmh) {
      ret = make_home(rmh_base, uid, name, secret, rmh_size, 0, auth, type);
      if (ret != 0) {
        ERROR ("The RM_H home partition could not be created.");
        goto cu_rollback_clip_home;
      }
    }
    if (g_with_rmb) {
      ret = make_home(rmb_base, uid, name, secret, rmb_size, 0, auth, type);
      if (ret != 0) {
        ERROR ("The RM_B home partition could not be created.");
        goto cu_rollback_rmh_home;
      }
    }
  }

  ret = CMD_OK;
  goto cu_passwd_free;

 cu_rollback_rmh_home:
  if (g_with_rmh && (remove_home (rmh_base, name, auth) != CMD_OK)) {
    ERROR ("An error occurred while canceling the creation of the CLIP partition.");
  }

 cu_rollback_clip_home:
  if (remove_home (clip_base, name, auth) != CMD_OK) {
    ERROR ("An error occurred while canceling the creation of the CLIP partition.");
  }
 
 cu_rollback_ssh:
  (void)clean_ssh_keys(name, type);

 cu_rollback_useradd:
  if (fork_exec (USERDEL, name, NULL) != 0)
    ERROR ("Could not rollback the useradd command! User %s may still exist", name);

  if(auth == AUTH_PKCS) {
    if(pkauth_del_user(name))
      ERROR ("useradd rollback : could delete pam user mapping");
    if(remove_file ("%s/keys/%s.masterkey", clip_base, name))
      ERROR ("useradd rollback : could not delete user masterkey");
  }

 cu_passwd_free:
  memset(enc_secret, 0, strlen(enc_secret));
  free (enc_secret);

 cu_return_ret:
  if(ctx) {
    (void)pkauth_logout(slot);
    (void)pkauth_finish(ctx, slots, nslots);
  }

  if (ret == CMD_OK)
    ret = put_cmd(s, CMD_OK, 0);
  else
    put_cmd(s, ret, 0);

 cu_pass_free:
  if (passwd) {
    memset(passwd, 0, strlen(passwd));
    free (passwd);
  }
  if (masterkey) {
    memset(masterkey, 0, strlen(masterkey));
    free (masterkey);
  }
  if (enc_masterkey)
    free (enc_masterkey);

 cu_namefree:
  free (name);
  
 cu_end:
  return ret;
}

static uint32_t chpw_user(int s, const char *name, usertype_t type) {
  authtype_t a;
  uint32_t ret, len;
  char *hpw = NULL, *oldpw = NULL, *newpw = NULL;
  char *buf;
  int n;

  ret = put_cmd(s, CMD_OK, 0);
  if (ret != CMD_OK)
    return ret;

  ret = get_field(s, CMD_PASSWD, &buf, &len, NULL);
  if (ret != CMD_OK)
    return ret;
  n = asprintf(&oldpw, "%.*s", len, buf);
  memset(buf, 0, len);
  free(buf);
  if (n <= 0) {
    ret = CMD_NOMEM;
    ERROR("out of memory");
    goto out_free;
  }
  ret = get_field(s, CMD_PASSWD, &buf, &len, NULL);
  if (ret != CMD_OK)
    return ret;
  n = asprintf(&newpw, "%.*s", len, buf);
  memset(buf, 0, len);
  free(buf);
  if (n <= 0) {
    ret = CMD_NOMEM;
    ERROR("out of memory");
    goto out_free;
  }

  a = get_authtype_from_name (name);

  if (a == AUTH_PKCS) { // Change smartcard PIN code

    ret = chpin(oldpw,newpw);
    if (ret != CMD_OK) {
      goto out_free;
    }
    
    LOG("Changed PIN code for user %s", name);
    /* Fall through */

  } else if(a == AUTH_PW) { // Change user password
    if (check_password(AUTH_PW, name, newpw)) {
      ret = CMD_WEAK_PASSWD;
      goto out_free;
    }
    
    ret = encrypt_password(newpw, &hpw);
    if (ret != CMD_OK)
      goto out_free;


    /* Change homes first, because that's where we check oldpw... */
    ret = chpw_homes(name, oldpw, newpw, type);
    if (ret != CMD_OK)
      goto out_free;


    if (fork_exec (USERMOD, "-p", hpw, name, NULL) != 0) {
      ERROR("failed to change password for %s, "
            "login will be impossible", name);
      ret = CMD_FAULT;
      goto out_free;
    }

    LOG("Changed password for user %s", name);
    ret = CMD_OK;
    /* Fall through */
  } else { // Unknown authentication type (?!)

      ERROR("failed to change password for %s, "
            "unknown auth type", name);
      goto out_free;
  }


out_free:
  if (oldpw) {
    memset(oldpw, 0, strlen(oldpw));
    free(oldpw);
  }
  if (newpw) {
    memset(newpw, 0, strlen(newpw));
    free(newpw);
  }
  if (hpw)
    free(hpw);

  if (ret != CMD_OK)
    (void)put_cmd(s, ret, 0);
  else 
    ret = put_cmd(s, ret, 0);
  return ret;
}








static uint32_t migrate_to_card_part(const char *base, char *key_fn, char *name, char *passwd, char *masterkey) {

  uint32_t ret;
  char* diskkey = NULL;
  uint32_t len = 0;

  ret = CMD_OK;

  // Unwrapping existing key
  ret = read_key(base, name, passwd, &diskkey, &len);
  if (ret != CMD_OK) {
    CMD_ERROR (ret = CMD_FAULT, "Failed to read key");
    goto mupart_end;
  }

  // Wrapping the diskey with the masterkey
  if (fork_exec_sin_env (diskkey, "PASS", masterkey, SUB_HELPER, ENCRYPT_STAGE2_KEY, "NOTHIN", "PASS", key_fn, "key", NULL) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while encrypting the key with the masterkey");
    goto mupart_diskkey_free;
  }

  if (chown (key_fn, 0, 0) != 0 || chmod (key_fn, S_IRUSR | S_IWUSR) != 0) {
    CMD_ERROR (ret = CMD_FAULT, "Error while changing key file's owner");
    goto mupart_diskkey_free;
  }

 mupart_diskkey_free:
  memset(diskkey, 0, strlen(diskkey));
  free (diskkey);

 mupart_end:
  return ret;
}



static uint32_t migrate_to_card(int s) {
  uint32_t ret, do_reply, do_rmb, do_rmh;
  char* name;
  char* passwd = NULL;
  char* pin = NULL;
  char* buf;
  uint32_t len;
  gid_t gids[T_USERTYPE_MAX + 1];
  int n;
  char* clip_key_fn = NULL;
  char* rmb_key_fn = NULL;
  char* rmh_key_fn = NULL;
  char* masterkey = NULL;
  char* enc_masterkey = NULL;
  unsigned int enc_masterkey_size;
  mode_t saved_umask;
  usertype_t type;

  PKCS11_CTX *ctx = NULL;
  PKCS11_SLOT *slots, *slot;
  unsigned int nslots;
  PKCS11_CERT *auth_cert, *enc_cert;

  do_reply = 0;
  do_rmb = 0;
  do_rmh = 0;

  ret = put_cmd(s, CMD_OK, 0);
  if (ret != CMD_OK)
    goto mu_end;

  

  // Arguments retrieval
  //--------------------
  ret = get_field(s, CMD_NAME, &buf, &len, NULL);
  if (ret != CMD_OK)
    goto mu_end;
  n = asprintf (&name, "%.*s", len, buf);
  free (buf);
  if (n <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");
    goto mu_end;
  }


  if (asprintf (&clip_key_fn, "%s/keys/%s.key.enc", clip_base, name) <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");    
    goto mu_name_free;
  }

  if (asprintf (&rmb_key_fn, "%s/keys/%s.key.enc", rmb_base, name) <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");    
    goto mu_clip_key_fn_free;
  }

  if (asprintf (&rmh_key_fn, "%s/keys/%s.key.enc", rmh_base, name) <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");    
    goto mu_rmb_key_fn_free;
  }


  // the current password is needed to unwrap de key
  ret = get_field(s, CMD_PASSWD, &buf, &len, NULL);
  if (ret != CMD_OK)
    goto mu_key_fn_free;
  n = asprintf (&passwd, "%.*s", len, buf);
  memset(buf, 0, len);
  free (buf);
  if (n <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");
    goto mu_key_fn_free;
  }

  // the pin code of the card
  ret = get_field(s, CMD_PASSWD, &buf, &len, NULL);
  if (ret != CMD_OK)
    goto mu_passwd_free;
  n = asprintf (&pin, "%.*s", len, buf);
  memset(buf, 0, len);
  free (buf);
  if (n <= 0) {
    CMD_ERROR (ret = CMD_NOMEM, "Not enough memory");
    goto mu_passwd_free;
  }


  do_reply = 1;

  // Arguments checks
  //-----------------

  // Check that the user exists
  ret = (getpwnam (name) != NULL) ? CMD_OK : CMD_UNKNOWNUSER;
  endpwent();
  if (ret != CMD_OK) {
    CMD_ERROR (ret = CMD_UNKNOWNUSER, "The user does not exist.");
    goto mu_pin_free;
  }

  // Checking whether the user to migrate is a valid CLIP account
  ret = get_gids (gids);
  if (ret != CMD_OK) {
    CMD_ERROR (ret, "Failed to retrieve user groups'");
    goto mu_pin_free;
  }

  // Get the type of user
  type = get_type_from_name (name, gids);
  if (type == T_UNKNOWN) {
     CMD_ERROR (ret = CMD_NOENT,
          "The account %s is not a valid CLIP account, and thus cannot be deleted",
          name);
     goto mu_pin_free;
  }
  if (type == T_USER || type == T_PRIV_USER || type == T_NOMAD_USER) {
    if (g_with_rmh) do_rmh = 1;
    if (g_with_rmb) do_rmb = 1;
  }

  // Check that the user is using password authentication
  ret = (get_authtype_from_name (name) != AUTH_PW) ? CMD_INVALID_AUTHTYPE : CMD_OK;
  if (ret != CMD_OK) {
    CMD_ERROR (ret = CMD_INVALID_AUTHTYPE, "The user does not use password authentication.");
    goto mu_pin_free;
  }

  // Initialize the smart card comm.
  ret = pkauth_init(&ctx, &slots, &nslots, &slot);
  if (ret != CMD_OK) {
    CMD_ERROR (ret = CMD_INVALID_CARD, "No smartcard found");
    goto mu_pin_free;
  }
  
  // Check and retrieve the disk encryption and authentication certs.
  ret = pkauth_list_certificates(slot, &auth_cert, &enc_cert);
  if (ret != CMD_OK) {
    goto mu_pkauth_clean;
  }

  // Generate masterkey
  ret = pkauth_gen_secret(&masterkey);
  if(ret != CMD_OK) {
    CMD_ERROR (ret, "Failed to generate masterkey");
    goto mu_pkauth_clean;
  }

  // Encrypt masterkey with certificate
  ret = pkauth_encrypt_secret(slot, enc_cert, pin, masterkey, &enc_masterkey, &enc_masterkey_size);
  if(ret != CMD_OK) {
    CMD_ERROR (ret, "Failed to encrypt masterkey");
    goto mu_masterkey_free;
  }

  saved_umask = umask (S_IRWXG | S_IRWXO);

  ret = migrate_to_card_part(clip_base, clip_key_fn, name, passwd, masterkey);
  if(ret != CMD_OK) {
    CMD_ERROR (ret, "Failed to migrate clip_base");
    (void) umask (saved_umask);
    goto mu_enc_masterkey_free;
  }

  if(do_rmb) {
    ret = migrate_to_card_part(rmb_base, rmb_key_fn, name, passwd, masterkey);
    if(ret != CMD_OK) {
      CMD_ERROR (ret, "Failed to migrate rmb_base");
      (void) umask (saved_umask);
      goto mu_remove_key_fn;
    }
  }

  if(do_rmh) {
    ret = migrate_to_card_part(rmh_base, rmh_key_fn, name, passwd, masterkey);
    if(ret != CMD_OK) {
      CMD_ERROR (ret, "Failed to migrate rmh_base");
      (void) umask (saved_umask);
      goto mu_remove_key_fn;
    }
  }
  
  // Storing encrypted masterkey
  ret = pkauth_record_secret(name, enc_masterkey, enc_masterkey_size);
  if(ret != CMD_OK) {
    CMD_ERROR (ret, "Failed to write encrypted masterkey to disk");
    (void) umask (saved_umask);
    goto mu_remove_key_fn;
  }

  (void) umask (saved_umask);


  // Binding the user to its certificate
  ret = pkauth_add_user(name, auth_cert);
  if(ret != CMD_OK) {
    CMD_ERROR (ret, "Failed to add pam user mapping");
    goto mu_remove_masterkey;
  }


  // Adding the current user to the correct group for smart card authentication
  ret = fork_exec (USERMOD, 
		   "-a",
		   "-G", clip_pkauth_grp,
		   name, NULL);
  if (ret != 0) {
    CMD_ERROR (ret, "Impossible to modify user %s (fork_exec returned %d)", name, ret);
    ret = CMD_FAULT;
    goto mu_rollback;
  }

  // Logout to avoid failures of operations below
  (void)pkauth_logout(slot);

  // Context needs to be closed *before* authentication
  (void)pkauth_finish(ctx, slots, nslots);
  ctx = NULL;

  // Checking certificate validity with a pam authentication request 
  if(try_user_authenticate(AUTH_PKCS, name, pin)) {
    CMD_ERROR (ret = CMD_INVALID_CA_CHAIN, "Failed to check certificate through authentication request");
    goto mu_del_group_rollback;
  }

  


  // Everything was OK, cleaning unused files
  (void)remove_file("%s/keys/%s.key", clip_base, name);
  (void)remove_file("%s/keys/%s.settings", clip_base, name);
  if(do_rmb) {
    (void)remove_file("%s/keys/%s.key", rmb_base, name);
    (void)remove_file("%s/keys/%s.settings", rmb_base, name);
  }
  if(do_rmh) {
    (void)remove_file("%s/keys/%s.key", rmh_base, name);
    (void)remove_file("%s/keys/%s.settings", rmh_base, name);
  }
  goto mu_commit;

  



 mu_del_group_rollback:
  // Adding the current user to the correct group for smart card authentication
  if(fork_exec (GPASSWD,
                "-d",
                name,
                clip_pkauth_grp,
                NULL)) {
    ERROR ("could not delete user from pkauth group");
  }
  
 mu_rollback:
  if(pkauth_del_user(name)) {
    ERROR ("could not delete certificate user mapping");
  }

 mu_remove_masterkey:
  if(remove_file ("%s/keys/%s.masterkey", clip_base, name)) {
    ERROR ("couldt not delete user masterkey");
  }

 mu_remove_key_fn:
  (void)remove_file ("%s", clip_key_fn);
  if(do_rmb)
    (void)remove_file ("%s", rmb_key_fn);
  if(do_rmh)
    (void)remove_file ("%s", rmh_key_fn);


 mu_commit:

 mu_enc_masterkey_free:
  free (enc_masterkey);
  
 mu_masterkey_free:
  memset(masterkey, 0, strlen(masterkey));
  free (masterkey);

 mu_pkauth_clean:
  if(ctx) {
    (void)pkauth_logout(slot);
    (void)pkauth_finish(ctx, slots, nslots);
  }

 mu_pin_free:
  memset(pin, 0, strlen(pin));
  free(pin);

 mu_passwd_free:
  memset(passwd, 0, strlen(passwd));
  free(passwd);
  
 mu_name_free:
  free(name);

 mu_key_fn_free:
  free(rmh_key_fn);

 mu_rmb_key_fn_free:
  free(rmb_key_fn);

 mu_clip_key_fn_free:
  free(clip_key_fn);

 mu_end:
  if(do_reply) {
    if (ret == CMD_OK)
      ret = put_cmd(s, CMD_OK, 0);
    else
      put_cmd(s, ret, 0);
  }

  return ret;
}




static int fork_handler(int s, struct clip_sock_t *__s, conn_handler_t handler){
  int status;
  pid_t pid, wret;
  
  pid = fork();
  switch (pid) {
    case -1:
      ERROR_ERRNO("fork failed for %s socket", __s->name);
      return -1;
    case 0:
      exit((*handler)(s, __s));
      break;
    default:
      for (;;) {
        wret = waitpid(pid, &status, 0);
        if (wret < 0) {
          if (errno == EINTR)
            continue;
          ERROR_ERRNO("waitpid failed on %s socket", __s->name);
          return -1;
        }
        if (wret != pid) {
          ERROR_ERRNO("weird waitpid result: %d != %d on %s socket", 
                                                wret, pid, __s->name);
          continue; /* Will error out anyway if no more children */
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
          ERROR("child handler returned an error on %s socket", __s->name);
          return -1;
        }

        return 0;
      }
  }
}

static inline int drop_privs(void) {
  if (clip_reducecaps(0)) {
    ERROR("failed to drop privileges");
    return -1;
  }

  return 0;
}

static int _admin_conn_handler(int s, struct clip_sock_t *__s) {
  uint32_t ret, uid, gid;
  cmd_t cmd;
  int retval = -1;
  
  /* Get client uid first */
  if (clip_getpeereid(s, &uid, &gid)) {
    ERROR("failed to get peer eid on socket %s", __s->name);
    return -1;
  }
  LOG("Got connect from uid %d on %s socket", uid, __s->name);
  
  if (set_nonblock(s)) {
    ERROR("failed to set %s connected socket non-blocking", __s->name);
    return -1;
  }
  
  ret = get_cmd(s, &cmd);
  if (ret != CMD_OK)
    return -1;
  
  switch (cmd.cmd) {
  case CMD_LISTUSERS:
    DEBUG("got CMD_LISTUSERS");
    if (drop_privs())
      return -1;
    ret = list_users(s);
    retval = (ret == CMD_OK) ? 0 : -1;
    LOG("CMD_LISTUSERS treatment %s", 
	(retval) ? "nok" : "ok");
    break;

  case CMD_DISKINFO:
    DEBUG("got CMD_DISKINFO");
    if (drop_privs())
      return -1;
    ret = disk_info(s);
    retval = (ret == CMD_OK) ? 0 : -1;
    LOG("CMD_DISKINFO treatment %s", 
	(retval) ? "nok" : "ok");
    break;

  case CMD_LOCKUSER:
    DEBUG("got CMD_LOCKUSER");
    if (drop_privs())
      return -1;
    ret = lock_user(s, 1);
    retval = (ret == CMD_OK) ? 0 : -1;
    LOG("CMD_LOCKUSER treatment %s", 
	(retval) ? "nok" : "ok");
    break;

  case CMD_UNLOCKUSER:
    DEBUG("got CMD_UNLOCKUSER");
    if (drop_privs())
      return -1;
    ret = lock_user(s, 0);
    retval = (ret == CMD_OK) ? 0 : -1;
    LOG("CMD_UNLOCKUSER treatment %s", 
	(retval) ? "nok" : "ok");
    break;

  case CMD_DELUSER:
    DEBUG("got CMD_DELUSER");
    if (drop_privs())
      return -1;
    ret = delete_user(s);
    retval = (ret == CMD_OK) ? 0 : -1;
    LOG("CMD_DELUSER treatment %s", 
	(retval) ? "nok" : "ok");
	break;

  case CMD_ADDUSER:
    DEBUG("got CMD_ADDUSER");
    ret = create_user(s);
    retval = (ret == CMD_OK) ? 0 : -1;
    LOG("CMD_ADDUSER treatment %s", 
	(retval) ? "nok" : "ok");
    break;

  case CMD_MIGRATETOCARD:
    DEBUG("got CMD_MIGRATETOCARD");
    ret = migrate_to_card(s);
    retval = (ret == CMD_OK) ? 0 : -1;
    LOG("CMD_MIGRATETOCARD treatment %s", 
	(retval) ? "nok" : "ok");
    break;

  default:
    ERROR("Unsupported admin command: 0x%x from uid %u on %s socket",
	  cmd.cmd, uid, __s->name);
    break;
  }
  
  return retval;
}

int admin_conn_handler(int s, struct clip_sock_t *__s) {
  return fork_handler(s, __s, _admin_conn_handler);
}
	

static int _user_conn_handler(int s, struct clip_sock_t *__s) {
  uint32_t ret, uid, gid;
  cmd_t cmd;
  int retval = -1;
  struct passwd *pw;
  char *name;
  usertype_t type;
  uid_t current_uid;
  gid_t gids[T_USERTYPE_MAX + 1];
  
  if (drop_privs())
    return -1;

  /* Get client uid first */
  if (clip_getpeereid(s, &uid, &gid)) {
    ERROR("failed to get peer eid on socket %s", __s->name);
    return -1;
  }
  LOG("Got connect from uid %d on %s socket", uid, __s->name);
  
  if (set_nonblock(s)) {
    ERROR("failed to set %s connected socket non-blocking", __s->name);
    return -1;
  }

  ret = get_cmd(s, &cmd);
  if (ret != CMD_OK)
    return -1;

  if (cmd.cmd != CMD_CHPASSWD) {
    ERROR("Invalid command %x", cmd.cmd);
    (void)put_cmd(s, CMD_INVAL, 0);
    return -1;
  }

  errno = 0;
  pw = getpwuid(uid);
  if (!pw) {
    ERROR_ERRNO("failed to retrieve user name");
    (void)put_cmd(s, CMD_NOENT, 0);
    return -1;
  }

  ret = get_current_user (&current_uid);
  if (ret != CMD_OK) {
    CMD_ERROR (ret, "get_current_user failed");
    (void)put_cmd(s, ret, 0);
    return -1;
  }

  if (uid != current_uid) {
    ERROR("Changing the password of a different user is not allowed");
    ret = CMD_PERM;
    (void)put_cmd(s, ret, 0);
    return -1;
  }

  ret = get_gids (gids);
  if (ret != CMD_OK) {
    CMD_ERROR (ret, "get_gids failed");
    (void)put_cmd(s, ret, 0);
    return -1;
  }

  type = get_type_from_gid(pw->pw_gid, gids);
  if (type == T_UNKNOWN) {
    ret = CMD_INVAL;
    CMD_ERROR (ret,
	       "The account %s is not a valid CLIP account, "
         "and thus cannot be modified", pw->pw_name);
    (void)put_cmd(s, ret, 0);
    return -1;
  }

  name = strdup(pw->pw_name);
  if (!name) {
    ERROR("out of memory copying user name");
    (void)put_cmd(s, CMD_NOMEM, 0);
    return -1;
  }
 
  ret = chpw_user(s, name, type);
  retval = (ret == CMD_OK) ? 0 : -1;
  LOG("CMD_CHPASSWD treatment %s", (retval) ? "nok" : "ok");

  free(name);
  return retval;
}

int user_conn_handler(int s, clip_sock_t *__s) {
  return fork_handler(s, __s, _user_conn_handler);
}
// vim:sw=2:ts=2:et:
