// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright Â© 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file client.c
 * Userd client main.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * @n
 * All rights reserved.
 */

#include <unistd.h>
#include <libgen.h>

#include "cmd.h"
#include "userd_priv.h"

static const char *g_sockpath = NULL;
static const char *g_oldpw = NULL;

int g_list, g_diskinfo, g_create, g_delete, g_lock, g_unlock, g_chpw, g_migrate;
userinfo_t* userinfo;

int g_verbose = 0;
int g_daemonized = 0; /* Not used */

int g_with_rmb = 0;
int g_with_rmh = 0;



static const char* type_str [] = {"Administrateur du socle",
				  "Auditeur du socle",
				  "Utilisateur",
				  "Utilisateur privilégié"
				  "Utilisateur nomade"};



static inline int
check_options(void)
{
  int sum = g_list + g_diskinfo + g_create 
          + g_delete + g_lock + g_unlock + g_chpw + g_migrate;
  if (sum > 1) {
    ERROR("Only one action may be specified at the same time");
    return -1;
  }
  if (!sum) {
    ERROR("At least one action must be specified");
    return -1;
  }
  if (!g_sockpath) {
    ERROR("missing socket path");
    return -1;
  }
  if (g_create + g_delete + g_lock + g_unlock + g_migrate == 1) {
    if (!userinfo->name || userinfo->name[0] == 0) {
      ERROR("Missing user name");
      return -1;
    }
  }
  if (g_create || g_chpw || g_migrate) {
    if (!userinfo->passwd || userinfo->passwd[0] == 0) {
      ERROR("Missing password/pin");
      return -1;
    }
  }
  if (g_create) {
    if ((userinfo->type & T_USERTYPE_MASK) == T_UNKNOWN) {
      ERROR("Missing type: should be one of admin, audit, user, privuser, nomad");
      return -1;
    }
    
    if ((userinfo->auth & AUTH_TYPE_MASK) == AUTH_UNKNOWN) {
      ERROR("Missing auth type: should be one of password, smartcard");
      return -1;
    }
    
    if ((userinfo->type & T_USERTYPE_MASK) == T_USER 
    			|| (userinfo->type & T_USERTYPE_MASK) == T_PRIV_USER
    			|| (userinfo->type & T_USERTYPE_MASK) == T_NOMAD_USER) {
      if ((g_with_rmh && (userinfo->rmh_size <= 0)) 
							|| (g_with_rmb && (userinfo->rmb_size <= 0))) {
				ERROR("Incorrect or missing sizes");
				return -1;
      }
    }
  }
  if(g_chpw || g_migrate) {
    if (!g_oldpw || g_oldpw[0] == 0) {
      ERROR("Missing old password");
      return -1;
    }    
  }
  
  return 0;
}

static void
print_help(const char *exe)
{
  printf("%s [-v+] -S <sock> -l\n", exe); // List users
  printf("%s [-v+] -S <sock> -i\n", exe); // Get disk info
  printf("%s [-v+] -S <sock> -c <name> -a <auth> -P <pass> -t <type> -H <RMH size> -B <RMB size>\n", exe); // Create
  printf("%s [-v+] -S <sock> -d <name>\n", exe); // Delete
  printf("%s [-v+] -S <sock> -L <name>\n", exe); // Lock
  printf("%s [-v+] -S <sock> -U <name>\n", exe); // Unlock
  printf("%s [-v+] -S <sock> -p <oldpass> -P <pass> -C\n", exe); // Change password
  printf("%s [-v+] -S <sock> -m <name> -p <pass> -P <pin>\n", exe); // Migrate to smartcard
}

#define set_if_not_set(var, msg) do {					\
    if (var) {								\
      ERROR(msg" already set to %s, can't set "				\
	    "it to %s", var, optarg);					\
      return -1;							\
    }									\
    var = strdup (optarg);						\
    if (!var) {								\
      ERROR("not enough memory to copy "msg);				\
      return -1;							\
    }									\
} while (0)

static int
get_options(int argc, char *argv[])
{
  int c;
  char* ptr;
  userinfo->type = T_UNKNOWN;
  userinfo->auth = AUTH_UNKNOWN;

  while ((c = getopt(argc, argv, "S:liCc:d:a:m:p:P:L:U:t:B:H:hv")) != -1) {
    switch (c) {
    case 'S':
      set_if_not_set(g_sockpath, "socket path");
      break;
    case 'l':
      g_list = 1;
      break;
    case 'i':
      g_diskinfo = 1;
      break;
    case 'c':
      g_create = 1;
      set_if_not_set(userinfo->name, "user name");
      userinfo->nlen = strlen (userinfo->name);
      break;
    case 'C':
      g_chpw = 1;
      break;
    case 'd':
      g_delete = 1;
      set_if_not_set(userinfo->name, "user name");
      userinfo->nlen = strlen (userinfo->name);
      break;
    case 'L':
      g_lock = 1;
      set_if_not_set(userinfo->name, "user name");
      userinfo->nlen = strlen (userinfo->name);
      break;
    case 'U':
      g_unlock = 1;
      set_if_not_set(userinfo->name, "user name");
      userinfo->nlen = strlen (userinfo->name);
      break;
    case 'm':
      g_migrate = 1;
      set_if_not_set(userinfo->name, "user name");
      userinfo->nlen = strlen (userinfo->name);
      break;
    case 'p':
      set_if_not_set(g_oldpw, "old password");
      break;
    case 'P':
      set_if_not_set(userinfo->passwd, "password");
      userinfo->plen = strlen (userinfo->passwd);
      break;
    case 'a':
      if (strcmp (optarg, "password") == 0)
				userinfo->auth = AUTH_PW;
      else if (strcmp (optarg, "smartcard") == 0)
				userinfo->auth = AUTH_PKCS;
      else
				userinfo->auth = AUTH_UNKNOWN;
      break;

    case 't':
      if (strcmp (optarg, "admin") == 0)
				userinfo->type = T_ADMIN;
      else if (strcmp (optarg, "audit") == 0)
				userinfo->type = T_AUDIT;
      else if (strcmp (optarg, "user") == 0)
				userinfo->type = T_USER;
      else if (strcmp (optarg, "privuser") == 0)
				userinfo->type = T_PRIV_USER;
      else if (strcmp (optarg, "nomad") == 0)
				userinfo->type = T_NOMAD_USER;
      else
				userinfo->type = T_UNKNOWN;
      break;

    case 'H':
			g_with_rmh = 1;
      userinfo->rmh_size = strtol (optarg, &ptr, 10);
      if (*ptr != 0) {
				ERROR ("A size was expected here...");
				return -1;
      }
      break;
    case 'B':
			g_with_rmb = 1;
      userinfo->rmb_size = strtol (optarg, &ptr, 10);
      if (*ptr != 0) {
				ERROR ("A size was expected here...");
				return -1;
      }
      break;

    case 'h':
      print_help((argc) ? basename(argv[0]) : "userclt");
      exit(0);
      break;
    case 'v':
      g_verbose++;
      break;
    default:
      ERROR("Unsupported option %c", c);
      return -1;
    }
  }
  
  if (check_options()) {
    ERROR("Invalid arguments");
    return -1;
  }
  
  return 0;
}



int main(int argc, char *argv[])
{
  int s;
  int ret = EXIT_FAILURE;
  userlist_t* iter;

  userinfo = userinfo_alloc();
  if (!userinfo) {
    ERROR("So soon out of memory ?!\n");
		exit (ret);
  }

  if (get_options(argc, argv))
    goto out;

  s = sock_connect(g_sockpath);
  if (s < 0)
    goto out;

  if (g_list) {
    userlist_t* list;
    ret = client_list_users (s, &list);
    if (ret != CMD_OK) {
      ERROR("Failed to get the list of users\n");
      goto out;
    }
    
    printf("List of users retrieved.\n");
    list_for_each (iter, list) {
      printf ("%.*s%c (%s, %ld, %ld)\n", iter->userinfo->nlen, iter->userinfo->name,
	      (iter->userinfo->type & T_CURRENT_USER) ? '*' : ' ',
	      type_str[iter->userinfo->type & T_USERTYPE_MASK],
	      iter->userinfo->rmh_size, iter->userinfo->rmb_size);
    }

    userlist_free_all (list);
    ret = EXIT_SUCCESS;
  }

  else if (g_diskinfo) {
    diskinfo_t* info;
    ret = client_disk_info (s, &info);
    if (ret != CMD_OK) {
      ERROR("Failed to get the disk informations\n");
      goto out;
    }

    printf("Disk space available: %ld.\n", info->space_available);
    printf("Minimum CLIP partition size: %ld.\n", info->clip_partition_minsize);
    printf("Minimum RM partition size: %ld.\n", info->rm_partition_minsize);
    printf("Recommanded RM partition size: %ld.\n", info->default_partsize);

    diskinfo_free (info);
    ret = EXIT_SUCCESS;
  }

  else if (g_lock) {
    ret = client_lock_user (s, userinfo->name);
    if (ret != CMD_OK) {
      if (ret == CMD_CURRENTUSER)
	ERROR("Cannot lock current user %s\n", userinfo->name);
      else 
	ERROR("Failed locking user %s\n", userinfo->name);
      goto out;
    }
    ret = EXIT_SUCCESS;
  }

  else if (g_unlock) {
    ret = client_unlock_user (s, userinfo->name);
    if (ret != CMD_OK) {
      if (ret == CMD_CURRENTUSER)
	ERROR("Cannot unlock current user %s\n", userinfo->name);
      else 
	ERROR("Failed unlocking user %s\n", userinfo->name);
      goto out;
    }
    ret = EXIT_SUCCESS;
  }

  else if (g_delete) {
    ret = client_delete_user (s, userinfo->name);
    if (ret != CMD_OK) {
      if (ret == CMD_CURRENTUSER)
	ERROR("Cannot delete current user %s\n", userinfo->name);
      else 
	ERROR("Failed deleting user %s\n", userinfo->name);
      goto out;
    }
    ret = EXIT_SUCCESS;
  }

  else if (g_create) {
    ret = client_create_user (s, userinfo);
    if (ret != CMD_OK) {
      if (ret == CMD_CURRENTUSER)
	ERROR("Cannot create current user %s\n", userinfo->name);
      else 
	ERROR("Failed creating user %s\n", userinfo->name);
      goto out;
    }
    ret = EXIT_SUCCESS;
  }

  else if (g_chpw) {
    ret = client_chpw_self (s, g_oldpw, userinfo->passwd);
    if (ret != CMD_OK) {
      CMD_ERROR(ret, "Failed to change password");
      goto out;
    }
    ret = EXIT_SUCCESS;
  }

  else if (g_migrate) {
    ret = client_migrate_user (s, userinfo->name, g_oldpw, userinfo->passwd);
    if (ret != CMD_OK) {
      ERROR("Failed migrating user %s\n", userinfo->name);
      goto out;
    }
    ret = EXIT_SUCCESS;
  }

  /* Fall through */
 out:
  userinfo_free (userinfo);
  return ret;
}
// vim:sw=2:ts=2:et:
