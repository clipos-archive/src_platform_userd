// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright Â© 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file user_server_aux.c
 * Helper functions for the userd server.
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * Copyright (C) 2013-2014 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#define	_GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <sys/select.h>

#include "cmd.h"
#include "user_server_aux.h"


const char clip_users_grp[] = "crypthomes";
const char clip_admin_grp[] = "core_admin";
const char clip_audit_grp[] = "core_audit";
const char clip_priv_users_grp[] = "priv_user";
const char clip_nomad_users_grp[] = "nomad_user";
const char clip_pkauth_grp[] = "pkauth";
const char admins_supp_grps[] = "crypthomes,mount_update";
const char clip_base[] = "/home";
const char part_rootpath[] = "/home/";
const char rmh_base[] = "/home/rm_h";
const char rmb_base[] = "/home/rm_b";

long minCLIPPartSize = 8;
long minRMPartSize = 64;
long defaultSize = 2048;
const long reservedSpace = 256;
const long _1MB = 1 << 20;


static char LAST[] = "/usr/bin/last";
char CP[] = "/bin/cp";
char DD[] = "/bin/dd";
char TR[] = "/usr/bin/tr";
char MKE2FS[] ="/sbin/mke2fs";
char MKFS_EXT4[] = "/sbin/mkfs.ext4";
char CRYPTSETUP[] ="/bin/cryptsetup";
char DMSETUP[] ="/sbin/dmsetup";
char LOSETUP[] ="/sbin/losetup";
char USERMOD[] = "/usr/sbin/usermod";
char USERDEL[] = "/usr/sbin/userdel";
char USERADD[] = "/usr/sbin/useradd";
char GPASSWD[] = "/usr/bin/gpasswd";

char CREATE_SSH[] = SBINDIR "/userd_create_ssh_keys";
char DELETE_SSH[] = SBINDIR "/userd_delete_ssh_keys";
char SUB_HELPER[] = SBINDIR "/userd_key_helper";

char HASH_PASS[] = "hash_password";
char CREATE_SETTINGS[] = "create_settings";
char ENCRYPT_STAGE2_KEY[] = "encrypt_stage2_key";
char OUTPUT_STAGE2_KEY[] = "output_stage2_key";
char CRACK_CHECK[] = "cracklib-check";

const int ENCPASSWD_MAXLEN = 512;
const int STAGE2KEY_MAXLEN = 512;


static uint32_t get_gid (gid_t* gid, const char* groupname) {
  struct group* g;
  uint32_t ret;

  g = getgrnam (groupname);
  if (g == NULL) {
    if (errno != 0)
      CMD_ERROR (ret = CMD_FAULT, "getgrnam failed");
    else
      CMD_ERROR (ret = CMD_NOENT, "The group %s does not exist", groupname);
  } else {
    *gid = g->gr_gid;
    ret = CMD_OK;
  }

  endgrent();
  return ret;
}


uint32_t get_gids (gid_t gids[]) {
  uint32_t res;
  res = get_gid (&gids[T_USER], clip_users_grp);
  if (res != CMD_OK) return res;
  res = get_gid (&gids[T_ADMIN], clip_admin_grp);
  if (res != CMD_OK) return res;
  res = get_gid (&gids[T_AUDIT], clip_audit_grp);
  if (res != CMD_OK) return res;
  res = get_gid (&gids[T_PRIV_USER], clip_priv_users_grp);
  if (res != CMD_OK) return res;
  res = get_gid (&gids[T_NOMAD_USER], clip_nomad_users_grp);
  return res;
}


usertype_t get_type_from_gid (gid_t gid, gid_t gids[]) {
  int i;
  for (i=0; i<=T_USERTYPE_MAX; i++)
    if (gid == gids[i])
      return (usertype_t) i;

  return T_UNKNOWN;
}

authtype_t get_authtype_from_name (const char *user) {
  char *const *member;
  authtype_t auth = AUTH_PW;
  const struct group *grp = getgrnam(clip_pkauth_grp);

  if (!grp) 
    return auth;

  member = (char *const *)grp->gr_mem;
  while (*member) {
    if (!strcmp(*member, user)) {
      auth = AUTH_PKCS;
      break;
    }
    member++;
  }

  return auth;
}

usertype_t get_type_from_name (const char* user, gid_t gids[]) {
  struct passwd* p;
  usertype_t res = T_UNKNOWN;

  p = getpwnam (user);
  if (p == NULL)
    goto cg_end;

  res = get_type_from_gid (p->pw_gid, gids);

 cg_end:
  endpwent();
  return res;
}

const char *
get_type_name(usertype_t type)
{
  switch (type) {
    case T_USER:
      return "user";
    case T_ADMIN:
      return "admin";
    case T_AUDIT:
      return "audit";
    case T_PRIV_USER:
      return "privuser";
    case T_NOMAD_USER:
      return "nomad";
    default:
      return NULL;
  }
}

static pid_t _vfork_exec (int fd_input, int fd_output, int fd_err, char* env_var, char *arg, va_list arg_list, int fd_toclose) {
  pid_t pid = -1;
  va_list va_bak;

  char** cmdline;
  int nArgs;
  char* env[2];

  if (fd_input < 0) {
    fd_input = open ("/dev/null", O_RDONLY, "r");
    if (fd_input < 0) {
      ERROR ("unable to open /dev/null");
      goto fe_end;
    }
  }

  if (fd_output < 0) {
    fd_output = open ("/dev/null", O_WRONLY, "w");
    if (fd_output < 0) {
      ERROR ("unable to open /dev/null");
      goto fe_end;
    } 
   }

  if (fd_err < 0) {
    fd_err = open ("/dev/null", O_WRONLY, "w");
    if (fd_err < 0) {
      ERROR ("unable to open /dev/null");
      goto fe_end;
    } 
   }

  if ((pid = fork()) < 0) {
    ERROR ("unable to fork");
    goto fe_end;
  }

  // Traitement du fils
  if (pid == 0) {
    if (fd_toclose >= 0) (void) close (fd_toclose);

    if (dup2 (fd_input, 0) != 0 || dup2 (fd_output, 1) != 1 || dup2 (fd_err, 2) != 2) {
      ERROR ("dup2 failed");
      exit (EXIT_FAILURE);
    }
    (void) close (fd_err);
    (void) close (fd_output);
    (void) close (fd_input);

    va_copy(va_bak, arg_list);
    nArgs = 1;
    while (va_arg(arg_list, char*) != NULL)
      nArgs++;

    cmdline = malloc ((nArgs + 1) * sizeof (char*));
    if (cmdline == NULL) {
      ERROR ("Not enough memory");
      exit (EXIT_FAILURE);
    }

    va_copy(arg_list, va_bak);
    cmdline[0] = arg;
    nArgs = 1;
    while ((cmdline[nArgs++] = va_arg(arg_list, char*)) != NULL) ;

    va_end(va_bak);

    if (env_var != NULL) {
      env[0] = env_var;
      env[1] = NULL;
    } else
      env[0] = NULL;

    execve (arg, cmdline, env);
    exit (errno);
  }

  // Traitement du père
 fe_end:
  if (fd_output >= 0)
    (void) close (fd_output);
  if (fd_err >= 0)
    (void) close (fd_err);
  if (fd_input >= 0)
    (void) close (fd_input);
  return pid;
}





int fork_exec (char *arg, ...) {
  va_list arglist;
  pid_t pid;
  int res = -1;
  int status;

  va_start (arglist, arg);
  pid = _vfork_exec (-1, -1, -1, NULL, arg, arglist, -1);
  va_end (arglist);

  if (pid > 0) {
    while (waitpid (pid, &status, 0) < 0) {
      if (errno != EINTR) {
	ERROR ("waitpid failed");
	goto fe_end;
      }
    }    
    if (WIFEXITED (status)) {
      res = WEXITSTATUS (status);
    }
  }

 fe_end:
  return res;
}


pid_t fork_exec_fin_fout (int fd_input, int fd_output, char *arg, ...) {
  va_list arglist;
  pid_t pid;

  va_start (arglist, arg);
  pid = _vfork_exec (fd_input, fd_output, -1, NULL, arg, arglist, -1);
  va_end (arglist);

  return pid;
}


uint32_t fork_exec_sin_env (const char* input, const char* env_var, const char* env_val, char *arg, ...) {
  va_list arglist;
  char* env_v;
  pid_t pid;
  int fds[2];
  int len, n = 0;
  int status;

  if (asprintf (&env_v, "%s=%s", env_var, env_val)  <= 0) {
    ERROR ("Not enough memory");
    return CMD_FAULT;
  }

  if (pipe (fds) != 0) {
    ERROR ("pipe failed");
    return CMD_FAULT;
  }

  va_start (arglist, arg);
  pid = _vfork_exec (fds[0], -1, -1, env_v, arg, arglist, fds[1]);
  va_end (arglist);
 
  if (pid <= 0)
    goto fese_error_close_pipe;

  len = strlen (input);
  while (len > 0) {
    n = write (fds[1], input, len);
    
    if (n < 0 && errno != EINTR) {
      ERROR ("write failed");
      goto fese_error_close_pipe;
    }
    
    input+=len;
    len-=n;
  }

  (void) close (fds[1]);

  while (waitpid (pid, &status, 0) < 0) {
    if (errno != EINTR) {
      ERROR ("waitpid failed");
      return CMD_FAULT;
    }
  }    
  
  if (WIFEXITED (status) && WEXITSTATUS (status) == 0)
    return CMD_OK;
  return CMD_FAULT;

 fese_error_close_pipe:
  (void) close (fds[1]);
  return CMD_FAULT;
}



static char* _vfork_exec_fdin_sout (int fd_input, int maxOutput, int* status, char* env_var, char *arg, va_list arg_list) {
  pid_t pid;
  char* res = NULL;
  int fds[2];
  int n;
  char* buf;

  if (maxOutput <= 0) {
    ERROR ("maxOutput should be > 0");
    goto fes_end;
  }

  res = malloc ((maxOutput+1) * sizeof (char*));
  if (res == NULL) {
    ERROR ("not enough memory");
    goto fes_end;
  }
  buf = res;

  if (pipe (fds) != 0) {
    ERROR ("pipe failed");
    goto fes_error_free;
  }

  pid = _vfork_exec (fd_input, fds[1], -1, env_var, arg, arg_list, fds[0]);
  if (pid <= 0)
    goto fes_error_close_pipe;

  while (maxOutput > 0) {
    n = read (fds[0], buf, maxOutput);
    if (n < 0 && errno != EINTR) {
      ERROR ("read failed");
      goto fes_error_close_pipe;
    }
    
    if (n==0)
      break;

    maxOutput-=n;
    buf+=n;
  }

  *buf = 0;
  (void) close (fds[0]);

  while (waitpid (pid, status, 0) < 0) {
    if (errno != EINTR) {
      ERROR ("waitpid");
      goto fes_error_free;
    }
  }    

  return res;

  goto fes_error_free;

 fes_error_close_pipe:
  (void) close (fds[0]);

 fes_error_free:
  free (res);
  res = NULL;

 fes_end:
  return res;

}


char* fork_exec_fin_sout (const char* filename, int maxOutput, int* status, char *arg, ...) {
  va_list arglist;
  char* res = NULL;
  int fd_input;

  fd_input = open (filename, O_RDONLY, "r");
  if (fd_input < 0) {
    ERROR ("unable to open input file");
    return NULL;
  }

  va_start (arglist, arg);
  res = _vfork_exec_fdin_sout (fd_input, maxOutput, status, NULL, arg, arglist);
  va_end (arglist);

  return res;
}

char* fork_exec_sout (int maxOutput, int* status, char *arg, ...) {
  va_list arglist;
  char* res;
  va_start (arglist, arg);
  res = _vfork_exec_fdin_sout (-1, maxOutput, status, NULL, arg, arglist);
  va_end (arglist);

  return res;
}

char* fork_exec_sout_env (int maxOutput, int* status, const char* env_var, const char* env_val, char *arg, ...) {
  va_list arglist;
  char* res;
  char* env_v;

  if (asprintf (&env_v, "%s=%s", env_var, env_val)  <= 0)
    return NULL;

  va_start (arglist, arg);
  res = _vfork_exec_fdin_sout (-1, maxOutput, status, env_v, arg, arglist);
  va_end (arglist);

  free (env_v);
  return res;
}




uint32_t get_current_user (uid_t* res) {
  int fds[2];
  char* line = NULL;
  size_t line_len = 0;
  FILE* output;
  int retval = CMD_FAULT;
  pid_t pid;
  struct passwd* p;

  if (pipe (fds) != 0) {
    ERROR ("pipe failed");
    return retval;
  }

  pid = fork_exec_fin_fout (-1, fds[1], LAST, "-w", "-f", "/var/run/utmp", NULL);
  if (pid <= 0)
    goto gcu_closefd;

  output = fdopen (fds[0], "r");
  if (output == NULL) {
    ERROR ("Unable to wrap the file descriptor with fdopen");
    goto gcu_waitpid;
  }

  while (getline (&line, &line_len, output) > 0) {
    char* ptr = strstr (line, ":0");
    if (ptr != NULL) {
      int n = ptr - line;
      line[n] = 0;
      while (n >= 0 && isblank(line[n-1]))
	line[--n]=0;
      p = getpwnam (line);
      if (p == NULL) {
	ERROR ("Unable to get the uid of %s", line);
        continue;
      }
      else {
	*res = p->pw_uid;
	retval = CMD_OK;
      }
      endpwent();
      goto gcu_free;
    }
  }

  retval = CMD_UNDET_USER;

 gcu_free:
  free (line);
  (void) fclose (output);

 gcu_waitpid:
  while (waitpid (pid, NULL, 0) < 0) {
    if (errno != EINTR) {
      ERROR ("waitpid failed");
      break;
    }
  }
   
  return retval;

  // Function failed before opening the *FILE struct
 gcu_closefd:
  (void) close (fds[0]);
  return retval;
}



/* check_uid checks returns
   - CMD_UNKNOWNUSER if the username is not a valid UNIX account
   - CMD_CURRENTUSER if the username corresponds to the user currently logged
   - CMD_OK if the username exists and is not logged */
uint32_t check_uid (const char* const username) {
  struct passwd* p;
  int retval;
  uid_t userid;
  uid_t current_user = 0;
 
  p = getpwnam (username);
  if (p == NULL) {
    endpwent();
    return CMD_UNKNOWNUSER;
  }
  userid = p->pw_uid;
  endpwent();
  
  retval = get_current_user(&current_user);
  if (retval) {
    if (retval == CMD_UNDET_USER) {
      return CMD_OK;
    } else {
      ERROR ("Unable to find out who the current user is");
      return retval;
    }
  }

  if (userid == current_user)
    return CMD_CURRENTUSER;

  return CMD_OK;
}

uint32_t remove_file (const char *fmt, ...) {
  va_list arglist;
  char* filename;
  struct stat buf;
  uint32_t ret = CMD_OK;

  va_start (arglist, fmt);

  if (vasprintf (&filename, fmt, arglist) <= 0) {
    ERROR ("Not enough memory");
    ret = CMD_NOMEM;
    goto rf_vaend;
  }
  (void) unlink (filename);

  if (stat (filename, &buf) != -1 || errno != ENOENT) {
    ERROR ("Could not remove file %s", filename);
    ret = CMD_FAULT;
  }

  free (filename);

 rf_vaend:
  va_end (arglist);

  return ret;
}

uint32_t get_free_space (long* space) {
  struct statfs64 diskinfo;

  if (statfs64 (part_rootpath, &diskinfo)) {
    ERROR ("Failed to retrieve disk information");
    return CMD_FAULT;
  }

  *space = (_1MB > diskinfo.f_bsize) ?
    diskinfo.f_bavail / (_1MB / diskinfo.f_bsize) :
    diskinfo.f_bavail * (diskinfo.f_bsize / _1MB);
  *space -= reservedSpace;

  return CMD_OK;
}
// vim:sw=2:ts=2:et:
