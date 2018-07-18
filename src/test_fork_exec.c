// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright Â© 2009-2018 ANSSI. All Rights Reserved.
#include "user_server_aux.h"
#include <stdio.h>

/*************************************************************/
/*                     Global options                        */
/*************************************************************/

int g_verbose = 0;
int g_daemonized = 0;


static void test_0 (char* cmd) {
  int res;
  res = fork_exec (cmd, NULL);
  if (res != 0) {
    printf ("Command \"%s\" failed with code %d.\n", cmd, res);
    exit (1);
  } else {
    printf ("Command \"%s\" succeeded.\n", cmd);
  }    
}

static void test_1 (char* cmd, char* arg1) {
  int res;
  res = fork_exec (cmd, arg1, NULL);
  if (res != 0) {
    printf ("Command \"%s %s\" failed with code %d.\n", cmd, arg1, res);
    exit (1);
  } else {
    printf ("Command \"%s %s\" succeeded.\n", cmd, arg1);
  }    
}

static void test_2 (char* cmd, char* arg1, char* arg2) {
  int res;
  res = fork_exec (cmd, arg1, arg2, NULL);
  if (res != 0) {
    printf ("Command \"%s %s %s\" failed with code %d.\n", cmd, arg1, arg2, res);
    exit (1);
  } else {
    printf ("Command \"%s %s %s\" succeeded.\n", cmd, arg1, arg2);
  }    
}

static void test_out_2 (char* cmd, char* arg1, char* arg2) {
  char* res;
  res = fork_exec_sout (1024, NULL, cmd, arg1, arg2, NULL);
  if (res == NULL) {
    printf ("Command \"%s %s %s\" failed.\n", cmd, arg1, arg2);
    exit (1);
  } else {
    printf ("Command \"%s %s %s\" succeeded.and returned:\n%s\n\n", cmd, arg1, arg2, res);
    free (res);
  }    
}


static void test_random (void) {
  char* res;
  res = fork_exec_fin_sout ("/dev/urandom", 119, NULL, "/usr/bin/tr", "-cd", "[:graph:]", NULL);

  if (res == NULL) {
    printf ("Command \"/usr/bin/tr -cd [:graph:]\" failed.\n");
    exit (1);
  } else {
    printf ("Command \"/usr/bin/tr -cd [:graph:]\" succeeded.and returned:\n%s\n\n", res);
    free (res);
  }    
}

static void test_fork_exec_sin_env (void) {
  uint32_t res;

  res = fork_exec_sin_env ("tititoto", "PASS", "pouetpouet", "./test.sh", NULL);
  if (res != 0) {
    printf ("Command failed.\n");
    exit (1);
  } else {
    printf ("Command succeeded.\n");
  }    
}


int main (int argc __attribute((unused)), char* argv[] __attribute((unused))) {
  uid_t uid;

  test_0 ("/bin/true");
  test_0 ("/bin/ls");
  test_1 ("/bin/ls", "-l");
  test_2 ("/bin/ls", "-a", "-l");
  test_out_2 ("/bin/ls", "-a", "-l");

  test_random ();

  if (get_current_user (&uid) == CMD_OK)
    printf ("Utilisateur courant : %d \n", uid);
  else {
    printf ("Impossible de déterminer l'utilisateur courant.\n");
    exit (1);
  }

  switch (check_uid ("admin")) {
  case (CMD_OK):
    printf ("L'utilisateur courant n'est pas celui connecté.\n");
    break;
  case (CMD_UNKNOWNUSER):
    printf ("Impossible de déterminer l'utilisateur testé.\n");
    break;
  case (CMD_CURRENTUSER):
    printf ("L'utilisateur testé est celui connecté.\n");
    break;
  default:
    printf ("Erreur ?");
    exit (1);
  }

  test_fork_exec_sin_env();

  return 0;
}
// vim:sw=2:ts=2:et:
