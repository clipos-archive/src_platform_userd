// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file pam_check.c
 * Userd pam interface.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2013-2014 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

#include "pam_check.h"
#include "userd_priv.h"


typedef struct {
  authtype_t auth;
  const char *username;
  const char *secret;
} auth_info_t;



static int
conversation(int num_msg,
             const struct pam_message **msg,
             struct pam_response **resp,
             void *data) {
  int i;
  struct pam_response *reply;
  /* AFAIK, these should not be freed once they've
   * been passed to PAM */
  char *secret, *user;
  
  const auth_info_t *info = data;
  
  if (num_msg < 0) /* WTF ? */
    return PAM_CONV_ERR;

  reply = calloc(num_msg, sizeof(*reply));
  if (!reply)
    return PAM_CONV_ERR;

  for (i = 0; i < num_msg; i++) {
    switch (msg[i]->msg_style) {
      case PAM_PROMPT_ECHO_OFF:
        secret = strdup(info->secret);
        if (!secret)
          goto out_free;
        reply[i].resp = secret;
        reply[i].resp_retcode = PAM_SUCCESS;
        break;

      case PAM_PROMPT_ECHO_ON:
        user = strdup(info->username);
        if (!user)
          goto out_free;
        reply[i].resp = user;
        reply[i].resp_retcode = PAM_SUCCESS;
        break;
      
      case PAM_TEXT_INFO:
        LOG("PAM message: %s", msg[i]->msg);
        reply[i].resp_retcode = PAM_SUCCESS;
        break;
      
      case PAM_ERROR_MSG:
        ERROR("PAM error: %s", msg[i]->msg);
        reply[i].resp_retcode = PAM_SUCCESS;
        break;

      default:
        goto out_free;
    }
  }

  *resp = reply;
  return PAM_SUCCESS;

 out_free:
  for (i = 0; i < num_msg; i++) {
    if (reply[i].resp)
      free(reply[i].resp);
  }
  free(reply);
  return PAM_CONV_ERR;
}

/*
 * Sanity check : try authentication with the credentials passed as arguments,
 * using the *pwcheckd* PAM stack.
 */
int
try_user_authenticate(authtype_t auth, const char *username, 
                                                const char *secret)
{
  int error;
  pam_handle_t *pamh;

  auth_info_t info = {
    .auth = auth,
    .username = username,
    .secret = secret,
  };
  
  int ret = -1;
  struct pam_conv conv = {
    .conv = conversation,
    .appdata_ptr = &info,
  };

  error = pam_start("pwcheckd", info.username, &conv, &pamh);
  if (error != PAM_SUCCESS) {
    ERROR("pam_start error: %s", pam_strerror(pamh, error));
    goto end_pam;
  }

  error = pam_authenticate(pamh, 0);
  if (error != PAM_SUCCESS) {
    ERROR("pam_authenticate error: %s", pam_strerror(pamh, error));
    goto end_pam;
  }

  error = pam_acct_mgmt(pamh, 0);
  if (error != PAM_SUCCESS) {
    ERROR("pam_acct_mgmt error: %s", pam_strerror(pamh, error));
    goto end_pam;
  }

  ret = 0;

 end_pam:
  error = pam_end(pamh, error);
  if (error != PAM_SUCCESS) {
    ERROR("pam_end error: %s", pam_strerror(pamh, error));
    return -1;
  }

  return ret;
}

int
check_password(authtype_t auth, const char *username, const char *secret)
{
  int error, ret = -1;
  pam_handle_t *pamh;
  /* We use different PAM modules for different auth types, to be able 
   * to perform different checks for e.g. a PIN code or a password. */
  const char *module; 

  auth_info_t info = {
    .auth = auth,
    .username = username,
    .secret = secret,
  };

  struct pam_conv conv = {
    .conv = conversation,
    .appdata_ptr = &info,
  };

  switch (auth) {
    case AUTH_PW:
      module = "userd-passwd";
      break;
    case AUTH_PKCS:
      module = "userd-pkcs";
      break;
    default:
      ERROR("Unsupported auth type for password check: %d", auth);
      return -1;
  }

  error = pam_start(module, info.username, &conv, &pamh);
  if (error != PAM_SUCCESS) {
    ERROR("pam_start error: %s", pam_strerror(pamh, error));
    goto end_pam;
  }

  error = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
  if (error != PAM_SUCCESS) {
    ERROR("pam_chauthtok error: %s", pam_strerror(pamh, error));
    goto end_pam;
  }

  ret = 0;
  /* Fall through */

 end_pam:
  error = pam_end(pamh, error);
  if (error != PAM_SUCCESS) {
    ERROR("pam_end error: %s", pam_strerror(pamh, error));
    return -1;
  }

  return ret;
}

// vim:sw=2:ts=2:et:
