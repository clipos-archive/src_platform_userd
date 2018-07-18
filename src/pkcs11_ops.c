// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file pkcs11_ops.c
 * PKCS11 functions for userd.
 * @author Benjamin Morin <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2010-2013 SGDSN/ANSSI
 *
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>

#include "userd_priv.h"
#include "pkcs11_ops.h"

#define MAX_LABEL_LEN 64
#define MAX_DN_SIZE 512
#define ADDUSER 0
#define DELUSER 1

extern char* module_lib_path;
extern char* auth_cert_label;
extern char* enc_cert_label;

extern const char clip_base[];

static CK_SLOT_ID slotid;
static CK_C_INITIALIZE_ARGS p11_init_args = {
  NULL,
  NULL,
  NULL,
  NULL,
  CKF_OS_LOCKING_OK,
  NULL
};


static inline int 
_read(int fd, char *buf, size_t len)
{
	ssize_t rlen;
	char *ptr = buf;
	size_t remaining = len;

	for (;;) {
		rlen = read(fd, ptr, remaining);
		if (rlen < 0) {
			if (errno == EINTR)
				continue;
			perror("read");
			return -1;
		}
		ptr += rlen;
		remaining -= rlen;
		if (!remaining)
			break;
	}
	return 0;
}

static inline int
_write(int fd, char *buf, size_t len)
{
	ssize_t wlen;
	char *ptr = buf;
	size_t remaining = len;

	for (;;) {
		wlen = write(fd, buf, remaining);
		if (wlen < 0) {
			if (errno == EINTR)
				continue;
			perror("write");
			return -1;
		}
		ptr += wlen;
		remaining -= wlen;
		if (!remaining)
			break;
	}
	return 0;
}


int
open_and_lock_mapperfile(int deluser)
{
	int fd;

	char *mapperfile = NULL;

	if(asprintf(&mapperfile, "%s/etc.users/subject_mapping", clip_base) <= 0) {
	  ERROR("Not enough memory");
	  return -1;
	}

	if (deluser)
		fd = open(mapperfile, O_RDWR|O_NOFOLLOW);
	else {
		mode_t saved_umask;

		saved_umask = umask(S_IWGRP|S_IWOTH);
		fd = open(mapperfile, O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW, 
					S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		(void)umask(saved_umask);
	}
	
	if (fd == -1) {
		perror("open");
		free(mapperfile);
		return -1;
	}

	/* Lock the file to avoid mangling it on concurrent runs
	 * Unlocking done by update_mapper_adduser/update_mapper_deluser.
	 */
	if (lockf(fd, F_LOCK, 0) == -1) {
		perror("lockf");
		if (close(fd))
			perror("close");
		free(mapperfile);
		return -1;
	}

	free(mapperfile);

	return fd;
}



int
update_mapper_adduser(int fd, const char* dn, const char *username)
{
	const char *ptr;
	char *buf;
	size_t len;
	ssize_t wlen;
	int ret = -1;

	ptr = dn;

	while (isspace(*ptr))
		ptr++;
	len = strlen(ptr) + strlen(username);
	/* +4 for " -> ", +1 for \n */
	len += 5;
	buf = malloc(len + 1);
	if (!buf) {
		ERROR("Out of memory\n");
		goto out_unlock;
	}
	wlen = snprintf(buf, len + 1, "%s -> %s\n", ptr, username);
	if (wlen < 0) {
		perror("snprintf");
		goto out_free;
	}
	if ((size_t)wlen != len) {
		ERROR("snprintf : wrong length\n");
		goto out_free;
	}

	ret = _write(fd, buf, len);
	/* Fall through */

out_free:
	free(buf);
out_unlock:
	if (lockf(fd, F_ULOCK, 0))
		perror("lockf F_ULOCK");
	if (close(fd))
		perror("close");
	return ret;
}

int
update_mapper_deluser(int fd, const char *username)
{
  char *buf, *dstptr, *end1, *start2;
  struct stat stbuf;
  off_t offset;
  
  int ret = -1;
  size_t len = strlen(username);
  
  /* What we really need to match is " -> username" */
  char * pattern = malloc(len + 5);
  if (!pattern) {
    ERROR("Out of memory\n");
    goto out_unlock;
  }
  ret = snprintf(pattern, len+5, " -> %s", username);
  printf("ret = %d, pattern=%s\n", ret, pattern);
  if (ret < 0) {
    perror("snprintf");
    ret = -1;
    goto out_freepat;
  }
  if ((size_t)ret != len+4) {
    ERROR("snprintf: wrong length\n");
    ret = -1;
    goto out_freepat;
  }
  ret = -1;
  
  if (fstat(fd, &stbuf) == -1) {
    perror("fstat");
		goto out_freepat;
  }
  buf = malloc(stbuf.st_size + 1);
  if (!buf) {
    ERROR("Out of memory\n");
    goto out_freepat;
  }
  
  if (_read(fd, buf, stbuf.st_size)) 
    goto out_freebuf;
  
  buf[stbuf.st_size] = '\0';
  
  /* Find first occurence of " -> username" */
  dstptr = strstr(buf, pattern);

  if (dstptr == NULL) {
    ret = -1;
    goto out_freebuf;
  }
	
  /* Find last '\n' before dstptr.
   * Destroying dstptr is no problem, since it won't be written
   * out anyway */
  *dstptr = '\0';
  end1 = strrchr(buf, '\n'); /* end1 == NULL ok: g_dst on first line */
  
  /* Find first '\n' after dstptr
   * dstptr + 1 is ok since strlen(pattern) > 0 */
  start2 = strchr(dstptr + 1, '\n');
  if (!start2) {
    ERROR("mapper file missing a newline\n");
    goto out_freebuf;
  }
  
  if (lseek(fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    goto out_freebuf;
  }
  
  if (end1 && end1 != buf && _write(fd, buf, end1 - buf + 1)) 
    goto out_freebuf;	
  /* start2 is at most the penultimate character in buf, since we
   * added a '\0' at the end... If it is, that means g_dst was the
   * last line and there is nothing to copy after it. */
  start2++; /* skip newline */
  if (*start2 && _write(fd, start2, stbuf.st_size - (start2 - buf)))
    goto out_freebuf;
  
  /* He is just too lazy to count :) */
  offset = lseek(fd, 0, SEEK_CUR);
  if (offset == -1) {
    perror("lseek SEEK_CUR");
    goto out_freebuf;
  }
  if (ftruncate(fd, offset) == -1) {
    perror("ftruncate");
    goto out_freebuf;
  }
  
  ret = 0;
  /* Fall through */
  
 out_freebuf:
  free(buf);
 out_freepat:
  free(pattern);
 out_unlock:
  if (lockf(fd, F_ULOCK, 0))
    perror("lockf F_ULOCK");
  if (close(fd))
    perror("close");
  return ret;
}


/* 
 * Check PIN correctness
 */

int
bad_pin(char* pin)
{
  int i;
  int l = strnlen (pin, MAX_PIN_LEN+1);

  /* We only accept PINs that are composed of characters
     and digits and are shorter than 16 characters */

  if (l > MAX_PIN_LEN || l < MIN_PIN_LEN)
    return 1;

  for (i=0; i<l; i++) {
    if (!((pin[i] >= 'a' && pin[i] <= 'z') || (pin[i] >= '0' && pin[i] <= '9'))) {
      return 1;
    }
  }
  
  return 0;

}

/*
   Generate "human-readable" master secret from /dev/urandom
*/
uint32_t
pkauth_gen_secret(char** thesecret)
{
  unsigned char alea[RANDOM_SIZE];
  int r,fd,i;
  uint32_t ret = CMD_OK;
  char * secret = NULL;

  secret = malloc((MASTER_KEY_SIZE+1)*sizeof(char));
  if(!secret) {
    ERROR("generate_secret : no memory left");
    ret = CMD_NOMEM;
    goto end;
  }

  fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    ERROR("Could not open /dev/urandom");
    ret = CMD_FAULT;
    goto free;
  }

  r = read(fd, alea, RANDOM_SIZE);
  if(r < RANDOM_SIZE) {
    ERROR("Could not read enough entropy");
    ret = CMD_FAULT;
    goto close;
  }

  for(i=0;i<RANDOM_SIZE;i++)
    snprintf(secret+2*i,3,"%02X",alea[i]&0xFF);

  *thesecret = secret;

  close(fd);

  return CMD_OK;

 close:
  close(fd);

 free:
  free(secret);

 end:
  return ret;
}

/*
  Init card
*/
uint32_t
pkauth_init(PKCS11_CTX **rctx, PKCS11_SLOT **rslots, unsigned int *rnslots, PKCS11_SLOT **rslot)
{
  PKCS11_CTX *ctx;
  PKCS11_SLOT *slots, *slot;
  unsigned int nslots;
  int rc = 0;
  uint32_t ret = CMD_FAULT;

  if(!module_lib_path) {
    ERROR("Empty PKCS11 lib path");
    return ret;
  }

  ctx = PKCS11_CTX_new();

  DEBUG("Loading P11 module...");

  rc = PKCS11_CTX_load(ctx, module_lib_path);
  if (rc) {
    ERROR("loading pkcs11 engine failed: %s",
	  ERR_reason_error_string(ERR_get_error()));
    goto nolib;
  }

  // get information on all slots
  rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
  if (rc < 0) {
    ERROR("no slots available"); goto noslots;
  }

  // get first slot with a token
  slot = PKCS11_find_token(ctx, slots, nslots);
  if (!slot || !slot->token) {
    ERROR("no token available"); goto notoken;
  }

  *rctx = ctx;
  *rslots = slots;
  *rnslots = nslots;
  *rslot = slot;

  return CMD_OK;

 notoken:
  PKCS11_release_all_slots(ctx, slots, nslots);
  
 noslots:
  PKCS11_CTX_unload(ctx);
  ret = CMD_INVALID_CARD;
  
 nolib:
  PKCS11_CTX_free(ctx);

  return ret;
}


uint32_t
pkauth_finish(PKCS11_CTX *ctx, PKCS11_SLOT *slots, unsigned int nslots)
{

  PKCS11_release_all_slots(ctx, slots, nslots);
  PKCS11_CTX_unload(ctx);
  PKCS11_CTX_free(ctx);

  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  ERR_remove_state(0);

  return CMD_OK;
}

int32_t
pkauth_list_certificates(PKCS11_SLOT *slot, PKCS11_CERT** auth_cert, PKCS11_CERT** enc_cert)
{
  int rc;

  PKCS11_CERT *certs, *currcert;
  unsigned int ncerts, i;

  *auth_cert = NULL;
  *enc_cert = NULL;

  if(!slot) {
    ERROR("No slot defined");
    return CMD_FAULT;
  }

  rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
  if (rc) {
    ERROR("PKCS11_enumerate_certs failed");
    return CMD_FAULT;
  }
  if (ncerts <= 0) {
    ERROR("no certificates found");
    return CMD_FAULT;
  }

  // Get authentication and disk decryption certificates
  for(i=0;i<ncerts;i++) {
    currcert = &certs[i];

    if(!strncmp(currcert->label, enc_cert_label, MAX_LABEL_LEN))
      *enc_cert = currcert;
    if(!strncmp(currcert->label, auth_cert_label, MAX_LABEL_LEN))
      *auth_cert = currcert;
  }

  if( *auth_cert == NULL || *enc_cert == NULL ) {
    ERROR("Certificates not found on card");
    return CMD_FAULT;
  }

  return CMD_OK;
}


/*
  Encrypt the master secret
 */
uint32_t 
pkauth_encrypt_secret (PKCS11_SLOT *slot, PKCS11_CERT *enccert, char* pin, char* secret, char** enc_secret, size_t* enc_secret_size)
{
  PKCS11_KEY *enckey;
  EVP_PKEY *pubkey = NULL;
  char *encrypted = NULL, *decrypted = NULL;

  int rc = 0, len;
  unsigned int secret_size = 0;

  // set to 1 to check that the generated master key can (really) be decrypted
  int check_master_key = 1;

  // get RSA key
  pubkey = X509_get_pubkey(enccert->x509);
  if (pubkey == NULL) {
    ERROR("could not extract public key");
    return CMD_FAULT;
  }

  // allocate destination buffer
  encrypted = malloc(RSA_size(pubkey->pkey.rsa));
  if (!encrypted) {
    ERROR("out of memory for encrypted data");
    return CMD_FAULT;
  }

  secret_size = strnlen(secret, MASTER_KEY_SIZE+1);
  if(secret_size < MASTER_KEY_SIZE) {
    ERROR("bad secret size");
    goto failed;
  }

  DEBUG("Encrypting master secret...");

  // use public key for encryption
  len = RSA_public_encrypt(secret_size, (unsigned char*)secret, (unsigned char*)encrypted, pubkey->pkey.rsa, RSA_PKCS1_PADDING);
  if (len < 0) {
    ERROR("fatal: RSA_public_encrypt failed");
    goto failed;
  }

  if(check_master_key) {
    DEBUG("Verifying that the master key can be decrypted...");
    // now decrypt
    if (!slot->token->loginRequired)
      goto loggedin;

    // perform pkcs #11 login
    rc = PKCS11_login(slot, 0, pin);
    if (rc != 0) {
      ERROR("PKCS11_login failed");
      goto failed;
    }

  loggedin:
    enckey = PKCS11_find_key(enccert);
    if (!enckey) {
      ERROR("no key matching certificate available");
      goto failed;
    }

    // allocate space for decrypted data 
    decrypted = malloc(RSA_size(pubkey->pkey.rsa));
    if (!decrypted)
      goto failed;

    rc = PKCS11_private_decrypt(len, (unsigned char*)encrypted, (unsigned char*)decrypted, enckey, RSA_PKCS1_PADDING);
    if (rc != MASTER_KEY_SIZE) {
      ERROR("fatal: PKCS11_private_decrypt failed");
      goto decr;
    }

    // check if original matches decypted
    if (memcmp(secret, decrypted, MASTER_KEY_SIZE) != 0) {
      ERROR("fatal: decrypted data does not match original\n");
      goto decr;
    }
  }

  if (pubkey != NULL)
    EVP_PKEY_free(pubkey);
  if (decrypted != NULL) {
    memset(decrypted,0,MASTER_KEY_SIZE);
    free(decrypted);
  }

  *enc_secret_size = len;
  *enc_secret = encrypted;

  return CMD_OK;

 decr:
  free(decrypted);

 failed:
  free(encrypted);
  ERROR("Error encrypting secret");
  return CMD_FAULT;
}



uint32_t
pkauth_logout(PKCS11_SLOT *slot) {
  if(PKCS11_logout(slot))
    return CMD_INVALID_CARD;
  return CMD_OK;
}

/*
  Add cert -> user mapping in /etc/pam_pkcs11/subject_mapping
 */

uint32_t
pkauth_add_user (char* username, PKCS11_CERT *authcert)
{
  char subject[MAX_DN_SIZE];
  int ret, fd;

  if(!username) {
    ERROR("adduser : username is null");
    return CMD_FAULT;
  }

  if(!authcert) {
    ERROR("adduser : authcert is null");
    return CMD_FAULT;
  }

  // Get the DN entry from the auth. certificate
  X509_NAME_oneline (X509_get_subject_name (authcert->x509), subject, MAX_DN_SIZE);

  // Add mapping
  fd = open_and_lock_mapperfile(ADDUSER);
  if(fd<0) {
    ERROR("Error opening mapping file");
    return CMD_FAULT;
  }

  ret = update_mapper_adduser(fd, subject, username);
  if(ret) {
    ERROR("Error adding user mapping");
    return CMD_FAULT;
  }

  return CMD_OK;
}

/*
  Remove cert -> user mapping in /etc/pam_pkcs11/subject_mapping
 */

uint32_t
pkauth_del_user (char* username)
{
  int ret, fd;

  if(!username) {
    ERROR("deluser : username is null");
    return CMD_FAULT;
  }

  // Del mapping
  fd = open_and_lock_mapperfile(DELUSER);
  if(fd<0) {
    ERROR("Error opening mapping file");
    return CMD_FAULT;
  }
  
  ret = update_mapper_deluser(fd, username);
  if(ret) {
    ERROR("Error removing user mapping");
    return CMD_FAULT;
  }

  return CMD_OK;
}

/*
  Write encrypted secret to disk
 */
uint32_t
pkauth_record_secret (char* username, char* enc_secret, size_t enc_secret_size)
{
  int fd,ret;
  ssize_t wr;
  char *filename = NULL;

  if (asprintf(&filename, "/home/keys/%s.masterkey", username) < 0) {
    ERROR("Out of memory");
    return CMD_NOMEM;
  }
 
  fd = open(filename, O_WRONLY|O_CREAT, S_IRUSR|S_IRGRP);
  if(fd == -1) {
    ERROR("Could not open encrypted masterkey file");
    ret = CMD_FAULT;
    goto out;
  }

  wr = write(fd, enc_secret, enc_secret_size);
  if(wr != (ssize_t)enc_secret_size) {
    ERROR("Could not write encrypted masterkey");
    ret = CMD_FAULT;
    goto out;
  }

  ret = CMD_OK;

 out:

  if(filename != NULL)
    free(filename);

  return ret;
}


/* Choose one slot 
   Note : this function actually takes the first slot
   in the list
   TODO : choose the one whose description matches some
   pattern
 */
CK_RV
choose_slot(CK_FUNCTION_LIST_PTR pkcs11)
{
  CK_RV rv;
  CK_SLOT_ID slots[1024];
  CK_ULONG slotsnum;
  CK_SLOT_ID slot;
  CK_SLOT_INFO info;
  int selected_slot = -1;

  if ((rv = pkcs11->C_GetSlotList(FALSE, NULL, &slotsnum)) != CKR_OK) {
    DEBUG("pkcs11_ops.c:slotlist : C_GetSlotList");
    return(rv);
  }

  if (slotsnum >= sizeof(slots)/sizeof(slots[0])) {
    DEBUG("pkcs11_ops.c:slotlist : buffer too small");
    return(CKR_BUFFER_TOO_SMALL);
  }

  if ( (rv = pkcs11->C_GetSlotList (FALSE, slots, &slotsnum)) != CKR_OK) {
    DEBUG("pkcs11_ops.c:slotlist : could not retrieve slot list");
    return(rv);
  }

  if (slotsnum == 0) {
    ERROR("No PKCS11 slot");
    return(-1);
  }

  for (slot=0; slot<slotsnum && slot < sizeof (slots)/sizeof (CK_SLOT_ID); slot++) {
    if ((rv = pkcs11->C_GetSlotInfo (slots[slot], &info)) == CKR_OK) {
      DEBUG("Using slot %lu (%s)", slots[slot], info.slotDescription);
      if ((selected_slot < 0) && (info.flags & CKF_TOKEN_PRESENT))
	selected_slot = slot;
    }
    else {
      DEBUG("pkcs11_ops.c:slotlist : C_GetSlotInfo failed (%08lx)\n", rv);
    }
  }

  if (selected_slot < 0) selected_slot = 0;
  slotid=slots[selected_slot];

  return CKR_OK;
}

uint32_t
chpin (char* old_pin, char* new_pin) 
{
  int ret = CMD_OK;

  void *module;
  CK_C_GetFunctionList func_get_list;
  CK_FUNCTION_LIST_PTR funcs;
  CK_RV rv;
  CK_SESSION_HANDLE session;

  if (bad_pin(new_pin)) {
    ERROR ("Bad PIN");
    return CMD_WEAK_PASSWD;
  }

  /* Load the library */
  module = dlopen(module_lib_path, RTLD_NOW);
  if(!module) {
    ERROR("couldn't open library: %s: %s\n", module_lib_path, dlerror());
    return CMD_FAULT;
  }

  /* Lookup function in library */
  func_get_list = (CK_C_GetFunctionList)dlsym (module, "C_GetFunctionList");
  if (!func_get_list) {
    DEBUG("pkcs11_ops:chpin: C_GetFunctionList() not found: %s", dlerror());
    ret = CMD_FAULT; goto dlclose;
  }

  /* Get the function list */
  rv = (func_get_list) (&funcs);
  if (rv != CKR_OK || !funcs) {
    DEBUG ("pkcs11_ops:chpin:C_GetFunctionList() (0x%08x)", (int)rv);
    ret = CMD_FAULT; goto dlclose;
  }

  /* Initialize module */
  rv = (funcs->C_Initialize) (&p11_init_args);
  switch (rv) {
  case CKR_OK: break;
  default:
    DEBUG ("pkcs11_ops:chpin:C_Initialize (0x%08x)", (int)rv);
    ret = CMD_FAULT; goto dlclose;
  }

  /* Choose one slot */
  rv = choose_slot(funcs);
  switch (rv) {
  case CKR_OK: break;
  default:
    DEBUG ("pkcs11_ops:chpin:choose_slot (0x%08x)", (int)rv);
    ret = CMD_FAULT; goto dlclose;
  }

  /* Open session */
  rv = funcs->C_OpenSession (slotid, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
  switch (rv) {
  case CKR_OK: break;
  default:
    DEBUG("pkcs11_ops:chpin:C_OpenSession (0x%08x)\n", (unsigned int)rv);
    ret = CMD_FAULT; goto finalize;
  }

  /* Login */
  rv=funcs->C_Login (session, CKU_USER, (CK_CHAR_PTR)old_pin, (CK_ULONG)strlen(old_pin));
  switch (rv) {
  case CKR_OK: break;
  case CKR_USER_ALREADY_LOGGED_IN: break;
  case CKR_PIN_INCORRECT:
    ERROR("Incorrect PIN");
    ret = CMD_INVALID_PWD;
    goto closesession;
  default:
    DEBUG("pkcs11_ops:chpin:C_Login (0x%08x)\n", (unsigned int)rv);
    ret = CMD_FAULT;
    goto closesession;
  }

  /* Change PIN */
  rv = funcs->C_SetPIN(session, (CK_CHAR_PTR)old_pin, (CK_ULONG)strlen(old_pin), (CK_CHAR_PTR)new_pin, (CK_ULONG)strlen(new_pin));
  switch (rv) {
  case CKR_OK: break;
  case CKR_PIN_INCORRECT:
    ERROR("Incorrect PIN");
    ret = CMD_INVALID_PWD;
    goto logout;
  default:
    DEBUG("pkcs11_ops:chpin:C_SetPIN (0x%08x)", (unsigned int)rv);
    ret = CMD_FAULT;
    goto logout;
  }

  LOG("PIN successfully changed");
  
 logout:
  /* Logout */
  funcs->C_Logout(session);
  switch (rv) {
  case CKR_OK: break;
  default:
    DEBUG("pkcs11_ops:chpin:C_Logout (0x%08x)", (unsigned int)rv);
    break;
  }

 closesession:
  /* Close session */
  funcs->C_CloseSession(session);
  switch (rv) {
  case CKR_OK: break;
  default:
    DEBUG("pkcs11_ops:chpin:C_CloseSession (0x%08x)", (unsigned int)rv);
    break;
  }

 finalize:
  /* Finalize */
  rv = (funcs->C_Finalize) (NULL);
  switch (rv) {
  case CKR_OK: break;
  default:
    DEBUG("pkcs11_ops:chpin:C_Finalize (0x%08x)", (unsigned int)rv);
    break;
  }

  /* Unload module */
 dlclose:
  dlclose(module);

  return ret;
}
// vim:sw=2:ts=2:et:
