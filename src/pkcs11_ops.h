// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
/**
 * @file pkcs11_ops.h
 * PKCS11 function prototypes for userd.
 * @author Benjamin Morin <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2010-2013 SGDSN/ANSSI
 *
 * @n
 * All rights reserved.
 */

#ifndef PKCS11_OPS_H
#define PKCS11_OPS_H

#include "pkcs11.h"
#include <libp11.h>

#define MASTER_KEY_SIZE 32
#define RANDOM_SIZE 16
#define MAX_PIN_LEN 16
#define MIN_PIN_LEN 4

int bad_pin(char* pin);

CK_RV choose_slot(CK_FUNCTION_LIST_PTR pkcs11);
extern uint32_t chpin (char* old_pin, char* new_pin);

uint32_t pkauth_gen_secret (char** secret);

uint32_t pkauth_encrypt_secret (PKCS11_SLOT *slot, PKCS11_CERT *enccert, char *pin, char* secret, char** enc_secret, size_t* enc_secret_size);

uint32_t pkauth_record_secret (char* username, char* enc_secret, size_t enc_secret_size);

int update_mapper_deluser(int fd, const char *username);

int update_mapper_adduser(int fd, const char* dn, const char *username);

int open_and_lock_mapperfile(int deluser);

uint32_t pkauth_init(PKCS11_CTX **rctx, PKCS11_SLOT **rslots, unsigned int *rnslots, PKCS11_SLOT **rslot);

uint32_t pkauth_logout(PKCS11_SLOT *slot);

uint32_t pkauth_finish(PKCS11_CTX *ctx, PKCS11_SLOT *slots, unsigned int nslots);

int32_t pkauth_list_certificates(PKCS11_SLOT *slot, PKCS11_CERT** auth_cert, PKCS11_CERT** enc_cert);

uint32_t pkauth_add_user (char* username, PKCS11_CERT *authcert);

uint32_t pkauth_del_user (char* username);

#endif // PKCS11_OPS_H

// vim:sw=2:ts=2:et:
