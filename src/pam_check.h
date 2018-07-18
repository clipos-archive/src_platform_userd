// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.
#ifndef __PAM_CHECK_H__
#define __PAM_CHECK_H__

#include "userd.h"

extern int
try_user_authenticate(authtype_t auth, const char *username, const char *secret);

extern int
check_password(authtype_t auth, const char *username, const char *secret);

#endif
// vim:sw=2:ts=2:et:
