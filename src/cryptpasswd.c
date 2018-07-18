// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2009-2018 ANSSI. All Rights Reserved.


/**
 * cryptopasswd.c
 *
 * @brief cryptpasswd encrypts a password with the crypt(3) function.
 * @see crypt
 *
 **/

/* Modified to accept a salt as input, read a password from the environment, and fix possible overflows
 * Vincent Strubel <clipos@ssi.gouv.fr>
 */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ow-crypt.h>
#include <getopt.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SIZEOF_SALT 	16
#define MIN_ROUNDS	8UL
#define MAX_ROUNDS	31UL
#define DEFAULT_ROUNDS	12UL

static char *password = NULL; /* cleartext password */
static char *salt = NULL;
static char *saltfile = NULL; 
static char *settings = NULL;
static unsigned long rounds = 0;

static int 
read_loop(int fd, char *buffer, int count)
{
  int offset, block;
  offset = 0;
  while (count > 0)
    {
      block = read(fd, &buffer[offset], count);
      
      if (block < 0)
	{
	  if (errno == EINTR) continue;
	  return block;
	}

      if (!block) return offset;
      
      offset += block;
      count -= block;
    }
  
  return offset;
}

/**
 * Affiche l'aide de la commande
 * Appele quand l'utilisateur positionne l'option '-h' (ou "--help") dans la commande
 **/
static void 
show_help(void)
{
  puts("usage: cryptpasswd [options] [argument]\n");

  puts("Options:");
  puts("\t--password <password> \t\t Password");
  puts("\t--passvar <var> \t\t Get password from env var <var>");
  puts("\t--salt <salt> \t\t Use <salt> as salt");
  puts("\t--settings <settings> \t\t Use <settings> as settings");
  printf("\t--rounds <rounds> \t\t Use <rounds> rounds (default %lu, min %lu, "
		  "max %lu) of the bcrypt algorithm", DEFAULT_ROUNDS, 
		  MIN_ROUNDS, MAX_ROUNDS);
  puts("\t-h or --help \t\t Print Help (this message) and exit");
  puts("\t-v or --version \t Print version and exit");
}

/**
 * Affiche la version de la commande
 * Appele quand l'utilisateur positionne l'option '-v' (ou "--version") dans la commande
 **/
static void 
show_version(void)
{
  //  fprintf(stderr, "cryptpassword %s\n", PACKAGE_VERSION);
  fprintf(stderr, "cryptpassword\n");
}

static const struct option long_options[] = {
      {"password", 1, 0, 0},
      {"help", 0, 0, 0},
      {"version", 0, 0, 0},
      {"passvar", 1, 0, 0},
      {"salt", 1, 0, 0},
      {"saltfile", 1, 0, 0},
      {"settings", 1, 0, 0},
      {"rounds", 1, 0, 0},
      {0, 0, 0, 0}
};

static inline int 
get_str(char **dest, const char *src, const char *name)
{
	if (*dest) {
		fprintf(stderr, "Error: %s defined twice\n", name);
		return -1;
	}

	*dest = strdup(src);
	if (!*dest) {
		fprintf(stderr, "Out of memory while allocating %s\n", name);
		return -1;
	}
	return 0;
}

static int
pad_salt(void) {
	char *tmp;
	char *ptr = realloc(salt, SIZEOF_SALT);
	if (!ptr) {
		fputs("Out of memory\n", stderr);
		return -1;
	}
	salt = ptr;
	while (ptr - salt < SIZEOF_SALT && *ptr)
		ptr++;
	tmp = ptr;
	while (ptr - salt < SIZEOF_SALT)
		*ptr++ = 0;
	fprintf(stderr, "Warning, padded %d bytes of salt\n", ptr - tmp);

	return 0;
}
	
static int
parse_long_opts(int idx, int *exit_now) 
{
	char *ptr;

	switch (idx) {
		case 0:
			if (get_str(&password, optarg, "password"))
				return -1;
			break;
		case 1:
			show_help();
			*exit_now = 1;
			break;
		case 2:
			show_version();
			*exit_now = 1;
			break;
		case 3:
			ptr = getenv(optarg);
			if (!ptr) {
				fprintf(stderr, "Variable %s is not defined "
						"in env\n", optarg);
				return -1;
			}
			if (get_str(&password, ptr, "password"))
				return -1;
			break;
		case 4:
			if (get_str(&salt, optarg, "salt"))
				return -1;

			if (strlen(salt) < SIZEOF_SALT) {
				if (pad_salt())
					return -1;
			}
			if (strlen(salt) > SIZEOF_SALT) {
				fprintf(stderr, "warning, salt size (%u) "
						"too long\n", strlen(salt));
				salt[SIZEOF_SALT] = '\0';
			}
			break;
		case 5:
			if (get_str(&saltfile, optarg, "saltfile"))
				return -1;
			break;
		case 6:
			if (get_str(&settings, optarg, "settings"))
				return -1;
			break;
		case 7:
			errno = 0;
			rounds = strtoul(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid rounds count: %s\n",
							optarg);
				return -1;
			}
			if (rounds < MIN_ROUNDS || rounds > MAX_ROUNDS) {
				fprintf(stderr, "Unsupported rounds count %s\n"
						"Supported counts are between "
						"%lu and %lu\n", optarg, 
						MIN_ROUNDS, MAX_ROUNDS);
				return -1;
			}
			break;
		default:
			fprintf(stderr, "Invalid long option index %d\n", idx);
			return -1;
			break;
	}
	return 0;
}

#define check2vars(var1, var2) do {					\
	if (var1 && var2) { 						\
		fprintf(stderr, "--%s and --%s cannot be specified at "	\
				"the same time\n", #var1, #var2);	\
		return -1;						\
	}								\
} while (0)

static int
check_opts(void)
{
	check2vars(salt, saltfile);
	check2vars(salt, settings);
	check2vars(saltfile, settings);
	check2vars(rounds, settings);
	return 0;
}

int main(int argc, char ** argv)
{
  int rlen;
  char* encryptedpassword = 0;
  int fd = 0;
  int ret = EXIT_FAILURE;
  int rand_salt = 0; /* One if using random salt source */

  /* Parse la ligne de commande */
  for (;;) {
    int option_index = 0;
    int exit_now = 0;

    int c = getopt_long (argc, argv, "vh", long_options, &option_index);

    if (c == -1)
	    break;

    switch (c) {
      case 0:
	if (parse_long_opts(option_index, &exit_now))
		goto out;
	if (exit_now)
		goto out_ok;
	break;

      case 'h':
	show_help();
	goto out_ok;
	break;

      case 'v':
	show_version();
	goto out_ok;
	break;

      default:
	fprintf (stderr, "cryptpassd : bad option %c\n", c);
	goto out;
      }
  }

  if (check_opts())
	  goto out;

  if (!password || !*password)
    {
    	fprintf(stderr, "cryptpasswd : password empty\n");
	return -1;
    }

  if (!settings && !salt && !saltfile) {
	  rand_salt = 1;
	  saltfile = strdup("/dev/urandom");
	  if (!saltfile) {
		  fputs("Out of memory\n", stderr);
		  goto out;
	  }
  }
  /* Generation du salt */
  if (!settings && !salt) {
    salt = malloc(SIZEOF_SALT+1);
    if (!salt) {
	    fputs("Out of memory\n", stderr);
	    goto out;
    }
    fd = open(saltfile, O_RDONLY);
    if (fd < 0)
      {
        perror("open urandom");
        goto out;
      }

    rlen = read_loop(fd, salt, SIZEOF_SALT);
    if (rlen < 0)
      {
        perror("read salt");
        close(fd);
        goto out;
      }
    close(fd);
    if (rlen != SIZEOF_SALT) {
	    if (rand_salt) {
		    fputs("Could not read enough salt off urandom\n", stderr);
		    goto out;
	    }
	    if (pad_salt())
		    goto out;
    }  
  }

  if (!rounds)
	  rounds = DEFAULT_ROUNDS;
  if (!settings) {
	  settings = crypt_gensalt_ra("$2a$", rounds, salt, SIZEOF_SALT);
	  if (!settings) {
		  perror("crypt_gensalt_ra");
		  goto out;
	  }
  }

  /* Crypto */
  encryptedpassword = crypt(password, settings);
  /* Error checking : crypt returns a 13-byte magic string on error.
   * strlen() < 16 is as good a way of detecting this as any */
  if (strlen(encryptedpassword) < SIZEOF_SALT) {
	  perror("crypt() error");
	  goto out;
  }

  printf("%s\n", encryptedpassword);

out_ok:
  ret = EXIT_SUCCESS;
  /* Fall through */
out:
  if (password)
	  free(password);
  if (salt)
	  free(salt);
  if (saltfile)
	  free(saltfile);
  if (settings)
	  free(settings);
  return ret;
}
// vim:sw=2:ts=2:et:
