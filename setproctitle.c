/* NOTE: Originally derived from ngx_setproctitle.c in
 * https://github.com/nginx/nginx - please send any changes which
 * aren't specific to our fork upstream.
 *
 * Copyright (C) 2002-2017 Igor Sysoev
 * Copyright (C) 2011-2017 Nginx, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* walters: replaced nginx util C headers and functions with ours */
#include "setproctitle.h"
#include "utils.h"

#define BWRAP_SETPROCTITLE_PAD '\0'

/*
 * To change the process title in Linux and Solaris we have to set argv[1]
 * to NULL and to copy the title to the same place where the argv[0] points to.
 * However, argv[0] may be too small to hold a new title.  Fortunately, Linux
 * and Solaris store argv[] and environ[] one after another.  So we should
 * ensure that is the continuous memory and then we allocate the new memory
 * for environ[] and copy it.  After this we could use the memory starting
 * from argv[0] for our process title.
 *
 * The Solaris's standard /bin/ps does not show the changed process title.
 * You have to use "/usr/ucb/ps -w" instead.  Besides, the UCB ps does not
 * show a new title if its length less than the origin command line length.
 * To avoid it we append to a new title the origin command line in the
 * parenthesis.
 */

/* The original */
static char **bwrap_os_argv;
static char **bwrap_os_environ;
extern char **environ;

static char *bwrap_os_argv_last;

/* In upstream nginx, this is called early in main.  However,
 * I don't see a reason not to merge it with ngx_init_setproctitle()
 */
static void
bwrap_save_argv(int argc, char *const *argv)
{
  bwrap_os_argv = (char **) argv;
  bwrap_os_environ = environ;
}

void
bwrap_init_setproctitle(int argc, char *const *argv)
{
    char      *p;
    size_t       size;
    unsigned   i;

    bwrap_save_argv(argc, argv);

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = xmalloc(size);

    bwrap_os_argv_last = bwrap_os_argv[0];

    for (i = 0; bwrap_os_argv[i]; i++) {
        if (bwrap_os_argv_last == bwrap_os_argv[i]) {
            bwrap_os_argv_last = bwrap_os_argv[i] + strlen(bwrap_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (bwrap_os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            bwrap_os_argv_last = environ[i] + size;

            strncpy(p, environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    bwrap_os_argv_last--;
}

void
bwrap_setproctitle(char *title)
{
    char     *p;

    bwrap_os_argv[1] = NULL;

    p = stpncpy(bwrap_os_argv[0], "bwrap: ",
                bwrap_os_argv_last - bwrap_os_argv[0]);

    p = stpncpy(p, title, bwrap_os_argv_last - p);

    if (bwrap_os_argv_last - p) {
        memset(p, BWRAP_SETPROCTITLE_PAD, bwrap_os_argv_last - p);
    }
}
