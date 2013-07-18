/***************************************************************************
 *  Simple Password Generator                                              *
 *  Copyright (C) 2013 by Poechtrager Thomas                               *
 *  t.poechtrager@gmail.com                                                *
 *                                                                         *
 *  This program is free software: you can redistribute it and/or modify   *
 *  it under the terms of the GNU General Public License as published by   *
 *  the Free Software Foundation, either version 3 of the License, or      *
 *  (at your option) any later version.                                    *
 *                                                                         *
 *  This program is distributed in the hope that it will be useful,        *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *  GNU General Public License for more details.                           *
 *                                                                         *
 *  You should have received a copy of the GNU General Public License      *
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.  *
 ***************************************************************************/

#ifdef _WIN32
#include <Windows.h>
#include <Wincrypt.h>
#elif __linux__
#include <unistd.h>
#include <fcntl.h>
#else
#error platform not supported
#endif /* _WIN32 */

#include <stdlib.h>
#include <stdio.h>

static const char acceptable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz!@#$%^&*()-+=_.,?";

typedef unsigned char uchar;

typedef struct
{
    size_t length;
    char *password;
} password;

static void init_password(password *pw)
{
    pw->password = malloc(pw->length+1);

    if (!pw->password)
    {
        fprintf(stderr, "unable to allocate memory for password\n");
        fflush(stderr);
        abort();
    }
}

static void destroy_memory(void *mem, const size_t length)
{
    volatile uchar *p = mem;
    volatile size_t *pi = mem;
    register size_t i, len = length;

    /* assume aligned memory */
    for (i = 0; i < len/sizeof(size_t); ++i) pi[i] = 0;
    for (; i < len; ++i) p[i] = 0;

    free(mem);
}

static uchar *get_entrophy(size_t length)
{
    uchar *p = malloc(length);
    if (!p) return NULL;

#ifdef _WIN32
    {
        HCRYPTPROV hprov;

        if (!CryptAcquireContext(&hprov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            destroy_memory(p, length);
            return NULL;
        }

        if (!CryptGenRandom(hprov, length, p))
        {
            destroy_memory(p, length);
            CryptReleaseContext(hprov, 0);
            return NULL;
        }

        CryptReleaseContext(hprov, 0);
    }
#else
    {
        /* 
         * Change /dev/urandom to /dev/random if you want very secure passwords,
         * but it may block, because of lack of entrophy data!
         */
        int fd = open("/dev/urandom", O_RDONLY);

        if (fd == -1)
        {
            destroy_memory(p, length);
            return NULL;
        }

        if (read(fd, p, length) == -1)
        {
            close(fd);
            return NULL;
        }

        close(fd);
    }
#endif /* _WIN32 */

    return p;
}

static int gen_password(password *pw)
{
    unsigned *ent;
    size_t i, j;
    static const size_t s = sizeof(acceptable)/sizeof(*acceptable)-1;

    ent = (unsigned *)get_entrophy(pw->length*sizeof(unsigned));
    if (!ent) return 0;

    for (i = 0, j = 0; i < pw->length; ++i, ++j)
    {
        unsigned x = ent[j]%s;
        pw->password[i] = acceptable[x];
    }

    pw->password[i] = '\0';

    free(ent);
    return 1;
}

int main(int argc, char **argv)
{
    password pw;
    size_t count = 0;

    pw.length = 0;

    if (argc > 1)
    {
        pw.length = strtoul(argv[1], NULL, 10);
        if (argc > 2) count = strtoul(argv[2], NULL, 10);
    }

    if (!pw.length)
    {
        char buf[20];
        fprintf(stdout, "how many characters long should the password be?: ");
        fflush(stdout);
        fgets(buf, sizeof(buf), stdin);
        pw.length = strtoul(buf, NULL, 10);
    }

    if (!count)
    {
        char buf[20];
        fprintf(stdout, "how many passwords should be generated?: ");
        fflush(stdout);
        fgets(buf, sizeof(buf), stdin);
        count = strtoul(buf, NULL, 10);
    }

    fprintf(stdout, "\n");

    init_password(&pw);

    for (; count > 0; --count)
    {
        if (!gen_password(&pw))
        {
            fprintf(stderr, "unable to generate password!\n");
            destroy_memory(pw.password, pw.length);
            return 1;
        }

        fprintf(stdout, "%s\n", pw.password);
    }

    destroy_memory(pw.password, pw.length);

#ifdef _WIN32
    fflush(stdout);
    getchar();
#endif /* _WIN32 */

    return 0;
}
