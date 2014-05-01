/*_
 * Copyright 2012 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "config.h"
#include "str.h"
#include <string.h>
#include <ctype.h>

/*
 * Trim right-side whitespaces
 */
void
str_rtrim(char *str)
{
    size_t len;
    size_t rptr;

    len = strlen(str);
    rptr = len - 1;

    while ( rptr >= 0 ) {
        if ( isspace(str[rptr]) ) {
            str[rptr] = '\0';
        } else {
            break;
        }
        rptr--;
    }
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
