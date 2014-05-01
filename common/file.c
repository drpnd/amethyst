/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: file.c,v 3d84dd1f2cba 2011/07/13 10:06:38 Hirochika $ */

#include "config.h"
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>		/* For BLKGETSIZE */
#endif
#if TARGET_DARWIN
#include <sys/disk.h>
#endif

/*
 * Check whether the specified file exists or not
 */
int
file_exists(const char *filename)
{
    FILE *fp;

    fp = fopen(filename, "r");
    if ( NULL == fp ) {
        return -1;
    }
    fclose(fp);

    return 0;

#if 0
    struct stat statbuf;

    if ( 0 != stat(filename, &statbuf) ) {
        if ( ENOENT == errno ) {
            /* File does not exist. */
            return -1;
        } else {
            return -1;
        }
    }

    return 0;
#endif
}

/*
 * Detect the size to be exported
 */
off_t
file_detectsize(const char *fname)
{
    int fd;
    off_t off;
    struct stat stat;
    int err;

    /* Open the target file */
    fd = open(fname, O_RDONLY);
    if ( fd < 0 ) {
        return 0;
    }

#ifdef HAVE_SYS_MOUNT_H
#ifdef HAVE_SYS_IOCTL_H
#ifdef BLKGETSIZE64
    uint64_t blks;

    /* Looking for export size with ioctl BLKGETSIZE64 */
    if ( 0 == ioctl(fd, BLKGETSIZE64, &blks) && blks ) {
        (void)close(fd);
        return (off_t)blks;
    }
#endif /* BLKGETSIZE64 */
#endif /* HAVE_SYS_IOCTL_H */
#endif /* HAVE_SYS_MOUNT_H */

#if TARGET_DARWIN
#ifdef DKIOCGETBLOCKSIZE
#ifdef DKIOCGETBLOCKCOUNT
    uint32_t d_blks;
    uint64_t d_blkc;

    /* Get block size and block count */
    if ( 0 == ioctl(fd, DKIOCGETBLOCKSIZE, &d_blks) && d_blks ) {
        if ( 0 == ioctl(fd, DKIOCGETBLOCKCOUNT, &d_blkc) && d_blkc ) {
            (void)close(fd);
            return (off_t)d_blks * d_blkc;
        }
    }
#endif /* DKIOCGETBLOCKCOUNT */
#endif /* DKIOCGETBLOCKSIZE */
#endif /* TARGET_DARWIN */

    /* Looking for the size with fstat */
    stat.st_size = 0;
    err = fstat(fd, &stat);
    if ( !err ) {
        if ( stat.st_size > 0 ) {
            /* Could get the size */
            (void)close(fd);
            return (off_t)stat.st_size;
        }
    } else {
        /* Fstat failed */
    }

    /* Looking for the size with lseek SEEK_END */
    off = lseek(fd, (off_t)0, SEEK_END);
    if ( off >= ((off_t)0) ) {
        /* Could get the size */
        (void)close(fd);
        return off;
    } else {
        /* Lseek failed */
    }

    (void)close(fd);

    /* Could not detect the size */
    return -1;
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
