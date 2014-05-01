/*_
 * Copyright 2009, 2011 Scyphus Solutions Co.,Ltd. All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id$ */

#include "config.h"

#include "pid_output.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

#ifndef HAVE_FCNTL

/*
 * Output pid file
 */
pid_t
pid_output(const char *path)
{
    FILE *fp;
    pid_t pid;
    mode_t oldumask;

    pid = getpid();

    oldumask = umask(0777 & ~LOGFILE_MASK);

    fp = fopen(path, "w");
    if ( NULL != fp ) {
        (void)flock(fileno(fp), LOCK_EX);
        fprintf(fp, "%d\n", (int) pid);
        (void)flock(fileno(fp), LOCK_UN);
        fclose(fp);
        umask(oldumask);
        return pid;
    }
    /* XXX Why do we continue instead of exiting?  This seems incompatible
       with the behavior of the fcntl version below. */
    /*zlog_warn("Can't fopen pid lock file %s (%s), continuing",
      path, safe_strerror(errno));*/
    umask(oldumask);

    return -1;
}
#else  /* HAVE_FCNTL */

/*
 * Output pid file
 */
pid_t
pid_output(const char *path)
{
  int tmp;
  int fd;
  pid_t pid;
  char buf[16];
  struct flock lock;
  mode_t oldumask;

  pid = getpid();

  oldumask = umask(0777 & ~LOGFILE_MASK);
  fd = open(path, O_RDWR | O_CREAT, LOGFILE_MASK);
  if ( fd < 0 ) {
      /*zlog_err("Can't create pid lock file %s (%s), exiting",
        path, safe_strerror(errno));*/
      umask(oldumask);
      exit(1);
  } else {
      size_t pidsize;

      umask(oldumask);
      memset(&lock, 0, sizeof(lock));

      lock.l_type = F_WRLCK;
      lock.l_whence = SEEK_SET;

      if ( fcntl(fd, F_SETLK, &lock) < 0 ) {
          /*zlog_err("Could not lock pid_file %s, exiting", path);*/
          exit(1);
      }

      sprintf (buf, "%d\n", (int) pid);
      pidsize = strlen(buf);
      if ( (tmp = write(fd, buf, pidsize)) != (int) pidsize ) {
          /*zlog_err("Could not write pid %d to pid_file %s, rc was %d: %s",
            (int)pid,path,tmp,safe_strerror(errno));*/
      } else if ( ftruncate(fd, pidsize) < 0 ) {
          /*zlog_err("Could not truncate pid_file %s to %u bytes: %s",
            path,(u_int)pidsize,safe_strerror(errno));*/
      }
  }

  return pid;
}

#endif  /* HAVE_FCNTL */

/*
 * Read pid file
 */
pid_t
pid_output_read(const char *path)
{
    FILE *fp;
    pid_t pid;

    fp = fopen (path, "r");
    if ( NULL != fp ) {
        (void)flock(fileno(fp), LOCK_SH);
        fscanf(fp, "%d", &pid);
        (void)flock(fileno(fp), LOCK_UN);
        fclose(fp);
        return pid;
    }

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
