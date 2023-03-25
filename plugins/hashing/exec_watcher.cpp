#include "exec_watcher.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>

// todo: this code is just used for the PoC, to get which files are executed

void exec_watcher(const std::string &dir, std::atomic<bool> &stop,
                  std::queue<std::string> &executed_files, std::mutex &mtx) {
  int fan;
  int mount_fd, event_fd;
  char buf[4096];
  char fdpath[32];
  char path[PATH_MAX + 1];
  struct file_handle *file_handle;

  ssize_t buflen, linklen;
  struct fanotify_event_metadata *metadata;
  struct fanotify_event_info_fid *fid;

  mount_fd = open(dir.c_str(), O_DIRECTORY | O_RDONLY);
  if (mount_fd == -1) {
    perror(dir.c_str());
    exit(EXIT_FAILURE);
  }

  fan = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID, O_RDWR);
  if (fan == -1) {
    perror("fanotify_init");
    exit(EXIT_FAILURE);
  }

  int ret = fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC,
                          AT_FDCWD, dir.c_str());
  if (ret == -1) {
    perror("fanotify_mark");
    exit(EXIT_FAILURE);
  }

  while (!stop.load()) {
    buflen = read(fan, buf, sizeof(buf));
    metadata = (struct fanotify_event_metadata *)&buf;

    for (; FAN_EVENT_OK(metadata, buflen);
         metadata = FAN_EVENT_NEXT(metadata, buflen)) {
      fid = (struct fanotify_event_info_fid *)(metadata + 1);
      file_handle = (struct file_handle *)fid->handle;

      /* Ensure that the event info is of the correct type */

      if (fid->hdr.info_type != FAN_EVENT_INFO_TYPE_FID) {
        fprintf(stderr, "Received unexpected event info type.\n");
        exit(EXIT_FAILURE);
      }

      event_fd = open_by_handle_at(mount_fd, file_handle, O_RDONLY);
      if (event_fd == -1) {
        if (errno == ESTALE) {
          printf(
              "File handle is no longer valid. "
              "File has been deleted\n");
          continue;
        } else {
          perror("open_by_handle_at");
          exit(EXIT_FAILURE);
        }
      }

      sprintf(fdpath, "/proc/self/fd/%d", event_fd);
      linklen = readlink(fdpath, path, sizeof(path) - 1);
      if (linklen == -1) {
        perror("readlink");
      }
      path[linklen] = '\0';

      mtx.lock();
      executed_files.push(std::string(path));
      mtx.unlock();

      close(metadata->fd);
      close(event_fd);
      metadata = FAN_EVENT_NEXT(metadata, buflen);
    }
  }
}