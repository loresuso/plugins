#include "watcher.h"

#include <errno.h>
#include <limits.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <thread>
#include <vector>

#include "utils.h"

constexpr size_t max_inotify_events_per_read = 10;
constexpr size_t buf_len =
    max_inotify_events_per_read * (sizeof(struct inotify_event) + NAME_MAX + 1);
constexpr int timeout = 1000;

watcher::watcher(std::string dir, rocksdb::DB *db) : m_dir(dir), m_db(db) {}

void watcher::operator()(std::atomic<bool> &stop) {
  // Initialize inotify
  int inotify_fd = inotify_init();
  if (inotify_fd == -1) {
    throw std::runtime_error("cannot initialize inotify watcher: " +
                             std::string(std::strerror(errno)));
  }

  // Get notifications about every new file that was opened for write and then
  // closed
  int watch_fd =
      inotify_add_watch(inotify_fd, m_dir.c_str(),
                        IN_CLOSE_WRITE);  // todo: check how to catch rename
  if (watch_fd == -1) {
    std::cout << errno << std::endl;
    throw std::runtime_error("cannot watch " + m_dir + ": " +
                             std::string(std::strerror(errno)));
  }

  int epoll_fd = epoll_create(1);
  if (epoll_fd == -1) {
    throw std::runtime_error("cannot create epoll fd " +
                             std::string(std::strerror(errno)));
  }

  epoll_event ev;
  ev.events = EPOLLIN;
  int res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev);
  if (res == -1) {
    throw std::runtime_error("cannot add fd with epoll_ctl" +
                             std::string(std::strerror(errno)));
  }

  ssize_t n;
  char buf[buf_len];
  while (!stop.load()) {
    res = epoll_wait(epoll_fd, &ev, 1, timeout);
    if (res == 0) {  // no ready file descriptors, timeout reached
      continue;
    } else if (res == -1) {
      throw std::runtime_error("epoll_wait error" +
                               std::string(std::strerror(errno)));
    }

    n = read(inotify_fd, buf, buf_len);
    if (n == -1) {
      throw std::runtime_error("cannot read inotify events " +
                               std::string(std::strerror(errno)));
    }

    // Get all new files
    std::vector<std::string> new_sst_files;
    for (char *p = buf; p < buf + n;) {
      inotify_event *inotify_event = (struct inotify_event *)p;
      std::string fullpath = m_dir + "/" + std::string(inotify_event->name);
      if (ends_with(fullpath, ".sst")) {
        new_sst_files.push_back(fullpath);
      }

      p += sizeof(struct inotify_event) + inotify_event->len;
    }

    // Let the database ingest them
    // todo what about synchronization here?
    std::cout << "ingesting external file" << std::endl;
    rocksdb::Status status = m_db->IngestExternalFile(
        new_sst_files, rocksdb::IngestExternalFileOptions());
    if (!status.ok()) {
      // todo: how to properly log?
      std::cout << "unable to ingest files: " << status.ToString() << std::endl;
    }
  }

  close(epoll_fd);
  inotify_rm_watch(inotify_fd, watch_fd);
  close(watch_fd);
  close(inotify_fd);
}
