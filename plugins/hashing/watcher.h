#pragma once

#include <rocksdb/db.h>
#include <sys/inotify.h>

#include <atomic>
#include <string>

class watcher {
 public:
  watcher(std::string dir, rocksdb::DB *db);
  void operator()(std::atomic<bool> &stop);

 private:
  // m_dir is the directory to watch
  std::string m_dir;
  // the current instance of db where files need to be ingested
  rocksdb::DB *m_db;
};