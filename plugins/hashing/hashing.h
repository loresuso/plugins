#pragma once

#include <falcosecurity/sdk.h>
#include <rocksdb/db.h>

#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "lru_cache.h"

constexpr int plugin_id = 999;

class hashing_instance : public falcosecurity::event_sourcer::instance {
 public:
  hashing_instance(const std::string& sst_dir);
  ~hashing_instance();
  ss_plugin_rc next(const falcosecurity::event_sourcer* p,
                    ss_plugin_event* evt) override;

 private:
  std::string m_sst_dir;
  std::mutex m_mtx;
  // m_db is the database containing the hash->category mappings
  rocksdb::DB* m_db;
  std::unique_ptr<std::thread> m_inotify_thread;
  std::unique_ptr<std::thread> m_execs_thread;
  std::atomic<bool> m_stop;  // todo: may be replaced with a signal
  std::queue<std::string> m_executed_files;
  std::mutex m_mutex;
  std::unique_ptr<LRUCache<std::string, std::string>> m_cache;
};

class hashing_plugin : public falcosecurity::event_sourcer,
                       public falcosecurity::field_extractor {
 public:
  void info(falcosecurity::plugin::information&) const override;
  bool init(const std::string& config) override;
  void last_error(std::string& out) const override;

  void fields(std::vector<field>& out) const override;
  bool extract(const ss_plugin_event* evt,
               ss_plugin_extract_field* field) override;

  uint32_t id() const;
  void event_source(std::string& out) const;
  std::unique_ptr<falcosecurity::event_sourcer::instance> open(
      const std::string& params) override;

 private:
  // A copy of the config provided to init()
  std::string m_config;
  // A string containing the last error the plugin encountered
  std::string m_lasterr;
};