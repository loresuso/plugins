/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* Reference "dummy" plugin, similar to the dummy plugin, but written
 * in C++. It uses the C++ sdk ../../sdk/cpp/falcosecurity_plugin.h
 * and implements classes that derive from
 * falcosecurity::source_plugin and falcosecurity::plugin_instance. */

#include "hashing.h"

#include <rocksdb/db.h>
#include <stdio.h>
#include <stdlib.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "exec_watcher.h"  // todo: just remove it
#include "hash_calculator.h"
#include "lru_cache.h"
#include "nlohmann/json.hpp"
#include "utils.h"
#include "watcher.h"

using ROCKSDB_NAMESPACE::DB;

using json = nlohmann::json;

void hashing_plugin::info(falcosecurity::plugin::information& out) const {
  out.name = "hashing";
  out.description = "Sample of hashing plugin";
  out.contact = "https://github.com/falcosecurity/plugins";
  out.version = "0.1.0";
}

bool hashing_plugin::init(const std::string& config) {
  m_config = config;
  return true;
}

void hashing_plugin::last_error(std::string& out) const { out = m_lasterr; }

void hashing_plugin::fields(
    std::vector<falcosecurity::field_extractor::field>& out) const {
  falcosecurity::field_extractor::field f;
  f.name = "hashing.has_match";
  f.type = FTYPE_UINT64;
  f.description = "some desc";
  f.display = "some display";
  out.clear();
  out.push_back(f);
}

bool hashing_plugin::extract(const ss_plugin_event* evt,
                             ss_plugin_extract_field* field) {
  hashing_event* e = (hashing_event*)evt->data;
  std::string category;
  rocksdb::Status status =
      e->db->Get(rocksdb::ReadOptions(), e->hash, &category);
  if (status.ok() && !category.empty()) {
    e->res = 1;
  } else {
    e->res = 0;
  }
  field->res.u64 = (uint64_t*)e->res;
  field->res_len = 1;
  return true;
}

uint32_t hashing_plugin::id() const { return plugin_id; }

void hashing_plugin::event_source(std::string& out) const { out = "hashing"; }

std::unique_ptr<falcosecurity::event_sourcer::instance> hashing_plugin::open(
    const std::string& params) {
  return std::unique_ptr<falcosecurity::event_sourcer::instance>(
      new hashing_instance("/tmp/sst_test"));
}

hashing_instance::hashing_instance(const std::string& sst_dir)
    : m_sst_dir(sst_dir) {
  std::vector<std::string> sst_files;

  for (const auto& entry : std::filesystem::directory_iterator(m_sst_dir)) {
    if (!entry.is_regular_file()) {
      continue;
    }

    if (ends_with(entry.path(), ".sst")) {
      sst_files.push_back(entry.path());
    }
  }

  // Open the RocksDB database
  std::filesystem::remove_all("/tmp/falco-hashing-db");
  rocksdb::Options options;
  options.IncreaseParallelism();
  options.OptimizeLevelStyleCompaction();
  options.create_if_missing = true;

  rocksdb::Status status =
      rocksdb::DB::Open(options, "/tmp/falco-hashing-db", &m_db);
  if (!status.ok()) {
    throw std::runtime_error("cannot open RocksDB database: " +
                             status.ToString());
  }

  // Ingest .sst files
  status =
      m_db->IngestExternalFile(sst_files, rocksdb::IngestExternalFileOptions());
  if (!status.ok()) {
    throw std::runtime_error("cannot ingest external files: " +
                             status.ToString());
  }

  // Start watching dir for new .sst files
  m_stop = false;
  watcher w("/tmp/sst_test", m_db);
  m_inotify_thread = std::make_unique<std::thread>(w, std::ref(m_stop));

  // Start getting notification about which files are executed
  m_execs_thread = std::make_unique<std::thread>(
      exec_watcher, "/", std::ref(m_stop), std::ref(m_executed_files),
      std::ref(m_mutex));

  // Init cache
  m_cache = std::make_unique<LRUCache<std::string, std::string>>(1000);
}

hashing_instance::~hashing_instance() {
  // Stop the watcher
  m_stop = true;
  m_inotify_thread->join();
  m_execs_thread->join();

  // Delete DB
  delete m_db;
}

ss_plugin_rc hashing_instance::next(const falcosecurity::event_sourcer* p,
                                    ss_plugin_event* evt) {
  std::string file;

  m_mutex.lock();
  if (!m_executed_files.empty()) {
    file = m_executed_files.front();
    m_executed_files.pop();
  }
  m_mutex.unlock();

  if (file.empty()) return SS_PLUGIN_TIMEOUT;

  // Try to get file from cache
  std::string hash;
  int64_t res;
  try {
    hash = m_cache->get(file);
  } catch (std::range_error e) {
    hash_calculator hc;
    res = hc.checksum(file, hash_calculator::HT_SHA256, &hash);
    if (!res) {
      m_cache->put(file, hash);
      std::cout << "new file " + file << std::endl;
    } else {
      return SS_PLUGIN_FAILURE;
    }
  }

  m_event.res = res;
  m_event.hash = hash;

  // Generate the event
  evt->data = (uint8_t*)&m_event;
  evt->datalen = sizeof(m_event);

  return SS_PLUGIN_SUCCESS;
}
