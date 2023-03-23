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
  LRUCache<unsigned long, std::string> cache(2);
  cache.put(3, "c");
  cache.put(1, "a");
  cache.put(2, "b");
  std::cout << "value 3: " << cache.get(3) << std::endl;
  std::cout << "value 1: " << cache.get(1) << std::endl;
  m_config = config;
  return true;
}

void hashing_plugin::last_error(std::string& out) const { out = m_lasterr; }

void hashing_plugin::fields(
    std::vector<falcosecurity::field_extractor::field>& out) const {
  falcosecurity::field_extractor::field f;
  f.name = "example.count";
  f.type = FTYPE_UINT64;
  f.description = "some desc";
  f.display = "some display";
  out.clear();
  out.push_back(f);
}

bool hashing_plugin::extract(const ss_plugin_event* evt,
                             ss_plugin_extract_field* field) {
  field->res.u64 = (uint64_t*)evt->data;
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
}

hashing_instance::~hashing_instance() {
  // Stop the watcher
  m_stop = true;
  m_inotify_thread->join();

  // Delete DB
  delete m_db;
}

ss_plugin_rc hashing_instance ::next(const falcosecurity::event_sourcer* p,
                                     ss_plugin_event* evt) {
  m_count++;
  evt->data = (uint8_t*)&m_count;
  evt->datalen = sizeof(uint64_t);
  // std::cout << m_count << std::endl;
  return SS_PLUGIN_SUCCESS;
}
