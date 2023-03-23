#pragma once

#include <string>

class hash_calculator {
 public:
  enum hash_type {
    HT_MD5,
    HT_SHA256,
  };

  int64_t checksum(const std::string &filename, hash_type type,
                   std::string *hash);
};