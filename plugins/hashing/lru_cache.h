#pragma once

#include <cstddef>
#include <list>
#include <string>
#include <unordered_map>

template <class key_t, class value_t>
class LRUCache {
 public:
  typedef
      typename std::list<std::pair<key_t, value_t>>::iterator list_iterator_t;
  LRUCache(int capacity) : m_capacity(capacity) {}
  value_t get(const key_t &key);
  void put(key_t key, value_t value);

 private:
  size_t m_capacity;
  std::unordered_map<key_t, list_iterator_t> m_map;
  std::list<std::pair<key_t, value_t>> m_list;
};

// Explicit instatiation
template class LRUCache<unsigned long, std::string>;