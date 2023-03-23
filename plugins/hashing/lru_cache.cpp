#include "lru_cache.h"

template <class key_t, class value_t>
value_t LRUCache<key_t, value_t>::get(const key_t &key) {
  auto found_iter = m_map.find(key);
  if (found_iter == m_map.end()) {  // cache miss
    return value_t();
  }

  // cache hit, move key to front
  m_list.splice(m_list.begin(), m_list, found_iter->second);

  // return value of the node
  return found_iter->second->second;
}

template <class key_t, class value_t>
void LRUCache<key_t, value_t>::put(key_t key, value_t value) {
  auto found_iter = m_map.find(key);
  if (found_iter != m_map.end()) {  // key exists
    // move key to front
    m_list.splice(m_list.begin(), m_list, found_iter->second);

    // update value
    found_iter->second->second = value;

    return;
  }

  if (m_map.size() == m_capacity) {  // reached capacity
    int key_to_del = m_list.back().first;

    // remove node in list;
    m_list.pop_back();

    // remove key in map
    m_map.erase(key_to_del);
  }

  // create new node in list, front position
  m_list.emplace_front(key, value);

  // create new node in map
  m_map[key] = m_list.begin();
}
