#pragma once

#include <atomic>
#include <mutex>
#include <queue>
#include <string>

void exec_watcher(const std::string &dir, std::atomic<bool> &stop,
                  std::queue<std::string> &executed_files, std::mutex &mtx);