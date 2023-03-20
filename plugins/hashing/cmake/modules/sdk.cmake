message("fetching sdk")

file(DOWNLOAD https://raw.githubusercontent.com/falcosecurity/plugin-sdk-cpp/52296e3a46d328791f61459e7be85ef00e44e786/include/plugin_info.h ${CMAKE_BINARY_DIR}/sdk/plugin_info.h)

file(DOWNLOAD https://raw.githubusercontent.com/falcosecurity/plugin-sdk-cpp/52296e3a46d328791f61459e7be85ef00e44e786/include/falcosecurity_plugin.h ${CMAKE_BINARY_DIR}/sdk/falcosecurity_plugin.h)

include_directories(${CMAKE_BINARY_DIR}/sdk)