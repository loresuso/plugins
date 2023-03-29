include(FetchContent)

FetchContent_Declare(
  plugin-sdk-cpp
  GIT_REPOSITORY https://github.com/falcosecurity/plugin-sdk-cpp.git # todo: change here
  GIT_TAG        20f7c2825853eee38b9d766b3402e64d50585b71 # desired git tag here
)

FetchContent_MakeAvailable(plugin-sdk-cpp)

include_directories(${plugin-sdk-cpp_SOURCE_DIR}/include)
