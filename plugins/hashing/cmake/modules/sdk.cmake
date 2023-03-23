include(FetchContent)

FetchContent_Declare(
  plugin-sdk-cpp
  GIT_REPOSITORY https://github.com/loresuso/plugin-sdk-cpp.git # todo: change here
  GIT_TAG        5e7f232eb6d7d1efdc7a4d0404c66a47b841676b # desired git tag here
)

FetchContent_MakeAvailable(plugin-sdk-cpp)

include_directories(${plugin-sdk-cpp_SOURCE_DIR}/include)
