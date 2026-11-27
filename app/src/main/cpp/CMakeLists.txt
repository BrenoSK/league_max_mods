cmake_minimum_required(VERSION 3.22)
project(lmx CXX)
set(CMAKE_CXX_STANDARD 17)

add_library(core SHARED core.cpp)
target_compile_definitions(core PRIVATE AS_LIB)
target_link_libraries(core log android EGL GLESv2 dl)

add_executable(injector core.cpp)
target_compile_definitions(injector PRIVATE AS_INJECTOR)
target_link_libraries(injector log dl)
set_target_properties(injector PROPERTIES SUFFIX ".so" OUTPUT_NAME "libinjector")