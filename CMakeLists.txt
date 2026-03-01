cmake_minimum_required(VERSION 3.16)
project(GelHook C CXX)

option(GELHOOK_BUILD_EXAMPLES "Build examples" ON)

add_library(gelhook INTERFACE)
target_include_directories(gelhook INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(gelhook INTERFACE c_std_99)

if (GELHOOK_BUILD_EXAMPLES)
  add_executable(gh_example_basic examples/basic.c)
  target_compile_definitions(gh_example_basic PRIVATE GELHOOK_IMPLEMENTATION)
  target_link_libraries(gh_example_basic PRIVATE gelhook)

  add_executable(gh_example_bp examples/breakpoint.c)
  target_compile_definitions(gh_example_bp PRIVATE GELHOOK_IMPLEMENTATION)
  target_link_libraries(gh_example_bp PRIVATE gelhook)

  add_executable(gh_example_rehook examples/rehook.c)
  target_compile_definitions(gh_example_rehook PRIVATE GELHOOK_IMPLEMENTATION)
  target_link_libraries(gh_example_rehook PRIVATE gelhook)

  add_executable(gh_example_vtable examples/vtable.cpp)
  target_compile_definitions(gh_example_vtable PRIVATE GELHOOK_IMPLEMENTATION)
  target_link_libraries(gh_example_vtable PRIVATE gelhook)

  if (WIN32)
    add_executable(gh_example_iat examples/iat.c)
    target_compile_definitions(gh_example_iat PRIVATE GELHOOK_IMPLEMENTATION)
    target_link_libraries(gh_example_iat PRIVATE gelhook dbghelp)

    add_executable(gh_example_hw_bp examples/hw_breakpoint.c)
    target_compile_definitions(gh_example_hw_bp PRIVATE GELHOOK_IMPLEMENTATION)
    target_link_libraries(gh_example_hw_bp PRIVATE gelhook)
  else()
    add_executable(gh_example_plt examples/plt.c)
    target_compile_definitions(gh_example_plt PRIVATE GELHOOK_IMPLEMENTATION)
    target_link_libraries(gh_example_plt PRIVATE gelhook dl)
  endif()
endif()
