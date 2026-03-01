cmake_minimum_required(VERSION 3.16)
project(GelHook C CXX)

option(GELHOOK_BUILD_EXAMPLES "Build examples" ON)

add_library(gelhook INTERFACE)
target_include_directories(gelhook INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(gelhook INTERFACE c_std_99)

if (GELHOOK_BUILD_EXAMPLES)
  add_executable(gh_example_basic examples/basic.c)
  target_link_libraries(gh_example_basic PRIVATE gelhook)

  add_executable(gh_example_bp examples/breakpoint.c)
  target_link_libraries(gh_example_bp PRIVATE gelhook)

  add_executable(gh_example_rehook examples/rehook.c)
  target_link_libraries(gh_example_rehook PRIVATE gelhook)

  add_executable(gh_example_vtable examples/vtable.cpp)
  target_link_libraries(gh_example_vtable PRIVATE gelhook)

  add_executable(gh_example_site examples/site_hook.c)
  target_link_libraries(gh_example_site PRIVATE gelhook)

  add_executable(gh_example_vtable_swap examples/vtable_swap.cpp)
  target_link_libraries(gh_example_vtable_swap PRIVATE gelhook)

  add_executable(gh_example_manager examples/manager.c)
  target_link_libraries(gh_example_manager PRIVATE gelhook)

  if (WIN32)
    target_link_libraries(gh_example_basic PRIVATE dbghelp)
    target_link_libraries(gh_example_bp PRIVATE dbghelp)
    target_link_libraries(gh_example_rehook PRIVATE dbghelp)
    target_link_libraries(gh_example_vtable PRIVATE dbghelp)
    target_link_libraries(gh_example_site PRIVATE dbghelp)
    target_link_libraries(gh_example_vtable_swap PRIVATE dbghelp)
    target_link_libraries(gh_example_manager PRIVATE dbghelp)

    add_executable(gh_example_iat examples/iat.c)
    target_link_libraries(gh_example_iat PRIVATE gelhook dbghelp)

    add_executable(gh_example_hw_bp examples/hw_breakpoint.c)
    target_link_libraries(gh_example_hw_bp PRIVATE gelhook dbghelp)

    add_executable(gh_example_eat examples/eat.c)
    target_link_libraries(gh_example_eat PRIVATE gelhook dbghelp)

    add_executable(gh_example_guard examples/guard_page.c)
    target_link_libraries(gh_example_guard PRIVATE gelhook dbghelp)

    add_executable(gh_example_hotpatch examples/hotpatch.c)
    target_link_libraries(gh_example_hotpatch PRIVATE gelhook dbghelp)
  else()
    add_executable(gh_example_plt examples/plt.c)
    target_link_libraries(gh_example_plt PRIVATE gelhook dl)
  endif()

  if (UNIX AND NOT APPLE)
    target_compile_definitions(gh_example_basic PRIVATE _GNU_SOURCE)
    target_compile_definitions(gh_example_bp PRIVATE _GNU_SOURCE)
    target_compile_definitions(gh_example_rehook PRIVATE _GNU_SOURCE)
    target_compile_definitions(gh_example_vtable PRIVATE _GNU_SOURCE)
    target_compile_definitions(gh_example_site PRIVATE _GNU_SOURCE)
    target_compile_definitions(gh_example_vtable_swap PRIVATE _GNU_SOURCE)
    target_compile_definitions(gh_example_manager PRIVATE _GNU_SOURCE)
    target_compile_definitions(gh_example_plt PRIVATE _GNU_SOURCE)
  endif()
endif()
