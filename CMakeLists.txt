
cmake_minimum_required (VERSION 3.4)

project (libv2xhsm)

set (SRC
	src/adaptlib.c
	src/nvm.c)

include_directories(include)
include_directories(../${CMAKE_INSTALL_INCLUDEDIR})

add_library (v2xhsm ${SRC})

install (TARGETS v2xhsm DESTINATION ${CMAKE_INSTALL_LIBDIR})
