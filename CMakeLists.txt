
cmake_minimum_required (VERSION 3.4)

project (libv2xhsm)

add_library (v2xhsm
	src/adaptlib.c
	src/nvm.c
	)

add_library(hsmstub STATIC IMPORTED)
set_target_properties(hsmstub PROPERTIES
	IMPORTED_LOCATION "${INSTALLED_LIBRARIES}/hsmstub/libhsmstub.a"
	INTERFACE_INCLUDE_DIRECTORIES "${INSTALLED_INCLUDES}/hsmstub"
	)

target_link_libraries(v2xhsm
	hsmstub
	)

target_include_directories (v2xhsm
	PUBLIC include
	)

set_target_properties (v2xhsm
	PROPERTIES PUBLIC_HEADER "include/v2xSe.h;include/v2xSeCommTypes.h"
	)

install (TARGETS v2xhsm
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/v2xhsm
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/v2xhsm
	)
