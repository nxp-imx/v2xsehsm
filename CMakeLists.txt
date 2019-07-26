
cmake_minimum_required (VERSION 3.4)

project (libv2xsehsm)

include(GenerateExportHeader)
include(CMakePackageConfigHelpers)

set (v2xsehsm_MAJOR 1)
set (v2xsehsm_MINOR 0)
set (v2xsehsm_PATCH 0)
set (v2xsehsm_VERSION ${v2xsehsm_MAJOR}.${v2xsehsm_MINOR}.${v2xsehsm_PATCH})

find_package(hsmstub REQUIRED)

add_library (v2xsehsm SHARED
	src/v2xsehsm.c
	src/nvm.c
	)

target_link_libraries(v2xsehsm
	hsmstub
	)

target_include_directories (v2xsehsm PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include/v2xsehsm>
	)

set_target_properties (v2xsehsm PROPERTIES
	PUBLIC_HEADER "include/v2xSe.h;include/v2xSeCommTypes.h"
	VERSION ${v2xsehsm_VERSION}
	SOVERSION ${v2xsehsm_MAJOR}
	)

install (TARGETS v2xsehsm
	EXPORT v2xsehsmTargets
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/v2xsehsm
	)

write_basic_package_version_file (
	"${CMAKE_CURRENT_BINARY_DIR}/v2xsehsmConfigVersion.cmake"
	VERSION ${v2xsehsm_VERSION}
	COMPATIBILITY AnyNewerVersion
	)

export (EXPORT v2xsehsmTargets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/v2xsehsm/v2xsehsmTargets.cmake"
	)

install (FILES
	${PROJECT_SOURCE_DIR}/v2xsehsmConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/v2xsehsm/v2xsehsmTargets.cmake
	${CMAKE_CURRENT_BINARY_DIR}/v2xsehsmConfigVersion.cmake
	DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/share/cmake/v2xsehsm
	)
