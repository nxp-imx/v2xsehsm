
cmake_minimum_required (VERSION 3.4)

project (libv2xhsm)

set (v2xhsm_VERSION 1.0.0)

include(GenerateExportHeader)
include(CMakePackageConfigHelpers)

find_package(hsmstub REQUIRED)

add_library (v2xhsm
	src/adaptlib.c
	src/nvm.c
	)

target_link_libraries(v2xhsm
	hsmstub
	)

target_include_directories (v2xhsm PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include/v2xhsm>
	)

set_target_properties (v2xhsm
	PROPERTIES PUBLIC_HEADER "include/v2xSe.h;include/v2xSeCommTypes.h"
	)

install (TARGETS v2xhsm
	EXPORT v2xhsmTargets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/v2xhsm
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/v2xhsm
	)

write_basic_package_version_file (
	"${CMAKE_CURRENT_BINARY_DIR}/v2xhsmConfigVersion.cmake"
	VERSION ${v2xhsm_VERSION}
	COMPATIBILITY AnyNewerVersion
	)

export (EXPORT v2xhsmTargets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/v2xhsm/v2xhsmTargets.cmake"
	)

configure_file(
	${PROJECT_SOURCE_DIR}/v2xhsmConfig.cmake
	"${CMAKE_CURRENT_BINARY_DIR}/v2xhsmConfig.cmake"
	COPYONLY
	)

export(PACKAGE v2xhsm)
