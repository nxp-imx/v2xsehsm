
cmake_minimum_required (VERSION 3.4)

project (libv2xsehsm)

include(GenerateExportHeader)
include(CMakePackageConfigHelpers)

set (v2xsehsm_MAJOR 0)
set (v2xsehsm_MINOR 3)
set (v2xsehsm_PATCH 0)
set (v2xsehsm_VERSION ${v2xsehsm_MAJOR}.${v2xsehsm_MINOR}.${v2xsehsm_PATCH})

configure_file (
	${PROJECT_SOURCE_DIR}/version.h.in
	${CMAKE_CURRENT_SOURCE_DIR}/include/version.h
	)

add_library (v2xCrypto SHARED
	src/v2xsehsm.c
	src/nvm.c
	src/keymanagement.c
	src/signature.c
	src/sm2_eces.c
	src/ecies.c
	src/datastorage.c
	src/utility.c
	src/keyimport.c
	src/trace.c
	src/cipher.c
	)

target_link_libraries(v2xCrypto
	${SECO_LIBS_DIR}/hsm_lib.a
	)

target_include_directories(v2xCrypto PRIVATE
	${SECO_LIBS_DIR}/include/
	${LTTNG_DIR}/include/
	${URCU_DIR}/include/
	)

target_include_directories (v2xCrypto PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include/v2xsehsm>
	)

set_target_properties (v2xCrypto PROPERTIES
	PUBLIC_HEADER "include/v2xSe.h"
	VERSION ${v2xsehsm_VERSION}
	SOVERSION ${v2xsehsm_MAJOR}
	)

target_compile_options(v2xCrypto PRIVATE -Werror -Wall ${TRACE_SETTING})

configure_file(
	${PROJECT_SOURCE_DIR}/Doxyfile.in
	${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
	@ONLY
	)

add_custom_target(doc
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND doxygen Doxyfile
	COMMAND make -C doxygen/latex pdf
	COMMAND mv doxygen/latex/refman.pdf v2xsehsm_api_manual.pdf
	VERBATIM)

install (TARGETS v2xCrypto
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
