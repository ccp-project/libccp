cmake_minimum_required(VERSION 3.10)

project("libccp" VERSION 1.0.0 LANGUAGES CXX C)

# set of headers that user of this lib would need to import
set(LIBCCP_PUBLIC_HEADERS
  ccp.h
  types.h
  ccp_error.h
)

# all source files
set(LIBCCP_SRCS
  ccp.c
  serialize.c
  machine.c
  ccp_priv.c
)

# create shared library
add_library (ccp          SHARED ${LIBCCP_PUBLIC_HEADERS} ${LIBCCP_SRCS})
target_include_directories (ccp        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
# create static library
add_library (ccp_static   STATIC ${LIBCCP_PUBLIC_HEADERS} ${LIBCCP_SRCS})
target_include_directories (ccp_static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

# needed for configure_package_config_File
include(CMakePackageConfigHelpers)

# NOTE: PROJECT_BINARY_DIR is the build directory (eg. <...>/libccp/build)

# where .so and .a will be installed
set(LIBCCP_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
# where public .h files will be installed
set(LIBCCP_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include/ccp)
# where cmake generated will be installed (for calling lib to access)
set(LIBCCP_CMAKE_DIR ${LIBCCP_LIB_DIR}/cmake/libccp)
# compiled version of cmake/libccp-config.cmake.in
set(project_config ${PROJECT_BINARY_DIR}/libccp-config.cmake)

# install both the shared and static versions
set(INSTALL_TARGETS ccp ccp_static)
set(targets_export_name libccp-targets)

# compile ./cmake/libccp-config.cmake.in and output to <build>/libccp-config.cmake
# then install to <install_prefix>/lib/cmake/libccp
configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/libccp-config.cmake.in
    ${project_config}
    INSTALL_DESTINATION ${LIBCCP_CMAKE_DIR})

# create the libccp-targets.cmake file
export(TARGETS ${INSTALL_TARGETS} NAMESPACE libccp::
    FILE ${PROJECT_BINARY_DIR}/${targets_export_name}.cmake)

# install the libccp-config.cmake file
install(FILES ${project_config} DESTINATION ${LIBCCP_CMAKE_DIR})
# install the libccp-targets.cmake file
install(EXPORT ${targets_export_name} DESTINATION ${LIBCCP_CMAKE_DIR} NAMESPACE libccp::)
# install the actual lib files
install(TARGETS ${INSTALL_TARGETS} EXPORT ${targets_export_name}
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
# install the headers
install(FILES ${LIBCCP_PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/ccp/)

# build unit test executable, which links against the shared library
add_executable (unittest unittest.c)
target_link_libraries (unittest LINK_PUBLIC ccp)
