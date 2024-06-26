cmake_minimum_required(VERSION 3.5)
project(sick_safevisionary_base)

if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  message("${PROJECT_NAME}: You did not request a specific build type: selecting 'Release'.")
  set(CMAKE_BUILD_TYPE Release)
endif()

## Add pybind11
set(pybind11_DIR C:\\Users\\sensory\\AppData\\Local\\Programs\\Python\\Python38\\lib\\site-packages\\pybind11\\share\\cmake\\pybind11)
find_package(pybind11 REQUIRED)


## System dependencies are found with CMake's conventions
# find_package(Boost REQUIRED COMPONENTS system)

###########
## Build ##
###########

## Declare a C++ library
aux_source_directory(src SRC_LIST)

add_library(${PROJECT_NAME}
  SHARED
  ${SRC_LIST}
)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_11)
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -pedantic)

target_include_directories(${PROJECT_NAME} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if(WIN32)
  target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
endif()

enable_testing()

#############
## Install ##
#############

install(TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}_targets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES DESTINATION include
)

install(
  EXPORT ${PROJECT_NAME}_targets
  DESTINATION lib/cmake/${PROJECT_NAME}
  FILE ${PROJECT_NAME}Targets.cmake
  NAMESPACE ${PROJECT_NAME}::
  )

## Mark cpp header files for installation
 install(
   DIRECTORY include/${PROJECT_NAME}/
   DESTINATION include/${PROJECT_NAME}
   FILES_MATCHING
   PATTERN "*.h"
   PATTERN "*.hpp"
 )

include(CMakePackageConfigHelpers)
write_basic_package_version_file(${PROJECT_NAME}ConfigVersion.cmake VERSION 1.0.0
  COMPATIBILITY SameMajorVersion)
install(
  FILES
    ${PROJECT_NAME}Config.cmake ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  DESTINATION
    lib/cmake/${PROJECT_NAME}
  )
