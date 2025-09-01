cmake_minimum_required(VERSION 3.18)
project(sv2_udp_dump LANGUAGES CXX)

# Point CMake at the repo-local install (no system install needed)
list(PREPEND CMAKE_PREFIX_PATH
  "${CMAKE_CURRENT_LIST_DIR}/../../external/sv2/win64/install")

find_package(sick_safevisionary_base REQUIRED)

add_executable(sv2_udp_dump src/udp_dump.cpp)
target_link_libraries(sv2_udp_dump PRIVATE sick_safevisionary_base::sick_safevisionary_base)
target_compile_features(sv2_udp_dump PRIVATE cxx_std_17)

# Copy the DLL next to the EXE after build (self-contained runtime)
add_custom_command(TARGET sv2_udp_dump POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "$<TARGET_FILE:sick_safevisionary_base::sick_safevisionary_base>"
    "$<TARGET_FILE_DIR:sv2_udp_dump>")
