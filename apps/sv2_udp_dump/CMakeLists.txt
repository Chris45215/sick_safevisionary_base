cmake_minimum_required(VERSION 3.18)
project(sv2_udp_dump LANGUAGES CXX)

# Vendor tree (the repo you built the DLL from)
set(VENDOR_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../")
set(VENDOR_SRC_DIR "${VENDOR_ROOT}/src")
set(VENDOR_INC_DIR "${VENDOR_ROOT}/include")

# Pull in ALL vendor .cpp sources so we don't chase missing files
file(GLOB VENDOR_SRCS "${VENDOR_SRC_DIR}/*.cpp")

add_executable(sv2_udp_dump
  src/udp_dump.cpp
  ${VENDOR_SRCS}
)

# Headers live under include/sick_safevisionary_base/...
target_include_directories(sv2_udp_dump PRIVATE
  "${VENDOR_INC_DIR}"
)

target_compile_features(sv2_udp_dump PRIVATE cxx_std_17)

# Windows needs Winsock
if (WIN32)
  target_link_libraries(sv2_udp_dump PRIVATE ws2_32)
endif()
