cmake_minimum_required(VERSION 3.24)

project(usbpcap LANGUAGES C RC)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_subdirectory(USBPcapCMD)
