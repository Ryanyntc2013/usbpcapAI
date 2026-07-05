set(USBPCAPCMD_SOURCES
    USBPcapCMD.rc
    cmd.c
    descriptors.c
    enum.c
    filters.c
    getopt.c
    iocontrol.c
    roothubs.c
    thread.c
)

add_executable(USBPcapCap WIN32 ${USBPCAPCMD_SOURCES})

target_include_directories(USBPcapCap PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/USBPcapDriver/include
)

target_link_libraries(USBPcapCap PRIVATE
    hid
    setupapi
    comdlg32
    advapi32
    cfgmgr32
    shell32
    shlwapi
)

if(MSVC)
    target_compile_definitions(USBPcapCap PRIVATE _CRT_NON_CONFORMING_SWPRINTFS)
    target_compile_options(USBPcapCap PRIVATE /W3)
    target_link_options(USBPcapCap PRIVATE "/MANIFESTUAC:level='asInvoker' uiAccess='false'")
endif()

set_target_properties(USBPcapCap PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
