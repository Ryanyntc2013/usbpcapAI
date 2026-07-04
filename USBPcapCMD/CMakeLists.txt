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

add_executable(USBPcapCMD WIN32 ${USBPCAPCMD_SOURCES})

target_include_directories(USBPcapCMD PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/USBPcapDriver/include
)

target_link_libraries(USBPcapCMD PRIVATE
    hid
    setupapi
    comdlg32
    advapi32
    cfgmgr32
    shell32
    shlwapi
)

if(MSVC)
    target_compile_definitions(USBPcapCMD PRIVATE _CRT_NON_CONFORMING_SWPRINTFS)
    target_compile_options(USBPcapCMD PRIVATE /W3)
    target_link_options(USBPcapCMD PRIVATE "/MANIFESTUAC:level='asInvoker' uiAccess='false'")
endif()

set_target_properties(USBPcapCMD PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
