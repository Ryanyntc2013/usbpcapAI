/*
 * Copyright (c) 2013 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef USBPCAP_CMD_THREAD_H
#define USBPCAP_CMD_THREAD_H

#include <windows.h>
#include "USBPcap.h"

#define USBPCAP_STORE_MODE_IMMEDIATE 0
#define USBPCAP_STORE_MODE_ON_MATCH  1

#define USBPCAP_TRANSFER_FILTER_UNSPECIFIED 0xFF

struct app_capture_filter
{
    BOOLEAN enabled;
    BOOLEAN has_vendor_id;
    BOOLEAN has_product_id;
    BOOLEAN has_endpoint;
    BOOLEAN has_transfer_type;
    USHORT vendor_id;
    USHORT product_id;
    UCHAR endpoint;
    UCHAR transfer_type;
};

struct device_metadata
{
    BOOLEAN present;
    USHORT vendor_id;
    USHORT product_id;
};

struct inject_descriptors
{
    void *descriptors;   /* Packets to inject after pcap header on capture start */
    int descriptors_len; /* inject_packets length in bytes */

    /* Buffer to keep track of pcap data read from driver. Once it is filled, the magic
     * and DLT is checked and if it matches, the the inject_packets are written after
     * the header and then the normal capture continues.
     */
    unsigned char buf[sizeof(pcap_hdr_t)];
    int buf_written;
};

struct thread_data
{
    char *device;   /* Filter device object name */
    char *filename; /* Output filename */
    char *address_list; /* Comma separated list with addresses of device to capture. */
    USBPCAP_ADDRESS_FILTER filter; /* Addresses that should be filtered */
    BOOLEAN capture_all; /* TRUE if all devices should be captured despite address_list. */
    BOOLEAN capture_new; /* TRUE if we should automatically capture from new devices. */
    UINT32 snaplen; /* Snapshot length */
    UINT32 bufferlen; /* Internal kernel-mode buffer size */
    volatile BOOL process; /* FALSE if thread should stop */
    HANDLE read_handle; /* Handle to read data from. */
    HANDLE write_handle; /* Handle to write data to. */
    HANDLE job_handle; /* Handle to job object of worker process. */
    HANDLE worker_process_thread; /* Handle to breakaway worker process main thread. */
    HANDLE exit_event; /* Handle to event that indicates that main thread should exit. */

    BOOLEAN inject_descriptors; /* TRUE if descriptors should be injected into capture. */
    struct inject_descriptors descriptors;

    UINT32 duration_seconds; /* Capture duration in seconds, 0 means unlimited. */
    UINT32 store_mode; /* USBPCAP_STORE_MODE_* */
    BOOLEAN triggered; /* TRUE if capture storage has started. */
    BOOLEAN output_created; /* TRUE if output file was created/written. */
    ULONG dropped_packets; /* Application-filter dropped packet count. */
    ULONGLONG last_flush_tick; /* Last output flush tick count. */

    struct app_capture_filter app_filter;
    struct device_metadata device_metadata[128];
};

HANDLE create_filter_read_handle(struct thread_data *data);
DWORD WINAPI read_thread(LPVOID param);

#endif /* USBPCAP_CMD_THREAD_H */
