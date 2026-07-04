/*
 * Copyright (c) 2013 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef USBPCAP_CMD_ENUM_H
#define USBPCAP_CMD_ENUM_H

#include <stddef.h>
#include <Windows.h>
#include <Usbioctl.h>

#define EXTCAP_ARGNUM_MULTICHECK 99

typedef void (*EnumConnectedPortCallback)(HANDLE hub, ULONG port, USHORT deviceAddress, USHORT parentAddress, PUSB_DEVICE_DESCRIPTOR desc, void *ctx);

typedef struct _USBPCAP_CONNECTED_DEVICE_INFO
{
	ULONG port;
	USHORT parentAddress;
	USHORT address;
	USHORT vendorId;
	USHORT productId;
	BOOLEAN isHub;
	char description[256];
} USBPCAP_CONNECTED_DEVICE_INFO, *PUSBPCAP_CONNECTED_DEVICE_INFO;

void enumerate_print_usbpcap_interactive(const char *filter);
void enumerate_print_extcap_config(const char *filter);
void enumerate_all_connected_devices(const char *filter, EnumConnectedPortCallback cb, void *ctx);
BOOL enumerate_get_connected_devices(const char *filter,
									 PUSBPCAP_CONNECTED_DEVICE_INFO *devices,
									 size_t *count);

#endif /* USBPCAP_CMD_ENUM_H */
