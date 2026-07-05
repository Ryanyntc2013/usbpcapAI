/*
 * Copyright (c) 2013-2018 Tomasz Moń <desowin@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define _CRT_SECURE_NO_DEPRECATE

#include <initguid.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Shellapi.h>
#include <Shlwapi.h>
#include <Usbiodef.h>
#include "filters.h"
#include "thread.h"
#include "enum.h"
#include "getopt.h"
#include "roothubs.h"
#include "version.h"
#include "descriptors.h"
#include "USBPcap.h"

#define INPUT_BUFFER_SIZE 1024

#define DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE (1024*1024)
#define DEFAULT_SNAPSHOT_LENGTH             (65535)

typedef struct _usbpcap_match_info
{
    USHORT address;
    USHORT vendor_id;
    USHORT product_id;
} usbpcap_match_info;

typedef struct _usbpcap_match_list
{
    usbpcap_match_info *items;
    size_t count;
    char *address_list;
} usbpcap_match_list;

static void configure_utf8_console(void)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

static int is_chinese_locale(void)
{
    LANGID langId = GetUserDefaultUILanguage();
    WORD primaryLang = PRIMARYLANGID(langId);
    return (primaryLang == LANG_CHINESE) ? 1 : 0;
}

static void json_print_escaped(FILE *stream, const char *value)
{
    const unsigned char *ptr = (const unsigned char *)value;

    fputc('"', stream);
    if (value != NULL)
    {
        while (*ptr)
        {
            switch (*ptr)
            {
                case '\\': fputs("\\\\", stream); break;
                case '"': fputs("\\\"", stream); break;
                case '\b': fputs("\\b", stream); break;
                case '\f': fputs("\\f", stream); break;
                case '\n': fputs("\\n", stream); break;
                case '\r': fputs("\\r", stream); break;
                case '\t': fputs("\\t", stream); break;
                default:
                    if (*ptr < 0x20)
                    {
                        fprintf(stream, "\\u%04x", *ptr);
                    }
                    else
                    {
                        fputc(*ptr, stream);
                    }
                    break;
            }
            ptr++;
        }
    }
    fputc('"', stream);
}

static void print_json_error(const char *code, const char *message, const char *hint)
{
    printf("{\"ok\":false,\"errorCode\":");
    json_print_escaped(stdout, code);
    printf(",\"message\":");
    json_print_escaped(stdout, message);
    if (hint != NULL)
    {
        printf(",\"hint\":");
        json_print_escaped(stdout, hint);
    }
    printf("}\n");
}

static BOOL parse_u32_value(const char *text, UINT32 *value)
{
    char *endptr;
    unsigned long parsed;

    if ((text == NULL) || (value == NULL) || (*text == '\0'))
    {
        return FALSE;
    }

    parsed = strtoul(text, &endptr, 0);
    if ((*endptr != '\0') || (parsed > 0xFFFFFFFFUL))
    {
        return FALSE;
    }

    *value = (UINT32)parsed;
    return TRUE;
}

static BOOL parse_u16_value(const char *text, USHORT *value)
{
    UINT32 parsed;
    if ((parse_u32_value(text, &parsed) == FALSE) || (parsed > 0xFFFFU))
    {
        return FALSE;
    }

    *value = (USHORT)parsed;
    return TRUE;
}

static const char *transfer_type_to_text(UCHAR transfer)
{
    switch (transfer)
    {
        case USBPCAP_TRANSFER_CONTROL: return "control";
        case USBPCAP_TRANSFER_BULK: return "bulk";
        case USBPCAP_TRANSFER_INTERRUPT: return "interrupt";
        case USBPCAP_TRANSFER_ISOCHRONOUS: return "isochronous";
        default: return "unknown";
    }
}

static BOOL parse_transfer_type(const char *text, UCHAR *transfer)
{
    if ((text == NULL) || (transfer == NULL))
    {
        return FALSE;
    }

    if (_stricmp(text, "control") == 0)
    {
        *transfer = USBPCAP_TRANSFER_CONTROL;
        return TRUE;
    }
    if (_stricmp(text, "bulk") == 0)
    {
        *transfer = USBPCAP_TRANSFER_BULK;
        return TRUE;
    }
    if (_stricmp(text, "interrupt") == 0)
    {
        *transfer = USBPCAP_TRANSFER_INTERRUPT;
        return TRUE;
    }
    if (_stricmp(text, "isochronous") == 0)
    {
        *transfer = USBPCAP_TRANSFER_ISOCHRONOUS;
        return TRUE;
    }
    if (_stricmp(text, "unknown") == 0)
    {
        *transfer = USBPCAP_TRANSFER_UNKNOWN;
        return TRUE;
    }

    return FALSE;
}

static void free_match_list(usbpcap_match_list *matches)
{
    if (matches == NULL)
    {
        return;
    }

    if (matches->items != NULL)
    {
        free(matches->items);
    }
    if (matches->address_list != NULL)
    {
        free(matches->address_list);
    }

    memset(matches, 0, sizeof(*matches));
}

static BOOL IsElevated()
{
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
        {
            fRet = Elevation.TokenIsElevated;
        }
        else
        {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER)
            {
                /* Running on Windows XP.
                 * Check if executed as administrator by reading Local Service key.
                 */
                HKEY key;
                if (ERROR_SUCCESS == RegOpenKey(HKEY_USERS, "S-1-5-19", &key))
                {
                    fRet = TRUE;
                }
                else
                {
                    /* If we were executed with SW_HIDE then the runas window won't be shown.
                     * In such case pretend here that we are running as administrator so
                     * the process will fail (and not simply be waiting indefinitely
                     * without giving any clue).
                     */
                    STARTUPINFO info;
                    GetStartupInfo(&info);
                    if (info.wShowWindow == SW_HIDE)
                    {
                        fRet = TRUE;
                    }
                }
            }
            else
            {
                fprintf(stderr, "GetTokenInformation failed with code %d\n", err);
            }
        }
    }

    if (hToken)
    {
        CloseHandle(hToken);
    }

    return fRet;
}

/*
 * GetModuleFullName:
 *
 *    Gets the full path and file name of the specified module and returns the length on success,
 *    (which does not include the terminating NUL character) 0 otherwise.  Use GetLastError() to
 *    get extended error information.
 *
 *       hModule              [in] Handle to a module loaded by the calling process, or NULL to
 *                            use the current process module handle.  This function does not
 *                            retrieve the name for modules that were loaded using LoadLibraryEx
 *                            with the LOAD_LIBRARY_AS_DATAFILE flag. For more information, see
 *                            LoadLibraryEx.
 *
 *       pszBuffer            [out] Pointer to the buffer which receives the module full name.
 *                            This paramater may be NULL, in which case the function returns the
 *                            size of the buffer in characters required to contain the full name,
 *                            including a NUL terminating character.
 *
 *       nMaxChars            [in] Specifies the size of the buffer in characters.  This must be
 *                            0 when pszBuffer is NULL, otherwise the function fails.
 *
 *       ppszFileName         [out] On return, the referenced pointer is assigned a position in
 *                            the buffer to the module's file name only.  This parameter may be
 *                            NULL if the file name is not required.
 */
EXTERN_C int WINAPI GetModuleFullName(__in HMODULE hModule, __out LPWSTR pszBuffer,
                                      __in int nMaxChars, __out LPWSTR* ppszFileName)
{
    /* Determine required buffer size when requested */
    int nLength = 0;
    DWORD dwStatus = NO_ERROR;

    /* Validate parameters */
    if (dwStatus == NO_ERROR)
    {
        if (pszBuffer == NULL && (nMaxChars != 0 || ppszFileName != NULL))
        {
             dwStatus = ERROR_INVALID_PARAMETER;
        }
        else if (pszBuffer != NULL && nMaxChars < 1)
        {
             dwStatus = ERROR_INVALID_PARAMETER;
        }
    }

    if (dwStatus == NO_ERROR)
    {
        if (pszBuffer == NULL)
        {
            HANDLE hHeap = GetProcessHeap();

            WCHAR  cwBuffer[2048] = { 0 };
            LPWSTR pszBuffer      = cwBuffer;
            DWORD  dwMaxChars     = _countof(cwBuffer);
            DWORD  dwLength       = 0;

            LPWSTR pszNew;
            SIZE_T nSize;

            for (;;)
            {
                /* Try to get the module's full path and file name */
                dwLength = GetModuleFileNameW(hModule, pszBuffer, dwMaxChars);

                if (dwLength == 0)
                {
                    dwStatus = GetLastError();
                    break;
                }

                /* If succeeded, return buffer size requirement:
                 *    o  Adds one for the terminating NUL character.
                 */
                if (dwLength < dwMaxChars)
                {
                    nLength = (int)dwLength + 1;
                    break;
                }

                /* Check the maximum supported full name length:
                 *    o  Assumes support for HPFS, NTFS, or VTFS of ~32K.
                 */
                if (dwMaxChars >= 32768U)
                {
                    dwStatus = ERROR_BUFFER_OVERFLOW;
                    break;
                }

                /* Double the size of our buffer and try again */
                dwMaxChars *= 2;

                pszNew = (pszBuffer == cwBuffer ? NULL : pszBuffer);
                nSize  = (SIZE_T)dwMaxChars * sizeof(WCHAR);

                if (pszNew == NULL)
                {
                    pszNew = (LPWSTR)HeapAlloc(hHeap, 0, nSize);
                }
                else
                {
                    LPWSTR pszTmp;
                    pszTmp = (LPWSTR)HeapReAlloc(hHeap, 0, pszNew, nSize);
                    if (pszTmp == NULL)
                    {
                        HeapFree(hHeap, 0, pszNew);
                        if (pszNew == pszBuffer)
                        {
                            pszBuffer = NULL;
                        }
                        pszNew = NULL;
                    }
                    else
                    {
                        pszNew = pszTmp;
                    }
                }

                if (pszNew == NULL)
                {
                    dwStatus = ERROR_OUTOFMEMORY;
                    break;
                }

                pszBuffer = pszNew;
            }

            /* Free the temporary buffer if allocated */
            if (pszBuffer != cwBuffer)
            {
                if (!HeapFree(hHeap, 0, pszBuffer))
                {
                   dwStatus = GetLastError();
                }
            }
        }
    }

    /* Get the module's full name and pointer to file name when requested */
    if (dwStatus == NO_ERROR)
    {
        if (pszBuffer != NULL)
        {
            nLength = (int)GetModuleFileNameW(hModule, pszBuffer, nMaxChars);

            if (nLength <= 0 || nLength == nMaxChars)
            {
                dwStatus = GetLastError();
            }
            else if (ppszFileName != NULL)
            {
                LPWSTR pszItr;
                *ppszFileName = pszBuffer;

                for (pszItr = pszBuffer; *pszItr != L'\0'; ++pszItr)
                {
                    if (*pszItr == L'\\' || *pszItr == L'/')
                    {
                        *ppszFileName = pszItr + 1;
                    }
               }
            }
         }
    }

    /* Return full name length or 0 on error */
    if (dwStatus != NO_ERROR)
    {
        nLength = 0;

        SetLastError(dwStatus);
    }

    return nLength;
}

static int list_interfaces(BOOL json_output)
{
    int i = 0;

    filters_initialize();
    if (json_output)
    {
        printf("{\"interfaces\":[");
    }

    while (usbpcapFilters[i] != NULL)
    {
        char *tmp = strrchr(usbpcapFilters[i]->device, '\\');
        if (tmp == NULL)
        {
            tmp = usbpcapFilters[i]->device;
        }
        else
        {
            tmp++;
        }

        if (json_output)
        {
            if (i > 0)
            {
                printf(",");
            }
            printf("{\"name\":");
            json_print_escaped(stdout, usbpcapFilters[i]->device);
            printf(",\"displayName\":");
            json_print_escaped(stdout, tmp);
            printf("}");
        }
        else
        {
            printf("%s\n", usbpcapFilters[i]->device);
        }

        i++;
    }

    if (json_output)
    {
        printf("]}\n");
    }

    filters_free();
    return 0;
}

static int list_devices(const char *filter, BOOL json_output)
{
    PUSBPCAP_CONNECTED_DEVICE_INFO devices = NULL;
    size_t count = 0;
    size_t i;

    if (filter == NULL)
    {
        fprintf(stderr, "Interface must be specified with --interface when using --list-devices.\n"
                        "Omit --interface to list devices from all interfaces.\n");
        return -1;
    }

    if (enumerate_get_connected_devices(filter, &devices, &count) == FALSE)
    {
        fprintf(stderr, "Failed to enumerate connected devices for %s\n", filter);
        return -1;
    }

    if (json_output)
    {
        printf("{\"interface\":");
        json_print_escaped(stdout, filter);
        printf(",\"devices\":[");
    }

    for (i = 0; i < count; i++)
    {
        if (json_output)
        {
            if (i > 0)
            {
                printf(",");
            }
            printf("{\"address\":%u,\"port\":%lu,\"parentAddress\":%u,\"vendorId\":\"0x%04x\",\"productId\":\"0x%04x\",\"isHub\":%s,\"description\":",
                   devices[i].address,
                   devices[i].port,
                   devices[i].parentAddress,
                   devices[i].vendorId,
                   devices[i].productId,
                   devices[i].isHub ? "true" : "false");
            json_print_escaped(stdout, devices[i].description);
            printf("}");
        }
        else
        {
            printf("address=%u port=%lu parent=%u vid=0x%04x pid=0x%04x isHub=%s",
                   devices[i].address,
                   devices[i].port,
                   devices[i].parentAddress,
                   devices[i].vendorId,
                   devices[i].productId,
                   devices[i].isHub ? "true" : "false");
            if (devices[i].description[0] != '\0')
            {
                printf("  %s", devices[i].description);
            }
            printf("\n");
        }
    }

    if (json_output)
    {
        printf("]}\n");
    }

    if (devices != NULL)
    {
        free(devices);
    }

    return 0;
}

static int list_all_devices(BOOL json_output)
{
    int i = 0;
    int device_count = 0;

    filters_initialize();

    if (json_output)
    {
        printf("{\"interfaces\":[");
    }

    while (usbpcapFilters[i] != NULL)
    {
        PUSBPCAP_CONNECTED_DEVICE_INFO devices = NULL;
        size_t count = 0;
        size_t j;
        const char *filter = usbpcapFilters[i]->device;

        if (enumerate_get_connected_devices(filter, &devices, &count) == FALSE)
        {
            i++;
            continue;
        }

        if (json_output)
        {
            if (i > 0)
            {
                printf(",");
            }
            printf("{\"interface\":");
            json_print_escaped(stdout, filter);
            printf(",\"devices\":[");
        }
        else
        {
            if (i > 0)
            {
                printf("\n");
            }
            printf("[%s]\n", filter);
        }

        for (j = 0; j < count; j++)
        {
            if (json_output)
            {
                if (j > 0)
                {
                    printf(",");
                }
                printf("{\"address\":%u,\"vendorId\":\"0x%04x\",\"productId\":\"0x%04x\",\"isHub\":%s,\"description\":",
                       devices[j].address,
                       devices[j].vendorId,
                       devices[j].productId,
                       devices[j].isHub ? "true" : "false");
                json_print_escaped(stdout, devices[j].description);
                printf("}");
            }
            else
            {
                printf("  address=%-3u vid=0x%04x pid=0x%04x",
                       devices[j].address,
                       devices[j].vendorId,
                       devices[j].productId);
                if (devices[j].isHub)
                {
                    printf("  [Hub]");
                }
                if (devices[j].description[0] != '\0')
                {
                    printf("  %s", devices[j].description);
                }
                printf("\n");
            }
            device_count++;
        }

        if (json_output)
        {
            printf("]}");
        }

        if (devices != NULL)
        {
            free(devices);
        }
        i++;
    }

    if (json_output)
    {
        printf("]}\n");
    }
    else
    {
        printf("\nTotal: %d device(s) across %d interface(s)\n", device_count, i);
    }

    filters_free();
    return 0;
}

static BOOL populate_device_metadata(struct thread_data *data, const char *filter)
{
    PUSBPCAP_CONNECTED_DEVICE_INFO devices = NULL;
    size_t count = 0;
    size_t i;

    if ((data == NULL) || (filter == NULL))
    {
        return FALSE;
    }

    memset(data->device_metadata, 0, sizeof(data->device_metadata));

    if (enumerate_get_connected_devices(filter, &devices, &count) == FALSE)
    {
        return FALSE;
    }

    for (i = 0; i < count; i++)
    {
        if (devices[i].address < 128)
        {
            data->device_metadata[devices[i].address].present = TRUE;
            data->device_metadata[devices[i].address].vendor_id = devices[i].vendorId;
            data->device_metadata[devices[i].address].product_id = devices[i].productId;
        }
    }

    if (devices != NULL)
    {
        free(devices);
    }

    return TRUE;
}

static BOOL resolve_filter_matches(const char *filter,
                                   BOOL has_vendor_id,
                                   USHORT vendor_id,
                                   BOOL has_product_id,
                                   USHORT product_id,
                                   usbpcap_match_list *matches)
{
    PUSBPCAP_CONNECTED_DEVICE_INFO devices = NULL;
    size_t count = 0;
    size_t i;
    size_t found = 0;
    size_t address_list_len = 0;

    if ((filter == NULL) || (matches == NULL))
    {
        return FALSE;
    }

    memset(matches, 0, sizeof(*matches));

    if (enumerate_get_connected_devices(filter, &devices, &count) == FALSE)
    {
        return FALSE;
    }

    matches->items = (usbpcap_match_info *)calloc(count == 0 ? 1 : count, sizeof(usbpcap_match_info));
    if (matches->items == NULL)
    {
        if (devices != NULL)
        {
            free(devices);
        }
        return FALSE;
    }

    for (i = 0; i < count; i++)
    {
        if (has_vendor_id && (devices[i].vendorId != vendor_id))
        {
            continue;
        }
        if (has_product_id && (devices[i].productId != product_id))
        {
            continue;
        }

        matches->items[found].address = devices[i].address;
        matches->items[found].vendor_id = devices[i].vendorId;
        matches->items[found].product_id = devices[i].productId;
        found++;
        address_list_len += 5;
    }

    matches->count = found;
    if (found > 0)
    {
        size_t offset = 0;
        matches->address_list = (char *)malloc(address_list_len + 1);
        if (matches->address_list == NULL)
        {
            if (devices != NULL)
            {
                free(devices);
            }
            free_match_list(matches);
            return FALSE;
        }

        for (i = 0; i < found; i++)
        {
            int written = sprintf_s(matches->address_list + offset,
                                    address_list_len + 1 - offset,
                                    (i == 0) ? "%u" : ",%u",
                                    matches->items[i].address);
            if (written < 0)
            {
                if (devices != NULL)
                {
                    free(devices);
                }
                free_match_list(matches);
                return FALSE;
            }
            offset += (size_t)written;
        }
    }

    if (devices != NULL)
    {
        free(devices);
    }

    return TRUE;
}

static BOOL auto_select_interface(BOOL has_vendor_id,
                                  USHORT vendor_id,
                                  BOOL has_product_id,
                                  USHORT product_id,
                                  char **selected_device,
                                  usbpcap_match_list *matches)
{
    int i = 0;
    int foundFilters = 0;
    usbpcap_match_list current;

    if ((selected_device == NULL) || (matches == NULL))
    {
        return FALSE;
    }

    memset(matches, 0, sizeof(*matches));
    filters_initialize();

    while (usbpcapFilters[i] != NULL)
    {
        memset(&current, 0, sizeof(current));
        if (resolve_filter_matches(usbpcapFilters[i]->device,
                                   has_vendor_id,
                                   vendor_id,
                                   has_product_id,
                                   product_id,
                                   &current) == FALSE)
        {
            filters_free();
            return FALSE;
        }

        if (current.count > 0)
        {
            foundFilters++;
            if (foundFilters == 1)
            {
                *selected_device = _strdup(usbpcapFilters[i]->device);
                *matches = current;
            }
            else
            {
                free_match_list(&current);
                filters_free();
                return FALSE;
            }
        }
        else
        {
            free_match_list(&current);
        }

        i++;
    }

    filters_free();
    return (foundFilters == 1);
}

/**
 *  Generates command line for worker process.
 *
 *  \param[in] data thread_data containing capture configuration.
 *  \param[out] appPath pointer to store application path. Must be freed using free().
 *  \param[out] appCmdLine commandline for worker process. Must be freed using free().
 *  \param[out] pcap_handle handle to pcap pipe (used if filename is "-"),
 *              if not writing to standard output it is set to INVALID_HANDLE_VALUE.
 *
 * \return BOOL TRUE on success, FALSE otherwise.
 */
static BOOL generate_worker_command_line(struct thread_data *data,
                                         PWSTR *appPath,
                                         PWSTR *appCmdLine,
                                         HANDLE *pcap_handle)
{
    PWSTR exePath;
    int exePathLen;
    PWSTR cmdLine = NULL;
    size_t cmdLineLen;
    PWSTR pipeName = NULL;
    int nChars;

    *pcap_handle = INVALID_HANDLE_VALUE;

    exePathLen = GetModuleFullName(NULL, NULL, 0, NULL);
    exePath = (WCHAR *)malloc(exePathLen * sizeof(WCHAR));

    if (exePath == NULL)
    {
        fprintf(stderr, "Failed to get module path\n");
        return FALSE;
    }

    GetModuleFullName(NULL, exePath, exePathLen, NULL);

    if (strncmp(data->filename, "-", 2) == 0)
    {
        /* Need to create pipe */
        WCHAR *tmp;
        int nChars = (int)(sizeof("\\\\.\\pipe\\") + strlen(data->device) + 1);
        pipeName = malloc((nChars + 1) * sizeof(WCHAR));
        if (pipeName == NULL)
        {
            fprintf(stderr, "Failed to allocate pipe name\n");
            free(exePath);
            return FALSE;
        }
        swprintf_s(pipeName, nChars,  L"\\\\.\\pipe\\%S", data->device);
        for (tmp = &pipeName[sizeof("\\\\.\\pipe\\")]; *tmp; tmp++)
        {
            if (*tmp == L'\\')
            {
                *tmp = L'_';
            }
        }

        *pcap_handle = CreateNamedPipeW(pipeName,
                                        /* Pipe is used for elevated worker -> caller process communication.
                                         * It is full duplex to allow caller to notice elevated worker that
                                         * it should terminate (read from this pipe in elevated worker will
                                         * result in ERROR_BROKEN_PIPE).
                                         */
                                        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                        2 /* Max instances of pipe */,
                                        data->bufferlen, data->bufferlen,
                                        0, NULL);


        if (*pcap_handle == INVALID_HANDLE_VALUE)
        {
            fprintf(stderr, "Failed to create named pipe - %d\n", GetLastError());
            free(exePath);
            free(pipeName);
            return FALSE;
        }
    }
    else
    {
        *pcap_handle = INVALID_HANDLE_VALUE;
    }

#define WORKER_CMD_LINE_FORMATTER             L"-d %S -b %u -o %S"
#define WORKER_CMD_LINE_FORMATTER_PIPE        L"-d %S -b %u -o %s"

#define WORKER_CMD_LINE_FORMATTER_SNAPLEN     L" -s %u"
#define WORKER_CMD_LINE_FORMATTER_DEVICES     L" --devices %S"
#define WORKER_CMD_LINE_FORMATTER_CAPTURE_ALL L" --capture-from-all-devices"
#define WORKER_CMD_LINE_FORMATTER_CAPTURE_NEW L" --capture-from-new-devices"
#define WORKER_CMD_LINE_FORMATTER_INJECT_DESCRIPTORS L" --inject-descriptors"
#define WORKER_CMD_LINE_FORMATTER_DURATION    L" --duration %u"
#define WORKER_CMD_LINE_FORMATTER_APP_FILTER  L" --app-filter"
#define WORKER_CMD_LINE_FORMATTER_VENDOR      L" --vendor-id %u"
#define WORKER_CMD_LINE_FORMATTER_PRODUCT     L" --product-id %u"
#define WORKER_CMD_LINE_FORMATTER_ENDPOINT    L" --endpoint %u"
#define WORKER_CMD_LINE_FORMATTER_TRANSFER    L" --transfer-type %S"
#define WORKER_CMD_LINE_FORMATTER_STORE_ON_MATCH L" --store-mode on-match"
#define WORKER_CMD_LINE_FORMATTER_NO_INTERACTIVE L" --no-interactive"

    cmdLineLen = MultiByteToWideChar(CP_ACP, 0, data->device, -1, NULL, 0);
    cmdLineLen += (pipeName == NULL) ? strlen(data->filename) : wcslen(pipeName);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER);
    cmdLineLen += 9 /* maximum bufferlen in characters */;
    cmdLineLen += 1 /* NULL termination */;
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_SNAPLEN);
    cmdLineLen += 10 /* maximum snaplen in characters */;
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_DEVICES);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_CAPTURE_ALL);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_CAPTURE_NEW);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_INJECT_DESCRIPTORS);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_DURATION);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_APP_FILTER);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_VENDOR);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_PRODUCT);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_ENDPOINT);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_TRANSFER);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_STORE_ON_MATCH);
    cmdLineLen += wcslen(WORKER_CMD_LINE_FORMATTER_NO_INTERACTIVE);
    cmdLineLen += (data->address_list == NULL) ? 0 : strlen(data->address_list);

    cmdLine = (PWSTR)malloc(cmdLineLen * sizeof(WCHAR));

    if (cmdLine == NULL)
    {
        fprintf(stderr, "Failed to allocate command line\n");
        free(exePath);
        free(pipeName);
        return FALSE;
    }

    if (pipeName == NULL)
    {
        nChars = swprintf_s(cmdLine,
                            cmdLineLen,
                            WORKER_CMD_LINE_FORMATTER,
                            data->device,
                            data->bufferlen,
                            data->filename);
    }
    else
    {
        nChars = swprintf_s(cmdLine,
                            cmdLineLen,
                            WORKER_CMD_LINE_FORMATTER_PIPE,
                            data->device,
                            data->bufferlen,
                            pipeName);
    }

    if (data->snaplen != DEFAULT_SNAPSHOT_LENGTH)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_SNAPLEN,
                             data->snaplen);
    }

    if (data->address_list != NULL)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_DEVICES,
                             data->address_list);
    }

    if (data->capture_all)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_CAPTURE_ALL);
    }

    if (data->capture_new)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_CAPTURE_NEW);
    }

    if (data->inject_descriptors)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_INJECT_DESCRIPTORS);
    }

    if (data->duration_seconds > 0)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_DURATION,
                             data->duration_seconds);
    }

    if (data->app_filter.enabled)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_APP_FILTER);
    }

    if (data->app_filter.has_vendor_id)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_VENDOR,
                             data->app_filter.vendor_id);
    }

    if (data->app_filter.has_product_id)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_PRODUCT,
                             data->app_filter.product_id);
    }

    if (data->app_filter.has_endpoint)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_ENDPOINT,
                             data->app_filter.endpoint);
    }

    if (data->app_filter.has_transfer_type)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_TRANSFER,
                             transfer_type_to_text(data->app_filter.transfer_type));
    }

    if (data->store_mode == USBPCAP_STORE_MODE_ON_MATCH)
    {
        nChars += swprintf_s(&cmdLine[nChars],
                             cmdLineLen - nChars,
                             WORKER_CMD_LINE_FORMATTER_STORE_ON_MATCH);
    }

    nChars += swprintf_s(&cmdLine[nChars],
                         cmdLineLen - nChars,
                         WORKER_CMD_LINE_FORMATTER_NO_INTERACTIVE);
#undef WORKER_CMD_LINE_FORMATTER_PIPE
#undef WORKER_CMD_LINE_FORMATTER

#undef WORKER_CMD_LINE_FORMATTER_INJECT_DESCRIPTORS
#undef WORKER_CMD_LINE_FORMATTER_CAPTURE_NEW
#undef WORKER_CMD_LINE_FORMATTER_CAPTURE_ALL
#undef WORKER_CMD_LINE_FORMATTER_DEVICES
#undef WORKER_CMD_LINE_FORMATTER_SNAPLEN
#undef WORKER_CMD_LINE_FORMATTER_DURATION
#undef WORKER_CMD_LINE_FORMATTER_APP_FILTER
#undef WORKER_CMD_LINE_FORMATTER_VENDOR
#undef WORKER_CMD_LINE_FORMATTER_PRODUCT
#undef WORKER_CMD_LINE_FORMATTER_ENDPOINT
#undef WORKER_CMD_LINE_FORMATTER_TRANSFER
#undef WORKER_CMD_LINE_FORMATTER_STORE_ON_MATCH
#undef WORKER_CMD_LINE_FORMATTER_NO_INTERACTIVE

    free(pipeName);

    *appPath = exePath;
    *appCmdLine = cmdLine;
    return TRUE;
}

/**
 *  Creates elevated worker process.
 *
 *  \param[in] appPath path to elevated worker module
 *  \param[in] cmdLine commandline to start elevated worker with
 *
 *  \return Handle to created process.
 */
static HANDLE create_elevated_worker(PWSTR appPath, PWSTR cmdLine)
{
    BOOL bSuccess = FALSE;
    SHELLEXECUTEINFOW exInfo = { 0 };

    exInfo.cbSize = sizeof(exInfo);
    exInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    exInfo.hwnd = NULL;
    exInfo.lpVerb = L"runas";
    exInfo.lpFile = appPath;
    exInfo.lpParameters = cmdLine;
    exInfo.lpDirectory = NULL;
    exInfo.nShow = SW_HIDE;
    /* exInfo.hInstApp is output parameter */
    /* exInfo.lpIDList, exInfo.lpClass, exInfo.hkeyClass, exInfo.dwHotKey, exInfo.DUMMYUNIONNAME
     * are ignored for our fMask value.
     */
    /* exInfo.hProcess is output parameter */

    bSuccess = ShellExecuteExW(&exInfo);

    if (FALSE == bSuccess)
    {
        fprintf(stderr, "Failed to create worker process!\n");
        return INVALID_HANDLE_VALUE;
    }

    return exInfo.hProcess;
}

/**
 *  Creates intermediate worker process that creates elevated worker process
 *  inside a job that will terminate all processes on close.
 *
 *  On success it modifies data->worker_process_thread handle.
 *
 *  \param[inout] data thread_data containing capture configuration.
 *  \param[in] appPath path to elevated worker module
 *  \param[in] cmdLine commandline to start elevated worker with
 *
 *  \return Handle to created process.
 */
static HANDLE create_breakaway_worker_in_job(struct thread_data *data, PWSTR appPath, PWSTR appCmdLine)
{
    HANDLE process = INVALID_HANDLE_VALUE;
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;
    PWSTR processCmdLine;
    int nChars;

    if (data->job_handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "create_breakaway_worker_in_job() cannot be called if data->job_handle is INVALID_HANDLE_VALUE!\n");
        return INVALID_HANDLE_VALUE;
    }

    memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    /* CreateProcessW works different to ShellExecuteExW.
     * It will always treat first token of command line as argv[0] in
     * created process.
     *
     * Hence create new string that will contain "appPath" appCmdLine.
     */
    nChars = (int)(wcslen(appPath) + wcslen(appCmdLine) +
             4 /* Two quotemarks, one space and NULL-terminator */);
    processCmdLine = (PWSTR)malloc(nChars * sizeof(WCHAR));
    if (processCmdLine == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for processCmdLine!\n");
        return INVALID_HANDLE_VALUE;
    }

    swprintf_s(processCmdLine, nChars, L"\"%s\" %s",
               appPath, appCmdLine);

    /* We need to breakaway from parent job and assign to data->job_handle. */
    if (0 == CreateProcessW(NULL, processCmdLine, NULL, NULL, FALSE,
                            CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED,
                            NULL, NULL, &startupInfo, &processInfo))
    {
        data->process = FALSE;
    }
    else
    {
        process = processInfo.hProcess;
        /* processInfo.hThread needs to be closed. */
        data->worker_process_thread = processInfo.hThread;

        /* process is not assigned to any job. Assign it. */
        if (AssignProcessToJobObject(data->job_handle, process) == FALSE)
        {
            fprintf(stderr, "Failed to Assign process to job object - %d\n",
                    GetLastError());
            /* This is fatal error. */
            CloseHandle(process);
            CloseHandle(data->worker_process_thread);
            data->process = FALSE;
            process = INVALID_HANDLE_VALUE;
            data->worker_process_thread = INVALID_HANDLE_VALUE;
        }
        else
        {
            /* Process is assigned to proper job. Resume it. */
            ResumeThread(data->worker_process_thread);
        }
    }

    free(processCmdLine);

    return process;
}

int cmd_interactive(struct thread_data *data)
{
    int i = 0;
    int max_i;
    char buffer[INPUT_BUFFER_SIZE];
    BOOL finished;
    BOOL exit = FALSE;

    /* Detach from parent console window. Make sure to reopen stdout
     * and stderr as otherwise wide_print() does not corectly detect
     * console.
     */
    FreeConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    /* If we are running interactive then we should show console window.
     * We are not automatically allocated a console window because the
     * application type is set to windows. This prevents console
     * window from showing when USBPcapCMD is used as extcap.
     * Since extcap is recommended cmd.exe users will notice a slight
     * inconvenience that USBPcapCMD opens new window.
     *
     * Please note that is it impossible to get parent's cmd.exe stdin
     * handle if application type is not console. The difference is
     * that in case of console application cmd.exe waits until the
     * process finishes and in case of windows applications there is
     * no wait for process termination and the cmd.exe console immadietely
     * regains standard input functionality.
     */
    if (AllocConsole() == FALSE)
    {
        return -1;
    }

    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    data->filename = NULL;
    data->capture_all = TRUE;
    data->inject_descriptors = TRUE;

    filters_initialize();
    if (usbpcapFilters[0] == NULL)
    {
        printf("No filter control devices are available.\n");

        if (is_usbpcap_upper_filter_installed() == FALSE)
        {
            printf("Please reinstall USBPcapDriver.\n");
            (void)getchar();
            filters_free();
            return -1;
        }

        printf("USBPcap UpperFilter entry appears to be present.\n"
               "Most likely you have not restarted your computer after installation.\n"
               "It is possible to restart all USB devices to get USBPcap working without reboot.\n"
               "\nWARNING:\n  Restarting all USB devices can result in data loss.\n"
               "  If you are unsure please answer 'n' and reboot in order to use USBPcap.\n\n");

        finished = FALSE;
        do
        {
            printf("Do you want to restart all USB devices (y, n)? ");
            if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL)
            {
                printf("Invalid input\n");
            }
            else
            {
                if (buffer[0] == 'y')
                {
                    finished = TRUE;
                    restart_all_usb_devices();
                    filters_free();
                    filters_initialize();
                }
                else if (buffer[0] == 'n')
                {
                    filters_free();
                    return -1;
                }
            }
        } while (finished == FALSE);
    }

    printf("Following filter control devices are available:\n");
    while (usbpcapFilters[i] != NULL)
    {
        printf("%d %s\n", i+1, usbpcapFilters[i]->device);
        enumerate_print_usbpcap_interactive(usbpcapFilters[i]->device);
        i++;
    }

    max_i = i;

    finished = FALSE;
    do
    {
        printf("Select filter to monitor (q to quit): ");
        if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL)
        {
            printf("Invalid input\n");
        }
        else
        {
            if (buffer[0] == 'q')
            {
                finished = TRUE;
                exit = TRUE;
            }
            else
            {
                int value = atoi(buffer);

                if (value <= 0 || value > max_i)
                {
                    printf("Invalid input\n");
                }
                else
                {
                    data->device = _strdup(usbpcapFilters[value-1]->device);
                    finished = TRUE;
                }
            }
        }
    } while (finished == FALSE);

    if (exit == TRUE)
    {
        filters_free();
        return -1;
    }

    finished = FALSE;
    do
    {
        printf("Output file name (.pcap): ");
        if (fgets(buffer, INPUT_BUFFER_SIZE, stdin) == NULL)
        {
            printf("Invalid input\n");
        }
        else if (buffer[0] == '\0')
        {
            printf("Empty filename not allowed\n");
        }
        else
        {
            for (i = 0; i < INPUT_BUFFER_SIZE; i++)
            {
                if (buffer[i] == '\n')
                {
                    buffer[i] = '\0';
                    break;
                }
            }
            data->filename = _strdup(buffer);
            finished = TRUE;
        }
    } while (finished == FALSE);

    filters_free();
    return 0;
}

/**
 * Wait for exit signal.
 *
 * Wait for either 'q' on standard input, data->exit_event or worker process termination.
 *
 * \param[in] data Thread data structure
 * \param[in] process Worker process handle
 *                    INVALID_HANDLE_VALUE if not using elevated worker.
 */
static void wait_for_exit_signal(struct thread_data *data, HANDLE process)
{
    HANDLE handle_table[4] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
    HANDLE stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE timer_handle = INVALID_HANDLE_VALUE;
    DWORD dw;
    int count = 0;

    /* Verify that stdin_handle can be used. */
    if ((stdin_handle != NULL) && (stdin_handle != INVALID_HANDLE_VALUE))
    {
        dw = WaitForSingleObject(stdin_handle, 0);
        if (dw != WAIT_FAILED)
        {
            handle_table[count] = stdin_handle;
            count++;
        }
    }

    if ((data->exit_event != NULL) && (data->exit_event != INVALID_HANDLE_VALUE))
    {
        handle_table[count] = data->exit_event;
        count++;
    }

    if ((process != NULL) && (process != INVALID_HANDLE_VALUE))
    {
        handle_table[count] = process;
        count++;
    }

    if (data->duration_seconds > 0)
    {
        LARGE_INTEGER dueTime;
        timer_handle = CreateWaitableTimer(NULL, TRUE, NULL);
        if (timer_handle != NULL)
        {
            dueTime.QuadPart = -((LONGLONG)data->duration_seconds * 10000000LL);
            if (SetWaitableTimer(timer_handle, &dueTime, 0, NULL, NULL, FALSE))
            {
                handle_table[count] = timer_handle;
                count++;
            }
            else
            {
                CloseHandle(timer_handle);
                timer_handle = INVALID_HANDLE_VALUE;
            }
        }
    }

    if (count == 0)
    {
        fprintf(stderr, "Nothing to wait for in wait_for_exit_signal().\n");
    }

    /* Wait for exit condition. */
    while (data->process == TRUE)
    {
        dw = WaitForMultipleObjects(count, handle_table, FALSE, INFINITE);
#pragma warning(default : 4296)
        if ((dw >= WAIT_OBJECT_0) && dw < (WAIT_OBJECT_0 + count))
        {
            int i = dw - WAIT_OBJECT_0;
            if (handle_table[i] == stdin_handle)
            {
                /* There is something new on standard input. */
                INPUT_RECORD record;
                DWORD events_read;

                if (ReadConsoleInput(stdin_handle, &record, 1, &events_read))
                {
                    if (record.EventType == KEY_EVENT)
                    {
                        if ((record.Event.KeyEvent.bKeyDown == TRUE) &&
                            (record.Event.KeyEvent.uChar.AsciiChar == 'q'))
                        {
                            /* There is 'q' on standard input. Quit. */
                            break;
                        }
                    }
                }
            }
            else if (handle_table[i] == process)
            {
                /* Elevated worker process terminated. Quit. */
                break;
            }
            else if (handle_table[i] == data->exit_event)
            {
                /* Read thread has finished. Quit. */
                break;
            }
            else if (handle_table[i] == timer_handle)
            {
                break;
            }
        }
        else if (dw == WAIT_FAILED)
        {
            fprintf(stderr, "WaitForMultipleObjects failed in wait_for_exit_signal(): %d\n", GetLastError());
            break;
        }
    }

    if (timer_handle != INVALID_HANDLE_VALUE)
    {
        CancelWaitableTimer(timer_handle);
        CloseHandle(timer_handle);
    }
}

static int start_capture(struct thread_data *data)
{
    HANDLE pipe_handle = INVALID_HANDLE_VALUE;
    HANDLE process = INVALID_HANDLE_VALUE;
    HANDLE thread = NULL;
    DWORD thread_id;

    /* Sanity check capture configuration. */
    if ((data->capture_all == FALSE) &&
        (data->capture_new == FALSE) &&
        (data->address_list == NULL))
    {
        fprintf(stderr, "Selected capture options result in empty capture.\n");
        fprintf(stderr, "Add command-line option -A to capture from all devices.\n");
        return -1;
    }

    if (FALSE == USBPcapInitAddressFilter(&data->filter, data->address_list, data->capture_all))
    {
        fprintf(stderr, "USBPcapInitAddressFilter failed!\n");
        return -1;
    }

    data->exit_event = CreateEvent(NULL, /* Handle cannot be inherited */
                                   TRUE, /* Manual Reset */
                                   FALSE, /* Default to not signalled */
                                   NULL);

    memset(&data->descriptors, 0, sizeof(data->descriptors));

    if (IsElevated() == TRUE)
    {
        data->read_handle = INVALID_HANDLE_VALUE;
        if (strncmp("-", data->filename, 2) == 0)
        {
            data->write_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            data->output_created = (data->write_handle != INVALID_HANDLE_VALUE);
        }
        else if (data->store_mode == USBPCAP_STORE_MODE_ON_MATCH)
        {
            data->write_handle = INVALID_HANDLE_VALUE;
        }
        else
        {
            data->write_handle = CreateFileA(data->filename,
                                             GENERIC_WRITE,
                                             0,
                                             NULL,
                                             CREATE_NEW,
                                             FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED,
                                             NULL);
            data->output_created = (data->write_handle != INVALID_HANDLE_VALUE);
        }

        if (data->inject_descriptors)
        {
            data->descriptors.descriptors = descriptors_generate_pcap(data->device, &data->descriptors.descriptors_len,
                                                                      &data->filter);
            data->descriptors.buf_written = 0;
        }

        data->read_handle = create_filter_read_handle(data);

        thread = CreateThread(NULL, /* default security attributes */
                              0,    /* use default stack size */
                              read_thread,
                              data,
                              0,    /* use default creation flag */
                              &thread_id);

        if (thread == NULL)
        {
            fprintf(stderr, "Failed to create thread\n");
            data->process = FALSE;
        }
    }
    else
    {
        PWSTR appPath = NULL;
        PWSTR appCmdLine = NULL;

        BOOL in_job = FALSE;

        if (FALSE == generate_worker_command_line(data, &appPath, &appCmdLine, &pipe_handle))
        {
            fprintf(stderr, "Failed to generate command line\n");
            data->process = FALSE;
        }
        else
        {
            /* Default state is USBPcapCMD running outside any job and hence
             * we need to create new job to take care of worker processes.
             */
            BOOL needs_breakaway = FALSE;
            BOOL needs_new_job = TRUE;

            /* We are not elevated. Check if we are running inside a job. */
            IsProcessInJob(GetCurrentProcess(), NULL, &in_job);

            if (in_job)
            {
                /* We are running inside a job. This can be Visual Studio debug session
                 * job or Windows 8.1 Wireshark job or USBPcap job or anything else.
                 *
                 * If the job has JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, then assume
                 * that whoever create the job will get care of any dangling processes.
                 *
                 * If the job has JOB_OBJECT_LIMIT_BREAKAWAY_OK (which is the case for
                 * Visual Studio and Windows 8.1 jobs) then we need to create intermediate
                 * worker to launch elevated worker. The intermediate worker needs to
                 * break from parent job.
                 *
                 * If the job has JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK we could omit
                 * the intermediate worker, but keep it there so there's no race condion
                 * (if parent gets terminated after executing elevated worker but before
                 * the elevated worker is assigned to a job, then the elevated worker
                 * will need to be manually terminated). If we are not running inside
                 * a job this race condition is not a problem because we first assign
                 * our process to a job (and hence all newly created processes are
                 * automatically assigned to that job).
                 *
                 *
                 * All this is because ShellExecuteEx() does not support
                 * CREATE_BREAKAWAY_FROM_JOB nor CREATE_SUSPENDED flags.
                 * CreateProcess() supports CREATE_BREAKAWAY_FROM_JOB and CREATE_SUSPENDED
                 * flag but do not support "runas" option. USBPcapCMD manifest does not
                 * require administrator access because that would result in UAC screen
                 * every time Wireshark gets extcap interface options.
                 */

                JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;

                memset(&info, 0, sizeof(info));
                if (0 == QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation,
                                                   &info, sizeof(info), NULL))
                {
                    fprintf(stderr, "Failed to query job information - %d\n", GetLastError());
                    /* This is fatal error. */
                    exit(-1);
                }

                if (info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
                {
                    /* There is no need to breakaway nor to create new job. */
                    needs_breakaway = FALSE;
                    needs_new_job = FALSE;
                }
                else if (info.BasicLimitInformation.LimitFlags &
                         (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))
                {
                   needs_breakaway = TRUE;
                   needs_new_job = TRUE;
                }
                else
                {
                    fprintf(stderr, "Unhandled job limit flags 0x%08X\n", info.BasicLimitInformation.LimitFlags);
                    /* This is not fatal. We cannot perform job breakaway though! */
                    needs_breakaway = FALSE;
                    needs_new_job = FALSE;
                }
            }

            if (needs_new_job)
            {
                if (data->job_handle == INVALID_HANDLE_VALUE)
                {
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;

                    data->job_handle = CreateJobObject(NULL, NULL);
                    if (data->job_handle == NULL)
                    {
                        fprintf(stderr, "Failed to create job object!\n");
                        data->process = FALSE;
                        data->job_handle = INVALID_HANDLE_VALUE;
                        return -1;
                    }

                    memset(&info, 0, sizeof(info));
                    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                    SetInformationJobObject(data->job_handle, JobObjectExtendedLimitInformation, &info, sizeof(info));
                }

                /* If breakaway is not needed for worker process, then assign ourselves to newly created job.
                 * This will result in automatic worker process assignment to newly created job.
                 */
                if (needs_breakaway == FALSE)
                {
                    if (AssignProcessToJobObject(data->job_handle, GetCurrentProcess()) == FALSE)
                    {
                        fprintf(stderr, "Failed to Assign process to job object - %d\n",
                                GetLastError());
                        /* This is fatal error. */
                        exit(-1);
                    }
                }
            }

            if (needs_breakaway == FALSE)
            {
                /* Create elevated worker process. It will automatically be assigned to proper job. */
                process = create_elevated_worker(appPath, appCmdLine);
            }
            else
            {
                process = create_breakaway_worker_in_job(data, appPath, appCmdLine);
            }

            /* Free worker path and command line strings as these are no longer needed. */
            free(appPath);
            free(appCmdLine);
            appPath = NULL;
            appCmdLine = NULL;

            if (process != INVALID_HANDLE_VALUE)
            {
                if (strncmp("-", data->filename, 2) == 0)
                {
                    data->write_handle = GetStdHandle(STD_OUTPUT_HANDLE);
                    data->read_handle = pipe_handle;

                    thread = CreateThread(NULL, /* default security attributes */
                                          0,    /* use default stack size */
                                          read_thread,
                                          data,
                                          0,    /* use default creation flag */
                                          &thread_id);
                }
                else
                {
                    /* Worker process saves directly to file */
                    data->write_handle = INVALID_HANDLE_VALUE;
                    data->read_handle = INVALID_HANDLE_VALUE;
                }
            }
            else
            {
                /* Worker couldn't be started. */
                data->process = FALSE;
                if (pipe_handle != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(pipe_handle);
                    pipe_handle = INVALID_HANDLE_VALUE;
                }
            }
        }
    }

    wait_for_exit_signal(data, process);
    data->process = FALSE;
    if (data->exit_event != INVALID_HANDLE_VALUE)
    {
        SetEvent(data->exit_event);
    }

    /* If we created worker thread, wait for it to terminate. */
    if (thread != NULL)
    {
        WaitForSingleObject(thread, INFINITE);
    }

    /* Closing read and write handles will terminate worker process. */

    if ((data->read_handle == INVALID_HANDLE_VALUE) &&
        (data->write_handle == INVALID_HANDLE_VALUE))
    {
        /* We should kill worker process if we created it.
         * We have no other way to let process know that it needs to quit.
         */
        if (process != INVALID_HANDLE_VALUE)
        {
            TerminateProcess(process, 0);
        }
    }

    if (data->read_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data->read_handle);
    }

    if (data->write_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data->write_handle);
    }

    /* If we created worker process, wait for it to terminate. */
    if (process != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(process, INFINITE);
        CloseHandle(process);
    }

    if ((data->output_created == FALSE) &&
        (data->filename != NULL) &&
        (strncmp(data->filename, "-", 2) != 0) &&
        PathFileExistsA(data->filename))
    {
        data->output_created = TRUE;
    }

    if (data->descriptors.descriptors)
    {
        descriptors_free_pcap(data->descriptors.descriptors);
    }

    return data->output_created || (data->store_mode == USBPCAP_STORE_MODE_IMMEDIATE) ? 0 : 1;
}

static void print_extcap_version(void)
{
    printf("extcap {version=" USBPCAPCMD_VERSION_STR "}{help=http://desowin.org/usbpcap/}\n");
}

static void print_extcap_interfaces(void)
{
    int i = 0;
    filters_initialize();

    while (usbpcapFilters[i] != NULL)
    {
        char *tmp = strrchr(usbpcapFilters[i]->device, '\\');
        if (tmp == NULL)
        {
            tmp = usbpcapFilters[i]->device;
        }
        else
        {
            tmp++;
        }

        printf("interface {value=%s}{display=%s}\n",
               usbpcapFilters[i]->device, tmp);
        i++;
    }

    filters_free();
}

static void print_extcap_dlts(void)
{
    printf("dlt {number=249}{name=USBPCAP}{display=USBPcap}\n");
}

static int print_extcap_options(const char *device)
{
    if (device == NULL)
    {
        return -1;
    }

    printf("arg {number=0}{call=--snaplen}"
           "{display=Snapshot length}{tooltip=Snapshot length}"
           "{type=unsigned}{default=%d}\n", DEFAULT_SNAPSHOT_LENGTH);
    printf("arg {number=1}{call=--bufferlen}"
           "{display=Capture buffer length}"
           "{tooltip=USBPcap kernel-mode capture buffer length in bytes}"
           "{type=integer}{range=0,134217728}{default=%d}\n",
           DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE);
    printf("arg {number=2}{call=--capture-from-all-devices}"
           "{display=Capture from all devices connected}"
           "{tooltip=Capture from all devices connected despite other options}"
           "{type=boolflag}{default=true}\n");
    printf("arg {number=3}{call=--capture-from-new-devices}"
           "{display=Capture from newly connected devices}"
           "{tooltip=Automatically start capture on all newly connected devices}"
           "{type=boolflag}{default=true}\n");
    printf("arg {number=4}{call=--inject-descriptors}"
           "{display=Inject already connected devices descriptors into capture data}"
           "{type=boolflag}{default=true}\n");
    printf("arg {number=%d}{call=--devices}{display=Attached USB Devices}{tooltip=Select individual devices to capture from}{type=multicheck}\n",
           EXTCAP_ARGNUM_MULTICHECK);

    enumerate_print_extcap_config(device);

    return 0;
}

static int run_as_extcap = 0;
static int do_extcap_version = 0;
static int do_extcap_interfaces = 0;
static int do_extcap_dlts = 0;
static int do_extcap_config = 0;
static int do_extcap_capture = 0;
static const char *wireshark_version = NULL;
static const char *extcap_interface = NULL;
static const char *extcap_fifo = NULL;

int cmd_extcap(struct thread_data *data)
{
    int ret = -1;

    if (do_extcap_version)
    {
        print_extcap_version();
        ret = 0;
    }

    if (do_extcap_interfaces)
    {
        print_extcap_interfaces();
        ret = 0;
    }

    if (do_extcap_dlts)
    {
        print_extcap_dlts();
        ret = 0;
    }

    if (do_extcap_config)
    {
        ret = print_extcap_options(extcap_interface);
    }

    /* --capture */
    if (do_extcap_capture)
    {
        if ((extcap_fifo == NULL) || (extcap_interface == NULL))
        {
            /* No fifo nor interface to capture from. */
            return -1;
        }

        if (data->device != NULL)
        {
            free(data->device);
        }
        data->device = _strdup(extcap_interface);
        if (data->filename != NULL)
        {
            free(data->filename);
        }
        data->filename = _strdup(extcap_fifo);
        data->process = TRUE;

        data->read_handle = INVALID_HANDLE_VALUE;
        data->write_handle = INVALID_HANDLE_VALUE;

        ret = start_capture(data);
        return (ret == 1) ? 0 : ret;
    }

    return ret;
}

BOOLEAN IsHandleRedirected(DWORD handle)
{
    HANDLE h = GetStdHandle(handle);
    if (h)
    {
        BY_HANDLE_FILE_INFORMATION fi;
        if (GetFileInformationByHandle(h, &fi))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static void attach_parent_console()
{
    HANDLE inHandle, outHandle, errHandle;
    BOOL outRedirected, errRedirected;

    inHandle = GetStdHandle(STD_INPUT_HANDLE);
    outHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    errHandle = GetStdHandle(STD_ERROR_HANDLE);

    outRedirected = IsHandleRedirected(STD_OUTPUT_HANDLE);
    errRedirected = IsHandleRedirected(STD_ERROR_HANDLE);

    if (outRedirected && errRedirected)
    {
        /* Both standard output and error handles are redirected.
         * There is no point in attaching to parent process console.
         */
        return;
    }

    if (AttachConsole(ATTACH_PARENT_PROCESS) == 0)
    {
        /* Console attach failed. */
        return;
    }

    if (inHandle != GetStdHandle(STD_INPUT_HANDLE))
    {
        /* Restore input handle. */
        SetStdHandle(STD_INPUT_HANDLE, inHandle);
    }

    /* Console attach succeded */
    if (outRedirected == FALSE)
    {
        freopen("CONOUT$", "w", stdout);
    }
    else if (GetStdHandle(STD_OUTPUT_HANDLE) != outHandle)
    {
        /* Attach Console changed STD_OUTPUT_HANDLE even though it is redirected.
         * Restore the redirected handle.
         */
        SetStdHandle(STD_OUTPUT_HANDLE, outHandle);
    }

    if (errRedirected == FALSE)
    {
        freopen("CONOUT$", "w", stderr);
    }
    else if (GetStdHandle(STD_ERROR_HANDLE) != errHandle)
    {
        /* Attach Console changed STD_ERROR_HANDLE even though it is redirected.
         * Restore the redirected handle.
         */
        SetStdHandle(STD_ERROR_HANDLE, errHandle);
    }
}

static void print_help(const char *topic)
{
    int zh = is_chinese_locale();

    if ((topic != NULL) && (_stricmp(topic, "capture") == 0))
    {
        if (zh)
        {
            printf("捕获帮助：\n"
                   "  -d <device>, --device <device>\n"
                   "    要打开的 USBPcap 控制设备。示例：-d \\\\.\\USBPcap1。\n"
                   "  --auto-interface\n"
                   "    自动选择唯一匹配 VID/PID 过滤条件的接口。\n"
                   "  -o <file>, --output <file>\n"
                   "    输出 .pcap 文件名。使用 '-' 表示 stdout（管道模式）。\n"
                   "  -s <len>, --snaplen <len>\n"
                   "    设置抓包快照长度（字节）。默认 65535。\n"
                   "  -b <len>, --bufferlen <len>\n"
                   "    设置内部捕获缓冲区长度。有效范围 <4096,134217728>。\n"
                   "  --duration <seconds>\n"
                   "    指定时长（秒）后停止捕获。0 表示无限制。\n"
                   "  -A, --capture-from-all-devices\n"
                   "    从所选根集线器连接的所有设备捕获数据。\n"
                   "  --capture-from-new-devices\n"
                   "    同时捕获新接入的设备（任意 VID/PID）。\n"
                   "  --inject-descriptors\n"
                   "    将已连接设备的描述符注入捕获数据。\n"
                   "  --store-mode <immediate|on-match>\n"
                   "    immediate：立即写入。on-match：仅在匹配到数据包后才开始写入。\n"
                   "  --json\n"
                   "    以 UTF-8 JSON 格式输出到 stdout，用于设备发现和捕获结果。\n"
                   "  --no-interactive\n"
                   "    参数缺失时直接报错退出，不进入交互模式。\n");
        }
        else
        {
            printf("Capture help:\n"
                   "  -d <device>, --device <device>\n"
                   "    USBPcap control device to open. Example: -d \\\\.\\USBPcap1.\n"
                   "  --auto-interface\n"
                   "    Automatically choose the only interface that matches VID/PID filters.\n"
                   "  -o <file>, --output <file>\n"
                   "    Output .pcap file name. Use '-' for stdout (pipe mode).\n"
                   "  -s <len>, --snaplen <len>\n"
                   "    Sets snapshot length in bytes. Default 65535.\n"
                   "  -b <len>, --bufferlen <len>\n"
                   "    Sets internal capture buffer length. Valid range <4096,134217728>.\n"
                   "  --duration <seconds>\n"
                   "    Stops capture after the specified duration. 0 means unlimited.\n"
                   "  -A, --capture-from-all-devices\n"
                   "    Captures data from all devices connected to selected root hub.\n"
                   "  --capture-from-new-devices\n"
                   "    Also captures newly attached devices (any VID/PID).\n"
                   "  --inject-descriptors\n"
                   "    Inject already connected device descriptors into capture data.\n"
                   "  --store-mode <immediate|on-match>\n"
                   "    immediate: write immediately. on-match: write only after matching packet.\n"
                   "  --json\n"
                   "    Print UTF-8 JSON to stdout for discovery and final capture result.\n"
                   "  --no-interactive\n"
                   "    Fails instead of entering interactive mode when parameters are missing.\n");
        }
        return;
    }

    if ((topic != NULL) && (_stricmp(topic, "filter") == 0))
    {
        if (zh)
        {
            printf("过滤器帮助：\n"
                   "  --vid/--vendor-id <hex-or-dec>   捕获前按 VID 过滤已连接设备。支持 0x 十六进制或十进制。\n"
                   "                                示例：--vid 0x1d57 或 --vid 7511\n"
                   "  --pid/--product-id <hex-or-dec>  可选 PID 过滤，与 --vid/--vendor-id 配合使用。\n"
                   "                                示例：--pid 0xfa60 或 --pid 64096\n"
                   "  --devices <list>              显式指定 USB 地址列表，如 1,2,7。\n"
                   "  --app-filter                  启用应用层过滤（数据包到达用户态后过滤）。\n"
                   "  --endpoint <hex-or-dec>       按端点过滤，如 0x81 (IN) 或 0x02 (OUT)。\n"
                   "  --transfer-type <name>        传输类型：control, bulk, interrupt, isochronous, unknown。\n"
                   "  --capture-from-new-devices    同时捕获任意 VID/PID 的新接入设备。无法按 VID/PID 精确过滤。\n");
        }
        else
        {
            printf("Filter help:\n"
                   "  --vid/--vendor-id <hex-or-dec>   Filter by VID before capture. Supports 0x hex or decimal.\n"
                   "                                Example: --vid 0x1d57 or --vid 7511\n"
                   "  --pid/--product-id <hex-or-dec>  Optional PID filter. Use with --vid/--vendor-id.\n"
                   "                                Example: --pid 0xfa60 or --pid 64096\n"
                   "  --devices <list>              Explicit USB address list, for example 1,2,7.\n"
                   "  --app-filter                  Enable application-layer filtering (post-driver).\n"
                   "  --endpoint <hex-or-dec>       Filter by endpoint, for example 0x81 (IN) or 0x02 (OUT).\n"
                   "  --transfer-type <name>        One of control, bulk, interrupt, isochronous, unknown.\n"
                   "  --capture-from-new-devices    Adds newly connected devices of any VID/PID. Not precise by VID/PID.\n");
        }
        return;
    }

    if ((topic != NULL) && (_stricmp(topic, "json") == 0))
    {
        if (zh)
        {
            printf("JSON 帮助：\n"
                   "  --json                        以机器可读的 UTF-8 JSON 格式输出到 stdout。\n"
                   "  JSON 模式下所有输出均为合法 JSON，错误信息包含 errorCode、message 和可选的 hint。\n"
                   "  捕获前使用 --list-interfaces 或 --list-devices 进行设备发现（建议加 --json）。\n"
                   "  自动化场景推荐组合：--json --no-interactive。\n");
        }
        else
        {
            printf("JSON help:\n"
                   "  --json                        Print machine-readable UTF-8 JSON to stdout.\n"
                   "  All output is valid JSON; errors include errorCode, message, and optional hint.\n"
                   "  Use --list-interfaces or --list-devices with --json for device discovery.\n"
                   "  Recommended for automation: --json --no-interactive.\n");
        }
        return;
    }

    if ((topic != NULL) && (_stricmp(topic, "examples") == 0))
    {
        printf("Examples:\n"
               "  USBPcapCap.exe --list-interfaces --json\n"
               "  USBPcapCap.exe --list-devices --json\n"
               "  USBPcapCap.exe --list-devices --interface \\\\.\\USBPcap2 --json\n"
               "  USBPcapCap.exe -d \\\\.\\USBPcap2 --vid 0x1d57 --output out.pcap --duration 10 --json --no-interactive\n"
               "  USBPcapCap.exe -d \\\\.\\USBPcap2 --vid 0x1d57 --endpoint 0x81 --app-filter --store-mode on-match --output monitor.pcap --duration 3600 --json --no-interactive\n");
        return;
    }

    if (zh)
    {
        printf("用法：USBPcapCap.exe [选项]\n"
               "  示例：\n"
               "  1. 指定 VID/PID 捕获一段文件：\n"
               "    USBPcapCap.exe -d \\\\.\\USBPcap2 --vid 0x1d57 --pid 0xfa60 -o capture.pcap --json --no-interactive\n"
               "  2. 在上例基础上增加时长限制（30 秒自动停止）：\n"
               "    USBPcapCap.exe -d \\\\.\\USBPcap2 --vid 0x1d57 --pid 0xfa60 -o capture.pcap --duration 30 --json --no-interactive\n"
               "  --------------------------------------------------\n"
               "  新增选项：\n"
               "  --list-devices [--interface <name>]\n"
               "    列出 USB 设备（VID/PID/描述/Hub）。不加 --interface 时列出所有接口的全部设备，\n"
               "    加 --interface 时仅列出指定接口下的设备。\n"
               "  --auto-interface\n"
               "    自动扫描所有 USBPcap 接口，找到唯一匹配 --vid/--vendor-id / --pid/--product-id 的接口并使用。\n"
               "    适用于不确定目标设备在哪个 USBPcap 接口上的场景，避免手动指定 -d。\n"
               "    前提：VID/PID 在所有接口中仅匹配到一个，否则报错。\n"
               "  --vid/--vendor-id <hex-or-dec>, --pid/--product-id <hex-or-dec>\n"
               "    捕获前按 VID/PID 过滤已连接设备。仅匹配 VID/PID 的设备会被捕获。\n"
               "    示例：--vid 0x1d57 --pid 0xfa60  (十六进制)\n"
               "          --vid 7511 --pid 64096      (十进制亦可)\n"
               "  --duration <seconds>\n"
               "    指定时长（秒）后自动停止捕获。默认 0 表示无限制，需手动 Ctrl+C 停止。\n"
               "    示例：--duration 30   (30 秒后自动停止)\n"
               "  --capture-from-new-devices\n"
               "    在捕获过程中也抓取中途新插入的 USB 设备数据。\n"
               "    用于热插拔测试场景：如设备周期性上下电、USB 插拔测试时需要捕获瞬时连接设备的流量。\n"
               "    注意：新设备的 VID/PID 不受过滤限制，只要是新接入的设备都会被捕获。\n"
               "  --inject-descriptors\n"
               "    在捕获开始前将已连接设备的 USB 描述符（设备/配置/接口/端点描述符）注入 pcap 文件。\n"
               "    这样 Wireshark 等工具能解析出设备类型和端点信息，即使实际抓包中未包含描述符请求。\n"
               "    注意：仅注入当前已连接设备的描述符，不包含中途新插入的设备。\n"
               "  --store-mode <immediate|on-match>\n"
               "    immediate：所有数据包立即写入 pcap 文件（默认行为）。\n"
               "    on-match：先缓存数据包，直到出现第一个匹配过滤规则的数据包后才开始写入，\n"
               "              之前缓存的数据包也会一并写入。适合只关注「匹配后」的流量。\n"
               "  --app-filter --endpoint <hex-or-dec> --transfer-type <name>\n"
               "    启用应用层（用户态）数据包过滤，在数据包到达用户态后按条件丢弃不匹配的包。\n"
               "    --endpoint：按 USB 端点地址过滤，如 0x81 (IN 端点)、0x02 (OUT 端点)。\n"
               "    --transfer-type：按传输类型过滤，可选：control, bulk, interrupt, isochronous, unknown。\n"
               "    注意：驱动层仍会捕获所有数据包，过滤发生在写入 pcap 之前。\n"
               "  --json\n"
               "    以 UTF-8 JSON 格式输出信息到 stdout（设备发现和捕获结果），便于脚本/程序解析。\n"
               "    非 JSON 模式输出人类可读文本。JSON 模式下所有错误也以 JSON 返回，\n"
               "    包含 errorCode、message 和可选的 hint 字段。\n"
               "    推荐自动化/无人值守场景使用 --json，需同时加 --no-interactive。\n"
               "  --no-interactive\n"
               "    批量/自动化模式：缺少必填参数时直接返回错误并退出，不会弹出交互式提示或控制台窗口。\n"
               "    适用于脚本调用、服务调用、CI/CD 等无人值守场景，与 --json 组合使用效果最佳。\n"
               "  --------------------------------------------------\n"
               "  -h, -?, --help [capture|filter|json|examples]\n"
               "    打印帮助信息。子主题：capture, filter, json, examples。\n"
               "  --list-interfaces\n"
               "    列出可用的 USBPcap 接口。\n"
               "  -d <device>, --device <device>, --interface <name>\n"
               "    要打开的 USBPcap 控制设备。示例：-d \\\\.\\USBPcap1。\n"
               "  -o <file>, --output <file>\n"
               "    输出 .pcap 文件名。使用 '-' 表示 stdout（管道模式）。\n"
               "  -s <len>, --snaplen <len>\n"
               "    设置抓包快照长度。\n"
               "  -b <len>, --bufferlen <len>\n"
               "    设置内部捕获缓冲区长度。有效范围 <4096,134217728>。\n"
               "  -A, --capture-from-all-devices\n"
               "    从所选根集线器连接的所有设备捕获数据。\n"
               "  --devices <list>\n"
               "    仅从列表中指定地址的设备捕获数据。\n"
               "  -I, --init-non-standard-hwids\n"
               "    初始化 USBPcapDriver 使用的 NonStandardHWIDs 注册表项。\n");
    }
    else
    {
        printf("Usage: USBPcapCap.exe [options]\n"
               "  Examples:\n"
               "  1. Capture with VID/PID filter:\n"
               "    USBPcapCap.exe -d \\\\.\\USBPcap2 --vid 0x1d57 --pid 0xfa60 -o capture.pcap --json --no-interactive\n"
               "  2. Add duration limit (auto-stop after 30s):\n"
               "    USBPcapCap.exe -d \\\\.\\USBPcap2 --vid 0x1d57 --pid 0xfa60 -o capture.pcap --duration 30 --json --no-interactive\n"
               "  --------------------------------------------------\n"
               "  New options:\n"
               "  --list-devices [--interface <name>]\n"
               "    Lists USB devices (VID/PID/description/hub). Without --interface, lists all\n"
               "    devices across every USBPcap interface. With --interface, limits to that interface.\n"
               "  --auto-interface\n"
               "    Automatically scans all USBPcap interfaces and selects the one that uniquely\n"
               "    matches the given --vid/--vendor-id / --pid/--product-id. Use when you don't know which\n"
               "    USBPcap interface your target device is on — eliminates manual -d discovery.\n"
               "    Prerequisite: VID/PID must match exactly one interface, or an error is returned.\n"
               "  --vid/--vendor-id <hex-or-dec>, --pid/--product-id <hex-or-dec>\n"
               "    Filters connected devices by VID/PID before capture starts. Only matching devices\n"
               "    are captured. Supports hex (0x prefix) or decimal.\n"
               "    Example: --vid 0x1d57 --pid 0xfa60  (hex)\n"
               "             --vendor-id 7511 --product-id 64096      (decimal also works)\n"
               "  --duration <seconds>\n"
               "    Automatically stops capture after N seconds. Default 0 = unlimited (Ctrl+C to stop).\n"
               "    Example: --duration 30   (auto-stop after 30s)\n"
               "  --capture-from-new-devices\n"
               "    Also captures USB devices that are hot-plugged during the capture session.\n"
               "    Use for hot-plug testing: devices that power-cycle periodically, or USB\n"
               "    plug/unplug scenarios where you need to capture transient device traffic.\n"
               "    Note: new devices are captured regardless of VID/PID filter settings.\n"
               "  --inject-descriptors\n"
               "    Injects the USB descriptors (device/config/interface/endpoint) of currently\n"
               "    connected devices into the pcap file before capture begins. This helps tools\n"
               "    like Wireshark resolve device types and endpoint info even when the capture\n"
               "    doesn't contain the original descriptor requests.\n"
               "    Note: only injects descriptors present at capture start, not mid-session hot-plugs.\n"
               "  --store-mode <immediate|on-match>\n"
               "    immediate: write every packet to the pcap file immediately (default).\n"
               "    on-match: buffer packets until a matching packet arrives, then start writing\n"
               "              (previously buffered packets are flushed first). Useful when you\n"
               "              only care about traffic after a specific trigger event.\n"
               "  --app-filter --endpoint <hex-or-dec> --transfer-type <name>\n"
               "    Enables user-mode packet filtering. Packets that don't match are discarded\n"
               "    before writing to the pcap file.\n"
               "    --endpoint: filter by USB endpoint address, e.g. 0x81 (IN), 0x02 (OUT).\n"
               "    --transfer-type: control, bulk, interrupt, isochronous, or unknown.\n"
               "    Note: the driver still captures all packets; filtering happens in user mode.\n"
               "  --json\n"
               "    Output machine-readable UTF-8 JSON to stdout for discovery results and capture\n"
               "    results. Errors also return JSON with errorCode, message, and optional hint.\n"
               "    Recommended for automation/scripting; combine with --no-interactive.\n"
               "  --no-interactive\n"
               "    Batch/automation mode: fails immediately with an error instead of prompting\n"
               "    interactively or opening a console window when required parameters are missing.\n"
               "    Designed for scripts, services, and CI/CD pipelines. Best used with --json.\n"
               "  --------------------------------------------------\n"
               "  -h, -?, --help [capture|filter|json|examples]\n"
               "    Prints help. Topics: capture, filter, json, examples.\n"
               "  --list-interfaces\n"
               "    Lists available USBPcap interfaces.\n"
               "  -d <device>, --device <device>, --interface <name>\n"
               "    USBPcap control device to open. Example: -d \\\\.\\USBPcap1.\n"
               "  -o <file>, --output <file>\n"
               "    Output .pcap file name. Use '-' for stdout (pipe mode).\n"
               "  -s <len>, --snaplen <len>\n"
               "    Sets snapshot length.\n"
               "  -b <len>, --bufferlen <len>\n"
               "    Sets internal capture buffer length. Valid range <4096,134217728>.\n"
               "  -A, --capture-from-all-devices\n"
               "    Captures data from all devices connected to selected root hub.\n"
               "  --devices <list>\n"
               "    Captures data only from devices with addresses present in list.\n"
               "  -I, --init-non-standard-hwids\n"
               "    Initializes NonStandardHWIDs registry key used by USBPcapDriver.\n");
    }
}

/* Commandline arguments without short option */
#define ARG_DEVICES                    900
#define ARG_CAPTURE_FROM_NEW_DEVICES   901
#define ARG_INJECT_DESCRIPTORS         902
#define ARG_JSON                       903
#define ARG_LIST_INTERFACES            904
#define ARG_LIST_DEVICES               905
#define ARG_VENDOR_ID                  906
#define ARG_PRODUCT_ID                 907
#define ARG_AUTO_INTERFACE             908
#define ARG_DURATION                   909
#define ARG_NO_INTERACTIVE             910
#define ARG_APP_FILTER                 911
#define ARG_ENDPOINT                   912
#define ARG_TRANSFER_TYPE              913
#define ARG_STORE_MODE                 914
#define ARG_EXTCAP_VERSION            1000
#define ARG_EXTCAP_INTERFACES         1001
#define ARG_EXTCAP_INTERFACE          1002
#define ARG_EXTCAP_DLTS               1003
#define ARG_EXTCAP_CONFIG             1004
#define ARG_EXTCAP_CAPTURE            1005
#define ARG_EXTCAP_FIFO               1006

#if _MSC_VER >= 1700
int __cdecl usbpcapcmd_main(int argc, CHAR **argv)
#else
int __cdecl main(int argc, CHAR **argv)
#endif
{
    int ret = -1;
    int capture_ret;
    struct thread_data data;
    usbpcap_match_list matches;
    BOOL json_output = FALSE;
    BOOL list_interfaces_flag = FALSE;
    BOOL list_devices_flag = FALSE;
    BOOL no_interactive = FALSE;
    BOOL auto_interface = FALSE;
    BOOL has_vendor_id = FALSE;
    BOOL has_product_id = FALSE;
    USHORT vendor_id = 0;
    USHORT product_id = 0;
    const char *help_topic = NULL;
    static struct option long_options[] =
    {
        {"help", no_argument, 0, 'h'},
        {"device", required_argument, 0, 'd'},
        {"interface", required_argument, 0, 'd'},
        {"output", required_argument, 0, 'o'},
        {"snaplen", required_argument, 0, 's'},
        {"bufferlen", required_argument, 0, 'b'},
        {"init-non-standard-hwids", no_argument, 0, 'I'},
        /* Capture options. */
        {"json", no_argument, 0, ARG_JSON},
        {"list-interfaces", no_argument, 0, ARG_LIST_INTERFACES},
        {"list-devices", no_argument, 0, ARG_LIST_DEVICES},
        {"devices", required_argument, 0, ARG_DEVICES},
        {"vendor-id", required_argument, 0, ARG_VENDOR_ID},
        {"vid", required_argument, 0, ARG_VENDOR_ID},
        {"product-id", required_argument, 0, ARG_PRODUCT_ID},
        {"pid", required_argument, 0, ARG_PRODUCT_ID},
        {"auto-interface", no_argument, 0, ARG_AUTO_INTERFACE},
        {"duration", required_argument, 0, ARG_DURATION},
        {"no-interactive", no_argument, 0, ARG_NO_INTERACTIVE},
        {"app-filter", no_argument, 0, ARG_APP_FILTER},
        {"endpoint", required_argument, 0, ARG_ENDPOINT},
        {"transfer-type", required_argument, 0, ARG_TRANSFER_TYPE},
        {"store-mode", required_argument, 0, ARG_STORE_MODE},
        {"capture-from-all-devices", no_argument, 0, 'A'},
        {"capture-from-new-devices", no_argument, 0, ARG_CAPTURE_FROM_NEW_DEVICES},
        {"inject-descriptors", no_argument, 0, ARG_INJECT_DESCRIPTORS},
        /* Extcap interface. Please note that there are no short
         * options for these and the numbers are just gopt keys.
         */
        {"extcap-version", optional_argument, 0, ARG_EXTCAP_VERSION},
        {"extcap-interfaces", no_argument, &do_extcap_interfaces, ARG_EXTCAP_INTERFACES},
        {"extcap-interface", required_argument, 0, ARG_EXTCAP_INTERFACE},
        {"extcap-dlts", no_argument, &do_extcap_dlts, ARG_EXTCAP_DLTS},
        {"extcap-config", no_argument, &do_extcap_config, ARG_EXTCAP_CONFIG},
        {"capture", no_argument, &do_extcap_capture, ARG_EXTCAP_CAPTURE},
        {"fifo", required_argument, 0, ARG_EXTCAP_FIFO},
        {0, 0, 0, 0}
    };
    int option_index = 0;
    int c;

    attach_parent_console();
    configure_utf8_console();

    memset(&matches, 0, sizeof(matches));

    data.filename = NULL;
    data.device = NULL;
    data.address_list = NULL;
    data.capture_all = FALSE;
    data.capture_new = FALSE;
    data.inject_descriptors = FALSE;
    data.snaplen = DEFAULT_SNAPSHOT_LENGTH;
    data.bufferlen = DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE;
    data.job_handle = INVALID_HANDLE_VALUE;
    data.worker_process_thread = INVALID_HANDLE_VALUE;
    data.read_handle = INVALID_HANDLE_VALUE;
    data.write_handle = INVALID_HANDLE_VALUE;
    data.exit_event = INVALID_HANDLE_VALUE;
    data.duration_seconds = 0;
    data.store_mode = USBPCAP_STORE_MODE_IMMEDIATE;
    data.triggered = FALSE;
    data.output_created = FALSE;
    data.dropped_packets = 0;
    memset(&data.app_filter, 0, sizeof(data.app_filter));
    memset(data.device_metadata, 0, sizeof(data.device_metadata));

    while (-1 != (c = getopt_long(argc, argv, "hd:o:s:b:IA", long_options, &option_index)))
    {
        switch (c)
        {
            case 0:
                /* getopt_long has set the flag. */
                break;
            case 'h': /* --help */
                if ((optind < argc) && (argv[optind][0] != '-'))
                {
                    help_topic = argv[optind];
                }
                print_help(help_topic);
                return 0;
            case 'd': /* --device */
#pragma warning(push)
#pragma warning(disable:28193)
                data.device = _strdup(optarg);
#pragma warning(pop)
                break;
            case 'o': /* --output */
#pragma warning(push)
#pragma warning(disable:28193)
                data.filename = _strdup(optarg);
#pragma warning(pop)
                break;
            case 's': /* --snaplen */
                data.snaplen = atol(optarg);
                if (data.snaplen == 0)
                {
                    fprintf(stderr, "Invalid snapshot length!\n");
                    return -1;
                }
                break;
            case 'b': /* --bufferlen */
                data.bufferlen = atol(optarg);
                /* Minimum buffer size if 4 KiB, maximum 128 MiB */
                if (data.bufferlen < 4096 || data.bufferlen > 134217728)
                {
                    fprintf(stderr, "Invalid buffer length! "
                                    "Valid range <4096,134217728>.\n");
                    return -1;
                }
                break;
            case 'I': /* --init-non-standard-hwids */
                init_non_standard_roothub_hwid();
                return 0;
            case ARG_DEVICES:
                data.address_list = optarg;
                break;
            case ARG_JSON:
                json_output = TRUE;
                break;
            case ARG_LIST_INTERFACES:
                list_interfaces_flag = TRUE;
                break;
            case ARG_LIST_DEVICES:
                list_devices_flag = TRUE;
                break;
            case ARG_VENDOR_ID:
                if (parse_u16_value(optarg, &vendor_id) == FALSE)
                {
                    fprintf(stderr, "Invalid vendor id: %s\n", optarg);
                    return -1;
                }
                has_vendor_id = TRUE;
                break;
            case ARG_PRODUCT_ID:
                if (parse_u16_value(optarg, &product_id) == FALSE)
                {
                    fprintf(stderr, "Invalid product id: %s\n", optarg);
                    return -1;
                }
                has_product_id = TRUE;
                break;
            case ARG_AUTO_INTERFACE:
                auto_interface = TRUE;
                break;
            case ARG_DURATION:
                if (parse_u32_value(optarg, &data.duration_seconds) == FALSE)
                {
                    fprintf(stderr, "Invalid duration: %s\n", optarg);
                    return -1;
                }
                break;
            case ARG_NO_INTERACTIVE:
                no_interactive = TRUE;
                break;
            case ARG_APP_FILTER:
                data.app_filter.enabled = TRUE;
                break;
            case ARG_ENDPOINT:
            {
                USHORT endpoint;
                if (parse_u16_value(optarg, &endpoint) == FALSE || endpoint > 0xFF)
                {
                    fprintf(stderr, "Invalid endpoint: %s\n", optarg);
                    return -1;
                }
                data.app_filter.enabled = TRUE;
                data.app_filter.has_endpoint = TRUE;
                data.app_filter.endpoint = (UCHAR)endpoint;
                break;
            }
            case ARG_TRANSFER_TYPE:
                if (parse_transfer_type(optarg, &data.app_filter.transfer_type) == FALSE)
                {
                    fprintf(stderr, "Invalid transfer type: %s\n", optarg);
                    return -1;
                }
                data.app_filter.enabled = TRUE;
                data.app_filter.has_transfer_type = TRUE;
                break;
            case ARG_STORE_MODE:
                if (_stricmp(optarg, "immediate") == 0)
                {
                    data.store_mode = USBPCAP_STORE_MODE_IMMEDIATE;
                }
                else if (_stricmp(optarg, "on-match") == 0)
                {
                    data.store_mode = USBPCAP_STORE_MODE_ON_MATCH;
                }
                else
                {
                    fprintf(stderr, "Invalid store mode: %s\n", optarg);
                    return -1;
                }
                break;
            case 'A': /* --capture-from-all-devices */
                data.capture_all = TRUE;
                break;
            case ARG_CAPTURE_FROM_NEW_DEVICES:
                data.capture_new = TRUE;
                break;
            case ARG_INJECT_DESCRIPTORS:
                data.inject_descriptors = TRUE;
                break;
            case ARG_EXTCAP_VERSION:
                do_extcap_version = 1;
                wireshark_version = optarg;
                break;
            case ARG_EXTCAP_INTERFACE:
                extcap_interface = optarg;
                break;
            case ARG_EXTCAP_FIFO:
                run_as_extcap = 1;
                extcap_fifo = optarg;
                break;

            case ':':
            case '?':
                fprintf(stderr, "Try 'USBPcapCap.exe --help' for more information.\n");
                return -1;

            default:
                printf("getopt_long() returned character code 0x%X. Please report.\n", c);
                return -1;
        }
    }

    if (has_vendor_id)
    {
        data.app_filter.has_vendor_id = TRUE;
        data.app_filter.vendor_id = vendor_id;
    }
    if (has_product_id)
    {
        data.app_filter.has_product_id = TRUE;
        data.app_filter.product_id = product_id;
    }

    if (data.snaplen > (data.bufferlen - sizeof(pcaprec_hdr_t)))
    {
        fprintf(stderr, "Packets larger than %zu bytes won't be captured due to too small buffer.\n",
            (size_t)(data.bufferlen - sizeof(pcaprec_hdr_t)));
    }

    /* Handle extcap options separately from standard USBPcapCMD options. */
    if (run_as_extcap || do_extcap_version || do_extcap_interfaces || do_extcap_dlts || do_extcap_config || do_extcap_capture)
    {
        ret = cmd_extcap(&data);
    }
    else if (list_interfaces_flag)
    {
        ret = list_interfaces(json_output);
    }
    else if (list_devices_flag)
    {
        if (data.device != NULL)
        {
            ret = list_devices(data.device, json_output);
        }
        else
        {
            ret = list_all_devices(json_output);
        }
    }
    else
    {
        ret = 0;

        if (auto_interface && (data.device == NULL))
        {
            if (!has_vendor_id && !has_product_id)
            {
                if (json_output)
                {
                    print_json_error("AUTO_INTERFACE_REQUIRES_FILTER",
                                     "--auto-interface requires --vendor-id or --product-id.",
                                     "Specify --vendor-id first, or pass --device explicitly.");
                }
                else
                {
                    fprintf(stderr, "--auto-interface requires --vendor-id or --product-id.\n");
                }
                ret = -1;
            }
            else if (auto_select_interface(has_vendor_id, vendor_id, has_product_id, product_id, &data.device, &matches) == FALSE)
            {
                if (json_output)
                {
                    print_json_error("AUTO_INTERFACE_NOT_UNIQUE",
                                     "Unable to auto-select a unique USBPcap interface for the requested VID/PID.",
                                     "Run USBPcapCap.exe --list-interfaces --json and USBPcapCap.exe --list-devices --device <name> --json.");
                }
                else
                {
                    fprintf(stderr, "Unable to auto-select a unique USBPcap interface for the requested VID/PID.\n");
                }
                ret = -1;
            }
        }

        if ((ret == 0) && (data.device != NULL) && (has_vendor_id || has_product_id) && (matches.count == 0))
        {
            if (resolve_filter_matches(data.device,
                                       has_vendor_id,
                                       vendor_id,
                                       has_product_id,
                                       product_id,
                                       &matches) == FALSE)
            {
                if (json_output)
                {
                    print_json_error("ENUMERATION_FAILED",
                                     "Failed to enumerate connected USB devices.",
                                     "Verify that the USBPcap driver is installed and the selected interface exists.");
                }
                else
                {
                    fprintf(stderr, "Failed to enumerate connected USB devices.\n");
                }
                ret = -1;
            }
            else if (matches.count == 0)
            {
                if (json_output)
                {
                    print_json_error("NO_MATCHED_DEVICE",
                                     "No connected USB device matched the requested VID/PID.",
                                     "Run USBPcapCap.exe --list-devices --device <name> --json to inspect current devices.");
                }
                else
                {
                    fprintf(stderr, "No connected USB device matched the requested VID/PID.\n");
                }
                ret = -1;
            }
            else
            {
                data.address_list = matches.address_list;
            }
        }

        if ((ret == 0) && ((data.filename == NULL) || (data.device == NULL)))
        {
            if (no_interactive)
            {
                if (json_output)
                {
                    print_json_error("MISSING_REQUIRED_ARGUMENT",
                                     "Capture mode requires both --device and --output unless discovery mode is used.",
                                     "Use --list-interfaces / --list-devices first, or omit --no-interactive to use interactive mode.");
                }
                else
                {
                    fprintf(stderr, "Capture mode requires both --device and --output unless discovery mode is used.\n");
                }
                ret = -1;
            }
            else
            {
                if (data.filename != NULL)
                {
                    free(data.filename);
                    data.filename = NULL;
                }

                if (data.device != NULL)
                {
                    free(data.device);
                    data.device = NULL;
                }

                ret = cmd_interactive(&data);
            }
        }

        if (ret == 0)
        {
            if (populate_device_metadata(&data, data.device) == FALSE)
            {
                memset(data.device_metadata, 0, sizeof(data.device_metadata));
            }

            data.process = TRUE;
            capture_ret = start_capture(&data);
            if ((capture_ret == 1) && (data.store_mode == USBPCAP_STORE_MODE_ON_MATCH))
            {
                ret = 0;
            }
            else
            {
                ret = capture_ret;
            }

            if (json_output)
            {
                printf("{\"ok\":true,\"storeMode\":");
                json_print_escaped(stdout, data.store_mode == USBPCAP_STORE_MODE_ON_MATCH ? "on-match" : "immediate");
                printf(",\"triggered\":%s,\"output\":", data.triggered ? "true" : "false");
                if (data.output_created && (data.filename != NULL))
                {
                    json_print_escaped(stdout, data.filename);
                }
                else
                {
                    printf("null");
                }
                printf(",\"droppedPackets\":%lu,\"matchedDevices\":[", data.dropped_packets);
                for (option_index = 0; option_index < (int)matches.count; option_index++)
                {
                    if (option_index > 0)
                    {
                        printf(",");
                    }
                    printf("{\"interface\":");
                    json_print_escaped(stdout, data.device);
                    printf(",\"address\":%u,\"vendorId\":\"0x%04x\",\"productId\":\"0x%04x\"}",
                           matches.items[option_index].address,
                           matches.items[option_index].vendor_id,
                           matches.items[option_index].product_id);
                }
                printf("]");
                if ((data.store_mode == USBPCAP_STORE_MODE_ON_MATCH) && (data.triggered == FALSE))
                {
                    printf(",\"reason\":");
                    json_print_escaped(stdout, "No packet matched trigger conditions before capture ended.");
                }
                printf("}\n");
            }
        }
    }

    /* Clean up */
    if (data.device != NULL)
    {
        free(data.device);
    }
    if (data.filename != NULL)
    {
        free(data.filename);
    }
    if (data.worker_process_thread != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data.worker_process_thread);
    }
    if (data.job_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data.job_handle);
    }
    if (data.exit_event != INVALID_HANDLE_VALUE)
    {
        CloseHandle(data.exit_event);
    }
    free_match_list(&matches);

    return ret;
}

#if _MSC_VER >= 1700
int CALLBACK WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine,
                     int nCmdShow)
{
    return usbpcapcmd_main(__argc, __argv);
}
#endif
