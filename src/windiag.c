#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define WINVER 0x0601

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <pdh.h>
#include <winhttp.h>
#include <shellapi.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#include <time.h>

#define TOP_COUNT 8
#define EVENT_BUFFER_SIZE 65536
#define MAX_NOTE_LENGTH 512

#if defined(_MSC_VER)
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

typedef struct {
    DWORD pid;
    char name[260];
    SIZE_T private_bytes;
    SIZE_T working_set;
} ProcessMemory;

static void make_log_directory(wchar_t *out_dir, size_t out_count) {
    wchar_t local_app_data[32768];
    DWORD count = GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data,
                                          (DWORD)(sizeof(local_app_data) / sizeof(local_app_data[0])));
    if (count == 0 || count >= sizeof(local_app_data) / sizeof(local_app_data[0])) {
        if (out_count) out_dir[0] = L'\0';
        return;
    }

    wchar_t parent[32768];
    if (swprintf(parent, sizeof(parent) / sizeof(parent[0]), L"%ls\\WinDiag", local_app_data) < 0 ||
        swprintf(out_dir, out_count, L"%ls\\logs", parent) < 0) {
        if (out_count) out_dir[0] = L'\0';
        return;
    }
    CreateDirectoryW(parent, NULL);
    CreateDirectoryW(out_dir, NULL);
}

static int append_log_line(const char *message) {
    wchar_t dir[32768];
    make_log_directory(dir, sizeof(dir) / sizeof(dir[0]));
    if (!dir[0]) return 0;

    SYSTEMTIME now;
    GetLocalTime(&now);
    wchar_t path[32768];
    if (swprintf(path, sizeof(path) / sizeof(path[0]),
                 L"%ls\\winddiag_%04u%02u%02u_%02u.log", dir,
                 now.wYear, now.wMonth, now.wDay, now.wHour) < 0) return 0;

    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;

    char row[4096];
    int length = snprintf(row, sizeof(row), "[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n",
                          now.wYear, now.wMonth, now.wDay,
                          now.wHour, now.wMinute, now.wSecond, message);
    DWORD written = 0;
    BOOL ok = length > 0 && (size_t)length < sizeof(row) &&
              WriteFile(file, row, (DWORD)length, &written, NULL) && written == (DWORD)length;
    CloseHandle(file);
    return ok ? 1 : 0;
}

static void report(const char *format, ...) {
    char message[3072];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    printf("%s\n", message);
    fflush(stdout);
    append_log_line(message);
}

static ULONGLONG filetime_to_u64(FILETIME value) {
    ULARGE_INTEGER n;
    n.LowPart = value.dwLowDateTime;
    n.HighPart = value.dwHighDateTime;
    return n.QuadPart;
}

static int get_cpu_load(double *percent) {
    FILETIME idle_a, kernel_a, user_a;
    FILETIME idle_b, kernel_b, user_b;
    if (!GetSystemTimes(&idle_a, &kernel_a, &user_a)) return 0;

    Sleep(500);
    if (!GetSystemTimes(&idle_b, &kernel_b, &user_b)) return 0;

    ULONGLONG idle = filetime_to_u64(idle_b) - filetime_to_u64(idle_a);
    ULONGLONG kernel = filetime_to_u64(kernel_b) - filetime_to_u64(kernel_a);
    ULONGLONG user = filetime_to_u64(user_b) - filetime_to_u64(user_a);
    ULONGLONG total = kernel + user;
    if (!total) return 0;

    *percent = 100.0 * (double)(total - (idle > total ? total : idle)) / (double)total;
    return 1;
}

static int compare_process_memory(const void *left, const void *right) {
    const ProcessMemory *a = (const ProcessMemory *)left;
    const ProcessMemory *b = (const ProcessMemory *)right;
    if (a->private_bytes < b->private_bytes) return 1;
    if (a->private_bytes > b->private_bytes) return -1;
    return 0;
}

static void report_top_processes(void) {
    ProcessMemory top[TOP_COUNT];
    size_t used = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        report("Processes: cannot enumerate (error %lu).", GetLastError());
        return;
    }

    PROCESSENTRY32W entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
            if (!process) continue;

            PROCESS_MEMORY_COUNTERS_EX counters;
            ZeroMemory(&counters, sizeof(counters));
            counters.cb = sizeof(counters);
            if (GetProcessMemoryInfo(process, (PROCESS_MEMORY_COUNTERS *)&counters, sizeof(counters))) {
                ProcessMemory item;
                item.pid = entry.th32ProcessID;
                item.private_bytes = counters.PrivateUsage;
                item.working_set = counters.WorkingSetSize;
                int converted = WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1,
                                                    item.name, (int)sizeof(item.name), NULL, NULL);
                if (!converted) snprintf(item.name, sizeof(item.name), "(name unavailable)");

                if (used < TOP_COUNT) {
                    top[used++] = item;
                } else {
                    qsort(top, used, sizeof(top[0]), compare_process_memory);
                    if (item.private_bytes > top[used - 1].private_bytes) top[used - 1] = item;
                }
            }
            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    qsort(top, used, sizeof(top[0]), compare_process_memory);
    report("Largest processes by private memory (read-only snapshot):");
    for (size_t i = 0; i < used; ++i) {
        report("  PID %-6lu %-32s private %.0f MB | working set %.0f MB",
               top[i].pid, top[i].name,
               (double)top[i].private_bytes / (1024.0 * 1024.0),
               (double)top[i].working_set / (1024.0 * 1024.0));
    }
    if (used == 0) report("  No process memory details were accessible.");
}

static void report_system_snapshot(const char *label) {
    report("--- %s ---", label);

    double cpu = 0.0;
    if (get_cpu_load(&cpu)) report("CPU total: %.1f%% (500 ms sample)", cpu);
    else report("CPU total: unavailable (error %lu).", GetLastError());

    MEMORYSTATUSEX memory;
    ZeroMemory(&memory, sizeof(memory));
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) {
        ULONGLONG committed = memory.ullTotalPageFile - memory.ullAvailPageFile;
        report("RAM: %.2f GB available / %.2f GB physical; commit approx %.2f / %.2f GB",
               (double)memory.ullAvailPhys / (1024.0 * 1024.0 * 1024.0),
               (double)memory.ullTotalPhys / (1024.0 * 1024.0 * 1024.0),
               (double)committed / (1024.0 * 1024.0 * 1024.0),
               (double)memory.ullTotalPageFile / (1024.0 * 1024.0 * 1024.0));
    } else {
        report("RAM status: unavailable (error %lu).", GetLastError());
    }

    wchar_t windows_dir[MAX_PATH];
    if (GetWindowsDirectoryW(windows_dir, MAX_PATH) != 0) {
        wchar_t root[4] = { windows_dir[0], L':', L'\\', L'\0' };
        ULARGE_INTEGER free_available, total, total_free;
        if (GetDiskFreeSpaceExW(root, &free_available, &total, &total_free)) {
            report("Windows drive %c: free %.1f GB / total %.1f GB",
                   (char)windows_dir[0],
                   (double)free_available.QuadPart / (1024.0 * 1024.0 * 1024.0),
                   (double)total.QuadPart / (1024.0 * 1024.0 * 1024.0));
        } else {
            report("Disk space: unavailable (error %lu).", GetLastError());
        }
    }

    report_top_processes();
}

static void check_performance_counters(void) {
    PDH_HQUERY query = NULL;
    PDH_HCOUNTER counter = NULL;
    PDH_STATUS status = PdhOpenQueryW(NULL, 0, &query);
    if (status == ERROR_SUCCESS) {
        status = PdhAddEnglishCounterW(query, L"\\Memory\\Available MBytes", 0, &counter);
    }
    if (status == ERROR_SUCCESS) status = PdhCollectQueryData(query);
    if (status == ERROR_SUCCESS) {
        Sleep(250);
        status = PdhCollectQueryData(query);
    }

    if (status == ERROR_SUCCESS) {
        PDH_FMT_COUNTERVALUE value;
        DWORD counter_type = 0;
        ZeroMemory(&value, sizeof(value));
        status = PdhGetFormattedCounterValue(counter, PDH_FMT_LARGE, &counter_type, &value);
        if (status == ERROR_SUCCESS && value.CStatus == ERROR_SUCCESS) {
            report("Performance counters: OK (English PDH memory counter returned %lld MB).",
                   (long long)value.largeValue);
        } else {
            report("Performance counters: FAIL (PDH status 0x%08lX).", (unsigned long)status);
        }
    } else {
        report("Performance counters: FAIL (PDH status 0x%08lX).", (unsigned long)status);
        report("  Suggested next step: from an elevated terminal, run `lodctr /R`, then reboot if Windows requests it.");
        report("  WinDiag does not rebuild counters automatically.");
    }

    if (query) PdhCloseQuery(query);
}

static int read_registry_string(HKEY root, const char *subkey, const char *value_name,
                                char *buffer, DWORD buffer_size) {
    DWORD type = 0;
    DWORD size = buffer_size;
    LONG status = RegGetValueA(root, subkey, value_name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                               &type, buffer, &size);
    if (status != ERROR_SUCCESS) return 0;
    buffer[buffer_size - 1] = '\0';
    return buffer[0] != '\0';
}

static void check_proxy_configuration(void) {
    const char *key = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    DWORD enabled = 0;
    DWORD size = sizeof(enabled);
    LONG status = RegGetValueA(HKEY_CURRENT_USER, key, "ProxyEnable", RRF_RT_REG_DWORD,
                               NULL, &enabled, &size);
    char proxy_server[2048] = {0};
    char pac_url[2048] = {0};
    int has_server = read_registry_string(HKEY_CURRENT_USER, key, "ProxyServer",
                                          proxy_server, sizeof(proxy_server));
    int has_pac = read_registry_string(HKEY_CURRENT_USER, key, "AutoConfigURL",
                                       pac_url, sizeof(pac_url));
    DWORD auto_detect = 0;
    size = sizeof(auto_detect);
    int has_auto_detect = RegGetValueA(HKEY_CURRENT_USER, key, "AutoDetect", RRF_RT_REG_DWORD,
                                       NULL, &auto_detect, &size) == ERROR_SUCCESS && auto_detect != 0;

    if (status == ERROR_SUCCESS) {
        report("Current-user proxy: %s; proxy address configured: %s; PAC URL configured: %s; auto-detect: %s.",
               enabled ? "enabled" : "disabled", has_server ? "yes" : "no",
               has_pac ? "yes" : "no", has_auto_detect ? "yes" : "no");
    } else {
        report("Current-user proxy settings: could not read (registry status %ld).", status);
    }

    WINHTTP_PROXY_INFO info;
    ZeroMemory(&info, sizeof(info));
    if (WinHttpGetDefaultProxyConfiguration(&info)) {
        const char *mode = info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY ? "named proxy" :
                           info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY ? "direct" : "system/default";
        report("WinHTTP proxy: %s. (Address intentionally omitted from the log.)", mode);
        if (info.lpszProxy) GlobalFree(info.lpszProxy);
        if (info.lpszProxyBypass) GlobalFree(info.lpszProxyBypass);
    } else {
        report("WinHTTP proxy settings: unavailable (error %lu).", GetLastError());
    }
}

static void scan_event_channel(const char *channel) {
    HANDLE log = OpenEventLogA(NULL, channel);
    if (!log) {
        report("Event log %s: unavailable (error %lu).", channel, GetLastError());
        return;
    }

    BYTE buffer[EVENT_BUFFER_SIZE];
    DWORD bytes_read = 0, bytes_needed = 0;
    DWORD recent = 0;
    DWORD shown = 0;
    DWORD cutoff = (DWORD)time(NULL) - 3600;
    int stop = 0;

    while (!stop && ReadEventLogA(log, EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
                                  0, buffer, sizeof(buffer), &bytes_read, &bytes_needed)) {
        DWORD offset = 0;
        while (offset + sizeof(EVENTLOGRECORD) <= bytes_read) {
            EVENTLOGRECORD *record = (EVENTLOGRECORD *)(buffer + offset);
            if (record->Length < sizeof(EVENTLOGRECORD) || offset + record->Length > bytes_read) {
                stop = 1;
                break;
            }
            if (record->TimeGenerated < cutoff) {
                stop = 1;
                break;
            }
            if (record->EventType == EVENTLOG_ERROR_TYPE || record->EventType == EVENTLOG_WARNING_TYPE) {
                recent++;
                if (shown < 20) {
                    const char *source = (const char *)(buffer + offset + sizeof(EVENTLOGRECORD));
                    time_t event_time = (time_t)record->TimeGenerated;
                    struct tm *event_local = localtime(&event_time);
                    char event_stamp[32] = "unknown time";
                    if (event_local) strftime(event_stamp, sizeof(event_stamp), "%Y-%m-%d %H:%M:%S", event_local);
                    report("Event %s: %s | %s | ID %lu | %s (last hour).",
                           channel,
                           record->EventType == EVENTLOG_ERROR_TYPE ? "error" : "warning",
                           source,
                           (unsigned long)(record->EventID & 0xFFFF),
                           event_stamp);
                    shown++;
                }
            }
            offset += record->Length;
        }
    }

    DWORD error = GetLastError();
    if (recent == 0) report("Event %s: no warnings or errors found in the last hour.", channel);
    else if (recent > shown) report("Event %s: %lu matching warnings/errors total; shown %lu newest records.",
                                    channel, (unsigned long)recent, (unsigned long)shown);
    if (!stop && error != ERROR_HANDLE_EOF && error != ERROR_SUCCESS && error != ERROR_INVALID_PARAMETER) {
        report("Event %s scan stopped (error %lu).", channel, error);
    }
    CloseEventLog(log);
}

static void check_wmi_repository(void) {
    report("WMI repository check: running `winmgmt /verifyrepository` (read-only).");
    int result = _wsystem(L"winmgmt.exe /verifyrepository");
    report("WMI verification command returned %d. Review the message above; no WMI data was changed.", result);
}

static void run_diagnostics(void) {
    report("WinDiag diagnostic started. Read-only checks; no system settings are changed.");
    report_system_snapshot("Current system snapshot");
    check_performance_counters();
    check_proxy_configuration();
    check_wmi_repository();
    scan_event_channel("System");
    scan_event_channel("Application");
    report("Diagnostic finished. Log files are in %%LOCALAPPDATA%%\\WinDiag\\logs.");
}

static void run_watch(unsigned long minutes) {
    report("Monitoring started; samples are written every 60 seconds to hourly log files.");
    report("Press Ctrl+C to stop. No system settings will be changed.");
    unsigned long elapsed = 0;
    for (;;) {
        report_system_snapshot("Monitor sample");
        if (elapsed % 60 == 0) {
            scan_event_channel("System");
            scan_event_channel("Application");
        }
        if (minutes && elapsed >= minutes) break;
        Sleep(60000);
        elapsed++;
    }
    report("Monitoring stopped.");
}

static void open_settings(const char *which) {
    const wchar_t *uri = NULL;
    if (_stricmp(which, "notifications") == 0) uri = L"ms-settings:notifications";
    else if (_stricmp(which, "updates") == 0 || _stricmp(which, "update") == 0)
        uri = L"ms-settings:windowsupdate";
    else {
        report("Unknown settings page. Use: settings notifications | settings updates");
        return;
    }

    report("Opening the Windows Settings page. WinDiag does not toggle notifications or disable updates.");
    HINSTANCE result = ShellExecuteW(NULL, L"open", uri, NULL, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)result <= 32) report("Could not open Settings (ShellExecute code %ld).", (long)(INT_PTR)result);
}

static void write_marker(const char *text) {
    char safe[MAX_NOTE_LENGTH + 1];
    size_t i = 0;
    for (; text[i] && i < MAX_NOTE_LENGTH; ++i) {
        safe[i] = (text[i] == '\r' || text[i] == '\n') ? ' ' : text[i];
    }
    safe[i] = '\0';
    report("USER MARKER: %s", safe[0] ? safe : "(empty)");
}

static void print_help(const char *program) {
    printf("WinDiag - Windows diagnostics and hourly logs (C / terminal only)\n\n");
    printf("Usage:\n");
    printf("  %s diagnose                 Run read-only diagnostics\n", program);
    printf("  %s watch [minutes]          Log CPU/RAM/disk/processes every minute\n", program);
    printf("  %s mark <text>              Add a lag/problem marker to the current log\n", program);
    printf("  %s settings notifications   Open Windows notification settings\n", program);
    printf("  %s settings updates         Open Windows Update settings\n", program);
    printf("  %s help                     Show this help\n\n", program);
    printf("The tool does not reset WMI, rebuild counters, stop services, or disable updates.\n");
    printf("Logs are stored under %%LOCALAPPDATA%%\\WinDiag\\logs, one file per hour.\n");
}

static void interactive_menu(void) {
    char line[256];
    for (;;) {
        printf("\nWinDiag - Windows diagnostics\n");
        printf("1. Run diagnostics\n");
        printf("2. Start continuous monitoring (Ctrl+C to stop)\n");
        printf("3. Mark that a slowdown started\n");
        printf("4. Open notification settings\n");
        printf("5. Open Windows Update settings\n");
        printf("0. Exit\n> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) return;
        int choice = atoi(line);
        if (choice == 0) return;
        if (choice == 1) run_diagnostics();
        else if (choice == 2) run_watch(0);
        else if (choice == 3) {
            printf("What happened? ");
            fflush(stdout);
            if (fgets(line, sizeof(line), stdin)) write_marker(line);
        } else if (choice == 4) open_settings("notifications");
        else if (choice == 5) open_settings("updates");
        else printf("Unknown option.\n");
    }
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc == 1) {
        interactive_menu();
        return 0;
    }
    if (_stricmp(argv[1], "help") == 0 || _stricmp(argv[1], "--help") == 0 ||
        _stricmp(argv[1], "-h") == 0) {
        print_help(argv[0]);
        return 0;
    }
    if (_stricmp(argv[1], "diagnose") == 0 || _stricmp(argv[1], "doctor") == 0) {
        run_diagnostics();
        return 0;
    }
    if (_stricmp(argv[1], "watch") == 0) {
        unsigned long minutes = 0;
        if (argc >= 3) {
            char *end = NULL;
            unsigned long parsed = strtoul(argv[2], &end, 10);
            if (!end || *end || parsed > 100000) {
                fprintf(stderr, "Invalid duration in minutes.\n");
                return 2;
            }
            minutes = parsed;
        }
        run_watch(minutes);
        return 0;
    }
    if (_stricmp(argv[1], "mark") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s mark <text>\n", argv[0]);
            return 2;
        }
        char note[1024] = {0};
        size_t length = 0;
        for (int i = 2; i < argc && length < sizeof(note) - 2; ++i) {
            if (i > 2) note[length++] = ' ';
            size_t part = strlen(argv[i]);
            if (part > sizeof(note) - length - 1) part = sizeof(note) - length - 1;
            memcpy(note + length, argv[i], part);
            length += part;
        }
        note[length] = '\0';
        write_marker(note);
        return 0;
    }
    if (_stricmp(argv[1], "settings") == 0 && argc >= 3) {
        open_settings(argv[2]);
        return 0;
    }

    fprintf(stderr, "Unknown command. Run `%s help`.\n", argv[0]);
    return 2;
}
