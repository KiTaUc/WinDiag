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
        report("Не удалось получить список процессов (код ошибки %lu).", GetLastError());
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
                if (!converted) snprintf(item.name, sizeof(item.name), "(имя недоступно)");

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
    report("Процессы с наибольшим объёмом частной памяти (снимок без изменений):");
    for (size_t i = 0; i < used; ++i) {
        report("  PID %-6lu %-32s частная память: %.0f МБ | в ОЗУ: %.0f МБ",
               top[i].pid, top[i].name,
               (double)top[i].private_bytes / (1024.0 * 1024.0),
               (double)top[i].working_set / (1024.0 * 1024.0));
    }
    if (used == 0) report("  Не удалось прочитать данные о памяти процессов.");
}

static void report_system_snapshot(const char *label) {
    report("--- %s ---", label);

    double cpu = 0.0;
    if (get_cpu_load(&cpu)) report("Загрузка процессора: %.1f%% (выборка 0,5 с)", cpu);
    else report("Загрузка CPU недоступна (код ошибки %lu).", GetLastError());

    MEMORYSTATUSEX memory;
    ZeroMemory(&memory, sizeof(memory));
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) {
        ULONGLONG committed = memory.ullTotalPageFile - memory.ullAvailPageFile;
        report("Физическая ОЗУ: доступно %.2f ГБ из %.2f ГБ; виртуальная память (commit): занято %.2f ГБ из предела %.2f ГБ",
               (double)memory.ullAvailPhys / (1024.0 * 1024.0 * 1024.0),
               (double)memory.ullTotalPhys / (1024.0 * 1024.0 * 1024.0),
               (double)committed / (1024.0 * 1024.0 * 1024.0),
               (double)memory.ullTotalPageFile / (1024.0 * 1024.0 * 1024.0));
    } else {
        report("Сведения об ОЗУ недоступны (код ошибки %lu).", GetLastError());
    }

    wchar_t windows_dir[MAX_PATH];
    if (GetWindowsDirectoryW(windows_dir, MAX_PATH) != 0) {
        wchar_t root[4] = { windows_dir[0], L':', L'\\', L'\0' };
        ULARGE_INTEGER free_available, total, total_free;
        if (GetDiskFreeSpaceExW(root, &free_available, &total, &total_free)) {
            report("Диск Windows (%c:): свободно %.1f ГБ из %.1f ГБ",
                   (char)windows_dir[0],
                   (double)free_available.QuadPart / (1024.0 * 1024.0 * 1024.0),
                   (double)total.QuadPart / (1024.0 * 1024.0 * 1024.0));
        } else {
            report("Не удалось получить сведения о диске (код ошибки %lu).", GetLastError());
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
            report("Счётчик производительности работает: доступная память по PDH — %lld МБ.",
                   (long long)value.largeValue);
        } else {
            report("Счётчик производительности НЕ ПРОШЁЛ проверку (код PDH 0x%08lX).", (unsigned long)status);
        }
    } else {
        report("Счётчик производительности НЕ ПРОШЁЛ проверку (код PDH 0x%08lX).", (unsigned long)status);
        report("  Если счётчики действительно неисправны: откройте CMD от администратора и выполните `lodctr /R`; перезагрузитесь, если Windows попросит.");
        report("  WinDiag не восстанавливает счётчики автоматически.");
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
        report("Прокси текущего пользователя: %s; адрес задан: %s; PAC-скрипт задан: %s; автообнаружение: %s.",
               enabled ? "включён" : "выключен", has_server ? "да" : "нет",
               has_pac ? "да" : "нет", has_auto_detect ? "да" : "нет");
    } else {
        report("Не удалось прочитать настройки прокси пользователя (код реестра %ld).", status);
    }

    WINHTTP_PROXY_INFO info;
    ZeroMemory(&info, sizeof(info));
    if (WinHttpGetDefaultProxyConfiguration(&info)) {
        const char *mode = info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY ? "задан прокси" :
                           info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY ? "прямое подключение" : "системные настройки";
        report("Прокси WinHTTP: %s. Адрес в журнал не записывается.", mode);
        if (info.lpszProxy) GlobalFree(info.lpszProxy);
        if (info.lpszProxyBypass) GlobalFree(info.lpszProxyBypass);
    } else {
        report("Настройки прокси WinHTTP недоступны (код ошибки %lu).", GetLastError());
    }
}

static void scan_event_channel(const char *channel) {
    const char *display_channel = _stricmp(channel, "System") == 0 ? "Система" : "Приложения";
    HANDLE log = OpenEventLogA(NULL, channel);
    if (!log) {
        report("Журнал событий «%s» недоступен (код ошибки %lu).", display_channel, GetLastError());
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
                    const char *display_source = _stricmp(source, "Service Control Manager") == 0
                                                     ? "Диспетчер управления службами" : source;
                    time_t event_time = (time_t)record->TimeGenerated;
                    struct tm *event_local = localtime(&event_time);
                    char event_stamp[32] = "время неизвестно";
                    if (event_local) strftime(event_stamp, sizeof(event_stamp), "%Y-%m-%d %H:%M:%S", event_local);
                    report("Журнал «%s»: %s | %s | событие %lu | %s (за последний час).",
                           display_channel,
                           record->EventType == EVENTLOG_ERROR_TYPE ? "ошибка" : "предупреждение",
                           display_source,
                           (unsigned long)(record->EventID & 0xFFFF),
                           event_stamp);
                    shown++;
                }
            }
            offset += record->Length;
        }
    }

    DWORD error = GetLastError();
    if (recent == 0) report("В журнале «%s» за последний час предупреждений и ошибок нет.", display_channel);
    else if (recent > shown) report("В журнале «%s» найдено событий с предупреждениями/ошибками: %lu; показаны последние %lu.",
                                    display_channel, (unsigned long)recent, (unsigned long)shown);
    if (!stop && error != ERROR_HANDLE_EOF && error != ERROR_SUCCESS && error != ERROR_INVALID_PARAMETER) {
        report("Чтение журнала «%s» остановлено (код ошибки %lu).", display_channel, error);
    }
    CloseEventLog(log);
}

static int contains_text_ci(const char *text, const char *needle) {
    size_t length = strlen(needle);
    if (!length) return 1;
    for (const char *p = text; *p; ++p) {
        if (_strnicmp(p, needle, length) == 0) return 1;
    }
    return 0;
}

static void check_wmi_repository(void) {
    report("Проверка хранилища WMI: запускаю штатную проверку Windows (только чтение).");
    SECURITY_ATTRIBUTES security = { sizeof(security), NULL, TRUE };
    HANDLE read_pipe = NULL, write_pipe = NULL;
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0)) {
        report("Не удалось создать канал для ответа WMI (код ошибки %lu).", GetLastError());
        return;
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    char system_dir[MAX_PATH];
    UINT system_len = GetSystemDirectoryA(system_dir, MAX_PATH);
    if (system_len == 0 || system_len >= MAX_PATH) {
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        report("Не удалось найти системную папку Windows для проверки WMI.");
        return;
    }
    char command_line[MAX_PATH + 64];
    snprintf(command_line, sizeof(command_line), "\"%s\\wbem\\winmgmt.exe\" /verifyrepository", system_dir);

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    if (!CreateProcessA(NULL, command_line, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) {
        DWORD error = GetLastError();
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        report("Не удалось запустить проверку WMI (код ошибки %lu).", error);
        return;
    }
    CloseHandle(write_pipe);

    char output[4096];
    DWORD total = 0, received = 0;
    while (total < sizeof(output) - 1 &&
           ReadFile(read_pipe, output + total, (DWORD)(sizeof(output) - 1 - total), &received, NULL) &&
           received > 0) total += received;
    output[total] = '\0';
    CloseHandle(read_pipe);

    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    if (contains_text_ci(output, "WMI repository is inconsistent")) {
        report("Хранилище WMI не согласовано. Не сбрасывайте его автоматически; сначала изучите причину.");
    } else if (contains_text_ci(output, "WMI repository is consistent")) {
        report("Хранилище WMI согласовано.");
    } else if (exit_code == 0) {
        report("Проверка WMI завершилась без ошибки; текст Windows не распознан.");
    } else {
        report("Проверка WMI завершилась с ошибкой. Код процесса: %lu.", exit_code);
    }
    report("Код завершения проверки WMI: %lu. Данные WMI не изменялись.", exit_code);
}

static void run_diagnostics(void) {
    report("WinDiag: диагностика начата. Проверки только для чтения; настройки Windows не меняются.");
    report_system_snapshot("Состояние системы на момент проверки");
    check_performance_counters();
    check_proxy_configuration();
    check_wmi_repository();
    scan_event_channel("System");
    scan_event_channel("Application");
    report("Диагностика завершена. Журналы находятся в %%LOCALAPPDATA%%\\WinDiag\\logs.");
}

static void run_watch(unsigned long minutes) {
    report("Наблюдение запущено: снимок раз в минуту, файлы журнала разделяются по часам.");
    report("Для остановки нажмите Ctrl+C. Настройки Windows не меняются.");
    unsigned long elapsed = 0;
    for (;;) {
        report_system_snapshot("Снимок наблюдения");
        if (elapsed % 60 == 0) {
            scan_event_channel("System");
            scan_event_channel("Application");
        }
        if (minutes && elapsed >= minutes) break;
        Sleep(60000);
        elapsed++;
    }
    report("Наблюдение остановлено.");
}

static void open_settings(const char *which) {
    const wchar_t *uri = NULL;
    if (_stricmp(which, "notifications") == 0) uri = L"ms-settings:notifications";
    else if (_stricmp(which, "updates") == 0 || _stricmp(which, "update") == 0)
        uri = L"ms-settings:windowsupdate";
    else {
        report("Неизвестная страница. Используйте: settings notifications | settings updates");
        return;
    }

    report("Открываю настройки Windows. WinDiag не меняет уведомления и не отключает обновления.");
    HINSTANCE result = ShellExecuteW(NULL, L"open", uri, NULL, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)result <= 32) report("Не удалось открыть настройки Windows (код ShellExecute %ld).", (long)(INT_PTR)result);
}

static void write_marker(const char *text) {
    char safe[MAX_NOTE_LENGTH + 1];
    size_t i = 0;
    for (; text[i] && i < MAX_NOTE_LENGTH; ++i) {
        safe[i] = (text[i] == '\r' || text[i] == '\n') ? ' ' : text[i];
    }
    safe[i] = '\0';
    report("ОТМЕТКА ПОЛЬЗОВАТЕЛЯ: %s", safe[0] ? safe : "(пусто)");
}

static void print_help(const char *program) {
    printf("WinDiag — диагностика Windows и почасовые журналы (C, только терминал)\n\n");
    printf("Команды:\n");
    printf("  %s diagnose                 выполнить диагностику без изменений\n", program);
    printf("  %s watch [минуты]          записывать загрузку процессора, ОЗУ, диска и процессы раз в минуту\n", program);
    printf("  %s mark <текст>              добавить отметку о проблеме в текущий журнал\n", program);
    printf("  %s settings notifications   открыть настройки уведомлений Windows\n", program);
    printf("  %s settings updates         открыть настройки Центра обновления Windows\n", program);
    printf("  %s help                     показать эту справку\n\n", program);
    printf("Программа не сбрасывает WMI, не восстанавливает счётчики, не останавливает службы и не отключает обновления.\n");
    printf("Журналы сохраняются в %%LOCALAPPDATA%%\\WinDiag\\logs, отдельный файл на каждый час.\n");
}

static void interactive_menu(void) {
    char line[256];
    for (;;) {
        printf("\nWinDiag — диагностика Windows\n");
        printf("1. Выполнить диагностику\n");
        printf("2. Начать наблюдение (Ctrl+C — остановка)\n");
        printf("3. Отметить начало тормозов\n");
        printf("4. Открыть настройки уведомлений\n");
        printf("5. Открыть настройки Центра обновления Windows\n");
        printf("0. Выход\n> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) return;
        int choice = atoi(line);
        if (choice == 0) return;
        if (choice == 1) run_diagnostics();
        else if (choice == 2) run_watch(0);
        else if (choice == 3) {
            printf("Что произошло? ");
            fflush(stdout);
            if (fgets(line, sizeof(line), stdin)) write_marker(line);
        } else if (choice == 4) open_settings("notifications");
        else if (choice == 5) open_settings("updates");
        else printf("Неизвестный пункт меню.\n");
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
                fprintf(stderr, "Некорректная длительность в минутах.\n");
                return 2;
            }
            minutes = parsed;
        }
        run_watch(minutes);
        return 0;
    }
    if (_stricmp(argv[1], "mark") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Команды: %s mark <текст>\n", argv[0]);
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

    fprintf(stderr, "Неизвестная команда. Запустите `%s help`.\n", argv[0]);
    return 2;
}
