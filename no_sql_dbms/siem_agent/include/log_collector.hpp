#pragma once

#include "position_manager.hpp"  // Добавлено
#include "../../include/vector.hpp"
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <filesystem>
#include <sys/inotify.h>

// Forward declarations
namespace siem {
    class SecurityEvent;
    class Config;
    class EventBuffer;
    struct LogSource;
    class PositionManager;
    struct FilePosition;
}

namespace siem {

// ========== Парсеры ==========

// Парсер для auditd логов
class AuditdParser {
public:
    static SecurityEvent parse_line(const std::string& line);

private:
    static std::string extract_audit_field(const std::string& line, const std::string& field);
    static std::string determine_audit_event_type(const std::string& msg);
    static std::string determine_audit_severity(const std::string& event_type);
};

// Парсер для syslog/auth.log
class SyslogParser {
public:
    static SecurityEvent parse_line(const std::string& line);

private:
    static bool is_security_event(const std::string& line);
    static std::string extract_syslog_field(const std::string& line, const std::string& field);
};

// Парсер для bash_history
class BashHistoryParser {
public:
    static SecurityEvent parse_line(const std::string& line,
                                    const std::string& username,
                                    const std::string& hostname);
};

// ========== Основной сборщик логов ==========

class LogCollector {
public:
    LogCollector(EventBuffer& buffer, const Config& config);
    ~LogCollector();

    void start();
    void stop();

    bool is_running() const { return running; }

private:
    // Основной цикл
    void run();

    // Inotify методы
    void initialize_inotify();
    void add_inotify_watch(const std::string& path);
    void monitor_inotify_events();

    // Polling методы (fallback)
    void poll_for_changes();
    void check_file_for_changes(const LogSource& source);

    // Обработка событий
    void handle_file_modification(const std::string& path);
    void handle_file_rotation(const std::string& path);

    // Чтение файлов
    void initial_scan();
    void process_source(const LogSource& source);
    void process_log_file(const LogSource& source,
                         const std::string& path,
                         const std::string& username = "");

    EventBuffer& buffer_ref;
    const Config& config_ref;

    std::thread collector_thread;
    std::atomic<bool> running{false};

    // Менеджер позиций
    PositionManager position_manager;

    // Inotify для мониторинга в реальном времени
    int inotify_fd;
    std::unordered_map<int, std::string> watch_descriptors;
};

} // namespace siem
