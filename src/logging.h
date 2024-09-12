// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <fs.h>
#include <tinyformat.h>

#include <atomic>
#include <cstdint>
#include <list>
#include <mutex>
#include <string>
#include <utility>

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;
static const bool DEFAULT_LOGTHREADNAMES = false;

extern bool fLogIPs;
extern const char *const DEFAULT_DEBUGLOGFILE;

struct CLogCategoryActive {
    std::string category;
    bool active;
};

namespace BCLog {

enum LogFlags : uint32_t {
    NONE = 0,
    NET = (1 << 0),
    TOR = (1 << 1),
    MEMPOOL = (1 << 2),
    HTTP = (1 << 3),
    BENCH = (1 << 4),
    ZMQ = (1 << 5),
    DB = (1 << 6),
    RPC = (1 << 7),
    ESTIMATEFEE = (1 << 8),
    ADDRMAN = (1 << 9),
    SELECTCOINS = (1 << 10),
    REINDEX = (1 << 11),
    CMPCTBLOCK = (1 << 12),
    RAND = (1 << 13),
    PRUNE = (1 << 14),
    PROXY = (1 << 15),
    MEMPOOLREJ = (1 << 16),
    LIBEVENT = (1 << 17),
    COINDB = (1 << 18),
    QT = (1 << 19),
    LEVELDB = (1 << 20),
    FINALIZATION = (1 << 21),
    PARKING = (1 << 22),
    DSPROOF = (1 << 23),

    //! Log *all* httpserver request and response data transferred to/from the
    //! client. Note: Unlike all the other categories, to avoid logs from
    //! filling up (and from revealing potentially sensitive data), this is
    //! NOT enabled automatically if using ALL. It must be enabled explicitly.
    HTTPTRACE = (1 << 24),

    ALL = ~uint32_t(0) & ~uint32_t(HTTPTRACE),
};

class Logger {
private:
    FILE *m_fileout = nullptr;
    std::mutex m_file_mutex;
    std::list<std::string> m_msgs_before_open;

    /**
     * m_started_new_line is a state variable that will suppress printing of the
     * timestamp when multiple calls are made that don't end in a newline.
     */
    std::atomic_bool m_started_new_line{true};

    /**
     * Log categories bitfield.
     */
    std::atomic<uint32_t> m_categories{0};

    void PrependTimestampStr(std::string &str);

public:
    bool m_print_to_console = false;
    bool m_print_to_file = false;

    bool m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
    bool m_log_time_micros = DEFAULT_LOGTIMEMICROS;
    bool m_log_threadnames = DEFAULT_LOGTHREADNAMES;

    fs::path m_file_path;
    std::atomic<bool> m_reopen_file{false};

    ~Logger();

    /** Send a string to the log output */
    void LogPrintStr(std::string &&str);
    void LogPrintStr(const std::string &str) { LogPrintStr(std::string{str}); }

    /** Returns whether logs will be written to any output */
    bool Enabled() const { return m_print_to_console || m_print_to_file; }

    bool OpenDebugLog();
    void ShrinkDebugFile();

    uint32_t GetCategoryMask() const { return m_categories.load(); }

    void EnableCategory(LogFlags category);
    bool EnableCategory(const std::string &str);
    void DisableCategory(LogFlags category);
    bool DisableCategory(const std::string &str);

    /** Return true if log accepts specified category */
    bool WillLogCategory(LogFlags category) const;

    /** Default for whether ShrinkDebugFile should be run */
    bool DefaultShrinkDebugFile() const;
};

} // namespace BCLog

BCLog::Logger &LogInstance();

/** Return true if log accepts specified category */
static inline bool LogAcceptCategory(BCLog::LogFlags category) {
    return LogInstance().WillLogCategory(category);
}

/** Returns a string with the log categories. */
std::string ListLogCategories();

/** Returns a vector of the active log categories. */
std::vector<CLogCategoryActive> ListActiveLogCategories();

/** Return true if str parses as a log category and set the flag */
bool GetLogCategory(BCLog::LogFlags &flag, const std::string &str);

// Be conservative when using LogPrintf/error or other things which
// unconditionally log to debug.log! It should not be the case that an inbound
// peer can fill up a user's disk with debug.log entries.
template <typename... Args>
static inline void LogPrintf(const char *fmt, const Args &... args) {
    if (LogInstance().Enabled()) {
        std::string log_msg;
        try {
            log_msg = tfm::format(fmt, args...);
        } catch (tinyformat::format_error &fmterr) {
            /**
             * Original format string will have newline so don't add one here
             */
            log_msg = "Error \"" + std::string(fmterr.what()) +
                      "\" while formatting log message: " + fmt;
        }
        LogInstance().LogPrintStr(std::move(log_msg));
    }
}

// Use a macro instead of a function for conditional logging to prevent
// evaluating arguments when logging for the category is not enabled.
#define LogPrint(category, ...)                                                \
    do {                                                                       \
        if (LogAcceptCategory((category))) {                                   \
            LogPrintf(__VA_ARGS__);                                            \
        }                                                                      \
    } while (0)

/**
 * These are aliases used to explicitly state that the message should not end
 * with a newline character. It allows for detecting the missing newlines that
 * could make the logs hard to read.
 */
#define LogPrintfToBeContinued LogPrintf
#define LogPrintToBeContinued LogPrint
