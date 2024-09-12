// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdio>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

/** Filesystem operations and types */
namespace fs = boost::filesystem;

/** Bridge operations to C stdio */
namespace fsbridge {
FILE *fopen(const fs::path &p, const char *mode);

class FileLock {
public:
    FileLock() = delete;
    FileLock(const FileLock &) = delete;
    FileLock(FileLock &&) = delete;
    explicit FileLock(const fs::path &file);
    ~FileLock();
    bool TryLock();
    std::string GetReason() { return reason; }

private:
    std::string reason;
#ifndef WIN32
    int fd = -1;
#else
    // INVALID_HANDLE_VALUE
    void *hFile = (void *)-1;
#endif
};

std::string get_filesystem_error_message(const fs::filesystem_error &e);
}; // namespace fsbridge
