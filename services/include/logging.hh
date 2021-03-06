/* -*- mode: C++; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 99; -*-
 */
/* vim: set ts=4 sw=4 et tw=99:  */
/*
    This file is part of Icecream.

    Copyright (c) 2004 Stephan Kulow <coolo@suse.de>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef _LOGGING_HH_
#define _LOGGING_HH_

extern "C" {
#include <sys/time.h>
#include <unistd.h>
}

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

// Verbosity level, from least to most.
enum VerbosityLevel
{
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,

    MaxVerboseLevel = Debug
};

extern std::ostream * logfile_info;
extern std::ostream * logfile_warning;
extern std::ostream * logfile_error;
extern std::ostream * logfile_trace;
extern std::string    logfile_prefix;

void
setup_debug(int                 level,
            const std::string & logfile = "",
            const std::string & prefix = "");
void
reset_debug_if_needed(); // if we get SIGHUP, this will handle the reset
void
reset_debug();
void
close_debug();
void
flush_debug();

inline std::ostream &
output_date(std::ostream & os)
{
    time_t      t = time(0);
    struct tm * tmp = localtime(&t);
    char        buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %T: ", tmp);

    if (logfile_prefix.size()) {
        os << logfile_prefix;
    }

    os << "[" << getpid() << "] ";

    os << buf;
    return os;
}

inline std::ostream &
log_info()
{
    if (!logfile_info) {
        return std::cerr;
    }

    return output_date(*logfile_info);
}

inline std::ostream &
log_warning()
{
    if (!logfile_warning) {
        return std::cerr;
    }

    return output_date(*logfile_warning);
}

inline std::ostream &
log_error()
{
    if (!logfile_error) {
        return std::cerr;
    }

    return output_date(*logfile_error);
}

inline std::ostream &
trace()
{
    if (!logfile_trace) {
        return std::cerr;
    }

    return output_date(*logfile_trace);
}

inline std::ostream &
log_errno(const char * prefix, int tmp_errno)
{
    return log_error() << prefix << "(Error: " << strerror(tmp_errno) << ")"
                       << '\n';
}

inline std::ostream &
log_perror(const char * prefix)
{
    return log_errno(prefix, errno);
}

inline std::ostream &
log_perror(const std::string & prefix)
{
    return log_perror(prefix.c_str());
}

inline std::ostream &
log_errno_trace(const char * prefix, int tmp_errno)
{
    return trace() << prefix << "(Error: " << strerror(tmp_errno) << ")"
                   << '\n';
}

inline std::ostream &
log_perror_trace(const char * prefix)
{
    return log_errno_trace(prefix, errno);
}

class LogBlock {
    static unsigned nesting;
    timeval         m_start;
    char *          m_label;

public:
    LogBlock(const char * label = 0)
    {
        for (unsigned i = 0; i < nesting; ++i) {
            log_info() << "  ";
        }

        log_info() << "<" << (label ? label : "") << ">\n";

        m_label = strdup(label ? label : "");
        ++nesting;
        gettimeofday(&m_start, 0);
    }

    ~LogBlock()
    {
        timeval end;
        gettimeofday(&end, 0);

        --nesting;

        for (unsigned i = 0; i < nesting; ++i) {
            log_info() << "  ";
        }

        log_info() << "</" << m_label << ": "
                   << (end.tv_sec - m_start.tv_sec) * 1000 +
                          (end.tv_usec - m_start.tv_usec) / 1000
                   << "ms>\n";

        free(m_label);
    }
};

template<class T>
inline std::string
toString(const T & val)
{
    std::ostringstream os;
    os << val;
    return os.str();
}

#endif // _LOGGING_HH_
