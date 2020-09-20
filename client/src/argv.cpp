/* Create and destroy argument vectors (argv's)
   Copyright (C) 1992-2017 Free Software Foundation, Inc.
   Written by Fred Fish @ Cygnus Support

This file is part of the libiberty library.
Libiberty is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

Libiberty is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with libiberty; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 51 Franklin Street - Fifth
Floor, Boston, MA 02110-1301, USA.  */

/*  Create and destroy argument vectors.  An argument vector is simply an
    array of string pointers, terminated by a nullptr pointer. */

#include "argv.hh"

extern "C" {
#include <sys/stat.h>
}

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>

#ifndef EOS
#define EOS '\0'
#endif

#define INITIAL_MAXARGC 8 /* Number of args + nullptr in initial argv */

namespace {

template<typename Container, typename InputIterator>
Container
argv_from_file(InputIterator && begin, InputIterator && end)
{
    Container result{};

    bool squote{false};
    bool dquote{false};
    bool bsquote{false};

    const auto  size = std::distance(begin, end);
    std::string copybuf(size, '\0');
    const auto  copy_begin = copybuf.begin();

    auto it = begin;
    while (*it != EOS) {
        /* Pick off argv[argc] */
        it = std::find_if(it, end, [](char x) { return isspace(x) == 0; });

        /* Begin scanning arg */
        auto arg = copy_begin;
        while (*it != EOS) {
            if (isspace(*it) && !squote && !dquote && !bsquote) {
                break;
            }

            if (bsquote) {
                bsquote = false;
                *arg++ = *it;
            } else if (*it == '\\') {
                bsquote = true;
            } else if (squote) {
                if (*it == '\'') {
                    squote = false;
                } else {
                    *arg++ = *it;
                }
            } else if (dquote) {
                if (*it == '"') {
                    dquote = false;
                } else {
                    *arg++ = *it;
                }
            } else {
                if (*it == '\'') {
                    squote = true;
                } else if (*it == '"') {
                    dquote = true;
                } else {
                    *arg++ = *it;
                }
            }
            ++it;
        }

        if (arg != copy_begin) {
            result.emplace_back(copy_begin, arg);
        }
    }

    return result;
}

} // namespace

/*

@deftypefn Extension void expandargv (int *@var{argcp}, char ***@var{argvp})

The @var{argcp} and @code{argvp} arguments are pointers to the usual
@code{argc} and @code{argv} arguments to @code{main}.  This function
looks for arguments that begin with the character @samp{@@}.  Any such
arguments are interpreted as ``response files''.  The contents of the
response file are interpreted as additional command line options.  In
particular, the file is separated into whitespace-separated strings;
each such string is taken as a command-line option.  The new options
are inserted in place of the option naming the response file, and
@code{*argcp} and @code{*argvp} will be updated.  If the value of
@code{*argvp} is modified by this function, then the new value has
been dynamically allocated and can be deallocated by the caller with
@code{freeargv}.  However, most callers will simply call
@code{expandargv} near the beginning of @code{main} and allow the
operating system to free the memory when the program exits.

@end deftypefn

*/

std::vector<std::string>
expand_argv(int argc, char ** argv)
{
    using ResultT = std::list<std::string>;
    ResultT expanded{};

    for (int i = 0; i < argc; ++i) {
        expanded.emplace_back(argv[1]);
    }

    /* Limit the number of response files that we parse in order
       to prevent infinite recursion.  */
    int iteration_limit = 2000;

    /* Loop over the arguments, handling response files.  We always skip
       ARGVP[0], as that is the name of the program being run.  */
    for (auto it = std::next(expanded.begin()); it != expanded.end(); ++it) {
        /* We are only interested in options of the form "@file".  */
        if (it->compare("@file") != 0) {
            continue;
        }

        // The next argument should be the actual file name
        const auto file_it = std::next(it);
        if (file_it == expanded.end()) {
            std::cerr << argv[0]
                      << ": error: Expected file name but got nothing\n";
            exit(1);
        }
        const auto & filename = *file_it;

        /* If we have iterated too many times then stop.  */
        if (--iteration_limit <= 0) {
            std::cerr << argv[0] << ": error: too many @-files encountered\n";
            exit(1);
        }

        // Check whether the file exists
        using stat_t = struct stat;
        stat_t sb{};
        if (stat(filename.c_str(), &sb) < 0) {
            continue;
        }

        // Make sure that the file isn't a directory
        if (S_ISDIR(sb.st_mode)) {
            std::cerr << argv[0] << ": error: @-file refers to a directory\n";
            exit(1);
        }

        // Open the file
        std::ifstream f(filename);
        if (!f) {
            std::cerr << argv[0] << ": error: Unable to open the file at \""
                      << filename << "\"\n";
            continue;
        }

        // Read data
        using IterT = std::istreambuf_iterator<char>;
        std::string buffer{IterT{f}, IterT{}};

        // Parse file to a list of new arguments
        auto new_args = argv_from_file<ResultT>(buffer.cbegin(), buffer.cend());

        /* Rescan all of the arguments just read to support response
files that include other response files.  */
        if (!new_args.empty()) {
            --it;
        }

        expanded.splice(it, new_args);
    }

    return {expanded.begin(), expanded.end()};
}
