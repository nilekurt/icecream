/* -*- mode: C++; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 99; -*-
 */
/* vim: set ts=4 sw=4 et tw=99:  */
/*
 * distcc -- A simple distributed compiler system
 *
 * Copyright (C) 2002, 2003 by Martin Pool <mbp@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file
 *
 * Run the preprocessor.  Client-side only.
 **/

#include "call_cpp.hh"

#include "client_util.hh"
#include "local.hh"
#include "logging.hh"
#include "safeguard.hh"

#include <algorithm>

namespace {

bool
dcc_is_preprocessed(const std::string & sfile)
{
    if (sfile.size() < 3) {
        return false;
    }

    int last = sfile.size() - 1;

    if ((sfile[last - 1] == '.') && (sfile[last] == 'i')) {
        return true; // .i
    }

    if ((sfile[last - 2] == '.') && (sfile[last - 1] == 'i') &&
        (sfile[last] == 'i')) {
        return true; // .ii
    }

    return false;
}

std::list<std::string>
filtered_flags(const CompileJob & job)
{
    auto result = job.localFlags();

    result.splice(result.end(), job.restFlags());

    for (auto it = result.begin(); it != result.end();) {
        /* This has a duplicate meaning. it can either include a file
           for preprocessing or a precompiled header. decide which one. */
        if ((*it) == "-include") {
            ++it;

            if (it != result.end()) {
                std::string p = (*it);

                if (access(p.c_str(), R_OK) < 0 &&
                    access((p + ".gch").c_str(), R_OK) == 0) {
                    // PCH is useless for preprocessing, ignore the flag.
                    auto o = --it;
                    ++it;
                    result.erase(o);
                    o = it++;
                    result.erase(o);
                }
            }
        } else if ((*it) == "-include-pch") {
            auto o = it;
            ++it;
            if (it != result.end()) {
                std::string p = (*it);
                if (access(p.c_str(), R_OK) == 0) {
                    // PCH is useless for preprocessing (and probably
                    // slows things down), ignore the flag.
                    result.erase(o);
                    o = it++;
                    result.erase(o);
                }
            }
        } else if ((*it) == "-fpch-preprocess") {
            // This would add #pragma GCC pch_preprocess to the
            // preprocessed output, which would make the remote GCC try
            // to load the PCH directly and fail. Just drop it. This may
            // cause a build failure if the -include check above failed
            // to detect usage of a PCH file (e.g. because it needs to
            // be found in one of the -I paths, which we don't check)
            // and the header file itself doesn't exist.
            result.erase(it++);
        } else if ((*it) == "-fmodules" || (*it) == "-fcxx-modules" ||
                   (*it) == "-fmodules-ts" ||
                   (*it).find("-fmodules-cache-path=") == 0) {
            // Clang modules, handle like with PCH, remove the flags and
            // compile remotely without them.
            result.erase(it++);
        } else {
            ++it;
        }
    }

    return result;
}

std::vector<std::string>
make_argv(const CompileJob & job)
{
    auto flags = filtered_flags(job);

    std::vector<std::string> result{};

    if (dcc_is_preprocessed(job.inputFile())) {
        /* already preprocessed, great.
           write the file to the fdwrite (using cat) */
        result.emplace_back("/bin/cat");
        result.emplace_back(job.inputFile());
        return result;
    }

    result.reserve(flags.size() + 4);
    result.emplace_back(find_compiler(job));

    result.insert(result.end(),
                  std::make_move_iterator(flags.begin()),
                  std::make_move_iterator(flags.end()));

    result.emplace_back("-E");
    result.emplace_back(job.inputFile());

    if (compiler_only_rewrite_includes(job)) {
        if (compiler_is_clang(job)) {
            result.emplace_back("-frewrite-includes");
        } else { // gcc
            result.emplace_back("-fdirectives-only");
        }
    }

    return result;
}

} // namespace

/**
 * If the input filename is a plain source file rather than a
 * preprocessed source file, then preprocess it to a temporary file
 * and return the name in @p cpp_fname.
 *
 * The preprocessor may still be running when we return; you have to
 * wait for @p cpp_fid to exit before the output is complete.  This
 * allows us to overlap opening the TCP socket, which probably doesn't
 * use many cycles, with running the preprocessor.
 **/
pid_t
call_cpp(CompileJob & job, int fdwrite, int fdread)
{
    flush_debug();
    pid_t pid = fork();

    if (pid == -1) {
        log_perror("failed to fork:");
        return -1; /* probably */
    }

    if (pid != 0) {
        /* Parent.  Close the write fd.  */
        if (fdwrite > -1) {
            if ((-1 == close(fdwrite)) && (errno != EBADF)) {
                log_perror("close() failed");
            }
        }

        return pid;
    }

    /* Child.  Close the read fd, in case we have one.  */
    if (fdread > -1) {
        if ((-1 == close(fdread)) && (errno != EBADF)) {
            log_perror("close failed");
        }
    }

    int ret = dcc_ignore_sigpipe(0);

    if (ret) { /* set handler back to default */
        _exit(ret);
    }

    auto argv = make_argv(job);

    if (argv.empty()) {
        throw std::runtime_error("Argument list is empty");
    }

    std::string argstxt = argv[0];
    for (auto it = argv.begin() + 1; it != argv.end(); ++it) {
        argstxt += ' ';
        argstxt += *it;
    }
    trace() << "preparing source to send: " << argstxt << '\n';

    if (fdwrite != STDOUT_FILENO) {
        /* Ignore failure */
        close(STDOUT_FILENO);
        dup2(fdwrite, STDOUT_FILENO);
        close(fdwrite);
    }

    dcc_increment_safeguard(SafeguardStepCompiler);

    const std::vector<char *> argv_char_ptr = [&argv] {
        std::vector<char *> result(argv.size() + 1, nullptr);

        std::transform(argv.begin(),
                       argv.end(),
                       result.begin(),
                       [](std::string & s) { return &s[0]; });

        return result;
    }();

    execv(argv_char_ptr[0], argv_char_ptr.data());
    int exitcode = (errno == ENOENT ? 127 : 126);
    log_perror("execv " + argv[0] + " failed");
    _exit(exitcode);
}
