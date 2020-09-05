/* -*- mode: C++; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 99; -*-
 */
/* vim: set ts=4 sw=4 et tw=99:  */
/*
Copyright (C) 2012 Lubos Lunak <l.lunak@suse.cz>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
Older icecream versions assume the compiler is always GCC. This can
be fixed on the local side, but remote nodes would need icecream upgrade.
As a workaround icecc-create-env includes this wrapper binary in the environment
if clang is to be used as well, that will either call clang or the real gcc.
Which one depends on an extra argument added by icecream.
*/

extern "C" {
#include <unistd.h>
}

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

int
main(int argc, char * argv[])
{
    bool        is_cxx = false;
    std::size_t argv0len = strlen(argv[0]);

    if (argv0len > 2 && argv[0][argv0len - 1] == '+' &&
        argv[0][argv0len - 2] == '+') {
        is_cxx = true;
    }

#if DEBUG_LEVEL > 0
    std::cout << "Args1:\n";

    for (int i = 0; i < argc; ++i) {
        std::cout << argv[i] << '\n';
    }
    std::cout << '\n';
#endif

    bool is_clang = (argc >= 2) && (strcmp(argv[1], "clang") ==
                                    0); // the extra argument from icecream
    // 1 extra for -no-canonical-prefixes
    std::vector<std::string> args{};
    args.emplace_back(argv[0], argv0len);

    const auto separator_pos = args[0].rfind('/');

#if 0
    char ** args = new char *[argc + 2];
    args[0] = new char[strlen(argv[0]) + 20];
    char * separator = strrchr(args[0], '/');
#endif

    if (separator_pos == std::string::npos) {
        args[0].resize(0);
    } else {
        args[0].resize(separator_pos);
    }

    if (is_clang) {
        args[0].append("clang");
    } else if (is_cxx) {
        args[0].append("g++.bin");
    } else {
        args[0].append("gcc.bin");
    }

    if (is_clang) {
        args.emplace_back("-no-canonical-prefixes"); // otherwise clang tries to
                                                     // access /proc/self/exe
        // clang wants the -x argument early, otherwise it seems to ignore it
        // (and treats the file as already preprocessed)
        int x_arg_pos = -1;

        for (int i = 2; // 2 - skip the extra "clang" argument
             i < argc;
             ++i) {
            if (strcmp(argv[i], "-x") == 0 && i + 1 < argc &&
                (strcmp(argv[i + 1], "c") == 0 ||
                 strcmp(argv[i + 1], "c++") == 0)) {
                x_arg_pos = i;
                args.emplace_back("-x");
                args.emplace_back(argv[i + 1]);
                break;
            }
        }

        for (int i = 2; // 2 - skip the extra "clang" argument
             i < argc;
             ++i) {
            // strip options that icecream adds but clang doesn't know or need
            if (strcmp(argv[i], "-fpreprocessed") == 0) {
                continue; // clang doesn't know this (it presumably needs to
                          // always preprocess anyway)
            }

            if (strcmp(argv[i], "--param") == 0 && i + 1 < argc) {
                if (strncmp(argv[i + 1],
                            "ggc-min-expand=",
                            strlen("ggc-min-expand=")) == 0 ||
                    strncmp(argv[i + 1],
                            "ggc-min-heapsize=",
                            strlen("ggc-min-heapsize=")) == 0) {
                    // drop --param and the parameter itself
                    ++i;
                    continue;
                }
            }

            if (i == x_arg_pos) {
                ++i; // skip following
                continue; // and skip this one
            }

            args.emplace_back(argv[i]);
        }
    } else { // !is_clang , just copy the arguments
        for (int i = 1; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }
    }

#if DEBUG_LEVEL > 0
    fprintf(stderr, "Args2:\n");

    for (int i = 0; i < pos; ++i) {
        fprintf(stderr, "%s\n", args[i]);
    }

    fprintf(stderr, "\n");
#endif

    const auto execv_args = [&args] {
        std::vector<char *> result{};
        result.reserve(args.size() + 1);

        std::transform(args.begin(),
                       args.end(),
                       std::back_inserter(result),
                       [](std::string & x) {
                           // Since C++11 string data is guaranteed to end with
                           // a null character
                           return &x[0];
                       });
        result.emplace_back(nullptr);

        return result;
    }();

    execv(execv_args[0], execv_args.data());
    // Execution should stop here if the execv call was successful
    std::cerr << "execv " << args[0] << " failed:\n" << strerror(errno) << '\n';

    return -1;
}
