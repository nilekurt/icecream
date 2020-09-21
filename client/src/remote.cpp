/* -*- mode: C++; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 99; -*-
 */
/* vim: set ts=4 sw=4 et tw=99:  */
/*
    This file is part of Icecream.

    Copyright (c) 2004 Stephan Kulow <coolo@suse.de>
                  2002, 2003 by Martin Pool <mbp@samba.org>

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

#include "remote.hh"

#include "call_cpp.hh"
#include "client_util.hh"
#include "errors.h"
#include "exitcode.h"
#include "local.hh"
#include "logging.hh"
#include "md5.h"
#include "pipes.h"
#include "services_util.hh"
#include "tempfile.hh"

extern "C" {
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
}

#include <algorithm>
#include <map>
#include <unordered_map>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

std::string remote_daemon;

namespace {

bool
endswith(const std::string & orig,
         const std::string & suffix,
         std::string &       ret)
{

    if (orig.size() > suffix.size()) {
        const auto base_length = orig.size() - suffix.size();

        if (orig.substr(base_length).compare(suffix) == 0) {
            ret = orig.substr(0, base_length);
            return true;
        }
    }

    return false;
}

Environments
rip_out_paths(const Environments &                 envs,
              std::map<std::string, std::string> & version_map,
              std::map<std::string, std::string> & versionfile_map)
{
    version_map.clear();

    Environments env2;

    // @TODO: make_array
    constexpr std::array<const char *, 6> suffixes{
        ".tar.xz", ".tar.zst", ".tar.bz2", ".tar.gz", ".tar", ".tgz"};

    std::string versfile;

    // host platform + filename
    for (const auto & env : envs) {
        for (const char * suffix : suffixes) {
            if (endswith(env.second, suffix, versfile)) {
                versionfile_map[env.first] = env.second;
                versfile = find_basename(versfile);
                version_map[env.first] = versfile;
                env2.push_back(make_pair(env.first, versfile));
            }
        }
    }

    return env2;
}

UseCSMsg &
get_use_cs(Msg & msg)
{
    auto * use_cs = ext::get_if<UseCSMsg>(&msg);
    if (use_cs == nullptr) {
        const auto * msg_type = message_type(msg);

        log_warning() << "reply was not expected use_cs " << msg_type << '\n';
        std::ostringstream unexpected_msg;
        unexpected_msg << "Error 1 - expected use_cs reply, but got "
                       << msg_type << " instead";
        throw ClientError(1, unexpected_msg.str());
    }

    return *use_cs;
}

int
get_niceness()
{
    errno = 0;
    int niceness = getpriority(PRIO_PROCESS, getpid());
    if ((niceness < 0) && (errno != 0))
        niceness = 0;
    return niceness;
}

int
niceness_timeout()
{
    return (get_niceness() > 0) ? (60 * 60) : (4 * 60);
}

void
check_for_failure(const Msg & msg, MsgChannel * cserver)
{
    const auto * status = ext::get_if<StatusTextMsg>(&msg);
    if (status != nullptr) {
        log_error() << "Remote status (compiled on " << cserver->name
                    << "): " << status->text << '\n';
        throw ClientError(23,
                          "Error 23 - Remote status (compiled on " +
                              cserver->name + ")\n" + status->text);
    }
}

// 'unlock_sending' = dcc_lock_host() is held when this is called,
// temporarily yield the lock while doing network transfers
void
write_fd_to_server(int fd, MsgChannel * cserver, bool unlock_sending = false)
{
    unsigned char buffer[100000]; // some random but huge number
    off_t         offset = 0;
    size_t        uncompressed = 0;
    size_t        compressed = 0;

    do {
        ssize_t bytes;

        do {
            bytes = read(fd, buffer + offset, sizeof(buffer) - offset);

            if (bytes < 0 &&
                (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }

            if (bytes < 0) {
                log_perror("write_fd_to_server() reading from fd");
                close(fd);
                throw ClientError(16, "Error 16 - error reading local file");
            }

            break;
        } while (1);

        offset += bytes;

        if (!bytes || offset == sizeof(buffer)) {
            if (offset) {
                // If write_fd_to_server() is called for sending
                // preprocessed data, the dcc_lock_host() lock is held to
                // limit the number cpp invocations to the cores available
                // to prevent overload. But that would essentially also
                // limit network transfers, so temporarily yield and
                // reaquire again.
                if (unlock_sending)
                    dcc_unlock();
                Msg msg{ext::in_place_type_t<FileChunkMsg>{}, buffer, offset};

                if (!cserver->sendMsg(msg)) {
                    constexpr int timeout{2};
                    auto          msg = cserver->getMsg(timeout);
                    check_for_failure(msg, cserver);

                    log_error() << "write of source chunk to host "
                                << cserver->name.c_str() << '\n';
                    log_perror("failed ");
                    close(fd);
                    throw ClientError(15, "Error 15 - write to host failed");
                }
                auto * fcmsg = ext::get_if<FileChunkMsg>(&msg);
                assert(fcmsg != nullptr);

                uncompressed += fcmsg->buffer.size();
                compressed += fcmsg->compressed;
                offset = 0;
                if (unlock_sending) {
                    if (!dcc_lock_host()) {
                        log_error()
                            << "can't reaquire lock for local cpp\n";
                        close(fd);
                        throw ClientError(32, "Error 32 - lock failed");
                    }
                }
            }

            if (!bytes) {
                break;
            }
        }
    } while (1);

    if (compressed) {
        auto percentage_part = [](auto part, auto total) {
            return 100.0F * part / total;
        };
        trace() << "sent " << compressed << " bytes ("
                << percentage_part(compressed, uncompressed) << "%)\n";
    }

    if ((close(fd) < 0) && (errno != EBADF)) {
        log_perror("close failed");
    }
}

void
receive_file(const std::string & output_file, MsgChannel * cserver)
{
    std::string tmp_file = output_file + "_icetmp";
    int         obj_fd = open(
        tmp_file.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_LARGEFILE, 0666);

    if (obj_fd < 0) {
        std::string errmsg("can't create ");
        errmsg += tmp_file + ":";
        log_perror(errmsg.c_str());
        throw ClientError(31, "Error 31 - " + errmsg);
    }

    size_t uncompressed = 0;
    size_t compressed = 0;

    while (1) {
        constexpr int timeout{40};
        auto          msg = cserver->getMsg(timeout);

        if (ext::holds_alternative<ext::monostate>(
                msg)) { // the network went down?
            unlink(tmp_file.c_str());
            throw ClientError(19, "Error 19 - (network failure?)");
        }

        check_for_failure(msg, cserver);

        if (ext::holds_alternative<EndMsg>(msg)) {
            break;
        }

        auto * fcmsg = ext::get_if<FileChunkMsg>(&msg);
        if (fcmsg == nullptr) {
            unlink(tmp_file.c_str());
            throw ClientError(20, "Error 20 - unexpected message");
        }

        compressed += fcmsg->compressed;
        uncompressed += fcmsg->buffer.size();

        const auto buf_size = static_cast<ssize_t>(fcmsg->buffer.size());
        if (write(obj_fd, fcmsg->buffer.data(), buf_size) != buf_size) {
            log_perror("Error writing file: ");
            unlink(tmp_file.c_str());
            throw ClientError(21, "Error 21 - error writing file");
        }
    }

    if (uncompressed)
        trace() << "got " << compressed << " bytes ("
                << (compressed * 100 / uncompressed) << "%)\n";

    if (close(obj_fd) != 0) {
        log_perror("Failed to close temporary file: ");
        if (unlink(tmp_file.c_str()) != 0) {
            log_perror("delete temporary file - might be related to close "
                       "failure above");
        }
        throw ClientError(30, "Error 30 - error closing temp file");
    }
    if (rename(tmp_file.c_str(), output_file.c_str()) != 0) {
        log_perror("Failed to rename temporary file: ");
        if (unlink(tmp_file.c_str()) != 0) {
            log_perror("delete temporary file - might be related to rename "
                       "failure above");
        }
        throw ClientError(30, "Error 30 - error closing temp file");
    }
}

int
build_remote_int(CompileJob &        job,
                 const UseCSMsg &    usecs,
                 MsgChannel *        local_daemon,
                 const std::string & environment,
                 const std::string & version_file,
                 const char *        preproc_file,
                 bool                output)
{
    const auto & hostname = usecs.hostname;
    unsigned int port = usecs.port;
    int          job_id = usecs.job_id;
    bool         got_env = usecs.got_env;

    job.setJobID(job_id);
    job.setEnvironmentVersion(environment); // hoping on the scheduler's wisdom
    trace() << "Have to use host " << hostname << ":" << port
            << " - Job ID: " << job.jobID() << " - env: " << usecs.host_platform
            << " - has env: " << (got_env ? "true" : "false")
            << " - match j: " << usecs.matched_job_id << "\n";

    int status = 255;

    MsgChannel * cserver = nullptr;

    try {
        cserver = Service::createChannel(hostname, port, 10);

        if (!cserver) {
            log_error() << "no server found behind given hostname " << hostname
                        << ":" << port << '\n';
            throw ClientError(2, "Error 2 - no server found at " + hostname);
        }

        if (!got_env) {
            LogBlock b("Transfer Environment");
            // transfer env
            struct stat buf;

            if (stat(version_file.c_str(), &buf)) {
                log_perror("error stat'ing file")
                    << "\t" << version_file << '\n';
                throw ClientError(4, "Error 4 - unable to stat version file");
            }

            EnvTransferMsg msg(job.targetPlatform(), job.environmentVersion());

            if (!cserver->sendMsg(msg)) {
                throw ClientError(
                    6, "Error 6 - send environment to remote failed");
            }

            int env_fd = open(version_file.c_str(), O_RDONLY);

            if (env_fd < 0) {
                throw ClientError(5,
                                  "Error 5 - unable to open version file:\n\t" +
                                      version_file);
            }

            write_fd_to_server(env_fd, cserver);

            if (!cserver->sendMsg(EndMsg())) {
                log_error() << "write of environment failed\n";
                throw ClientError(
                    8, "Error 8 - write environment to remote failed");
            }

            if (IS_PROTOCOL_31(cserver)) {
                VerifyEnvMsg verifymsg(job.targetPlatform(),
                                       job.environmentVersion());

                if (!cserver->sendMsg(verifymsg)) {
                    throw ClientError(22,
                                      "Error 22 - error sending environment");
                }

                constexpr int timeout{60};
                auto          msg = cserver->getMsg(timeout);

                auto * verify_env = ext::get_if<VerifyEnvResultMsg>(&msg);
                if (verify_env != nullptr) {
                    if (!verify_env->ok) {
                        // The remote can't handle the environment at all
                        // (e.g. kernel too old), mark it as never to be
                        // used again for this environment.
                        log_warning()
                            << "Host " << hostname
                            << " did not successfully verify environment."
                            << '\n';
                        BlacklistHostEnvMsg blacklist(job.targetPlatform(),
                                                      job.environmentVersion(),
                                                      hostname);
                        local_daemon->sendMsg(blacklist);
                        throw ClientError(24,
                                          "Error 24 - remote " + hostname +
                                              " unable to handle environment");
                    } else
                        trace()
                            << "Verified host " << hostname
                            << " for environment " << job.environmentVersion()
                            << " (" << job.targetPlatform() << ")\n";
                } else {
                    throw ClientError(25,
                                      "Error 25 - other error verifying "
                                      "environment on remote");
                }
            }
        }

        if (!IS_PROTOCOL_31(cserver) && ignore_unverified()) {
            log_warning() << "Host " << hostname << " cannot be verified."
                          << '\n';
            throw ClientError(26,
                              "Error 26 - environment on " + hostname +
                                  " cannot be verified");
        }

        // Older remotes don't set properly -x argument.
        if ((job.language() == CompileJob::Lang_OBJC ||
             job.language() == CompileJob::Lang_OBJCXX) &&
            !IS_PROTOCOL_38(cserver)) {
            job.appendFlag("-x", ArgumentType::REMOTE);
            job.appendFlag(job.language() == CompileJob::Lang_OBJC
                               ? "objective-c"
                               : "objective-c++",
                           ArgumentType::REMOTE);
        }

        {
            LogBlock b("send compile_file");

            if (!cserver->sendMsg(CompileFileMsg{job})) {
                log_warning() << "write of job failed\n";
                throw ClientError(9, "Error 9 - error sending file to remote");
            }
        }

        if (!preproc_file) {
            int sockets[2];

            if (create_large_pipe(sockets) != 0) {
                log_perror("build_remote_in pipe");
                /* for all possible cases, this is something severe */
                throw ClientError(32, "Error 18 - (fork error?)");
            }

            if (!dcc_lock_host()) {
                log_error() << "can't lock for local cpp\n";
                return EXIT_DISTCC_FAILED;
            }
            HostUnlock hostUnlock; // automatic dcc_unlock()

            /* This will fork, and return the pid of the child.  It will not
               return for the child itself.  If it returns normally it will
               have closed the write fd, i.e. sockets[1].  */
            pid_t cpp_pid = call_cpp(job, sockets[1], sockets[0]);

            if (cpp_pid < 0) {
                throw ClientError(18, "Error 18 - (fork error?)");
            }

            try {
                LogBlock bl2("write_fd_to_server from cpp");
                write_fd_to_server(sockets[0], cserver, true /*yield lock*/);
            } catch (...) {
                kill(cpp_pid, SIGTERM);
                throw;
            }

            LogBlock wait_cpp("wait for cpp");

            while ((waitpid(cpp_pid, &status, 0) < 0) && (errno == EINTR)) {
            }

            if (shell_exit_status(status) != 0) { // failure
                delete cserver;
                cserver = nullptr;
                log_warning() << "call_cpp process failed with exit status "
                              << shell_exit_status(status) << '\n';
                // GCC's -fdirectives-only has a number of cases that it
                // doesn't handle properly, so if in such mode preparing the
                // source fails, try again recompiling locally. This will
                // cause double error in case it is a real error, but it'll
                // build successfully if it was just -fdirectives-only being
                // broken. In other cases fail directly, Clang's
                // -frewrite-includes is much more reliable than
                // -fdirectives-only, so is GCC's plain -E.
                if (!compiler_is_clang(job) &&
                    compiler_only_rewrite_includes(job))
                    throw RemoteError(103,
                                      "Error 103 - local cpp invocation "
                                      "failed, trying to recompile locally");
                else
                    return shell_exit_status(status);
            }
        } else {
            int cpp_fd = open(preproc_file, O_RDONLY);

            if (cpp_fd < 0) {
                throw ClientError(
                    11, "Error 11 - unable to open preprocessed file");
            }

            LogBlock cpp_block("write_fd_to_server preprocessed");
            write_fd_to_server(cpp_fd, cserver);
        }

        if (!cserver->sendMsg(EndMsg())) {
            log_warning() << "write of end failed\n";
            throw ClientError(12, "Error 12 - failed to send file to remote");
        }

        Msg msg{};
        {
            LogBlock      wait_cs("wait for cs");
            constexpr int timeout{12 * 60};
            msg = cserver->getMsg(timeout);
        }

        check_for_failure(msg, cserver);

        auto * crmsg_p = ext::get_if<CompileResultMsg>(&msg);
        if (crmsg_p == nullptr) {
            log_warning() << "waited for compile result, but got "
                          << message_type(msg) << '\n';
            throw ClientError(
                13, "Error 13 - did not get compile response message");
        }
        auto & crmsg = *crmsg_p;

        status = crmsg.status;
        if (status && crmsg.was_out_of_memory) {
            log_warning() << "the server ran out of memory, recompiling locally"
                          << '\n';
            throw RemoteError(101,
                              "Error 101 - the server ran out of memory, "
                              "recompiling locally");
        }

        if (output) {
            if ((!crmsg.out.empty() || !crmsg.err.empty()) &&
                output_needs_workaround(job)) {
                log_warning() << "command needs stdout/stderr workaround, "
                                 "recompiling locally"
                              << '\n';
                log_warning()
                    << "(set ICECC_CARET_WORKAROUND=0 to override)\n";
                throw RemoteError(102,
                                  "Error 102 - command needs stdout/stderr "
                                  "workaround, recompiling locally");
            }

            if (crmsg.err.find("file not found") != std::string::npos) {
                log_warning()
                    << "remote is missing file, recompiling locally\n";
                throw RemoteError(104,
                                  "Error 104 - remote is missing file, "
                                  "recompiling locally");
            }

            ignore_result(
                write(STDOUT_FILENO, crmsg.out.c_str(), crmsg.out.size()));

            if (colorify_wanted(job)) {
                colorify_output(crmsg.err);
            } else {
                ignore_result(
                    write(STDERR_FILENO, crmsg.err.c_str(), crmsg.err.size()));
            }

            if (status && (crmsg.err.length() || crmsg.out.length())) {
                log_info() << "Compiled on " << hostname << '\n';
            }
        }

        bool have_dwo_file = crmsg.have_dwo_file;

        assert(!job.outputFile().empty());

        if (status == 0) {
            receive_file(job.outputFile(), cserver);
            if (have_dwo_file) {
                std::string dwo_output =
                    job.outputFile().substr(0, job.outputFile().rfind('.')) +
                    ".dwo";
                receive_file(dwo_output, cserver);
            }
        }
    } catch (...) {
        // Handle pending status messages, if any.
        if (cserver) {
            Msg msg{};
            do {
                msg = cserver->getMsg(0, true);
                if (auto * stmsg = ext::get_if<StatusTextMsg>(&msg)) {
                    log_error()
                        << "Remote status (compiled on " << cserver->name
                        << "): " << stmsg->text << '\n';
                }
            } while (!ext::holds_alternative<ext::monostate>(msg));
            delete cserver;
            cserver = nullptr;
        }

        throw;
    }

    delete cserver;
    return status;
}

std::string
md5_for_file(const std::string & file)
{
    md5_state_t state;
    std::string result;

    md5_init(&state);
    FILE * f = fopen(file.c_str(), "rb");

    if (!f) {
        return result;
    }

    md5_byte_t buffer[40000];

    while (true) {
        size_t size = fread(buffer, 1, 40000, f);

        if (!size) {
            break;
        }

        md5_append(&state, buffer, size);
    }

    fclose(f);

    md5_byte_t digest[16];
    md5_finish(&state, digest);

    char digest_cache[33];

    for (int di = 0; di < 16; ++di) {
        sprintf(digest_cache + di * 2, "%02x", digest[di]);
    }

    digest_cache[32] = 0;
    result = digest_cache;
    return result;
}

bool
maybe_build_local(MsgChannel *     local_daemon,
                  const UseCSMsg & usecs,
                  CompileJob &     job,
                  int &            ret)
{
    remote_daemon = usecs.hostname;

    if (usecs.hostname == "127.0.0.1") {
        // If this is a test build, do local builds on the local daemon
        // that has --no-remote, use remote building for the remaining ones.
        if (getenv("ICECC_TEST_REMOTEBUILD") && usecs.port != 0)
            return false;
        trace() << "building myself, but telling localhost\n";
        int job_id = usecs.job_id;
        job.setJobID(job_id);
        job.setEnvironmentVersion("__client");

        if (!local_daemon->sendMsg(CompileFileMsg{job})) {
            log_warning() << "write of job failed\n";
            throw ClientError(29, "Error 29 - write of job failed");
        }

        struct timeval begintv, endtv;

        struct rusage ru;

        gettimeofday(&begintv, nullptr);

        ret = build_local(job, local_daemon, &ru);

        gettimeofday(&endtv, nullptr);

        // filling the stats, so the daemon can play proxy for us
        JobDoneMsg msg(job_id, ret, JobDoneMsg::FROM_SUBMITTER);

        msg.real_msec = (endtv.tv_sec - begintv.tv_sec) * 1000 +
                        (endtv.tv_usec - begintv.tv_usec) / 1000;

        struct stat st;

        msg.out_uncompressed = 0;
        if (!stat(job.outputFile().c_str(), &st)) {
            msg.out_uncompressed += st.st_size;
        }
        if (!stat((job.outputFile().substr(0, job.outputFile().rfind('.')) +
                   ".dwo")
                      .c_str(),
                  &st)) {
            msg.out_uncompressed += st.st_size;
        }

        msg.user_msec = ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000;
        msg.sys_msec = ru.ru_stime.tv_sec * 1000 + ru.ru_stime.tv_usec / 1000;
        msg.pfaults = ru.ru_majflt + ru.ru_minflt + ru.ru_nswap;
        msg.exitcode = ret;

        if (msg.user_msec > 50 && msg.out_uncompressed > 1024) {
            trace() << "speed=" << float(msg.out_uncompressed / msg.user_msec)
                    << '\n';
        }

        return local_daemon->sendMsg(msg);
    }

    return false;
}

// Minimal version of remote host that we want to use for the job.
int
minimalRemoteVersion(const CompileJob & job)
{
    int version = MIN_PROTOCOL_VERSION;
    if (ignore_unverified()) {
        version = std::max(version, 31);
    }

    if (job.dwarfFissionEnabled()) {
        version = std::max(version, 35);
    }

    return version;
}

unsigned int
requiredRemoteFeatures()
{
    unsigned int features = 0;
    if (const char * icecc_env_compression = getenv("ICECC_ENV_COMPRESSION")) {
        if (strcmp(icecc_env_compression, "xz") == 0)
            features = features | NODE_FEATURE_ENV_XZ;
        if (strcmp(icecc_env_compression, "zstd") == 0)
            features = features | NODE_FEATURE_ENV_ZSTD;
    }
    return features;
}

} // namespace

Environments
parse_icecc_version(const std::string & target_platform,
                    const std::string & prefix)
{
    Environments envs;

    std::string icecc_version = getenv("ICECC_VERSION");
    assert(!icecc_version.empty());

    // free after the C++-Programming-HOWTO
    std::string::size_type lastPos = icecc_version.find_first_not_of(',', 0);
    std::string::size_type pos = icecc_version.find(',', lastPos);
    bool def_targets = icecc_version.find('=') != std::string::npos;

    std::list<std::string> platforms;

    while (pos != std::string::npos || lastPos != std::string::npos) {
        std::string couple = icecc_version.substr(lastPos, pos - lastPos);
        std::string platform = target_platform;
        std::string version = couple;
        std::string::size_type colon = couple.find(':');

        if (colon != std::string::npos) {
            platform = couple.substr(0, colon);
            version = couple.substr(colon + 1, couple.length());
        }

        // Skip delimiters.  Note the "not_of"
        lastPos = icecc_version.find_first_not_of(',', pos);
        // Find next "non-delimiter"
        pos = icecc_version.find(',', lastPos);

        if (def_targets) {
            colon = version.find('=');

            if (colon != std::string::npos) {
                if (prefix != version.substr(colon + 1, version.length())) {
                    continue;
                }

                version = version.substr(0, colon);
            } else if (!prefix.empty()) {
                continue;
            }
        }

        if (find(platforms.begin(), platforms.end(), platform) !=
            platforms.end()) {
            log_error() << "there are two environments for platform "
                        << platform << " - ignoring " << version << '\n';
            continue;
        }

        if (::access(version.c_str(), R_OK) < 0) {
            log_error() << "$ICECC_VERSION has to point to an existing file to "
                           "be installed "
                        << version << '\n';
            continue;
        }

        struct stat st;

        if (lstat(version.c_str(), &st) || !S_ISREG(st.st_mode) ||
            st.st_size < 500) {
            log_error() << "$ICECC_VERSION has to point to an existing file to "
                           "be installed "
                        << version << '\n';
            continue;
        }

        envs.push_back(make_pair(platform, version));
        platforms.push_back(platform);
    }

    return envs;
}

int
build_remote(CompileJob &         job,
             MsgChannel *         local_daemon,
             const Environments & _envs,
             int                  permill)
{
    constexpr int default_exit_code = 42;

    srand(time(nullptr) + getpid());

    int  to_repeat = 1;
    bool has_split_dwarf = job.dwarfFissionEnabled();

    if (!compiler_is_clang(job)) {
        if (rand() % 1000 < permill) {
            to_repeat = 3;
        }
    }

    if (to_repeat == 1) {
        trace() << "preparing " << job.inputFile() << " to be compiled for "
                << job.targetPlatform() << "\n";
    } else {
        trace() << "preparing " << job.inputFile() << " to be compiled "
                << to_repeat << " times for " << job.targetPlatform() << "\n";
    }

    std::map<std::string, std::string> versionfile_map, version_map;
    Environments envs = rip_out_paths(_envs, version_map, versionfile_map);

    if (!envs.size()) {
        log_error() << "$ICECC_VERSION needs to point to .tar files\n";
        throw ClientError(
            22, "Error 22 - $ICECC_VERSION needs to point to .tar files");
    }

    const char * preferred_host = getenv("ICECC_PREFERRED_HOST");

    if (to_repeat == 1) {
        std::string            fake_filename;
        std::list<std::string> args = job.remoteFlags();

        for (auto it = args.begin(); it != args.end(); ++it) {
            fake_filename += "/" + *it;
        }

        args = job.restFlags();

        for (auto it = args.begin(); it != args.end(); ++it) {
            fake_filename += "/" + *it;
        }

        fake_filename += get_absfilename(job.inputFile());

        GetCSMsg getcs(envs,
                       fake_filename,
                       job.language(),
                       to_repeat,
                       job.targetPlatform(),
                       job.argumentFlags(),
                       preferred_host ? preferred_host : std::string(),
                       minimalRemoteVersion(job),
                       requiredRemoteFeatures(),
                       get_niceness());

        trace() << "asking for host to use\n";
        if (!local_daemon->sendMsg(getcs)) {
            log_warning() << "asked for CS\n";
            throw ClientError(24, "Error 24 - asked for CS");
        }

        auto msg = local_daemon->getMsg(niceness_timeout());

        const auto & usecs = get_use_cs(msg);
        int          ret;

        if (!maybe_build_local(local_daemon, usecs, job, ret)) {
            ret = build_remote_int(job,
                                   usecs,
                                   local_daemon,
                                   version_map[usecs.host_platform],
                                   versionfile_map[usecs.host_platform],
                                   nullptr,
                                   true);
        }

        return ret;
    } else {
        std::string preproc;
        if (dcc_make_tmpnam("icecc", ".ix", preproc, 0) != 0) {
            throw std::runtime_error("Unable to make tmpname");
        }

        int cpp_fd = open(preproc.c_str(), O_WRONLY);

        if (!dcc_lock_host()) {
            log_error() << "can't lock for local cpp\n";
            return EXIT_DISTCC_FAILED;
        }
        HostUnlock hostUnlock; // automatic dcc_unlock()

        /* When call_cpp returns normally (for the parent) it will have closed
           the write fd, i.e. cpp_fd.  */
        pid_t cpp_pid = call_cpp(job, cpp_fd);

        if (cpp_pid < 0) {
            unlink(preproc.c_str());
            throw ClientError(10, "Error 10 - (unable to fork process?)");
        }

        int status = 255;
        waitpid(cpp_pid, &status, 0);

        if (shell_exit_status(status)) { // failure
            log_warning() << "call_cpp process failed with exit status "
                          << shell_exit_status(status) << '\n';
            unlink(preproc.c_str());
            return shell_exit_status(status);
        }
        dcc_unlock();

        char rand_seed[400]; // "designed to be oversized" (Levi's)
        sprintf(rand_seed, "-frandom-seed=%d", rand());
        job.appendFlag(rand_seed, ArgumentType::REMOTE);

        GetCSMsg getcs(envs,
                       get_absfilename(job.inputFile()),
                       job.language(),
                       to_repeat,
                       job.targetPlatform(),
                       job.argumentFlags(),
                       preferred_host ? preferred_host : std::string(),
                       minimalRemoteVersion(job),
                       0,
                       get_niceness());

        if (!local_daemon->sendMsg(getcs)) {
            log_warning() << "asked for CS\n";
            throw ClientError(0, "Error 0 - asked for CS");
        }

        std::unordered_map<pid_t, int> jobmap;
        std::vector<CompileJob>        jobs(to_repeat, job);

        std::vector<Msg> msgs{};
        msgs.reserve(to_repeat);
        std::vector<std::reference_wrapper<UseCSMsg>> umsgs{};
        umsgs.reserve(to_repeat);

        std::vector<int> exit_codes(to_repeat, default_exit_code);
        bool             misc_error = false;

        // Launch build processes
        for (int i = 0; i < to_repeat; i++) {
            std::string buffer{};

            if (i != 0) {
                dcc_make_tmpnam("icecc", ".o", buffer, 0);
                jobs[i].setOutputFile(buffer);
            } else {
                buffer = job.outputFile();
            }

            auto msg = local_daemon->getMsg(niceness_timeout());
            msgs.emplace_back(std::move(msg));

            UseCSMsg & umsg = get_use_cs(msgs.back());
            umsgs.emplace_back(umsg);

            remote_daemon = umsg.hostname;

            trace() << "got_server_for_job " << umsg.hostname << '\n';

            flush_debug();

            pid_t pid = fork();

            if (pid < 0) {
                log_perror("failure of fork");
                status = -1;
            }

            if (!pid) {
                int ret = 42;

                try {
                    if (!maybe_build_local(
                            local_daemon, umsgs.back(), jobs[i], ret))
                        ret = build_remote_int(
                            jobs[i],
                            umsg,
                            local_daemon,
                            version_map[umsg.host_platform],
                            versionfile_map[umsg.host_platform],
                            preproc.c_str(),
                            i == 0);
                } catch (const std::exception & e) {
                    log_info() << "build_remote_int failed and has thrown "
                               << e.what() << '\n';
                    kill(getpid(), SIGTERM);
                    return 0; // shouldn't matter
                }

                _exit(ret);
                return 0; // doesn't matter
            }

            jobmap[pid] = i;
        }

        for (int i = 0; i < to_repeat; i++) {
            pid_t pid = wait(&status);

            if (pid < 0) {
                log_perror("wait failed");
                status = -1;
            } else {
                if (WIFSIGNALED(status)) {
                    // there was some misc error in processing
                    misc_error = true;
                    break;
                }

                exit_codes[jobmap[pid]] = shell_exit_status(status);
            }
        }

        if (!misc_error) {
            std::string first_md5 = md5_for_file(jobs[0].outputFile());

            for (int i = 1; i < to_repeat; i++) {
                const UseCSMsg & first_umsg = umsgs[0];
                const UseCSMsg & umsg = umsgs[i];
                if (!exit_codes[0]) { // if the first failed, we fail anyway
                    if (exit_codes[i] ==
                        42) { // they are free to fail for misc reasons
                        continue;
                    }

                    if (exit_codes[i]) {
                        log_error()
                            << umsg.hostname << " compiled with exit code "
                            << exit_codes[i] << " and " << first_umsg.hostname
                            << " compiled with exit code " << exit_codes[0]
                            << " - aborting!\n";
                        if (unlink(jobs[0].outputFile().c_str()) < 0) {
                            log_perror("unlink outputFile failed")
                                << "\t" << jobs[0].outputFile() << '\n';
                        }
                        if (has_split_dwarf) {
                            std::string dwo_file =
                                jobs[0].outputFile().substr(
                                    0, jobs[0].outputFile().rfind('.')) +
                                ".dwo";
                            if (unlink(dwo_file.c_str()) < 0) {
                                log_perror("unlink failed")
                                    << "\t" << dwo_file << '\n';
                            }
                        }
                        exit_codes[0] = -1; // overwrite
                        break;
                    }

                    std::string other_md5 = md5_for_file(jobs[i].outputFile());

                    if (other_md5 != first_md5) {
                        log_error()
                            << umsg.hostname << " compiled "
                            << jobs[0].outputFile() << " with md5 sum "
                            << other_md5 << "(" << jobs[i].outputFile() << ")"
                            << " and " << first_umsg.hostname
                            << " compiled with md5 sum " << first_md5
                            << " - aborting!\n";
                        rename(jobs[0].outputFile().c_str(),
                               (jobs[0].outputFile() + ".caught").c_str());
                        rename(preproc.c_str(),
                               (std::string(preproc) + ".caught").c_str());
                        if (has_split_dwarf) {
                            std::string dwo_file =
                                jobs[0].outputFile().substr(
                                    0, jobs[0].outputFile().rfind('.')) +
                                ".dwo";
                            rename(dwo_file.c_str(),
                                   (dwo_file + ".caught").c_str());
                        }
                        exit_codes[0] = -1; // overwrite
                        break;
                    }
                }

                if (unlink(jobs[i].outputFile().c_str()) < 0) {
                    log_perror("unlink failed")
                        << "\t" << jobs[i].outputFile() << '\n';
                }
                if (has_split_dwarf) {
                    std::string dwo_file =
                        jobs[i].outputFile().substr(
                            0, jobs[i].outputFile().rfind('.')) +
                        ".dwo";
                    if (unlink(dwo_file.c_str()) < 0) {
                        log_perror("unlink failed") << "\t" << dwo_file << '\n';
                    }
                }
            }
        } else {
            if (unlink(jobs[0].outputFile().c_str()) < 0) {
                log_perror("unlink failed")
                    << "\t" << jobs[0].outputFile() << '\n';
            }
            if (has_split_dwarf) {
                std::string dwo_file = jobs[0].outputFile().substr(
                                           0, jobs[0].outputFile().rfind('.')) +
                                       ".dwo";
                if (unlink(dwo_file.c_str()) < 0) {
                    log_perror("unlink failed") << "\t" << dwo_file << '\n';
                }
            }

            for (int i = 1; i < to_repeat; i++) {
                if (unlink(jobs[i].outputFile().c_str()) < 0) {
                    log_perror("unlink failed")
                        << "\t" << jobs[i].outputFile() << '\n';
                }
                if (has_split_dwarf) {
                    std::string dwo_file =
                        jobs[i].outputFile().substr(
                            0, jobs[i].outputFile().rfind('.')) +
                        ".dwo";
                    if (unlink(dwo_file.c_str()) < 0) {
                        log_perror("unlink failed") << "\t" << dwo_file << '\n';
                    }
                }
            }
        }

        if (unlink(preproc.c_str()) < 0) {
            log_perror("unlink failed") << "\t" << preproc << '\n';
        }

        int ret = exit_codes[0];

        if (misc_error) {
            throw ClientError(27, "Error 27 - misc error");
        }

        return ret;
    }

    return 0;
}
