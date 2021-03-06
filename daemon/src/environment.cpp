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

#include "environment.hh"

#include "exitcode.h"
#include "logging.hh"
#include "services_util.hh"

extern "C" {
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/wait.h>
}

namespace {

size_t
sumup_dir(const std::string & dir)
{
    size_t res = 0;
    DIR *  envdir = opendir(dir.c_str());

    if (!envdir) {
        return res;
    }

    struct stat st;

    std::string tdir = dir + "/";

    for (struct dirent * ent = readdir(envdir); ent; ent = readdir(envdir)) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
            continue;
        }

        if (lstat((tdir + ent->d_name).c_str(), &st)) {
            perror("stat");
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            res += sumup_dir(tdir + ent->d_name);
        } else if (S_ISREG(st.st_mode)) {
            res += st.st_size;
        }

        // else ignore
    }

    closedir(envdir);
    return res;
}

void
list_target_dirs(const std::string & current_target,
                 const std::string & targetdir,
                 Environments &      envs)
{
    DIR * envdir = opendir(targetdir.c_str());

    if (!envdir) {
        return;
    }

    for (struct dirent * ent = readdir(envdir); ent; ent = readdir(envdir)) {
        std::string dirname = ent->d_name;

        if (access(
                std::string(targetdir + "/" + dirname + "/usr/bin/as").c_str(),
                X_OK) == 0) {
            envs.push_back(make_pair(current_target, dirname));
        }
    }

    closedir(envdir);
}

/* Returns true if the child exited with success */
bool
exec_and_wait(const char * const argv[])
{
    pid_t pid = fork();

    if (pid == -1) {
        log_perror("failed to fork");
        return false;
    }

    if (pid) {
        // parent
        int status;

        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }

        return shell_exit_status(status) == 0;
    }

    // child
    execv(argv[0], const_cast<char * const *>(argv));
    std::ostringstream errmsg;
    errmsg << "execv " << argv[0] << " failed";
    log_perror(errmsg.str());
    _exit(-1);
}

// Removes everything in the directory recursively, but not the directory
// itself.
bool
cleanup_directory(const std::string & directory)
{
    DIR * dir = opendir(directory.c_str());

    if (dir == nullptr) {
        return false;
    }

    while (dirent * f = readdir(dir)) {
        if (strcmp(f->d_name, ".") == 0 || strcmp(f->d_name, "..") == 0) {
            continue;
        }

        std::string fullpath = directory + '/' + f->d_name;
        struct stat st;

        if (lstat(fullpath.c_str(), &st)) {
            perror("stat");
            return false;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!cleanup_directory(fullpath) || rmdir(fullpath.c_str()) != 0) {
                return false;
            }
        } else {
            if (unlink(fullpath.c_str()) != 0) {
                return false;
            }
        }
    }

    closedir(dir);
    return true;
}

int
copy_data(struct archive * ar, struct archive * aw)
{
    int          r;
    const void * buff;
    size_t       size;

#if ARCHIVE_VERSION_NUMBER >= 3000000
    int64_t offset;
#else
    off_t offset;
#endif
    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF) {
            return (ARCHIVE_OK);
        }
        r = archive_write_data_block(aw, buff, size, offset);
        if (r != ARCHIVE_OK) {
            trace() << "copy_data(): Error after write: "
                    << archive_error_string(aw) << '\n';
            return (r);
        }
    }
}

void
error_client(MsgChannel * client, std::string error)
{
    if (IS_PROTOCOL_23(client)) {
        client->sendMsg(StatusTextMsg(error));
    }
}

} // namespace

bool
cleanup_cache(const std::string & basedir, uid_t user_uid, gid_t user_gid)
{
    flush_debug();

    if (access(basedir.c_str(), R_OK) == 0 && !cleanup_directory(basedir)) {
        log_error() << "failed to clean up envs dir\n";
        return false;
    }

    if (mkdir(basedir.c_str(), 0755) && errno != EEXIST) {
        if (errno == EPERM) {
            log_error() << "permission denied on mkdir " << basedir << '\n';
        } else {
            log_perror("mkdir in cleanup_cache() failed")
                << "\t" << basedir << '\n';
        }

        return false;
    }

    if (chown(basedir.c_str(), user_uid, user_gid) ||
        chmod(basedir.c_str(), 0775)) {
        log_perror("chown/chmod in cleanup_cache() failed")
            << "\t" << basedir << '\n';
        ;
        return false;
    }

    return true;
}

Environments
available_environments(const std::string & basedir)
{
    Environments envs;

    DIR * envdir = opendir(basedir.c_str());

    if (!envdir) {
        log_info() << "can't open envs dir " << strerror(errno) << '\n';
    } else {
        for (struct dirent * target_ent = readdir(envdir); target_ent;
             target_ent = readdir(envdir)) {
            std::string dirname = target_ent->d_name;

            if (dirname.at(0) == '.') {
                continue;
            }

            if (dirname.substr(0, 7) == "target=") {
                std::string current_target =
                    dirname.substr(7, dirname.length() - 7);
                list_target_dirs(current_target, basedir + "/" + dirname, envs);
            }
        }

        closedir(envdir);
    }

    return envs;
}

// Returns fd for icecc-create-env output
int
start_create_env(const std::string &            basedir,
                 uid_t                          user_uid,
                 gid_t                          user_gid,
                 const std::string &            compiler,
                 const std::list<std::string> & extrafiles,
                 const std::string &            compression)
{
    std::string nativedir = basedir + "/native/";
    if (mkdir(nativedir.c_str(), 0775) && errno != EEXIST) {
        return 0;
    }

    if (chown(nativedir.c_str(), user_uid, user_gid) ||
        chmod(nativedir.c_str(), 0775)) {
        log_perror("chown/chmod failed");
        if (-1 == rmdir(nativedir.c_str())) {
            log_perror("rmdir failed");
        }
        return 0;
    }

    flush_debug();
    int pipes[2];
    if (pipe(pipes) == -1) {
        log_error() << "failed to create pipe: " << strerror(errno) << '\n';
        _exit(147);
    }
    pid_t pid = fork();

    if (pid == -1) {
        log_perror("failed to fork");
        _exit(147);
    }

    if (pid) {
        if ((-1 == close(pipes[1])) && (errno != EBADF)) {
            log_perror("close failed");
        }
        fcntl(pipes[0], F_SETFD, FD_CLOEXEC);
        return pipes[0];
    }
    // else

#ifndef HAVE_LIBCAP_NG
    if (getuid() != user_uid || geteuid() != user_uid || getgid() != user_gid ||
        getegid() != user_gid) {

        if (setgroups(0, NULL) < 0) {
            log_perror("setgroups failed");
            _exit(143);
        }

        if (setgid(user_gid) < 0) {
            log_perror("setgid failed");
            _exit(143);
        }

        if (!geteuid() && setuid(user_uid) < 0) {
            log_perror("setuid failed");
            _exit(142);
        }
    }
#endif

    if (chdir(nativedir.c_str())) {
        log_perror("chdir") << "\t" << nativedir << '\n';
        _exit(1);
    }

    if ((-1 == close(pipes[0])) && (errno != EBADF)) {
        log_perror("close failed");
    }

    if (-1 == dup2(pipes[1], 5)) { // icecc-create-env will write the hash there
        log_perror("dup2 failed");
    }

    if ((-1 == close(pipes[1])) && (errno != EBADF)) {
        log_perror("close failed");
    }

    if ((-1 == close(STDOUT_FILENO)) &&
        (errno != EBADF)) { // hide output from icecc-create-env
        log_perror("close failed");
    }

    const char ** argv;
    argv = new const char *[4 + extrafiles.size()];
    int pos = 0;
    argv[pos++] = BINDIR "/icecc";
    argv[pos++] = "--build-native";
    const int first_to_free = pos;
    argv[pos++] = strdup(compiler.c_str());

    for (const std::string & extrafile : extrafiles) {
        argv[pos++] = strdup(extrafile.c_str());
    }

    argv[pos++] = nullptr;

    if (!compression.empty()) {
        // icecc will read it from ICECC_ENV_COMPRESSION, we are in a forked
        // process, so simply set it
        setenv("ICECC_ENV_COMPRESSION", compression.c_str(), 1);
    }

    if (!exec_and_wait(argv)) {
        log_error() << BINDIR "/icecc --build-native failed\n";
        _exit(1);
    }
    for (int i = first_to_free; i < pos; ++i)
        free((void *)argv[i]);
    delete[] argv;

    _exit(0);
}

size_t
finish_create_env(int                 pipe,
                  const std::string & basedir,
                  std::string &       native_environment)
{
    // We don't care about waitpid() , icecc-create-env prints the name of the
    // tarball as the very last action before exit, so if there's something in
    // the pipe, just block on it until it closes.

    char buf[1024];
    buf[0] = '\0';

    while (read(pipe, buf, 1023) < 0 && errno == EINTR) {
    }

    if (char * nl = strchr(buf, '\n')) {
        *nl = '\0';
    }

    if (buf[0] == '\0') {
        trace() << "native_environment creation failed\n";
        return 0;
    }

    std::string nativedir = basedir + "/native/";
    native_environment = nativedir + buf;

    if ((-1 == close(pipe)) && (errno != EBADF)) {
        log_perror("close failed");
    }
    trace() << "native_environment " << native_environment << '\n';
    struct stat st;

    if (!native_environment.empty() &&
        (stat(native_environment.c_str(), &st) == 0)) {
        return st.st_size;
    }

    if (-1 == rmdir(nativedir.c_str())) {
        log_perror("rmdir failed");
    }
    return 0;
}

pid_t
start_install_environment(const std::string & basename,
                          const std::string & target,
                          const std::string & name,
                          MsgChannel *        c,
                          int &               pipe_to_child,
                          int &               pipe_from_child,
                          FileChunkMsg &      out_fcmsg,
                          uid_t               user_uid,
                          gid_t               user_gid,
                          int                 extract_priority)
{
    log_info() << "start_install_environment: " << basename << " target "
               << target << " Name: " << name << '\n';
    if (!name.size()) {
        log_error() << "illegal name for environment " << name << '\n';
        return 0;
    }

    for (std::string::size_type i = 0; i < name.size(); ++i) {
        if (isascii(name[i]) && !isspace(name[i]) && name[i] != '/' &&
            isprint(name[i])) {
            continue;
        }

        log_error() << "illegal char '" << name[i]
                    << "' - rejecting environment " << name << '\n';
        return 0;
    }

    std::string dirname = basename + "/target=" + target;
    Msg         msg = c->getMsg(30);

    auto * fcmsg = ext::get_if<FileChunkMsg>(&msg);
    if (fcmsg == nullptr) {
        trace() << "Expected first file chunk\n";
        return 0;
    }

    out_fcmsg = std::move(*fcmsg);

    if (mkdir(dirname.c_str(), 0770) && errno != EEXIST) {
        log_perror("mkdir target") << "\t" << dirname << '\n';
        return 0;
    }

    if (chown(dirname.c_str(), user_uid, user_gid) ||
        chmod(dirname.c_str(), 0770)) {
        log_perror("chown,chmod target") << "\t" << dirname << '\n';
        return 0;
    }

    dirname = dirname + "/" + name;

    if (mkdir(dirname.c_str(), 0770)) {
        log_perror("mkdir name") << "\t" << dirname << '\n';
        return 0;
    }

    if (chown(dirname.c_str(), user_uid, user_gid) ||
        chmod(dirname.c_str(), 0770)) {
        log_perror("chown,chmod name") << "\t" << dirname << '\n';
        return 0;
    }

    int fds_in[2]; // for receiving data
    int fds_out[2]; // for sending out final status

    if (pipe(fds_in) == -1 || pipe(fds_out) == -1) {
        log_perror(
            "start_install_environment: pipe creation failed for receiving "
            "environment");
        return 0;
    }

    flush_debug();
    pid_t pid = fork();

    if (pid == -1) {
        log_perror("start_install_environment - fork()");
        return 0;
    }
    if (pid) {
        // Runs only on parent(PID value is 0 in child and PID id on parent)
        trace() << "Created fork for receiving environment on pid " << pid
                << '\n';

        if ((-1 == close(fds_in[0])) && (errno != EBADF)) {
            log_perror("Failed to close read end of pipe");
        }
        if ((-1 == close(fds_out[1])) && (errno != EBADF)) {
            log_perror("Failed to close write end of pipe");
        }
        pipe_to_child =
            fds_in[1]; // Set write end of pipe to pass to parent thread
        pipe_from_child =
            fds_out[0]; // Set write end of pipe to pass to parent thread
        fcntl(pipe_to_child, F_SETFD, FD_CLOEXEC);
        fcntl(pipe_from_child, F_SETFD, FD_CLOEXEC);

        return pid;
    }

    // else
#ifndef HAVE_LIBCAP_NG

    if (setgroups(0, NULL) < 0) {
        log_perror("setgroups fails");
        _exit(143);
    }

    if (setgid(user_gid) < 0) {
        log_perror("setgid fails");
        _exit(143);
    }

    if (!geteuid() && setuid(user_uid) < 0) {
        log_perror("setuid fails");
        _exit(142);
    }

#endif

    // reset SIGPIPE and SIGCHILD handler so that tar
    // isn't confused when gzip/bzip2 aborts
    signal(SIGCHLD, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);

    if ((-1 == close(fds_in[1])) && (errno != EBADF)) {
        log_perror("Failed to close write end of pipe");
    }
    if ((-1 == close(fds_out[0])) && (errno != EBADF)) {
        log_perror("Failed to close write end of pipe");
    }

    int niceval = nice(extract_priority);
    if (-1 == niceval) {
        log_warning() << "failed to set nice value: " << strerror(errno)
                      << '\n';
    }

    /* libarchive stream reader */
    struct archive *       a;
    struct archive *       ext;
    struct archive_entry * entry;
    int                    flags;

    flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;

    a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if (archive_read_open_fd(a, fds_in[0], out_fcmsg.buffer.size()) !=
        ARCHIVE_OK) {
        log_error()
            << "start_install_environment: archive_read_open_fd() failed"
            << '\n';
        _exit(1);
    }

    for (;;) {
        int r = archive_read_next_header(a, &entry);
        if (r == ARCHIVE_EOF) {
            trace() << "start_install_environment: reached end of archive, done"
                    << '\n';
            break;
        }
        if (r < ARCHIVE_WARN) {
            log_error() << "start_install_environment: r  < ARCHIVE_WARN "
                        << archive_error_string(a) << '\n';
            _exit(1);
        }

        /*Extracting archive*/
        const char *      currentFile = archive_entry_pathname(entry);
        const std::string fullOutputPath = dirname + "/" + currentFile;
        archive_entry_set_pathname(entry, fullOutputPath.c_str());
        r = archive_write_header(ext, entry);

        if (archive_entry_size(entry) > 0) {
            r = copy_data(a, ext);
            if (r < ARCHIVE_WARN) {
                log_error() << "start_install_environment: "
                            << archive_error_string(ext) << '\n';
                _exit(1);
            }
        }
        r = archive_write_finish_entry(ext);
        if (r < ARCHIVE_WARN) {
            log_error() << "start_install_environment: "
                        << archive_error_string(ext) << '\n';
            _exit(1);
        }
    }
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    /*libarchive stream reader ends*/

    // Tell our parent that we have successfully finished.
    char resultByte = 0;
    ignore_result(write(fds_out[1], &resultByte, 1));

    _exit(0);
}

size_t
finalize_install_environment(const std::string & basename,
                             const std::string & target,
                             uid_t               user_uid,
                             gid_t               user_gid)
{
    std::string dirname = basename + "/target=" + target;
    errno = 0;
    mkdir((dirname + "/tmp").c_str(), 01775);
    ignore_result(chown((dirname + "/tmp").c_str(), user_uid, user_gid));
    chmod((dirname + "/tmp").c_str(), 01775);
    if (errno == -1) {
        log_error() << "failed to setup " << dirname
                    << "/tmp :" << strerror(errno) << '\n';
    }

    return sumup_dir(dirname);
}

void
remove_environment_files(const std::string & basename, const std::string & env)
{
    std::string dirname = basename + "/target=" + env;

    flush_debug();
    pid_t pid = fork();

    if (pid == -1) {
        log_perror("failed to fork");
        return;
    }

    if (pid) {
        int status = 0;

        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }

        if (WIFEXITED(status)) {
            return;
        }

        // something went wrong.
        return;
    }

    // else

    char ** argv;
    argv = new char *[5];
    argv[0] = strdup("/bin/rm");
    argv[1] = strdup("-rf");
    argv[2] = strdup("--");
    argv[3] = strdup(dirname.c_str());
    argv[4] = nullptr;

    execv(argv[0], argv);
    std::ostringstream errmsg;
    errmsg << "execv " << argv[0] << " failed";
    log_perror(errmsg.str());
    _exit(-1);
}

void
remove_native_environment_files(const std::string & env)
{
    if (env.empty()) {
        return;
    }

    struct stat st;

    if (stat(env.c_str(), &st) == 0) {
        if (-1 == unlink(env.c_str())) {
            log_perror("unlink failed") << "\t" << env << '\n';
        }
    }
}

void
chdir_to_environment(MsgChannel *        client,
                     const std::string & dirname,
                     uid_t               user_uid,
                     gid_t               user_gid)
{
#ifdef HAVE_LIBCAP_NG

    if (chdir(dirname.c_str()) < 0) {
        error_client(client, std::string("chdir to ") + dirname + "failed");
        log_perror("chdir() failed") << "\t" << dirname << '\n';
        _exit(145);
    }

    if (chroot(dirname.c_str()) < 0) {
        error_client(client, std::string("chroot ") + dirname + "failed");
        log_perror("chroot() failed") << "\t" << dirname << '\n';
        _exit(144);
    }

    (void)user_uid;
    (void)user_gid;
#else

    if (getuid() == 0) {
        // without the chdir, the chroot will escape the
        // jail right away
        if (chdir(dirname.c_str()) < 0) {
            error_client(client, std::string("chdir to ") + dirname + "failed");
            log_perror("chdir() failed") << "\t" << dirname << '\n';
            _exit(145);
        }

        if (chroot(dirname.c_str()) < 0) {
            error_client(client, std::string("chroot ") + dirname + "failed");
            log_perror("chroot() failed") << "\t" << dirname << '\n';
            _exit(144);
        }

        if (setgroups(0, NULL) < 0) {
            error_client(client, std::string("setgroups failed"));
            log_perror("setgroups() failed");
            _exit(143);
        }

        if (setgid(user_gid) < 0) {
            error_client(client, std::string("setgid failed"));
            log_perror("setgid() failed");
            _exit(143);
        }

        if (setuid(user_uid) < 0) {
            error_client(client, std::string("setuid failed"));
            log_perror("setuid() failed");
            _exit(142);
        }
    } else {
        error_client(client, "cannot chroot to environment");
        _exit(146);
    }

#endif
}

// Verify that the environment works by simply running the bundled bin/true.
bool
verify_env(MsgChannel *        client,
           const std::string & basedir,
           const std::string & target,
           const std::string & env,
           uid_t               user_uid,
           gid_t               user_gid)
{
    if (target.empty() || env.empty()) {
        error_client(client, "verify_env: target or env empty");
        log_error() << "verify_env target or env empty\n\t" << target << "\n\t"
                    << env << '\n';
        return false;
    }

    std::string dirname = basedir + "/target=" + target + "/" + env;

    if (::access(std::string(dirname + "/bin/true").c_str(), X_OK) < 0) {
        error_client(
            client,
            dirname +
                "/bin/true is not executable, installed environment removed?");
        log_error() << "I don't have environment " << env << "(" << target
                    << ") to verify.\n";
        return false;
    }

    flush_debug();
    pid_t pid = fork();
    assert(pid >= 0);

    if (pid > 0) { // parent
        int status;

        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }

        return shell_exit_status(status) == 0;
    } else if (pid < 0) {
        log_perror("Failed to fork for verifying environment");
        return false;
    }

    // child
    reset_debug();
    chdir_to_environment(client, dirname, user_uid, user_gid);
    execl("bin/true", "bin/true", (void *)nullptr);
    log_perror("execl bin/true failed");
    _exit(-1);
}
