/* -*- mode: C++; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 99; -*-
 */
/* vim: set ts=4 sw=4 et tw=99:  */
/*
    This file is part of Icecream.

    Copyright (c) 2004 Michael Matz <matz@suse.de>
                  2004 Stephan Kulow <coolo@suse.de>

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

#ifndef _COMM_HH_
#define _COMM_HH_

#include "services_job.hh"
#include "variant.hh"
#include "visitor.hh"

#ifdef __linux__
#include <cstdint>
#endif

extern "C" {
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
}

#include <algorithm>
#include <memory>
#include <vector>

// if you increase the PROTOCOL_VERSION, add a macro below and use that
#define PROTOCOL_VERSION 43
// if you increase the MIN_PROTOCOL_VERSION, comment out macros below and clean
// up the code
#define MIN_PROTOCOL_VERSION 21

#define MAX_SCHEDULER_PONG 3
// MAX_SCHEDULER_PING must be multiple of MAX_SCHEDULER_PONG
#define MAX_SCHEDULER_PING 12 * MAX_SCHEDULER_PONG
// maximum amount of time in seconds a daemon can be busy installing
#define MAX_BUSY_INSTALLING 120

#define IS_PROTOCOL_22(c) ((c)->protocol >= 22)
#define IS_PROTOCOL_23(c) ((c)->protocol >= 23)
#define IS_PROTOCOL_24(c) ((c)->protocol >= 24)
#define IS_PROTOCOL_25(c) ((c)->protocol >= 25)
#define IS_PROTOCOL_26(c) ((c)->protocol >= 26)
#define IS_PROTOCOL_27(c) ((c)->protocol >= 27)
#define IS_PROTOCOL_28(c) ((c)->protocol >= 28)
#define IS_PROTOCOL_29(c) ((c)->protocol >= 29)
#define IS_PROTOCOL_30(c) ((c)->protocol >= 30)
#define IS_PROTOCOL_31(c) ((c)->protocol >= 31)
#define IS_PROTOCOL_32(c) ((c)->protocol >= 32)
#define IS_PROTOCOL_33(c) ((c)->protocol >= 33)
#define IS_PROTOCOL_34(c) ((c)->protocol >= 34)
#define IS_PROTOCOL_35(c) ((c)->protocol >= 35)
#define IS_PROTOCOL_36(c) ((c)->protocol >= 36)
#define IS_PROTOCOL_37(c) ((c)->protocol >= 37)
#define IS_PROTOCOL_38(c) ((c)->protocol >= 38)
#define IS_PROTOCOL_39(c) ((c)->protocol >= 39)
#define IS_PROTOCOL_40(c) ((c)->protocol >= 40)
#define IS_PROTOCOL_41(c) ((c)->protocol >= 41)
#define IS_PROTOCOL_42(c) ((c)->protocol >= 42)
#define IS_PROTOCOL_43(c) ((c)->protocol >= 43)

// Terms used:
// S  = scheduler
// C  = client
// CS = daemon

enum class MsgType : uint32_t
{
    // so far unknown
    UNKNOWN = 'A',

    /* When the scheduler didn't get STATS from a CS
       for a specified time (e.g. 10m), then he sends a
       ping */
    PING = 'B',

    /* Either the end of file chunks or connection (A<->A) */
    END = 'C',

    TIMEOUT = 'D', // unused

    // C --> CS
    GET_NATIVE_ENV = 'E',
    // CS -> C
    USE_NATIVE_ENV = 'F',

    // C --> S
    GET_CS = 'G',
    // S --> C
    USE_CS = 'H',
    // C --> CS
    COMPILE_FILE = 'I',
    // generic file transfer
    FILE_CHUNK = 'J',
    // CS --> C
    COMPILE_RESULT = 'K',

    // CS --> S (after the C got the CS from the S, the CS tells the S when the
    // C asks him)
    JOB_BEGIN = 'L',
    JOB_DONE = 'M',

    // C --> CS, CS --> S (forwarded from C), _and_ CS -> C as start ping
    JOB_LOCAL_BEGIN = 'N',
    JOB_LOCAL_DONE = 'O',

    // CS --> S, first message sent
    LOGIN = 'P',
    // CS --> S (periodic)
    STATS = 'Q',

    // messages between monitor and scheduler
    MON_LOGIN = 'R',
    MON_GET_CS = 'S',
    MON_JOB_BEGIN = 'T',
    MON_JOB_DONE = 'U',
    MON_LOCAL_JOB_BEGIN = 'V',
    MON_STATS = 'W',

    ENV_TRANSFER = 'X',

    TEXT_DEPRECATED = 'Y',
    STATUS_TEXT = 'Z',
    GET_INTERNAL_STATUS = '[',

    // S --> CS, answered by LOGIN
    CONF_CS = '\\',

    // C --> CS, after installing an environment
    VERIFY_ENV = ']',
    // CS --> C
    VERIFY_ENV_RESULT = '^',
    // C --> CS, CS --> S (forwarded from C), to not use given host for given
    // environment
    BLACKLIST_HOST_ENV = '_',
    // S --> CS
    NO_CS = '`'
};

enum Compression
{
    C_LZO = 0,
    C_ZSTD = 1
};

// The remote node is capable of unpacking environment compressed as .tar.xz .
const int NODE_FEATURE_ENV_XZ = (1 << 0);
// The remote node is capable of unpacking environment compressed as .tar.zst .
const int NODE_FEATURE_ENV_ZSTD = (1 << 1);

class MsgChannel;

// a list of pairs of host platform, filename
typedef std::list<std::pair<std::string, std::string>> Environments;

// just convenient functions to create MsgChannels
class Service {
public:
    static MsgChannel *
    createChannel(const std::string & host, unsigned short p, int timeout);
    static MsgChannel *
    createChannel(const std::string & domain_socket);
    static MsgChannel *
    createChannel(int remote_fd, struct sockaddr *, socklen_t);
};

class Broadcasts {
public:
    // Broadcasts a message about this scheduler and its information.
    static void
    broadcastSchedulerVersion(int          scheduler_port,
                              const char * netname,
                              time_t       starttime);
    // Checks if the data received is a scheduler version broadcast.
    static bool
    isSchedulerVersion(const char * buf, int buflen);
    // Reads data from a scheduler version broadcast.
    static void
    getSchedulerVersionData(const char *  buf,
                            int *         protocol,
                            time_t *      time,
                            std::string * netname);
    /// Broadcasts the given data on the given port.
    static const int BROAD_BUFLEN = 268;

private:
    static void
    broadcastData(int port, const char * buf, int size);
};

// --------------------------------------------------------------------------
// this class is also used by icecream-monitor
class DiscoverSched {
public:
    /* Connect to a scheduler waiting max. TIMEOUT seconds.
       schedname can be the hostname of a box running a scheduler, to avoid
       broadcasting, port can be specified explicitly */
    DiscoverSched(const std::string & _netname = std::string(),
                  int                 _timeout = 2,
                  const std::string & _schedname = std::string(),
                  int                 port = 0);
    ~DiscoverSched();

    bool
    timedOut();

    int
    listenFd() const
    {
        return schedname.empty() ? ask_fd : -1;
    }

    int
    connectFd() const
    {
        return schedname.empty() ? -1 : ask_fd;
    }

    // compat for icecream monitor
    int
    getFd() const
    {
        return listenFd();
    }

    /* Attempt to get a conenction to the scheduler.

       Continue to call this while it returns NULL and timed_out()
       returns false. If this returns NULL you should wait for either
       more data on listen_fd() (use select), or a timeout of your own.
       */
    MsgChannel *
    tryGetScheduler();

    // Returns the hostname of the scheduler - set by constructor or by
    // tryGetScheduler
    std::string
    schedulerName() const
    {
        return schedname;
    }

    // Returns the network name of the scheduler - set by constructor or by
    // tryGetScheduler
    std::string
    networkName() const
    {
        return netname;
    }

    /* Return a list of all reachable netnames.  We wait max. WAITTIME
       milliseconds for answers.  */
    static std::list<std::string>
    getNetnames(int waittime = 2000, int port = 8765);

    // Checks if the data is from a scheduler discovery broadcast, returns
    // version of the sending daemon is yes.
    static bool
    isSchedulerDiscovery(const char * buf, int buflen, int * daemon_version);
    // Prepares data for sending a reply to a scheduler discovery broadcast.
    static int
    prepareBroadcastReply(char * buf, const char * netname, time_t starttime);

private:
    struct sockaddr_in remote_addr;
    std::string        netname;
    std::string        schedname;
    int                timeout;
    int                ask_fd;
    int                ask_second_fd; // for debugging
    time_t             time0;
    unsigned int       sport;
    int                best_version;
    time_t             best_start_time;
    std::string        best_schedname;
    int                best_port;
    bool               multiple;

    void
    attemptSchedulerConnect();

    void
    sendSchedulerDiscovery(int version);

    static bool
    getBroadAnswer(int                  ask_fd,
                   int                  timeout,
                   char *               buf2,
                   struct sockaddr_in * remote_addr,
                   socklen_t *          remote_len);
    static void
    getBroadData(const char *  buf,
                 const char ** out_string,
                 int *         out_version,
                 time_t *      out_start_time);
};
// --------------------------------------------------------------------------

/* Return a list of all reachable netnames.  We wait max. WAITTIME
   milliseconds for answers.  */
std::list<std::string>
get_netnames(int waittime = 2000, int port = 8765);

struct PingMsg {
    void
    fillFromChannel(MsgChannel * /*unused*/)
    {
    }

    void
    sendToChannel(MsgChannel * /*unused*/) const
    {
    }

    static constexpr const char *
    msgName()
    {
        return "PingMsg";
    }
};

struct EndMsg {
    void
    fillFromChannel(MsgChannel * /*unused*/)
    {
    }

    void
    sendToChannel(MsgChannel * /*unused*/) const
    {
    }

    static constexpr const char *
    msgName()
    {
        return "EndMsg";
    }
};

struct GetCSMsg {
    GetCSMsg()
        : count(1), arg_flags(0), client_id(0), client_count(0), niceness(0)
    {
    }

    GetCSMsg(const Environments & envs,
             const std::string &  f,
             CompileJob::Language _lang,
             unsigned int         _count,
             std::string          _target,
             unsigned int         _arg_flags,
             const std::string &  host,
             int                  _minimal_host_version,
             unsigned int         _required_features,
             int                  _niceness,
             unsigned int         _client_count = 0);

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "GetCSMsg";
    }

    Environments         versions;
    std::string          filename;
    CompileJob::Language lang;
    uint32_t count; // the number of UseCS messages to answer with - usually 1
    std::string target;
    uint32_t    arg_flags;
    uint32_t    client_id;
    std::string preferred_host;
    int         minimal_host_version;
    uint32_t    required_features;
    uint32_t    client_count; // number of CS -> C connections at the moment
    uint32_t    niceness; // nice priority (0-20)
};

struct UseCSMsg {
    UseCSMsg() {}
    UseCSMsg(std::string  platform,
             std::string  host,
             unsigned int p,
             unsigned int id,
             bool         gotit,
             unsigned int _client_id,
             unsigned int matched_host_jobs)
        : job_id(id),
          hostname(host),
          port(p),
          host_platform(platform),
          got_env(gotit),
          client_id(_client_id),
          matched_job_id(matched_host_jobs)
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "UseCSMsg";
    }

    uint32_t    job_id;
    std::string hostname;
    uint32_t    port;
    std::string host_platform;
    uint32_t    got_env;
    uint32_t    client_id;
    uint32_t    matched_job_id;
};

struct NoCSMsg {
    NoCSMsg() {}
    NoCSMsg(unsigned int id, unsigned int _client_id)
        : job_id{id}, client_id{_client_id}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "NoCSMsg";
    }

    uint32_t job_id;
    uint32_t client_id;
};

struct GetNativeEnvMsg {
    GetNativeEnvMsg() {}

    GetNativeEnvMsg(const std::string &            c,
                    const std::list<std::string> & e,
                    const std::string &            comp)
        : compiler{c}, extrafiles{e}, compression{comp}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "GetNativeEnvMsg";
    }

    std::string            compiler; // "gcc", "clang" or the actual binary
    std::list<std::string> extrafiles;
    std::string compression; // "" (=default), "none", "gzip", "xz", etc.
};

struct UseNativeEnvMsg {
    UseNativeEnvMsg() = default;

    UseNativeEnvMsg(const std::string & _native) : nativeVersion{_native} {}

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "UseNativeEnvMsg";
    }

    std::string nativeVersion;
};

struct CompileFileMsg {
    CompileFileMsg() : job{std::make_unique<CompileJob>()} {}

    explicit CompileFileMsg(const CompileJob & j)
        : job{std::make_unique<CompileJob>(j)}
    {
    }

    CompileFileMsg(const CompileFileMsg &) = delete;
    CompileFileMsg(CompileFileMsg && other)
        : job{std::exchange(other.job, nullptr)}
    {
    }

    ~CompileFileMsg() = default;

    CompileFileMsg &
    operator=(const CompileFileMsg &) = delete;
    CompileFileMsg &
    operator=(CompileFileMsg && other)
    {
        job = std::exchange(other.job, nullptr);
        return *this;
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "CompileFileMsg";
    }

    CompileJob::UPtr
    takeJob()
    {
        return std::move(job);
    }

private:
    std::string
    remoteCompilerName() const;

    CompileJob::UPtr job;
};

struct FileChunkMsg {
    FileChunkMsg(uint8_t * _buffer, size_t _len)
    {
        buffer.resize(_len);
        std::copy_n(_buffer, _len, buffer.begin());
    }

    FileChunkMsg() = default;

    FileChunkMsg(const FileChunkMsg &) = delete;

    FileChunkMsg(FileChunkMsg && other) noexcept
    {
        buffer = std::exchange(other.buffer, {});
        compressed = std::exchange(other.compressed, 0);
    }

    FileChunkMsg &
    operator=(const FileChunkMsg &) = delete;

    FileChunkMsg &
    operator=(FileChunkMsg && other) noexcept
    {
        buffer = std::exchange(other.buffer, {});
        compressed = std::exchange(other.compressed, 0);

        return *this;
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "FileChunkMsg";
    }

    std::vector<uint8_t> buffer{};
    mutable size_t       compressed{};
};

struct CompileResultMsg {
    CompileResultMsg()
        : status(0), was_out_of_memory(false), have_dwo_file(false)
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "CompileResultMsg";
    }

    int         status;
    std::string out;
    std::string err;
    bool        was_out_of_memory;
    bool        have_dwo_file;
};

struct JobBeginMsg {
    JobBeginMsg() {}

    JobBeginMsg(unsigned int j, unsigned int _client_count)
        : job_id(j), stime(time(0)), client_count(_client_count)
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "JobBeginMsg";
    };
    uint32_t job_id;
    uint32_t stime;
    uint32_t client_count; // number of CS -> C connections at the moment
};

struct JobDoneMsg {
    /* FROM_SERVER: this message was generated by the daemon responsible
          for remotely compiling the job (i.e. job->server).
       FROM_SUBMITTER: this message was generated by the daemon connected
          to the submitting client.  */
    enum from_type
    {
        FROM_SERVER = 0,
        FROM_SUBMITTER = 1
    };

    // other flags
    enum
    {
        UnknownJobId = (1 << 1)
    };

    JobDoneMsg(int          job_id = 0,
               int          exitcode = -1,
               unsigned int flags = FROM_SERVER,
               unsigned int _client_count = 0);

    void
    setFrom(from_type from)
    {
        flags |= (uint32_t)from;
    }

    bool
    isFromServer() const
    {
        return (flags & FROM_SUBMITTER) == 0;
    }

    void
    setUnknownJobClientId(uint32_t clientId);

    uint32_t
    unknownJobClientId() const;

    void
    setJobId(uint32_t jobId);

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "JobDoneMsg";
    }

    uint32_t real_msec; /* real time it used */
    uint32_t user_msec; /* user time used */
    uint32_t sys_msec; /* system time used */
    uint32_t pfaults; /* page faults */

    int exitcode; /* exit code */

    uint32_t flags;

    uint32_t in_compressed;
    uint32_t in_uncompressed;
    uint32_t out_compressed;
    uint32_t out_uncompressed;

    uint32_t job_id;
    uint32_t client_count; // number of CS -> C connections at the moment
};

struct JobLocalBeginMsg {
    JobLocalBeginMsg(uint32_t job_id = 0, const std::string & file = "")
        : id{job_id}, outfile{file}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "JobLocalBeginMsg";
    }

    uint32_t    id;
    std::string outfile;
    uint32_t    stime;
};

struct JobLocalDoneMsg {
    JobLocalDoneMsg(uint32_t id = 0) : job_id{id} {}

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "JobLocalDoneMsg";
    }

    uint32_t job_id;
};

struct LoginMsg {
    LoginMsg(uint32_t            myport,
             const std::string & _nodename,
             const std::string & _host_platform,
             unsigned int        my_features);
    LoginMsg() {}

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "LoginMsg";
    }

    uint32_t     port;
    Environments envs;
    uint32_t     max_kids;
    bool         noremote;
    bool         chroot_possible;
    std::string  nodename;
    std::string  host_platform;
    uint32_t supported_features; // bitmask of various features the node supports
};

struct ConfCSMsg {
    ConfCSMsg()
        : max_scheduler_pong(MAX_SCHEDULER_PONG),
          max_scheduler_ping(MAX_SCHEDULER_PING)
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "ConfCSMsg";
    }

    uint32_t max_scheduler_pong;
    uint32_t max_scheduler_ping;
};

struct StatsMsg {
    StatsMsg() {}

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "StatsMsg";
    }

    /**
     * For now the only load measure we have is the
     * load from 0-1000.
     * This is defined to be a daemon defined value
     * on how busy the machine is. The higher the load
     * is, the slower a given job will compile (preferably
     * linear scale). Load of 1000 means to not schedule
     * another job under no circumstances.
     */
    uint32_t load;

    uint32_t loadAvg1;
    uint32_t loadAvg5;
    uint32_t loadAvg10;
    uint32_t freeMem;

    uint32_t client_count; // number of CS -> C connections at the moment
};

struct EnvTransferMsg {
    EnvTransferMsg() {}

    EnvTransferMsg(const std::string & _target, const std::string & _name)
        : target{_target}, name{_name}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "EnvTransferMsg";
    }

    std::string target;
    std::string name;
};

struct GetInternalStatusMsg {
    void
    fillFromChannel(MsgChannel * /*unused*/)
    {
    }

    void
    sendToChannel(MsgChannel * /*unused*/) const
    {
    }

    static constexpr const char *
    msgName()
    {
        return "GetInternalStatusMsg";
    }
};

struct MonLoginMsg {
    void
    fillFromChannel(MsgChannel * /*unused*/)
    {
    }

    void
    sendToChannel(MsgChannel * /*unused*/) const
    {
    }

    static constexpr const char *
    msgName()
    {
        return "MonLoginMsg";
    }
};

struct MonGetCSMsg final : public GetCSMsg {
    MonGetCSMsg() : GetCSMsg()
    { // overwrite
        clientid = job_id = 0;
    }

    MonGetCSMsg(uint32_t jobid, uint32_t hostid, const GetCSMsg & m)
        : GetCSMsg(Environments(),
                   m.filename,
                   m.lang,
                   1,
                   m.target,
                   0,
                   std::string(),
                   false,
                   m.client_count,
                   m.niceness),
          job_id{jobid},
          clientid{hostid}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "MonGetCSMsg";
    }

    uint32_t job_id;
    uint32_t clientid;
};

struct MonJobBeginMsg {
    MonJobBeginMsg() {}

    MonJobBeginMsg(uint32_t id, uint32_t time, uint32_t _hostid)
        : job_id{id}, stime{time}, hostid{_hostid}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "MonJobBeginMsg";
    }

    uint32_t job_id;
    uint32_t stime;
    uint32_t hostid;
};

struct MonJobDoneMsg final : public JobDoneMsg {
    MonJobDoneMsg() = default;

    explicit MonJobDoneMsg(const JobDoneMsg & m) : JobDoneMsg(m) {}

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "MonJobDoneMsg";
    }
};

struct MonLocalJobBeginMsg {
    MonLocalJobBeginMsg() {}

    MonLocalJobBeginMsg(unsigned int        id,
                        const std::string & _file,
                        unsigned int        time,
                        int                 _hostid)
        : job_id(id), stime(time), hostid(_hostid), file(_file)
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "MonLocalJobBeginMsg";
    }

    uint32_t    job_id;
    uint32_t    stime;
    uint32_t    hostid;
    std::string file;
};

struct MonStatsMsg {
    MonStatsMsg() {}

    MonStatsMsg(uint32_t id, const std::string & _statmsg)
        : hostid{id}, statmsg{_statmsg}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "MonStatsMsg";
    }

    uint32_t    hostid;
    std::string statmsg;
};

struct StatusTextMsg {
    StatusTextMsg() {}

    StatusTextMsg(const std::string & _text) : text{_text} {}

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "StatusTextMsg";
    }

    std::string text;
};

struct VerifyEnvMsg {
    VerifyEnvMsg() {}

    VerifyEnvMsg(const std::string & _target, const std::string & _environment)
        : target{_target}, environment{_environment}
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "VerifyEnvMsg";
    }

    std::string target;
    std::string environment;
};

struct VerifyEnvResultMsg {
    VerifyEnvResultMsg() {}

    VerifyEnvResultMsg(bool _ok) : ok{_ok} {}

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "VerifyEnvResultMsg";
    }

    bool ok;
};

struct BlacklistHostEnvMsg {
    BlacklistHostEnvMsg() {}

    BlacklistHostEnvMsg(const std::string & _target,
                        const std::string & _environment,
                        const std::string & _hostname)
        : environment(_environment), target(_target), hostname(_hostname)
    {
    }

    void
    fillFromChannel(MsgChannel * c);
    void
    sendToChannel(MsgChannel * c) const;

    static constexpr const char *
    msgName()
    {
        return "BlacklistHostEnvMsg";
    }

    std::string environment;
    std::string target;
    std::string hostname;
};

using Msg = ext::variant<ext::monostate,
                         PingMsg,
                         EndMsg,
                         GetCSMsg,
                         UseCSMsg,
                         NoCSMsg,
                         GetNativeEnvMsg,
                         UseNativeEnvMsg,
                         CompileFileMsg,
                         FileChunkMsg,
                         CompileResultMsg,
                         JobBeginMsg,
                         JobDoneMsg,
                         JobLocalBeginMsg,
                         JobLocalDoneMsg,
                         LoginMsg,
                         ConfCSMsg,
                         StatsMsg,
                         EnvTransferMsg,
                         GetInternalStatusMsg,
                         MonLoginMsg,
                         MonJobBeginMsg,
                         MonLocalJobBeginMsg,
                         MonStatsMsg,
                         StatusTextMsg,
                         VerifyEnvMsg,
                         VerifyEnvResultMsg,

                         BlacklistHostEnvMsg>;

template<typename T>
inline const char *
message_type(const T & /*unused*/)
{
    return T::msgName();
}

template<>
inline const char *
message_type(const ext::monostate & /*unused*/)
{
    return "UnknownMsg";
}

template<>
inline const char *
message_type(const Msg & msg)
{
    return ext::visit(
        ext::make_visitor([](const auto & m) { return message_type(m); }), msg);
}

class MsgChannel {
public:
    enum SendFlags
    {
        SendBlocking = 1 << 0,
        SendNonBlocking = 1 << 1,
        SendBulkOnly = 1 << 2
    };

    virtual ~MsgChannel();

    void
    setBulkTransfer();

    std::string
    dump() const;
    // NULL  <--> channel closed or timeout
    // Will warn in log if EOF and !eofAllowed.
    Msg
    getMsg(int timeout = 10, bool eofAllowed = false);

    // false <--> error (msg not send)
    bool
    sendMsg(const Msg & msg, int SendFlags = SendBlocking);

    bool
    hasMsg() const
    {
        return eof_ || instate == HAS_MSG;
    }

    // Returns ture if there were no errors filling inbuf.
    bool
    readSome();

    bool
    eof() const
    {
        return instate != HAS_MSG && eof_;
    }

    void
    readcompressed(std::vector<uint8_t> & buffer, size_t & _clen);
    void
    writecompressed(const unsigned char * in_buf,
                    size_t                _in_len,
                    size_t &              _out_len);
    void
    writeEnvironments(const Environments & envs);
    void
    readEnvironments(Environments & envs);
    void
    readLine(std::string & line);
    void
    writeLine(const std::string & line);

    bool
    eq_ip(const MsgChannel & s) const;

    MsgChannel &
    operator>>(uint32_t &);
    MsgChannel &
    operator>>(std::string &);
    MsgChannel &
    operator>>(std::list<std::string> &);

    MsgChannel & operator<<(uint32_t);
    MsgChannel &
    operator<<(const std::string &);
    MsgChannel &
    operator<<(const std::list<std::string> &);

    // our filedesc
    int fd;

    // the minimum protocol version between me and him
    int protocol;
    // the actual maximum protocol the remote supports
    int maximum_remote_protocol;

    std::string name;
    time_t      last_talk;

protected:
    MsgChannel(int _fd, struct sockaddr *, socklen_t);

    bool
    waitProtocol();
    // returns false if there was an error sending something
    bool
    flushWritebuf(bool blocking);
    void
    writeFull(const void * _buf, size_t count);
    // returns false if there was an error in the protocol setup
    bool
    updateState(void);
    void
    chopInput(void);
    void
    chopOutput(void);
    bool
    waitMsg(int timeout);
    void
    setError(bool silent = false);

    char * msgbuf;
    size_t msgbuflen;
    size_t msgofs;
    size_t msgtogo;
    char * inbuf;
    size_t inbuflen;
    size_t inofs;
    size_t intogo;

    enum
    {
        NEED_PROTO,
        NEED_LEN,
        FILL_BUF,
        HAS_MSG,
        ERROR
    } instate;

    uint32_t inmsglen;

private:
    friend class Service;

    // deep copied
    struct sockaddr * addr;
    socklen_t         addr_len;
    bool              set_error_recursion;
    bool              eof_;
};

#endif // _COMM_HH_
