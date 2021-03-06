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

#include "comm.hh"
#include "compileserver.hh"
#include "getifaddrs.hh"
#include "logging.hh"
#include "scheduler_job.hh"
#include "services_job.hh"
#include "services_util.hh"

#ifndef _GNU_SOURCE
// getopt_long
#define _GNU_SOURCE 1
#endif

extern "C" {
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>

#ifdef HAVE_SYS_SIGNAL_H
#include <sys/signal.h>
#endif // HAVE_SYS_SIGNAL_H

#include <sys/stat.h>
}

#include <algorithm>
#include <atomic>
#include <fstream>

/* TODO:
   * leak check
   * are all filedescs closed when done?
   * simplify lifetime of the various structures (Jobs/Channels/CompileServers
   know of each other and sometimes take over ownership)
 */

/* TODO:
  - iron out differences in code size between architectures
   + ia64/i686: 1.63
   + x86_64/i686: 1.48
   + ppc/i686: 1.22
   + ppc64/i686: 1.59
  (missing data for others atm)
*/

/* The typical flow of messages for a remote job should be like this:
     prereq: daemon is connected to scheduler
     * client does GET_CS
     * request gets queued
     * request gets handled
     * scheduler sends USE_CS
     * client asks remote daemon
     * daemon sends JOB_BEGIN
     * client sends END + closes connection
     * daemon sends JOB_DONE (this can be swapped with the above one)
   This means, that iff the client somehow closes the connection we can and
   must remove all traces of jobs resulting from that client in all lists.
 */

namespace {

std::string pidFilePath;

std::map<int, CompileServer *> fd2cs;

std::atomic_flag exit_handler_called = ATOMIC_FLAG_INIT;
std::atomic_bool
    keep_running; // atomic_bool since test_and_set() is inconvenient

time_t       starttime;
time_t       last_announce;
std::string  scheduler_interface = "";
unsigned int scheduler_port = 8765;

// A subset of connected_hosts representing the compiler servers
std::list<CompileServer *>    css;
std::list<CompileServer *>    monitors;
std::list<CompileServer *>    controls;
std::list<std::string>        block_css;
unsigned int                  new_job_id;
std::map<unsigned int, Job *> jobs;

/* XXX Uah.  Don't use a queue for the job requests.  It's a hell
   to delete anything out of them (for clean up).  */
// Job requests from one submitter.
struct JobRequestsGroup {
    std::list<Job *> l;
    CompileServer *  submitter;
    // Priority as unix nice values 0 (highest) to 20 (lowest).
    // Values <0 are mapped to 0 (otherwise somebody could use this to starve
    // the whole cluster).
    int niceness;
    bool
    remove_job(Job *);
};
// All pending job requests, grouped by the same submitter and niceness value,
// and sorted with higher priority first.
std::list<JobRequestsGroup *> job_requests;

std::list<JobStat> all_job_stats;
JobStat            cum_job_stats;

float
server_speed(CompileServer * cs, Job * job = nullptr, bool blockDebug = false);

/* Searches the queue for JOB and removes it.
   Returns true if something was deleted.  */
bool
JobRequestsGroup::remove_job(Job * job)
{
    assert(niceness == job->niceness());
    for (auto it = l.begin(); it != l.end(); ++it)
        if (*it == job) {
            l.erase(it);
            return true;
        }
    return false;
}

void
add_job_stats(Job * job, const JobDoneMsg & msg)
{
    JobStat st;

    /* We don't want to base our timings on failed or too small jobs.  */
    if (msg.out_uncompressed < 4096 || msg.exitcode != 0) {
        return;
    }

    st.setOutputSize(msg.out_uncompressed);
    st.setCompileTimeReal(msg.real_msec);
    st.setCompileTimeUser(msg.user_msec);
    st.setCompileTimeSys(msg.sys_msec);
    st.setJobId(job->id());

    if (job->argFlags() & CompileJob::Flag_g) {
        st.setOutputSize(st.outputSize() * 10 /
                         36); // average over 1900 jobs: faktor 3.6 in osize
    } else if (job->argFlags() & CompileJob::Flag_g3) {
        st.setOutputSize(st.outputSize() * 10 /
                         45); // average over way less jobs: factor 1.25 over -g
    }

    // the difference between the -O flags isn't as big as the one between -O0
    // and -O>=1 the numbers are actually for gcc 3.3 - but they are _very_
    // rough heurstics anyway)
    if (job->argFlags() & CompileJob::Flag_O ||
        job->argFlags() & CompileJob::Flag_O2 ||
        job->argFlags() & CompileJob::Flag_Ol2) {
        st.setOutputSize(st.outputSize() * 58 / 35);
    }

    if (job->server()->lastCompiledJobs().size() >= 7) {
        /* Smooth out spikes by not allowing one job to add more than
           20% of the current speed.  */
        float this_speed = (float)st.outputSize() / (float)st.compileTimeUser();
        /* The current speed of the server, but without adjusting to the current
           job, hence no second argument.  */
        float cur_speed = server_speed(job->server());

        if ((this_speed / 1.2) > cur_speed) {
            st.setOutputSize(
                (long unsigned)(cur_speed * 1.2 * st.compileTimeUser()));
        } else if ((this_speed * 1.2) < cur_speed) {
            st.setOutputSize(
                (long unsigned)(cur_speed / 1.2 * st.compileTimeUser()));
        }
    }

    job->server()->appendCompiledJob(st);
    job->server()->setCumCompiled(job->server()->cumCompiled() + st);

    if (job->server()->lastCompiledJobs().size() > 200) {
        job->server()->setCumCompiled(
            job->server()->cumCompiled() -
            *job->server()->lastCompiledJobs().begin());
        job->server()->popCompiledJob();
    }

    job->submitter()->appendRequestedJobs(st);
    job->submitter()->setCumRequested(job->submitter()->cumRequested() + st);

    if (job->submitter()->lastRequestedJobs().size() > 200) {
        job->submitter()->setCumRequested(
            job->submitter()->cumRequested() -
            *job->submitter()->lastRequestedJobs().begin());
        job->submitter()->popRequestedJobs();
    }

    all_job_stats.push_back(st);
    cum_job_stats += st;

    if (all_job_stats.size() > 2000) {
        cum_job_stats -= *all_job_stats.begin();
        all_job_stats.pop_front();
    }

#if DEBUG_LEVEL > 1
    if (job->argFlags() < 7000) {
        trace() << "add_job_stats " << job->language() << " "
                << (time(0) - starttime) << " " << st.compileTimeUser() << " "
                << (job->argFlags() & CompileJob::Flag_g ? '1' : '0')
                << (job->argFlags() & CompileJob::Flag_g3 ? '1' : '0')
                << (job->argFlags() & CompileJob::Flag_O ? '1' : '0')
                << (job->argFlags() & CompileJob::Flag_O2 ? '1' : '0')
                << (job->argFlags() & CompileJob::Flag_Ol2 ? '1' : '0') << " "
                << st.outputSize() << " " << msg->out_uncompressed << " "
                << job->server()->nodeName() << " "
                << float(msg->out_uncompressed) / st.compileTimeUser() << " "
                << server_speed(job->server(), NULL, true) << '\n';
    }
#endif
}

bool
handle_end(CompileServer * cs);

void
notify_monitors(const Msg & m)
{
    for (auto it = monitors.begin(); it != monitors.end(); ++it) {
        /* If we can't send it, don't be clever, simply close this monitor.  */
        if (!(*it)->sendMsg(
                m,
                MsgChannel::SendNonBlocking /*| MsgChannel::SendBulkOnly*/)) {
            trace() << "monitor is blocking... removing\n";
            handle_end(*it);
        }
    }
}

float
server_speed(CompileServer * cs, Job * job, bool blockDebug)
{
#if DEBUG_LEVEL <= 2
    (void)blockDebug;
#endif
    if (cs->lastCompiledJobs().size() == 0 ||
        cs->cumCompiled().compileTimeUser() == 0) {
        return 0;
    } else {
        float f = (float)cs->cumCompiled().outputSize() /
                  (float)cs->cumCompiled().compileTimeUser();

        // we only care for the load if we're about to add a job to it
        if (job) {
            if (job->submitter() == cs) {
                int clientCount = cs->clientCount();
                if (clientCount == 0) {
                    // Older client/daemon that doesn't send client count. Use
                    // the number of jobs that we've already been told about as
                    // the fallback value (it will sometimes be an
                    // underestimate).
                    clientCount = cs->submittedJobsCount();
                }
                if (clientCount > cs->maxJobs()) {
                    // The submitter would be overloaded by building all its
                    // jobs locally, so penalize it heavily in order to send
                    // jobs preferably to other nodes, so that the submitter
                    // should preferably do tasks that cannot be distributed,
                    // such as linking or preparing jobs for remote nodes.
                    f *= 0.1;
#if DEBUG_LEVEL > 2
                    if (!blockDebug)
                        log_info() << "penalizing local build for job "
                                   << job->id() << '\n';
#endif
                } else if (clientCount == cs->maxJobs()) {
                    // This means the submitter would be fully loaded by its
                    // jobs. It is still preferable to distribute the job,
                    // unless the submitter is noticeably faster.
                    f *= 0.8;
#if DEBUG_LEVEL > 2
                    if (!blockDebug)
                        log_info() << "slightly penalizing local build for job "
                                   << job->id() << '\n';
#endif
                } else if (clientCount <= cs->maxJobs() / 2) {
                    // The submitter has only few jobs, slightly prefer building
                    // the job locally in order to save the overhead of
                    // distributing. Note that this is unreliable, the submitter
                    // may be in fact running a large parallel build but this is
                    // just the first of the jobs and other icecc instances
                    // haven't been launched yet. There's probably no good way
                    // to detect this reliably.
                    f *= 1.1;
#if DEBUG_LEVEL > 2
                    if (!blockDebug)
                        log_info() << "slightly preferring local build for job "
                                   << job->id() << '\n';
#endif
                } else {
                    // the remaining case, don't adjust
                    f *= 1;
                }
                // ignoring load for submitter - assuming the load is our own
            } else {
                f *= float(1000 - cs->load()) / 1000;
            }

            /* Gradually throttle with the number of assigned jobs. This
             * takes care of the fact that not all slots are equally fast on
             * CPUs with SMT and dynamic clock ramping.
             */
            f *= (1.0f - (0.5f * cs->jobList().size() / cs->maxJobs()));
        }

        // below we add a pessimism factor - assuming the first job a computer
        // got is not representative
        if (cs->lastCompiledJobs().size() < 7) {
            f *= (-0.5 * cs->lastCompiledJobs().size() + 4.5);
        }

        return f;
    }
}

void
handle_monitor_stats(CompileServer * cs, const StatsMsg * msg = nullptr)
{
    if (monitors.empty()) {
        return;
    }

    std::ostringstream ss{};
    ss << "Name:" << cs->nodeName().c_str()
       << "\n"
          "IP:"
       << cs->name.c_str()
       << "\n"
          "MaxJobs:"
       << cs->maxJobs()
       << "\n"
          "NoRemote:"
       << (cs->noRemote() ? "true" : "false")
       << "\n"
          "Platform:"
       << cs->hostPlatform().c_str()
       << "\n"
          "Version:"
       << cs->maximum_remote_protocol
       << "\n"
          "Features:"
       << supported_features_to_string(cs->supportedFeatures()).c_str()
       << "\n"
          "Speed:"
       << server_speed(cs) << '\n';

    if (msg) {
        ss << "Load:" << msg->load << '\n'
           << "LoadAvg1:" << msg->loadAvg1 << '\n'
           << "LoadAvg5:" << msg->loadAvg5 << '\n'
           << "LoadAvg10:" << msg->loadAvg10 << '\n'
           << "FreeMem:" << msg->freeMem << '\n';
    } else {
        ss << "Load:" << cs->load() << '\n';
    }

    notify_monitors(MonStatsMsg(cs->hostId(), ss.str()));
}

Job *
create_new_job(CompileServer * submitter)
{
    ++new_job_id;
    assert(jobs.find(new_job_id) == jobs.end());

    Job * job = new Job(new_job_id, submitter);
    jobs[new_job_id] = job;
    return job;
}

void
enqueue_job_request(Job * job)
{
    for (auto it = job_requests.begin(); it != job_requests.end(); ++it) {
        if ((*it)->submitter == job->submitter() &&
            (*it)->niceness == job->niceness()) {
            (*it)->l.push_back(job);
            return;
        }
        if ((*it)->niceness >
            job->niceness()) { // lower priority starts here, insert group
            JobRequestsGroup * newone = new JobRequestsGroup();
            newone->submitter = job->submitter();
            newone->niceness = job->niceness();
            newone->l.push_back(job);
            job_requests.insert(it, newone);
            return;
        }
    }
    JobRequestsGroup * newone = new JobRequestsGroup();
    newone->submitter = job->submitter();
    newone->niceness = job->niceness();
    newone->l.push_back(job);
    job_requests.push_back(newone);
}

void
enqueue_job_requests_group(JobRequestsGroup * group)
{
    for (auto it = job_requests.begin(); it != job_requests.end(); ++it) {
        if ((*it)->niceness >
            group->niceness) { // lower priority starts here, insert group
            job_requests.insert(it, group);
            return;
        }
    }
    job_requests.push_back(group);
}

// Gives a position in job_requests, used to iterate items.
struct JobRequestPosition {
    JobRequestPosition() : group(nullptr), job(nullptr) {}
    JobRequestPosition(JobRequestsGroup * g, Job * j) : group(g), job(j) {}
    bool
    isValid() const
    {
        return group != nullptr;
    }
    JobRequestsGroup * group;
    Job *              job;
};

JobRequestPosition
get_first_job_request()
{
    if (job_requests.empty()) {
        return JobRequestPosition();
    }

    JobRequestsGroup * first = job_requests.front();
    assert(!first->l.empty());
    return JobRequestPosition(first, first->l.front());
}

JobRequestPosition
get_next_job_request(const JobRequestPosition & pos)
{
    assert(!job_requests.empty());
    assert(pos.group != nullptr && pos.job != nullptr);

    JobRequestsGroup * group = pos.group;
    // Get next job in the same group.
    auto job_it = std::find(group->l.begin(), group->l.end(), pos.job);
    assert(job_it != group->l.end());
    ++job_it;
    if (job_it != group->l.end())
        return JobRequestPosition(group, *job_it);
    // Get next group.
    auto group_it = std::find(job_requests.begin(), job_requests.end(), group);
    assert(group_it != job_requests.end());
    ++group_it;
    if (group_it != job_requests.end()) {
        group = *group_it;
        assert(!group->l.empty());
        return JobRequestPosition(group, group->l.front());
    }
    // end
    return JobRequestPosition();
}

// Removes the given job request.
// Also tries to rotate submitters in a round-robin fashion to try to serve
// them all fairly.
void
remove_job_request(const JobRequestPosition & pos)
{
    assert(!job_requests.empty());
    assert(pos.group != nullptr && pos.job != nullptr);

    JobRequestsGroup * group = pos.group;
    assert(std::find(job_requests.begin(), job_requests.end(), group) !=
           job_requests.end());
    job_requests.remove(group);
    assert(std::find(group->l.begin(), group->l.end(), pos.job) !=
           group->l.end());
    group->remove_job(pos.job);

    if (group->l.empty()) {
        delete group;
    } else {
        enqueue_job_requests_group(group);
    }
}

bool
handle_cs_request(MsgChannel * cs, const GetCSMsg & msg)
{
    CompileServer * submitter = static_cast<CompileServer *>(cs);

    submitter->setClientCount(msg.client_count);

    Job * master_job = nullptr;

    for (unsigned int i = 0; i < msg.count; ++i) {
        Job * job = create_new_job(submitter);
        job->setEnvironments(msg.versions);
        job->setTargetPlatform(msg.target);
        job->setArgFlags(msg.arg_flags);
        switch (msg.lang) {
            case CompileJob::Lang_C: job->setLanguage("C"); break;
            case CompileJob::Lang_CXX: job->setLanguage("C++"); break;
            case CompileJob::Lang_OBJC: job->setLanguage("ObjC"); break;
            case CompileJob::Lang_OBJCXX: job->setLanguage("ObjC++"); break;
            case CompileJob::Lang_Custom: job->setLanguage("<custom>"); break;
            default:
                job->setLanguage("???"); // presumably newer client?
                break;
        }
        job->setFileName(msg.filename);
        job->setLocalClientId(msg.client_id);
        job->setPreferredHost(msg.preferred_host);
        job->setMinimalHostVersion(msg.minimal_host_version);
        job->setRequiredFeatures(msg.required_features);
        job->setNiceness(std::max(0, std::min(20, int(msg.niceness))));
        enqueue_job_request(job);
        std::ostream & dbg = log_info();
        dbg << "NEW " << job->id() << " client=" << submitter->nodeName()
            << " versions=[";

        Environments envs = job->environments();

        for (auto it = envs.begin(); it != envs.end();) {
            dbg << it->second << "(" << it->first << ")";

            if (++it != envs.end()) {
                dbg << ", ";
            }
        }

        dbg << "] " << msg.filename << " " << job->language() << " "
            << job->niceness() << '\n';
        notify_monitors(MonGetCSMsg(job->id(), submitter->hostId(), msg));

        if (!master_job) {
            master_job = job;
        } else {
            master_job->appendJob(job);
        }
    }

    return true;
}

void
handle_job_local_begin(CompileServer * cs, const JobLocalBeginMsg & msg)
{
    ++new_job_id;
    trace() << "handle_local_job " << msg.outfile << " " << msg.id << '\n';
    cs->insertClientJobId(msg.id, new_job_id);
    notify_monitors(
        MonLocalJobBeginMsg(new_job_id, msg.outfile, msg.stime, cs->hostId()));
}

void
handle_job_local_done(CompileServer * cs, const JobLocalDoneMsg & msg)
{
    trace() << "handle_local_job_done " << msg.job_id << '\n';
    notify_monitors(new JobLocalDoneMsg(cs->getClientJobId(msg.job_id)));
    cs->eraseClientJobId(msg.job_id);
}

/* Given a candidate CS and a JOB, check all installed environments
   on the CS for a match.  Return an empty std::string if none of the required
   environments for this job is installed.  Otherwise return the
   host platform of the first found installed environment which is among
   the requested.  That can be send to the client, which then completely
   specifies which environment to use (name, host platform and target
   platform).  */
std::string
envs_match(CompileServer * cs, const Job * job)
{
    if (job->submitter() == cs) {
        return cs->hostPlatform(); // it will compile itself
    }

    Environments compilerVersions = cs->compilerVersions();

    /* Check all installed envs on the candidate CS ...  */
    for (auto it = compilerVersions.begin(); it != compilerVersions.end();
         ++it) {
        if (it->first == job->targetPlatform()) {
            /* ... IT now is an installed environment which produces code for
               the requested target platform.  Now look at each env which
               could be installed from the client (i.e. those coming with the
               job) if it matches in name and additionally could be run
               by the candidate CS.  */
            Environments environments = job->environments();
            for (auto it2 = environments.begin(); it2 != environments.end();
                 ++it2) {
                if (it->second == it2->second &&
                    cs->platforms_compatible(it2->first)) {
                    return it2->first;
                }
            }
        }
    }

    return std::string();
}

CompileServer *
pick_server(Job * job)
{
#if DEBUG_LEVEL > 1
    trace() << "pick_server " << job->id() << " " << job->targetPlatform()
            << '\n';
#endif

#if DEBUG_LEVEL > 0

    /* consistency checking for now */
    for (auto it = css.begin(); it != css.end(); ++it) {
        CompileServer * cs = *it;

        std::list<Job *> jobList = cs->jobList();
        for (auto it2 = jobList.begin(); it2 != jobList.end(); ++it2) {
            assert(jobs.find((*it2)->id()) != jobs.end());
        }
    }

    for (auto it = jobs.begin(); it != jobs.end(); ++it) {
        Job * j = it->second;

        if (j->state() == Job::COMPILING) {
            CompileServer *  cs = j->server();
            std::list<Job *> jobList = cs->jobList();
            assert(find(jobList.begin(), jobList.end(), j) != jobList.end());
        }
    }

#endif

    /* if the user wants to test/prefer one specific daemon, we look for that
     * one first */
    if (!job->preferredHost().empty()) {
        for (CompileServer * const cs : css) {
            if (cs->matches(job->preferredHost()) && cs->is_eligible_now(job)) {
#if DEBUG_LEVEL > 1
                trace() << "taking preferred " << cs->nodeName() << " "
                        << server_speed(cs, job, true) << '\n';
#endif
                return cs;
            }
        }

        return nullptr;
    }

    /* If we have no statistics simply use any server which is usable.  */
    if (!all_job_stats.size()) {
        CompileServer * selected = nullptr;
        int             eligible_count = 0;

        for (CompileServer * const cs : css) {
            if (cs->is_eligible_now(job)) {
                ++eligible_count;
                // Do not select the first one (which could be broken and so we
                // might never get job stats), but rather select randomly.
                if (random() % eligible_count == 0)
                    selected = cs;
            }
        }

        if (selected != nullptr) {
            trace() << "no job stats - returning randomly selected "
                    << selected->nodeName() << " load: " << selected->load()
                    << " can install: " << selected->can_install(job) << '\n';
            return selected;
        }

        return nullptr;
    }

    CompileServer * best = nullptr;
    // best uninstalled
    CompileServer * bestui = nullptr;
    // best preloadable host
    CompileServer * bestpre = nullptr;

    uint matches = 0;

    for (CompileServer * const cs : css) {

        // Ignore ineligible servers
        if (!cs->is_eligible_now(job)) {
#if DEBUG_LEVEL > 1
            if ((int(cs->jobList().size()) >=
                 cs->maxJobs() + cs->maxPreloadCount()) ||
                (cs->load() >= 1000)) {
                trace() << "overloaded " << cs->nodeName() << " "
                        << cs->jobList().size() << "/" << cs->maxJobs()
                        << " jobs, load:" << cs->load() << '\n';
            } else
                trace() << cs->nodeName() << " not eligible\n";
#endif
            continue;
        }

        // incompatible architecture or busy installing
        if (!cs->can_install(job).size()) {
#if DEBUG_LEVEL > 2
            trace() << cs->nodeName() << " can't install " << job->id() << '\n';
#endif
            continue;
        }

        /* Don't use non-chroot-able daemons for remote jobs.  XXX */
        if (!cs->chrootPossible() && cs != job->submitter()) {
            trace() << cs->nodeName() << " can't use chroot\n";
            continue;
        }

        // Check if remote & if remote allowed
        if (!cs->check_remote(job)) {
            trace() << cs->nodeName() << " fails remote job check\n";
            continue;
        }

#if DEBUG_LEVEL > 1
        trace() << cs->nodeName() << " compiled "
                << cs->lastCompiledJobs().size()
                << " got now: " << cs->jobList().size()
                << " speed: " << server_speed(cs, job, true) << " compile time "
                << cs->cumCompiled().compileTimeUser() << " produced code "
                << cs->cumCompiled().outputSize()
                << " client count: " << cs->clientCount() << '\n';
#endif

        if ((cs->lastCompiledJobs().size() == 0) &&
            (cs->jobList().size() == 0) && cs->maxJobs()) {
            /* Make all servers compile a job at least once, so we'll get an
               idea about their speed.  */
            if (!envs_match(cs, job).empty()) {
                best = cs;
                matches++;
            } else {
                // if there is one server that already got the environment and
                // one that hasn't compiled at all, pick the one with
                // environment first
                bestui = cs;
            }

            break;
        }

        /* Distribute 5% of our jobs to servers which haven't been picked in a
           long time. This gives us a chance to adjust the server speed rating,
           which may change due to external influences out of our control. */
        if (!cs->lastPickedId() ||
            ((job->id() - cs->lastPickedId()) > (20 * css.size()))) {
            best = cs;
            break;
        }

        if (!envs_match(cs, job).empty()) {
            if (!best) {
                best = cs;
            }
            /* Search the server with the earliest projected time to compile
               the job.  (XXX currently this is equivalent to the fastest one)
             */
            else if ((best->lastCompiledJobs().size() != 0) &&
                     (server_speed(best, job) < server_speed(cs, job))) {
                if (int(cs->jobList().size()) < cs->maxJobs()) {
                    best = cs;
                } else {
                    bestpre = cs;
                }
            }

            matches++;
        } else {
            if (!bestui) {
                bestui = cs;
            }
            /* Search the server with the earliest projected time to compile
               the job.  (XXX currently this is equivalent to the fastest one)
             */
            else if ((bestui->lastCompiledJobs().size() != 0) &&
                     (server_speed(bestui, job) < server_speed(cs, job))) {
                if (int(cs->jobList().size()) < cs->maxJobs()) {
                    bestui = cs;
                } else {
                    bestpre = cs;
                }
            }
        }
    }

    if (best) {
#if DEBUG_LEVEL > 1
        trace() << "taking best installed " << best->nodeName() << " "
                << server_speed(best, job, true) << '\n';
#endif
        return best;
    }

    if (bestui) {
#if DEBUG_LEVEL > 1
        trace() << "taking best uninstalled " << bestui->nodeName() << " "
                << server_speed(bestui, job, true) << '\n';
#endif
        return bestui;
    }

    if (bestpre) {
#if DEBUG_LEVEL > 1
        trace() << "taking best preload " << bestpre->nodeName() << " "
                << server_speed(bestpre, job, true) << '\n';
#endif
    }

    return bestpre;
}

/* Prunes the list of connected servers by those which haven't
   answered for a long time. Return the number of seconds when
   we have to cleanup next time. */
time_t
prune_servers()
{
    time_t now = time(nullptr);
    time_t min_time = MAX_SCHEDULER_PING;

    for (auto it = controls.begin(); it != controls.end();) {
        if ((now - (*it)->last_talk) >= MAX_SCHEDULER_PING) {
            CompileServer * old = *it;
            ++it;
            handle_end(old);
            continue;
        }

        min_time =
            std::min(min_time, MAX_SCHEDULER_PING - now + (*it)->last_talk);
        ++it;
    }

    for (auto it = css.begin(); it != css.end();) {
        (*it)->startInConnectionTest();
        time_t cs_in_conn_timeout = (*it)->getNextTimeout();
        if (cs_in_conn_timeout != -1) {
            min_time = std::min(min_time, cs_in_conn_timeout);
        }

        if ((*it)->busyInstalling() &&
            ((now - (*it)->busyInstalling()) >= MAX_BUSY_INSTALLING)) {
            trace() << "busy installing for a long time - removing "
                    << (*it)->nodeName() << '\n';
            CompileServer * old = *it;
            ++it;
            handle_end(old);
            continue;
        }

        /* protocol version 27 and newer use TCP keepalive */
        if (IS_PROTOCOL_27(*it)) {
            ++it;
            continue;
        }

        if ((now - (*it)->last_talk) >= MAX_SCHEDULER_PING) {
            if ((*it)->maxJobs() >= 0) {
                trace() << "send ping " << (*it)->nodeName() << '\n';
                (*it)->setMaxJobs((*it)->maxJobs() *
                                  -1); // better not give it away

                if ((*it)->sendMsg(PingMsg())) {
                    // give it MAX_SCHEDULER_PONG to answer a ping
                    (*it)->last_talk = time(nullptr) - MAX_SCHEDULER_PING +
                                       2 * MAX_SCHEDULER_PONG;
                    min_time =
                        std::min(min_time, (time_t)2 * MAX_SCHEDULER_PONG);
                    ++it;
                    continue;
                }
            }

            // R.I.P.
            trace() << "removing " << (*it)->nodeName() << '\n';
            CompileServer * old = *it;
            ++it;
            handle_end(old);
            continue;
        } else {
            min_time =
                std::min(min_time, MAX_SCHEDULER_PING - now + (*it)->last_talk);
        }

#if DEBUG_LEVEL > 1
        if ((random() % 400) < 0) {
            // R.I.P.
            trace() << "FORCED removing " << (*it)->nodeName() << '\n';
            CompileServer * old = *it;
            ++it;
            handle_end(old);
            continue;
        }
#endif

        ++it;
    }

    return min_time;
}

bool
empty_queue()
{
    JobRequestPosition jobPosition = get_first_job_request();
    if (!jobPosition.isValid()) {
        return false;
    }

    assert(!css.empty());

    CompileServer * use_cs = nullptr;
    Job *           job = jobPosition.job;

    while (true) {
        use_cs = pick_server(job);

        if (use_cs) {
            break;
        }

        /* Ignore the load on the submitter itself if no other host could
           be found.  We only obey to its max job number.  */
        use_cs = job->submitter();
        if ((int(use_cs->jobList().size()) < use_cs->maxJobs()) &&
            job->preferredHost().empty()
            /* This should be trivially true.  */
            && use_cs->can_install(job).size()) {
            break;
        }

        jobPosition = get_next_job_request(jobPosition);
        if (!jobPosition
                 .isValid()) { // no job found in the whole job_requests list
            jobPosition = get_first_job_request();
            assert(jobPosition.isValid());
            job = jobPosition.job;
            for (CompileServer * const cs : css) {
                if (!job->preferredHost().empty() &&
                    !cs->matches(job->preferredHost()))
                    continue;
                if (cs->is_eligible_ever(job)) {
                    trace() << "No suitable host found, delaying\n";
                    return false;
                }
            }
            // This means that there's nobody who could possibly handle the job,
            // so there's no point in delaying.
            log_info() << "No suitable host found, assigning submitter\n";
            use_cs = job->submitter();
            break;
        }
    }

    remove_job_request(jobPosition);

    job->setState(Job::WAITINGFORCS);
    job->setServer(use_cs);

    std::string host_platform = envs_match(use_cs, job);
    bool        gotit = true;

    if (host_platform.empty()) {
        gotit = false;
        host_platform = use_cs->can_install(job);
    }

    // mix and match between job ids
    unsigned matched_job_id = 0;
    unsigned count = 0;

    std::list<JobStat> lastRequestedJobs =
        job->submitter()->lastRequestedJobs();
    for (auto l = lastRequestedJobs.begin(); l != lastRequestedJobs.end();
         ++l) {
        unsigned rcount = 0;

        std::list<JobStat> lastCompiledJobs = use_cs->lastCompiledJobs();
        for (auto r = lastCompiledJobs.begin(); r != lastCompiledJobs.end();
             ++r) {
            if (l->jobId() == r->jobId()) {
                matched_job_id = l->jobId();
            }

            if (++rcount > 16) {
                break;
            }
        }

        if (matched_job_id || (++count > 16)) {
            break;
        }
    }
    if (IS_PROTOCOL_37(job->submitter()) && use_cs == job->submitter()) {
        NoCSMsg m2(job->id(), job->localClientId());
        if (!job->submitter()->sendMsg(m2)) {
            trace() << "failed to deliver job " << job->id() << '\n';
            handle_end(job->submitter()); // will care for the rest
            return true;
        }
    } else {
        UseCSMsg m2(host_platform,
                    use_cs->name,
                    use_cs->remotePort(),
                    job->id(),
                    gotit,
                    job->localClientId(),
                    matched_job_id);
        if (!job->submitter()->sendMsg(m2)) {
            trace() << "failed to deliver job " << job->id() << '\n';
            handle_end(job->submitter()); // will care for the rest
            return true;
        }
    }

#if DEBUG_LEVEL >= 0
    if (!gotit) {
        trace() << "put " << job->id() << " in joblist of "
                << use_cs->nodeName() << " (will install now)\n";
    } else {
        trace() << "put " << job->id() << " in joblist of "
                << use_cs->nodeName() << '\n';
    }
#endif
    use_cs->appendJob(job);

    /* if it doesn't have the environment, it will get it. */
    if (!gotit) {
        use_cs->setBusyInstalling(time(nullptr));
    }

    std::string env;

    if (!job->masterJobFor().empty()) {
        Environments environments = job->environments();
        for (auto it = environments.begin(); it != environments.end(); ++it) {
            if (it->first == use_cs->hostPlatform()) {
                env = it->second;
                break;
            }
        }
    }

    if (!env.empty()) {
        std::list<Job *> masterJobFor = job->masterJobFor();
        for (Job * const jobTmp : masterJobFor) {
            // remove all other environments
            jobTmp->clearEnvironments();
            jobTmp->appendEnvironment(make_pair(use_cs->hostPlatform(), env));
        }
    }

    return true;
}

bool
handle_login(CompileServer * cs, const LoginMsg & msg)
{
    std::ostream & dbg = trace();

    cs->setRemotePort(msg.port);
    cs->setCompilerVersions(msg.envs);
    cs->setMaxJobs(msg.max_kids);
    cs->setNoRemote(msg.noremote);

    if (msg.nodename.length()) {
        cs->setNodeName(msg.nodename);
    } else {
        cs->setNodeName(cs->name);
    }

    cs->setHostPlatform(msg.host_platform);
    cs->setChrootPossible(msg.chroot_possible);
    cs->setSupportedFeatures(msg.supported_features);
    cs->pick_new_id();

    for (auto it = block_css.begin(); it != block_css.end(); ++it)
        if (cs->matches(*it)) {
            return false;
        }

    dbg << "login " << msg.nodename << " protocol version: " << cs->protocol
        << " features: " << supported_features_to_string(msg.supported_features)
        << " [";
    for (auto it = msg.envs.begin(); it != msg.envs.end(); ++it) {
        dbg << it->second << "(" << it->first << "), ";
    }
    dbg << "]\n";

    handle_monitor_stats(cs);

    /* remove any other clients with the same IP and name, they must be stale */
    for (auto it = css.begin(); it != css.end(); ++it) {
        if (cs->eq_ip(*(*it)) && cs->nodeName() == (*it)->nodeName()) {
            CompileServer * old = *it;
            handle_end(old);
        }
    }

    css.push_back(cs);

    /* Configure the daemon */
    if (IS_PROTOCOL_24(cs)) {
        cs->sendMsg(ConfCSMsg());
    }

    return true;
}

void
handle_relogin(CompileServer * cs, const LoginMsg & msg)
{
    cs->setCompilerVersions(msg.envs);
    cs->setBusyInstalling(0);

    std::ostream & dbg = trace();
    dbg << "RELOGIN " << cs->nodeName() << "(" << cs->hostPlatform() << "): [";

    for (auto it = msg.envs.begin(); it != msg.envs.end(); ++it) {
        dbg << it->second << "(" << it->first << "), ";
    }

    dbg << "]\n";

    /* Configure the daemon */
    if (IS_PROTOCOL_24(cs)) {
        cs->sendMsg(ConfCSMsg());
    }
}

void
handle_mon_login(CompileServer * cs, const MonLoginMsg & /*unused*/)
{
    monitors.push_back(cs);
    // monitors really want to be fed lazily
    cs->setBulkTransfer();

    for (auto it = css.begin(); it != css.end(); ++it) {
        handle_monitor_stats(*it);
    }

    fd2cs.erase(cs->fd); // no expected data from them
}

bool
handle_job_begin(CompileServer * cs, const JobBeginMsg & msg)
{
    auto job_it = jobs.find(msg.job_id);
    if (job_it == jobs.end()) {
        trace() << "handle_job_begin: no valid job id " << msg.job_id << '\n';
        return false;
    }

    Job * job = job_it->second;

    if (job->server() != cs) {
        trace() << "that job isn't handled by " << cs->name << '\n';
        return false;
    }

    cs->setClientCount(msg.client_count);

    job->setState(Job::COMPILING);
    job->setStartTime(msg.stime);
    job->setStartOnScheduler(time(nullptr));
    notify_monitors(MonJobBeginMsg(msg.job_id, msg.stime, cs->hostId()));
#if DEBUG_LEVEL >= 0
    trace() << "BEGIN: " << msg.job_id
            << " client=" << job->submitter()->nodeName() << "("
            << job->targetPlatform() << ")"
            << " server=" << job->server()->nodeName() << "("
            << job->server()->hostPlatform() << ")\n";
#endif

    return true;
}

bool
handle_job_done(CompileServer * cs, JobDoneMsg & msg)
{
    Job * j = nullptr;

    if (uint32_t clientId = msg.unknownJobClientId()) {
        // The daemon has sent a done message for a job for which it doesn't
        // know the job id (happens if the job is cancelled before we send back
        // the job id). Find the job using the client id.
        for (auto & id_and_job : jobs) {
            auto   id = id_and_job.first;
            auto * job = id_and_job.second;
            trace() << "looking for waitcs " << job->server() << " "
                    << job->submitter() << " " << cs << " " << job->state()
                    << " " << job->localClientId() << " " << clientId << '\n';

            if (job->server() == nullptr && job->submitter() == cs &&
                job->localClientId() == clientId) {
                trace() << "STOP (WAITFORCS) FOR " << id << '\n';
                j = job;
                msg.setJobId(j->id()); // Now we know the job's id.

                /* Unfortunately the job_requests queues are also tagged based
                on the daemon, so we need to clean them up also.  */
                for (auto it = job_requests.begin(); it != job_requests.end();
                     ++it)
                    if ((*it)->submitter == cs) {
                        JobRequestsGroup * l = *it;
                        for (auto jit = l->l.begin(); jit != l->l.end();
                             ++jit) {
                            if (*jit == j) {
                                l->l.erase(jit);
                                break;
                            }
                        }

                        if (l->l.empty()) {
                            it = job_requests.erase(it);
                            break;
                        }
                    }
            }
        }
    } else {
        auto job_it = jobs.find(msg.job_id);
        if (job_it != jobs.end()) {
            j = job_it->second;
        }
    }

    if (j == nullptr) {
        trace() << "job ID not present " << msg.job_id << '\n';
        return false;
    }

    if (msg.isFromServer() && (j->server() != cs)) {
        log_info() << "the server isn't the same for job " << msg.job_id
                   << '\n';
        log_info() << "server: " << j->server()->nodeName() << '\n';
        log_info() << "msg came from: " << cs->nodeName() << '\n';
        // the daemon is not following matz's rules: kick him
        handle_end(cs);
        return false;
    }

    if (!msg.isFromServer() && (j->submitter() != cs)) {
        log_info() << "the submitter isn't the same for job " << msg.job_id
                   << '\n';
        log_info() << "submitter: " << j->submitter()->nodeName() << '\n';
        log_info() << "msg came from: " << cs->nodeName() << '\n';
        // the daemon is not following matz's rules: kick him
        handle_end(cs);
        return false;
    }

    cs->setClientCount(msg.client_count);

    if (msg.exitcode == 0) {
        std::ostream & dbg = trace();
        dbg << "END " << msg.job_id << " status=" << msg.exitcode;

        if (msg.in_uncompressed)
            dbg << " in=" << msg.in_uncompressed << "("
                << int(msg.in_compressed * 100 / msg.in_uncompressed) << "%)";
        else {
            dbg << " in=0(0%)";
        }

        if (msg.out_uncompressed)
            dbg << " out=" << msg.out_uncompressed << "("
                << int(msg.out_compressed * 100 / msg.out_uncompressed) << "%)";
        else {
            dbg << " out=0(0%)";
        }

        dbg << " real=" << msg.real_msec << " user=" << msg.user_msec
            << " sys=" << msg.sys_msec << " pfaults=" << msg.pfaults
            << " server=" << j->server()->nodeName() << '\n';
    } else {
        trace() << "END " << msg.job_id << " status=" << msg.exitcode << '\n';
    }

    if (j->server()) {
        j->server()->removeJob(j);
    }

    add_job_stats(j, msg);
    notify_monitors(MonJobDoneMsg{msg});
    jobs.erase(msg.job_id);
    delete j;

    return true;
}

void
handle_ping(CompileServer * cs)
{
    cs->last_talk = time(nullptr);

    if (cs->maxJobs() < 0) {
        cs->setMaxJobs(cs->maxJobs() * -1);
    }
}

bool
handle_stats(CompileServer * cs, const StatsMsg & msg)
{
    /* Before protocol 25, ping and stat handling was
       clutched together.  */
    if (!IS_PROTOCOL_25(cs)) {
        cs->last_talk = time(nullptr);

        if (cs->maxJobs() < 0) {
            cs->setMaxJobs(cs->maxJobs() * -1);
        }
    }

    const auto end = css.end();
    auto       cs_it = std::find(css.begin(), end, cs);
    if (cs_it == end) {
        return false;
    }

    (*cs_it)->setLoad(msg.load);
    (*cs_it)->setClientCount(msg.client_count);
    handle_monitor_stats(*cs_it, &msg);

    return true;
}

void
handle_blacklist_host_env(CompileServer * cs, const BlacklistHostEnvMsg & msg)
{
    const auto end = css.end();
    auto cs_it = std::find_if(css.begin(), end, [&msg](CompileServer * cs) {
        return cs->name.compare(msg.hostname) == 0;
    });

    if (cs_it != end) {
        trace() << "Blacklisting host " << msg.hostname << " for environment "
                << msg.environment << " (" << msg.target << ")\n";
        cs->blacklistCompileServer(*cs_it,
                                   make_pair(msg.target, msg.environment));
    }
}

// return false if some error occurred, leaves C open.  */
bool
try_login(CompileServer * cs, const Msg & msg)
{
    bool ret = ext::visit(ext::make_visitor(
                              [cs](const LoginMsg & m) {
                                  cs->setType(CompileServer::DAEMON);
                                  return handle_login(cs, m);
                              },
                              [cs](const MonLoginMsg & m) {
                                  cs->setType(CompileServer::MONITOR);
                                  handle_mon_login(cs, m);
                                  return true;
                              },
                              [](const auto & m) {
                                  log_info() << "Invalid first message "
                                             << message_type(m) << '\n';
                                  return false;
                              }),
                          msg);

    if (ret) {
        cs->setState(CompileServer::LOGGEDIN);
    } else {
        handle_end(cs);
    }

    return ret;
}

bool
handle_end(CompileServer * toremove)
{
    trace() << "Handle_end " << toremove << '\n';

    switch (toremove->type()) {
        case CompileServer::MONITOR:
            assert(find(monitors.begin(), monitors.end(), toremove) !=
                   monitors.end());
            monitors.remove(toremove);
#if DEBUG_LEVEL > 1
            trace() << "handle_end(moni) " << monitors.size() << '\n';
#endif
            break;
        case CompileServer::DAEMON:
            log_info() << "remove daemon " << toremove->nodeName() << '\n';

            notify_monitors(MonStatsMsg(toremove->hostId(), "State:Offline\n"));

            /* A daemon disconnected.  We must remove it from the css list,
               and we have to delete all jobs scheduled on that daemon.
            There might be still clients connected running on the machine on
            which the daemon died.  We expect that the daemon dying makes the
            client disconnect soon too.  */
            css.remove(toremove);

            /* Unfortunately the job_requests queues are also tagged based on
               the daemon, so we need to clean them up also.  */

            for (auto it = job_requests.begin(); it != job_requests.end();) {
                if ((*it)->submitter == toremove) {
                    JobRequestsGroup * l = *it;

                    for (auto jit = l->l.begin(); jit != l->l.end(); ++jit) {
                        trace() << "STOP (DAEMON) FOR " << (*jit)->id() << '\n';
                        notify_monitors(
                            MonJobDoneMsg(JobDoneMsg((*jit)->id(), 255)));

                        if ((*jit)->server()) {
                            (*jit)->server()->setBusyInstalling(0);
                        }

                        jobs.erase((*jit)->id());
                        delete (*jit);
                    }

                    delete l;
                    it = job_requests.erase(it);
                } else {
                    ++it;
                }
            }

            for (auto mit = jobs.begin(); mit != jobs.end();) {
                Job * job = mit->second;

                if (job->server() == toremove || job->submitter() == toremove) {
                    trace() << "STOP (DAEMON2) FOR " << mit->first << '\n';
                    notify_monitors(MonJobDoneMsg(JobDoneMsg(job->id(), 255)));

                    /* If this job is removed because the submitter is removed
                    also remove the job from the servers joblist.  */
                    if (job->server() && job->server() != toremove) {
                        job->server()->removeJob(job);
                    }

                    if (job->server()) {
                        job->server()->setBusyInstalling(0);
                    }

                    jobs.erase(mit++);
                    delete job;
                } else {
                    ++mit;
                }
            }

            for (CompileServer * const cs : css) {
                cs->eraseCSFromBlacklist(toremove);
            }

            break;
        default: trace() << "remote end had UNKNOWN type?\n"; break;
    }

    fd2cs.erase(toremove->fd);
    delete toremove;
    return true;
}

/* Returns TRUE if C was not closed.  */
bool
handle_activity(CompileServer * cs)
{
    auto msg = cs->getMsg(0, true);

    if (ext::holds_alternative<ext::monostate>(msg)) {
        handle_end(cs);
        return false;
    }

    /* First we need to login.  */
    if (cs->state() == CompileServer::CONNECTED) {
        return try_login(cs, msg);
    }

    return ext::visit(
        ext::make_visitor(
            [cs](JobBeginMsg & m) { return handle_job_begin(cs, m); },
            [cs](JobDoneMsg & m) { return handle_job_done(cs, m); },
            [cs](PingMsg & /*unused*/) {
                handle_ping(cs);
                return true;
            },
            [cs](StatsMsg & m) { return handle_stats(cs, m); },
            [cs](EndMsg & /*unused*/) {
                handle_end(cs);
                return false;
            },
            [cs](JobLocalBeginMsg & m) {
                handle_job_local_begin(cs, m);
                return true;
            },
            [cs](JobLocalDoneMsg & m) {
                handle_job_local_done(cs, m);
                return true;
            },
            [cs](LoginMsg & m) {
                handle_relogin(cs, m);
                return true;
            },
            [cs](GetCSMsg & m) { return handle_cs_request(cs, m); },
            [cs](BlacklistHostEnvMsg & m) {
                handle_blacklist_host_env(cs, m);
                return true;
            },
            [cs](auto & m) {
                log_info() << "Invalid message type arrived " << message_type(m)
                           << '\n';
                handle_end(cs);
                return false;
            }),
        msg);
}

int
open_broad_listener(int port, const std::string & interface)
{
    int                listen_fd;
    struct sockaddr_in myaddr;

    if ((listen_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        log_perror("socket()");
        return -1;
    }

    int optval = 1;

    if (setsockopt(
            listen_fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
        log_perror("setsockopt()");
        return -1;
    }

    if (!build_address_for_interface(myaddr, interface, port)) {
        return -1;
    }

    if (::bind(listen_fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
        log_perror("bind()");
        return -1;
    }

    return listen_fd;
}

int
open_tcp_listener(short port, const std::string & interface)
{
    int                fd;
    struct sockaddr_in myaddr;

    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        log_perror("socket()");
        return -1;
    }

    int optval = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        log_perror("setsockopt()");
        return -1;
    }

    /* Although we poll() on fd we need O_NONBLOCK, due to
       possible network errors making accept() block although poll() said
       there was some activity.  */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        log_perror("fcntl()");
        return -1;
    }

    if (!build_address_for_interface(myaddr, interface, port)) {
        return -1;
    }

    if (::bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
        log_perror("bind()");
        return -1;
    }

    if (listen(fd, 1024) < 0) {
        log_perror("listen()");
        return -1;
    }

    return fd;
}

void
usage(const char * reason = nullptr)
{
    if (reason) {
        std::cerr << reason << '\n';
    }

    std::cerr << "ICECREAM scheduler " VERSION "\n";
    std::cerr << "usage: icecc-scheduler [options] \n"
              << "Options:\n"
              << "  -n, --netname <name>\n"
              << "  -i, --interface <net_interface>\n"
              << "  -p, --port <port>\n"
              << "  -h, --help\n"
              << "  -l, --log-file <file>\n"
              << "  -d, --daemonize\n"
              << "  -u, --user-uid\n"
              << "  -v[v[v]]]\n"
              << "  -r, --persistent-client-connection\n"
              << '\n';

    exit(1);
}

void
trigger_exit(int signum)
{
    if (!exit_handler_called.test_and_set(std::memory_order_relaxed)) {
        /*
         * We must guarantee that only one signal handler performs an operation
         * on keep_running since it may not be lock free.
         */
        keep_running.store(false, std::memory_order_relaxed);
    } else {
        // hmm, we got killed already. try better
        static const char msg[] = "forced exit.\n";
        ignore_result(write(STDERR_FILENO, msg, strlen(msg)));
        _exit(1);
    }

    // make BSD happy
    signal(signum, trigger_exit);
}

void
handle_scheduler_announce(const char *       buf,
                          const char *       netname,
                          bool               persistent_clients,
                          struct sockaddr_in broad_addr)
{
    /* Another scheduler is announcing it's running, disconnect daemons if it
       has a better version or the same version but was started earlier. */
    time_t      other_time;
    int         other_protocol_version;
    std::string other_netname;
    Broadcasts::getSchedulerVersionData(
        buf, &other_protocol_version, &other_time, &other_netname);
    trace() << "Received scheduler announcement from "
            << inet_ntoa(broad_addr.sin_addr) << ":"
            << ntohs(broad_addr.sin_port) << " (version "
            << int(other_protocol_version) << ", netname " << other_netname
            << ")\n";
    if (other_protocol_version >= 36) {
        if (other_netname == netname) {
            if (other_protocol_version > PROTOCOL_VERSION ||
                (other_protocol_version == PROTOCOL_VERSION &&
                 other_time < starttime)) {
                if (!persistent_clients) {
                    log_info()
                        << "Scheduler from " << inet_ntoa(broad_addr.sin_addr)
                        << ":" << ntohs(broad_addr.sin_port) << " (version "
                        << int(other_protocol_version)
                        << ") has announced itself as a preferred"
                           " scheduler, disconnecting all connections."
                        << '\n';
                    if (!css.empty() || !monitors.empty()) {
                        while (!css.empty()) {
                            handle_end(css.front());
                        }
                        while (!monitors.empty()) {
                            handle_end(monitors.front());
                        }
                    }
                }
            }
        }
    }
}

} // namespace

int
main(int argc, char * argv[])
{
    int                listen_fd;
    int                remote_fd;
    int                broad_fd;
    struct sockaddr_in remote_addr;
    socklen_t          remote_len;
    const char *       netname = "ICECREAM";
    bool               detach = false;
    bool               persistent_clients = false;
    int                debug_level = Error;
    std::string        logfile;
    uid_t              user_uid;
    gid_t              user_gid;
    int                warn_icecc_user_errno = 0;

    if (getuid() == 0) {
        struct passwd * pw = getpwnam("icecc");

        if (pw) {
            user_uid = pw->pw_uid;
            user_gid = pw->pw_gid;
        } else {
            warn_icecc_user_errno =
                errno ? errno
                      : ENOENT; // apparently errno can be 0 on error here
            user_uid = 65534;
            user_gid = 65533;
        }
    } else {
        user_uid = getuid();
        user_gid = getgid();
    }

    while (true) {
        int                        option_index = 0;
        static const struct option long_options[] = {
            {"netname", 1, nullptr, 'n'},
            {"help", 0, nullptr, 'h'},
            {"persistent-client-connection", 0, nullptr, 'r'},
            {"interface", 1, nullptr, 'i'},
            {"port", 1, nullptr, 'p'},
            {"daemonize", 0, nullptr, 'd'},
            {"log-file", 1, nullptr, 'l'},
            {"user-uid", 1, nullptr, 'u'},
            {nullptr, 0, nullptr, 0}};

        const int c = getopt_long(
            argc, argv, "n:i:p:hl:vdru:", long_options, &option_index);

        if (c == -1) {
            break; // eoo
        }

        switch (c) {
            case 0: (void)long_options[option_index].name; break;
            case 'd': detach = true; break;
            case 'r': persistent_clients = true; break;
            case 'l':
                if (optarg && *optarg) {
                    logfile = optarg;
                } else {
                    usage("Error: -l requires argument");
                }

                break;
            case 'v':

                if (debug_level < MaxVerboseLevel) {
                    debug_level++;
                }

                break;
            case 'n':

                if (optarg && *optarg) {
                    netname = optarg;
                } else {
                    usage("Error: -n requires argument");
                }

                break;
            case 'i':

                if (optarg && *optarg) {
                    std::string interface = optarg;
                    if (interface.empty()) {
                        usage("Error: Invalid network interface specified");
                    }

                    scheduler_interface = interface;
                } else {
                    usage("Error: -i requires argument");
                }

                break;
            case 'p':

                if (optarg && *optarg) {
                    scheduler_port = atoi(optarg);

                    if (0 == scheduler_port) {
                        usage("Error: Invalid port specified");
                    }
                } else {
                    usage("Error: -p requires argument");
                }

                break;
            case 'u':

                if (optarg && *optarg) {
                    struct passwd * pw = getpwnam(optarg);

                    if (!pw) {
                        usage("Error: -u requires a valid username");
                    } else {
                        user_uid = pw->pw_uid;
                        user_gid = pw->pw_gid;
                        warn_icecc_user_errno = 0;

                        if (!user_gid || !user_uid) {
                            usage("Error: -u <username> must not be root");
                        }
                    }
                } else {
                    usage("Error: -u requires a valid username");
                }

                break;

            default: usage();
        }
    }

    if (warn_icecc_user_errno != 0) {
        log_errno("No icecc user on system. Falling back to nobody.", errno);
    }

    if (getuid() == 0) {
        if (!logfile.size() && detach) {
            if (mkdir("/var/log/icecc",
                      S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
                if (errno == EEXIST) {
                    if (-1 == chmod("/var/log/icecc",
                                    S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH |
                                        S_IXOTH)) {
                        log_perror("chmod() failure");
                    }

                    if (-1 == chown("/var/log/icecc", user_uid, user_gid)) {
                        log_perror("chown() failure");
                    }
                }
            }

            logfile = "/var/log/icecc/scheduler.log";
        }

        if (setgroups(0, nullptr) < 0) {
            log_perror("setgroups() failed");
            return 1;
        }

        if (setgid(user_gid) < 0) {
            log_perror("setgid() failed");
            return 1;
        }

        if (setuid(user_uid) < 0) {
            log_perror("setuid() failed");
            return 1;
        }
    }

    setup_debug(debug_level, logfile);

    log_info() << "ICECREAM scheduler " VERSION " starting up, port "
               << scheduler_port << '\n';

    if (detach) {
        if (daemon(0, 0) != 0) {
            log_errno("Failed to detach.", errno);
            exit(1);
        }
    }

    listen_fd = open_tcp_listener(scheduler_port, scheduler_interface);

    if (listen_fd < 0) {
        return 1;
    }

    broad_fd = open_broad_listener(scheduler_port, scheduler_interface);

    if (broad_fd < 0) {
        return 1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        log_warning() << "signal(SIGPIPE, ignore) failed: " << strerror(errno)
                      << '\n';
        return 1;
    }

    starttime = time(nullptr);
    if (getenv("ICECC_FAKE_STARTTIME") != nullptr)
        starttime -= 1000;

    std::ofstream pidFile;
    std::string   progName = argv[0];
    progName = find_basename(progName);
    pidFilePath = std::string(RUNDIR) + "/" + progName + ".pid";
    pidFile.open(pidFilePath.c_str());
    pidFile << getpid() << '\n';
    pidFile.close();

    // Set running flag before activation of signal handlers
    keep_running.store(true, std::memory_order_relaxed);

    signal(SIGTERM, trigger_exit);
    signal(SIGINT, trigger_exit);
    signal(SIGALRM, trigger_exit);

    log_info() << "scheduler ready\n";

    time_t next_listen = 0;

    Broadcasts::broadcastSchedulerVersion(scheduler_port, netname, starttime);
    last_announce = starttime;
    while (keep_running.load(std::memory_order_relaxed)) {
        int timeout = prune_servers();

        while (empty_queue()) {
            continue;
        }

        /* Announce ourselves from time to time, to make other possible
           schedulers disconnect their daemons if we are the preferred scheduler
           (daemons with version new enough
           should automatically select the best scheduler, but old daemons
           connect randomly). */
        if (last_announce + 120 < time(nullptr)) {
            Broadcasts::broadcastSchedulerVersion(
                scheduler_port, netname, starttime);
            last_announce = time(nullptr);
        }

        std::vector<pollfd> pollfds;
        pollfds.reserve(fd2cs.size() + css.size() + 5);
        pollfd pfd; // tmp variable

        if (time(nullptr) >= next_listen) {
            pfd.fd = listen_fd;
            pfd.events = POLLIN;
            pollfds.push_back(pfd);
        }

        pfd.fd = broad_fd;
        pfd.events = POLLIN;
        pollfds.push_back(pfd);

        for (auto it = fd2cs.begin(); it != fd2cs.end();) {
            int             i = it->first;
            CompileServer * cs = it->second;
            bool            ok = true;
            ++it;

            /* handle_activity() can delete c and make the iterator
               invalid.  */
            while (ok && cs->hasMsg()) {
                if (!handle_activity(cs)) {
                    ok = false;
                }
            }

            if (ok) {
                pfd.fd = i;
                pfd.events = POLLIN;
                pollfds.push_back(pfd);
            }
        }

        std::list<CompileServer *> cs_in_tsts;
        for (CompileServer * const cs : css) {
            if (cs->getConnectionInProgress()) {
                int csInFd = cs->getInFd();
                cs_in_tsts.push_back(cs);
                pfd.fd = csInFd;
                pfd.events = POLLIN | POLLOUT;
                pollfds.push_back(pfd);
            }
        }

        int active_fds = poll(pollfds.data(), pollfds.size(), timeout * 1000);
        int poll_errno = errno;

        if (active_fds < 0 && errno == EINTR) {
            reset_debug_if_needed(); // we possibly got SIGHUP
            continue;
        }
        reset_debug_if_needed();

        if (active_fds < 0) {
            errno = poll_errno;
            log_perror("poll()");
            return 1;
        }

        if (pollfd_is_set(pollfds, listen_fd, POLLIN)) {
            active_fds--;
            bool pending_connections = true;

            while (pending_connections) {
                remote_len = sizeof(remote_addr);
                remote_fd = accept(
                    listen_fd, (struct sockaddr *)&remote_addr, &remote_len);

                if (remote_fd < 0) {
                    pending_connections = false;
                }

                if (remote_fd < 0 && errno != EAGAIN && errno != EINTR &&
                    errno != EWOULDBLOCK) {
                    log_perror("accept()");
                    /* don't quit because of ECONNABORTED, this can happen
                     * during floods  */
                }

                if (remote_fd >= 0) {
                    CompileServer * cs = new CompileServer(
                        remote_fd, (struct sockaddr *)&remote_addr, remote_len);
                    trace() << "accepted " << cs->name << '\n';
                    cs->last_talk = time(nullptr);

                    if (!cs->protocol) { // protocol mismatch
                        delete cs;
                        continue;
                    }

                    fd2cs[cs->fd] = cs;

                    while (!cs->readSome() || cs->hasMsg()) {
                        if (!handle_activity(cs)) {
                            break;
                        }
                    }
                }
            }

            next_listen = time(nullptr) + 1;
        }

        if (active_fds && pollfd_is_set(pollfds, broad_fd, POLLIN)) {
            active_fds--;
            char               buf[Broadcasts::BROAD_BUFLEN + 1];
            struct sockaddr_in broad_addr;
            socklen_t          broad_len = sizeof(broad_addr);
            /* We can get either a daemon request for a scheduler (1 byte) or
               another scheduler announcing itself (4 bytes + time). */

            int buflen = recvfrom(broad_fd,
                                  buf,
                                  Broadcasts::BROAD_BUFLEN,
                                  0,
                                  (struct sockaddr *)&broad_addr,
                                  &broad_len);
            if (buflen < 0 || buflen > Broadcasts::BROAD_BUFLEN) {
                int err = errno;
                log_perror("recvfrom()");

                /* Some linux 2.6 kernels can return from select with
                   data available, and then return from read() with EAGAIN
                   even on a blocking socket (breaking POSIX).  Happens
                   when the arriving packet has a wrong checksum.  So
                   we ignore EAGAIN here, but still abort for all other errors.
                 */
                if (err != EAGAIN && err != EWOULDBLOCK) {
                    return -1;
                }
            }
            int daemon_version;
            if (DiscoverSched::isSchedulerDiscovery(
                    buf, buflen, &daemon_version)) {
                /* Daemon is searching for a scheduler, only answer if daemon
                 * would be able to talk to us. */
                if (daemon_version >= MIN_PROTOCOL_VERSION) {
                    log_info()
                        << "broadcast from " << inet_ntoa(broad_addr.sin_addr)
                        << ":" << ntohs(broad_addr.sin_port) << " (version "
                        << daemon_version << ")\n";
                    int reply_len = DiscoverSched::prepareBroadcastReply(
                        buf, netname, starttime);
                    if (sendto(broad_fd,
                               buf,
                               reply_len,
                               0,
                               (struct sockaddr *)&broad_addr,
                               broad_len) != reply_len) {
                        log_perror("sendto()");
                    }
                }
            } else if (Broadcasts::isSchedulerVersion(buf, buflen)) {
                handle_scheduler_announce(
                    buf, netname, persistent_clients, broad_addr);
            }
        }

        for (auto it = fd2cs.begin(); active_fds > 0 && it != fd2cs.end();) {
            int             i = it->first;
            CompileServer * cs = it->second;
            /* handle_activity can delete the channel from the fd2cs list,
               hence advance the iterator right now, so it doesn't become
               invalid.  */
            ++it;

            if (pollfd_is_set(pollfds, i, POLLIN)) {
                while (!cs->readSome() || cs->hasMsg()) {
                    if (!handle_activity(cs)) {
                        break;
                    }
                }

                active_fds--;
            }
        }

        for (auto it = cs_in_tsts.begin(); it != cs_in_tsts.end(); ++it) {
            if (find(css.begin(), css.end(), *it) == css.end()) {
                continue; // deleted meanwhile
            }
            if ((*it)->getConnectionInProgress()) {
                if (active_fds > 0 &&
                    pollfd_is_set(
                        pollfds, (*it)->getInFd(), POLLIN | POLLOUT) &&
                    (*it)->isConnected()) {
                    active_fds--;
                    (*it)->updateInConnectivity(true);
                } else if ((active_fds == 0 ||
                            pollfd_is_set(
                                pollfds, (*it)->getInFd(), POLLIN | POLLOUT)) &&
                           !(*it)->isConnected()) {
                    (*it)->updateInConnectivity(false);
                }
            }
        }
    }

    shutdown(broad_fd, SHUT_RDWR);
    while (!css.empty())
        handle_end(css.front());
    while (!monitors.empty())
        handle_end(monitors.front());
    if ((-1 == close(broad_fd)) && (errno != EBADF)) {
        log_perror("close failed");
    }
    if (-1 == unlink(pidFilePath.c_str()) && errno != ENOENT) {
        log_perror("unlink failed") << "\t" << pidFilePath << '\n';
    }
    return 0;
}
