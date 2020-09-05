#ifndef _REMOTE_HH_
#define _REMOTE_HH_

#include "comm.hh"

extern std::string remote_daemon;

/**
 * permill is the probability it will be compiled three times
 */
int
build_remote(CompileJob &         job,
             MsgChannel *         scheduler,
             const Environments & envs,
             int                  permill);

Environments
parse_icecc_version(const std::string & target, const std::string & prefix);

#endif // _REMOTE_HH_
