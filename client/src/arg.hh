#ifndef _ARG_HH_
#define _ARG_HH_

#include "comm.hh"

bool
analyse_argv(const std::vector<std::string> & argv,
             CompileJob &                     job,
             bool                             icerun,
             std::list<std::string> *         extrafiles);

#endif // _ARG_HH_
