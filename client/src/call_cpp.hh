#ifndef _CALL_CPP_HH_
#define _CALL_CPP_HH_

#include "comm.hh"

pid_t
call_cpp(CompileJob & job, int fdwrite, int fdread = -1);

#endif // _CALL_CPP_HH_
