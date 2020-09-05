// No icecream ;(

#ifndef _DAEMON_EXCEPTION_HH_
#define _DAEMON_EXCEPTION_HH_

class DaemonException : public std::exception {
    int code_;

public:
    DaemonException(int exitcode) : exception(), code_(exitcode) {}
    int
    exitcode() const
    {
        return code_;
    }
};

#endif // _DAEMON_EXCEPTION_HH_
