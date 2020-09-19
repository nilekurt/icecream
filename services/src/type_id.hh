#ifndef _TYPE_ID_HH_
#define _TYPE_ID_HH_

#include "comm.hh"

namespace icecream {

template<typename T>
constexpr MsgType
type_id();

template<>
constexpr MsgType
type_id<ext::monostate>()
{
    return MsgType::UNKNOWN;
}

template<>
constexpr MsgType
type_id<PingMsg>()
{
    return MsgType::PING;
}

template<>
constexpr MsgType
type_id<EndMsg>()
{
    return MsgType::END;
}

template<>
constexpr MsgType
type_id<GetNativeEnvMsg>()
{
    return MsgType::GET_NATIVE_ENV;
}

template<>
constexpr MsgType
type_id<UseNativeEnvMsg>()
{
    return MsgType::USE_NATIVE_ENV;
}

template<>
constexpr MsgType
type_id<GetCSMsg>()
{
    return MsgType::GET_CS;
}

template<>
constexpr MsgType
type_id<UseCSMsg>()
{
    return MsgType::USE_CS;
}

template<>
constexpr MsgType
type_id<CompileFileMsg>()
{
    return MsgType::COMPILE_FILE;
}

template<>
constexpr MsgType
type_id<FileChunkMsg>()
{
    return MsgType::FILE_CHUNK;
}

template<>
constexpr MsgType
type_id<CompileResultMsg>()
{
    return MsgType::COMPILE_RESULT;
}

template<>
constexpr MsgType
type_id<JobBeginMsg>()
{
    return MsgType::JOB_BEGIN;
}

template<>
constexpr MsgType
type_id<JobDoneMsg>()
{
    return MsgType::JOB_DONE;
}

template<>
constexpr MsgType
type_id<JobLocalBeginMsg>()
{
    return MsgType::JOB_LOCAL_BEGIN;
}

template<>
constexpr MsgType
type_id<JobLocalDoneMsg>()
{
    return MsgType::JOB_LOCAL_DONE;
}

template<>
constexpr MsgType
type_id<LoginMsg>()
{
    return MsgType::LOGIN;
}

template<>
constexpr MsgType
type_id<StatsMsg>()
{
    return MsgType::STATS;
}

template<>
constexpr MsgType
type_id<MonLoginMsg>()
{
    return MsgType::MON_LOGIN;
}

template<>
constexpr MsgType
type_id<MonGetCSMsg>()
{
    return MsgType::MON_GET_CS;
}

template<>
constexpr MsgType
type_id<MonJobBeginMsg>()
{
    return MsgType::MON_JOB_BEGIN;
}

template<>
constexpr MsgType
type_id<MonJobDoneMsg>()
{
    return MsgType::MON_JOB_DONE;
}

template<>
constexpr MsgType
type_id<MonLocalJobBeginMsg>()
{
    return MsgType::MON_LOCAL_JOB_BEGIN;
}

template<>
constexpr MsgType
type_id<MonStatsMsg>()
{
    return MsgType::MON_STATS;
}

template<>
constexpr MsgType
type_id<EnvTransferMsg>()
{
    return MsgType::ENV_TRANSFER;
}

template<>
constexpr MsgType
type_id<StatusTextMsg>()
{
    return MsgType::STATUS_TEXT;
}

template<>
constexpr MsgType
type_id<GetInternalStatusMsg>()
{
    return MsgType::GET_INTERNAL_STATUS;
}

template<>
constexpr MsgType
type_id<ConfCSMsg>()
{
    return MsgType::CONF_CS;
}

template<>
constexpr MsgType
type_id<VerifyEnvMsg>()
{
    return MsgType::VERIFY_ENV;
}

template<>
constexpr MsgType
type_id<VerifyEnvResultMsg>()
{
    return MsgType::VERIFY_ENV_RESULT;
}

template<>
constexpr MsgType
type_id<BlacklistHostEnvMsg>()
{
    return MsgType::BLACKLIST_HOST_ENV;
}

template<>
constexpr MsgType
type_id<NoCSMsg>()
{
    return MsgType::NO_CS;
}

} // namespace icecream

#endif // _TYPE_ID_HH_
