include(CheckIncludeFile)

check_include_file(arpa/nameser.h HAVE_ARPA_NAMESER_H)
check_include_file(devstat.h HAVE_DEVSTAT_H)
check_include_file(kinfo.h HAVE_KINFO_H)
check_include_file(mach/host_info.h HAVE_MACH_HOST_INFO_H)
check_include_file(resolv.h HAVE_RESOLV_H)
check_include_file(sys/param.h HAVE_SYS_PARAM_H)
check_include_file(sys/signal.h HAVE_SYS_SIGNAL_H)
check_include_file(sys/user.h HAVE_SYS_USER_H)
check_include_file(sys/vfs.h HAVE_SYS_VFS_H)

add_executable(iceccd
    src/environment.cpp
    src/file_util.cpp
    src/load.cpp
    src/main.cpp
    src/serve.cpp
    src/workit.cpp)
target_compile_definitions(iceccd PRIVATE
    $<$<BOOL:${HAVE_ARPA_NAMESER_H}>:HAVE_ARPA_NAMESER_H>
    $<$<BOOL:${HAVE_DEVSTAT_H}>:HAVE_DEVSTAT_H>
    $<$<BOOL:${HAVE_KINFO_H}>:HAVE_KINFO_H>
    $<$<BOOL:${HAVE_MACH_HOST_INFO_H}>:HAVE_MACH_HOST_INFO_H>
    $<$<BOOL:${HAVE_RESOLV_H}>:HAVE_RESOLV_H>
    $<$<BOOL:${HAVE_SYS_PARAM_H}>:HAVE_SYS_PARAM_H>
    $<$<BOOL:${HAVE_SYS_SIGNAL_H}>:HAVE_SYS_SIGNAL_H>
    $<$<BOOL:${HAVE_SYS_USER_H}>:HAVE_SYS_USER_H>
    $<$<BOOL:${HAVE_SYS_VFS_H}>:HAVE_SYS_VFS_H>)
target_link_libraries(iceccd PRIVATE copts_common copts_pic icecc_la -larchive)