include(CheckCSourceCompiles)

check_c_source_compiles(
    "
    #include <string.h>
    void main()
    {
        char* result = strsignal(0);
    }
    "
    HAVE_STRSIGNAL)

check_c_source_compiles(
    "
    #include <sys/file.h>
    void main()
    {
        int result = flock(-1, LOCK_UN);
    }
    "
    HAVE_FLOCK)

check_c_source_compiles(
    "
    #include <unistd.h>
    void main()
    {
        int result = lockf(-1, F_TEST, 0);
    }
    "
    HAVE_LOCKF)

file(GLOB_RECURSE SRC src/*.c src/*.cpp)
file(GLOB_RECURSE INC include/*.h include/*.hh)

add_executable(icecc ${SRC} ${INC})
target_compile_definitions(icecc PRIVATE
    LIBEXECDIR="${CMAKE_INSTALL_PREFIX}/libexec"
    $<$<BOOL:${HAVE_STRSIGNAL}>:HAVE_STRSIGNAL>
    $<$<BOOL:${HAVE_FLOCK}>:HAVE_FLOCK>
    $<$<BOOL:${HAVE_LOCKF}>:HAVE_LOCKF>)
target_link_libraries(icecc PRIVATE copts_common icecc_la asio)

if (ICECREAM_LTO)
    set_property(TARGET icecc PROPERTY INTERPROCEDURAL_OPTIMIZATION ON)
endif()

install(TARGETS icecc DESTINATION bin)

