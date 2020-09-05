file(GLOB_RECURSE SRC src/*.cpp src/*.c)
file(GLOB_RECURSE INC include/*.h)

add_executable(compilerwrapper ${SRC} ${INC})
target_link_libraries(compilerwrapper PRIVATE copts_common)

install(TARGETS compilerwrapper DESTINATION libexec)

