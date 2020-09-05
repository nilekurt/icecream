file(GLOB_RECURSE SRC src/*.c src/*.cpp)
file(GLOB_RECURSE INC include/*.h include/*.hh)

add_executable(compilerwrapper ${SRC} ${INC})
target_link_libraries(compilerwrapper PRIVATE copts_common)

install(TARGETS compilerwrapper DESTINATION libexec)

