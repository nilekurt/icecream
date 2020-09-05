include(FetchContent)

if(NOT ICECREAM_SYSTEM_ASIO)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
)
FetchContent_GetProperties(asio)
if (NOT asio_POPULATED)
    FetchContent_Populate(asio)

    add_library(asio INTERFACE)
    target_include_directories(asio SYSTEM
        INTERFACE $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>)
    target_compile_definitions(asio
        INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
endif()
endif() # ICECREAM_SYSTEM_ASIO
