add_library(extensions INTERFACE)
target_include_directories(extensions
    INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(extensions INTERFACE mpark_variant tl_optional)
