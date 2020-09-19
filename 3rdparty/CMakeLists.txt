include(FetchContent)

FetchContent_Declare(
    tl_optional
    GIT_REPOSITORY https://github.com/TartanLlama/optional.git
)
FetchContent_GetProperties(tl_optional)
if (NOT tl_optional_POPULATED)
    FetchContent_Populate(tl_optional)

    add_library(tl_optional INTERFACE)
    target_include_directories(tl_optional SYSTEM
        INTERFACE $<BUILD_INTERFACE:${tl_optional_SOURCE_DIR}/include>)
endif()

set(mpark_variant_DOWNLOAD_DIR "${PROJECT_BINARY_DIR}/_deps/mpark_variant-download")
FetchContent_Declare(
    mpark_variant
    URL                 https://github.com/mpark/variant/releases/download/v1.4.0/variant.hpp
    URL_MD5             867d90d63f53b8406f5c8adbab1db2bf
    DOWNLOAD_NO_EXTRACT TRUE
    DOWNLOAD_DIR        ${mpark_variant_DOWNLOAD_DIR}
)
FetchContent_GetProperties(mpark_variant)
if (NOT mpark_variant_POPULATED)
    FetchContent_Populate(mpark_variant)

    file(COPY ${mpark_variant_DOWNLOAD_DIR}/variant.hpp
         DESTINATION ${mpark_variant_SOURCE_DIR}/mpark)
    add_library(mpark_variant INTERFACE)
    target_include_directories(mpark_variant SYSTEM
        INTERFACE $<BUILD_INTERFACE:${mpark_variant_SOURCE_DIR}>)
endif()
