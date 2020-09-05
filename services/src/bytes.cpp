#include "bytes.hh"

#include "logging.hh"

extern "C" {
#include <arpa/inet.h>
#include <lzo/lzo1x.h>
#include <zstd.h>
}

#include <algorithm>
#include <array>
#include <cassert>

namespace bytes {

namespace {

int
zstd_compression_level()
{
    const char * level = getenv("ICECC_COMPRESSION");
    if (!level || !*level)
        return ZSTD_CLEVEL_DEFAULT;

    char * endptr;
    int    n = strtol(level, &endptr, 0);
    if (*endptr)
        return ZSTD_CLEVEL_DEFAULT;
    return n;
}

} // namespace

uint32_t
compress(uint8_t *              data,
         std::size_t            size,
         std::vector<uint8_t> & out,
         CompressionMethod      method)
{
    const lzo_uint in_len = size;
    lzo_uint       out_len = [method, in_len] {
        switch (method) {
            case CompressionMethod::LZO: return in_len + in_len / 64 + 16 + 3;
            case CompressionMethod::ZSTD: return ZSTD_COMPRESSBOUND(in_len);
            default: return in_len;
        }
    }();

    // Uncompressed size
    serialize(static_cast<uint32_t>(in_len), out);

    // Placeholder for compressed size
    const auto compressed_index = out.size();
    serialize(uint32_t{0}, out);

    if (method == CompressionMethod::ZSTD) {
        serialize(static_cast<uint32_t>(method), out);
    }

    const auto old_size = out.size();
    out.resize(old_size + out_len);

    if (method == CompressionMethod::LZO) {
        std::array<uint8_t, LZO1X_MEM_COMPRESS> working_memory{};

        const int ret =
            lzo1x_1_compress(data,
                             in_len,
                             &out[old_size],
                             &out_len,
                             static_cast<lzo_voidp>(working_memory.data()));

        assert(ret == LZO_E_OK && "internal error - compression failed");
        (void)ret;

        std::cout << "LZO compressed " << in_len << " to " << out_len
                  << " bytes" << std::endl;
    } else // method == CompressionMethod::ZSTD
    {
        const size_t ret = ZSTD_compress(
            &out[old_size], out_len, data, in_len, zstd_compression_level());

        assert(!ZSTD_isError(ret) && "internal error - compression failed");
        assert(ret <= std::numeric_limits<lzo_uint>::max() &&
               "truncation error");

        out_len = ret;
        std::cout << "ZSTD compressed " << in_len << " to " << out_len
                  << " bytes" << std::endl;
    }
    out.resize(old_size + out_len);

    // Write real compressed size
    const uint32_t nbo = htonl(out_len);
    std::memcpy(&out[compressed_index], &nbo, sizeof(uint32_t));

    return out_len;
}

void
serialize(uint32_t x, std::vector<uint8_t> & out)
{
    const uint32_t nbo = htonl(x);

    const auto old_size = out.size();
    out.resize(old_size + sizeof(uint32_t));

    std::memcpy(&out[old_size], &nbo, sizeof(uint32_t));

    std::cout << "Wrote uint32_t 0x" << std::hex << x << " as NBO: 0x" << nbo
              << std::dec << std::endl;
}

void
serialize(const std::string & s, std::vector<uint8_t> & out)
{
    const auto str_size_with_null = s.size() + 1;
    serialize(static_cast<uint32_t>(str_size_with_null), out);

    const auto old_size = out.size();
    out.resize(old_size + str_size_with_null);
    // Since C++ 11 string data is guaranteed to end with a null character
    std::copy_n(s.c_str(), str_size_with_null, &out[old_size]);

    std::cout << "Wrote string \"" << s << "\" of length " << s.size() << " ("
              << str_size_with_null << " in memory)" << std::endl;
}

} // namespace bytes
