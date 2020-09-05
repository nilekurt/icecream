#ifndef _BYTES_HH_
#define _BYTES_HH_

#include <cstdint>
#include <string>
#include <vector>

namespace bytes {

enum class CompressionMethod
{
    LZO = 0,
    ZSTD = 1
};

uint32_t
compress(uint8_t *              data,
         std::size_t            size,
         std::vector<uint8_t> & out,
         CompressionMethod      method);

void
serialize(uint32_t x, std::vector<uint8_t> & out);

void
serialize(const std::string & s, std::vector<uint8_t> & out);

template<typename T, typename U>
inline void
serialize(const std::pair<T, U> & p, std::vector<uint8_t> & out)
{
    serialize(p.first, out);
    serialize(p.second, out);
}

template<typename Iterator>
inline void
serialize(Iterator && begin, Iterator && end, std::vector<uint8_t> & out)
{
    auto n_elements = std::distance(begin, end);
    serialize(static_cast<uint32_t>(n_elements), out);

    for (Iterator it = begin; it != end; ++it) {
        serialize(*it, out);
    }
}

} // namespace bytes

#endif // _BYTES_HH_
