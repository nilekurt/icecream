#ifndef _MAKE_ARRAY_HH_
#define _MAKE_ARRAY_HH_

#include <cstdint>

namespace ext {

namespace detail {

template<typename T, std::size_t N, std::size_t... Is>
constexpr std::array<std::decay_t<T>, N>
    make_array_impl(T(&&vals)[N], std::index_sequence<Is...>)
{
    return {std::forward<decltype(vals[0])>(vals[Is])...};
}

} // namespace detail

template<typename T, std::size_t N>
constexpr auto make_array(T(&&vals)[N])
{
    return detail::make_array_impl(std::forward<decltype(vals)>(vals),
                                   std::make_index_sequence<N>{});
}

} // namespace ext

#endif // _MAKE_ARRAY_HH_
