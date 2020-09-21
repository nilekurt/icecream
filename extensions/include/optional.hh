#ifndef _OPTIONAL_HH_
#define _OPTIONAL_HH_

#if __cplusplus >= 201703L
#include <optional>
#else
#include "tl/optional.hpp"
#endif // __cplusplus

namespace ext {

#if __cplusplus >= 201703L
using std::optional;
using std::make_optional;
using std::in_place;
using std::nullopt;
#else
using tl::optional;
using tl::make_optional;
using tl::in_place;
using tl::nullopt;
#endif // __cplusplus

} // namespace ext

#endif // _OPTIONAL_HH_
