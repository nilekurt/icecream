#ifndef _EXTENSIONS_HH_
#define _EXTENSIONS_HH_

#if __cplusplus >= 201703L
#include <optional>
#include <variant>
#else
#include "mpark/variant.hpp"
#include "tl/optional.hpp"
#endif // __cplusplus

namespace ext {

#if __cplusplus >= 201703L
using std::optional;
using std::make_optional;
using std::in_place;
using std::nullopt;

using std::variant;
using std::get_if;
using std::holds_alternative;
using std::in_place_type_t;
using std::monostate;
#else
using tl::optional;
using tl::make_optional;
using tl::in_place;
using tl::nullopt;

using mpark::variant;
using mpark::get_if;
using mpark::holds_alternative;
using mpark::in_place_type_t;
using mpark::monostate;
using mpark::visit;
#endif // __cplusplus

} // namespace ext

#endif // _EXTENSIONS_HH_
