#ifndef _VARIANT_HH_
#define _VARIANT_HH_

#if __cplusplus >= 201703L
#include <variant>
#else
#include "mpark/variant.hpp"
#endif // __cplusplus

namespace ext {

#if __cplusplus >= 201703L
using std::variant;
using std::get_if;
using std::holds_alternative;
using std::in_place_type_t;
using std::monostate;
#else
using mpark::variant;
using mpark::get_if;
using mpark::holds_alternative;
using mpark::in_place_type_t;
using mpark::monostate;
using mpark::visit;
#endif // __cplusplus

} // namespace ext

#endif // _VARIANT_HH_
