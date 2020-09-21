#ifndef _VISITOR_HH_
#define _VISITOR_HH_

namespace ext {

namespace detail {

template<typename... Ts>
struct Visitor;

template<typename T, typename... Ts>
struct Visitor<T, Ts...> : T, Visitor<Ts...> {

    Visitor(T && t, Ts &&... remaining)
        : T(std::forward<T>(t)), Visitor<Ts...>(std::forward<Ts>(remaining)...)
    {
    }

    using T::             operator();
    using Visitor<Ts...>::operator();
};

template<typename T>
struct Visitor<T> : T {
    explicit Visitor(T && t) : T(std::forward<T>(t)) {}

    using T::operator();
};

} // namespace detail

template<typename... Ts>
inline auto
make_visitor(Ts &&... ts) -> detail::Visitor<Ts...>
{
    return detail::Visitor<Ts...>(std::forward<Ts>(ts)...);
}

} // namespace ext

#endif // _VISITOR_HH_
