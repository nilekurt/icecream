#ifndef _STRING_VIEW_HH_
#define _STRING_VIEW_HH_

#include <limits>
#include <string>

namespace ext {
template<typename CharT, typename Traits = std::char_traits<CharT>>
struct basic_string_view {
    using traits_type = Traits;
    using value_type = CharT;

    using pointer = CharT *;
    using const_pointer = CharT const *;
    using reference = CharT &;
    using const_reference = CharT const &;

    using iterator = const_pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<const_iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    static constexpr size_type npos = std::numeric_limits<size_type>::max();

    constexpr basic_string_view() = default;

    constexpr basic_string_view(const basic_string_view & other) = default;

    constexpr basic_string_view(basic_string_view && other) = delete;

    explicit constexpr basic_string_view(std::basic_string<CharT> & s) noexcept
        : data_{&s[0]}, size_{s.size()}
    {
    }

    template<std::size_t N>
    explicit constexpr basic_string_view(CharT s[N]) noexcept
        : data_{&s[0]}, size_{N}
    {
    }

    explicit constexpr basic_string_view(CharT * s) noexcept
        : data_{s}, size_{std::strlen(s)}
    {
    }

    constexpr basic_string_view(CharT * s, size_type size) noexcept
        : data_{s}, size_{size}
    {
    }

    constexpr basic_string_view &
    operator=(const basic_string_view & other) = default;

    constexpr basic_string_view &
    operator=(basic_string_view && other) = delete;

    constexpr const_reference
    operator[](size_type i) const noexcept
    {
        return data_[i];
    }

    const_reference
    at(size_type i) const
    {
        if (i >= size_) {
            throw std::out_of_range{};
        }

        return data_[i];
    }

    constexpr std::basic_string<CharT>
    to_str() const noexcept
    {
        return {data_, data_ + size_};
    }

    constexpr bool
    operator==(const std::basic_string<CharT> & s) const noexcept
    {
        return s.compare(s, 0, size_) == 0;
    }

    constexpr bool
    operator==(basic_string_view other) const noexcept
    {
        return compare(other) == 0;
    }

    constexpr basic_string_view
    substr(size_type pos = 0, size_type n = npos) const
    {
        if (pos > size()) {
            throw std::out_of_range("nonstd::string_view::substr()");
        }
        return {data_ + pos, std::min(n, size_ - pos)};
    }

    constexpr int
    compare(basic_string_view other)
    {
        int sub_result =
            Traits::compare(data_, other.data_, std::min(size_, other.size_));

        return sub_result != 0
                   ? sub_result
                   : ((size_ == other.size_) ? 0
                                             : (size_ < other.size_ ? -1 : 1));
    }

    constexpr size_type
    size() const noexcept
    {
        return size_;
    }

    constexpr const_pointer
    data() const noexcept
    {
        return data_;
    }

    constexpr const_iterator
    begin() const noexcept
    {
        return data_;
    }
    constexpr const_iterator
    end() const noexcept
    {
        return data_ + size_;
    }

    constexpr const_iterator
    cbegin() const noexcept
    {
        return begin();
    }
    constexpr const_iterator
    cend() const noexcept
    {
        return end();
    }

private:
    pointer   data_;
    size_type size_;
};

using string_view = basic_string_view<char>;

} // namespace ext

#endif // _STRING_VIEW_HH_
