#ifndef ZOOM_ANALYSIS_RING_BUFFER_H
#define ZOOM_ANALYSIS_RING_BUFFER_H

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <stdexcept>
#include <vector>

template<typename Type>
class ring_buffer {
public:

    explicit ring_buffer(std::size_t size)
        : _ring(size), _size(size) {

        if (!_is_power_of_two(size)) {
            throw std::invalid_argument("ring_buffer::ring_buffer(): size must be power of two");
        }
    }

    ring_buffer(const ring_buffer& copy_from) = default;
    ring_buffer& operator=(const ring_buffer&) = default;
    ring_buffer(ring_buffer&&) noexcept = default;
    ring_buffer& operator=(ring_buffer&&) noexcept = default;

    bool push(const Type& item) {

        if (full()) return false;

        _ring[_tail] = item;
        _tail = _increment(_tail);
        return true;
    }

    bool pop(Type& item) {

        if (empty()) return false;

        item = _ring[_head];
        _head = _increment(_head);
        return true;
    }

    bool pop() {

        if (empty()) return false;

        _head = _increment(_head);
        return true;
    }

    [[nodiscard]] const Type& peek() const {

        if (empty())
            throw std::logic_error("ring_buffer::peek(): ring is empty");

        return _ring[_head];
    }

    [[nodiscard]] inline std::size_t size() const {
        return _size;
    }

    [[nodiscard]] inline std::size_t count() const {
        return (_size - _head + _tail) & (_size - 1);
    }

    [[nodiscard]] inline bool full() const {
        return _increment(_tail) == _head;
    }

    [[nodiscard]] inline bool empty() const {
        return _head == _tail;
    }

    ~ring_buffer() = default;

private:

    [[nodiscard]] inline static bool _is_power_of_two(std::size_t x) {
        return (x != 0) && ((x & (x - 1)) == 0);
    }

    [[nodiscard]] inline std::size_t _increment(std::size_t i) const {
        return (++i) & (_size - 1);
    }

    std::vector<Type> _ring;
    std::size_t _size = 0, _head = 0, _tail = 0;
};

#endif
