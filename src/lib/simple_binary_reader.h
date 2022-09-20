
#include <vector>
#include <filesystem>

#ifndef ZOOM_ANALYSIS_SIMPLE_BINARY_READER_H
#define ZOOM_ANALYSIS_SIMPLE_BINARY_READER_H

#include "file_stream.h"

template <typename T>
class simple_binary_reader : public file_stream
{
public:
    explicit simple_binary_reader(const std::string& file_name, bool use_buffer = false)
            : file_stream(file_name, std::ios::binary | std::ios::in),
              _file_name(file_name),
              _use_buffer(use_buffer),
              _data() {
        T t;

        if (_use_buffer) {
            while (!_eof()) {
                _stream.read((char*) &t, sizeof(T));
                _data.push_back(t);
            }
            _iter = std::begin(_data);
        }
    }

    bool next(T& t) {

        if (_count == 0)
            _start = std::chrono::high_resolution_clock::now();

        if (_use_buffer)
            t = *(_iter++);
        else
            _stream.read((char*) &t, sizeof(T));

        if (done())
            return false;

        _count++;
        return true;
    }

    [[nodiscard]] unsigned long size() const {
        return (unsigned long)
            std::filesystem::file_size(std::filesystem::path(_file_name)) / sizeof(T);
    }

    [[nodiscard]] unsigned long count() const {
        return _count;
    }

    [[nodiscard]] double time_in_loop() {

        if (!done()) {
            auto now = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now - _start);
            return (double) duration.count() / 1000000;
        }

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(_end - _start);
        return (double) duration.count() / 1000000;
    }

    void reset() {
        if (_use_buffer)
            _iter = std::begin(_data);
        else
            _reset();
    }

    bool done() {

        if (_use_buffer) {
            if (_iter == _data.end()) {
                _end = std::chrono::high_resolution_clock::now();
                return true;
            }
        } else {
            if (_eof()) {
                _end = std::chrono::high_resolution_clock::now();
                return true;
            }
        }

        return false;
    }

    ~simple_binary_reader() override = default;

private:
    std::string _file_name;
    bool _use_buffer;
    std::vector<T> _data;
    typename std::vector<T>::const_iterator _iter;
    unsigned long _count = 0;
    std::chrono::high_resolution_clock::time_point _start, _end;
};

#endif
