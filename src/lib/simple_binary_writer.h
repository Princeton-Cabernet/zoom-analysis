#ifndef ZOOM_ANALYSIS_SIMPLE_BINARY_WRITER_H
#define ZOOM_ANALYSIS_SIMPLE_BINARY_WRITER_H

#include "file_stream.h"

template <typename T>
class simple_binary_writer : public file_stream {
public:

    simple_binary_writer() = default;

    explicit simple_binary_writer(const std::string& file_name)
        : file_stream(file_name, std::ios::binary | std::ios::out) { }

    void open(const std::string& file_name) {
        file_stream::open(file_name, std::ios::binary | std::ios::out);
    }

    //! writes t to the file
    void write(const T& t) {
        _stream.write((char*) &t, sizeof(T));
        _count++;
    }

    //! returns number of entries written so far
    [[nodiscard]] unsigned long count() const {
        return _count;
    }

private:
    unsigned long _count = 0;
};

#endif
