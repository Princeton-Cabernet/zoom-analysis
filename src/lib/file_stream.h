
#ifndef VCA_ANALYSIS_FILE_STREAM_H
#define VCA_ANALYSIS_FILE_STREAM_H

#include <fstream>

class file_stream {
public:

    file_stream() = default;

    //! opens a file in the specified openmode, throws std::runtime_error upon error
    explicit file_stream(const std::string& file_name, std::ios::openmode open_mode) {

        open(file_name, open_mode);
    }

    //! opens a file in the specified openmode, throws std::runtime_error upon error
    void open(const std::string& file_name, std::ios::openmode open_mode) {

        if (_stream.is_open())
            throw std::logic_error("file_stream: already open");

        _stream.open(file_name, open_mode);

        if (!_stream.is_open())
            throw std::runtime_error("file_stream: could not open " + file_name);
    }

    //! closes the underlying file
    virtual void close() {
        _stream.close();
    }

    //! closes the underlying file if it is open
    virtual ~file_stream() {
        if (_stream.is_open())
            _stream.close();
    }

protected:

    //! returns true if the file pointer was advanced beyond the end of the file
    bool _eof() {
        return _stream.tellg() == std::istream::pos_type(-1);
    }

    //! sets the read cursor to the beginning of the file
    void _reset() {
        _stream.clear();
        _stream.seekg(0, std::ios::beg);
    }

    std::fstream _stream;
};

#endif
