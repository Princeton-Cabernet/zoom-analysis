
#ifndef ZOOM_ANALYSIS_UTIL_H
#define ZOOM_ANALYSIS_UTIL_H

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <stdexcept>
#include <string>
#include <string>
#include <unordered_map>
#include <vector>
#include <vector>

#include "net.h"

namespace util {

    static std::uint16_t extract_half_word(unsigned offset, const unsigned char* buf) {
        return ntohs(*((std::uint16_t*) (buf + offset)));
    }

    static std::uint32_t extract_word(unsigned offset, const unsigned char* buf) {
        return ntohl(*((std::uint32_t*) (buf + offset)));
    }

    static double seconds_since(std::chrono::time_point<std::chrono::high_resolution_clock> since) {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - since);
        return (double) duration.count() / 1000000;
    }

    static double seconds_since_epoch() {
        auto us = std::chrono::duration_cast<std::chrono::microseconds>
                (std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        return (double) us / 1e6;
    }

    template <typename HandlerFx>
    static void read_csv(const std::string& file_name, HandlerFx h, char comment = '#',
        char delim = ',') {

        std::string line, word;
        std::ifstream in;
        std::vector<std::string> words;

        in.open(file_name);

        if (!in) {
            throw std::system_error(errno, std::system_category(), "failed to open " + file_name);
        }

        while(std::getline(in, line)) {

            if (line[0] == comment || line.empty()) continue;

            std::stringstream ss(line);

            while (std::getline(ss, word, delim)) {
                words.push_back(word);
            }

            h(words);
            words.clear();
        }

        in.close();
    }

    template <typename UnsignedType>
    static inline UnsignedType str_to_unsigned(const std::string& s) {
        auto stoul_result = stoul(s, 0, 10);
        UnsignedType result = static_cast<UnsignedType>(stoul_result);
        if (result != stoul_result) throw std::out_of_range("string_to_unsigned: out of range");
        return result;
    }

    template <typename SignedType>
    static inline SignedType str_to_signed(const std::string& s) {
        auto stol_result = stol(s, 0, 10);
        SignedType result = static_cast<SignedType>(stol_result);
        if (result != stol_result) throw std::out_of_range("string_to_signed: out of range");
        return result;
    }

    /*!
     * returns list of non-hidden file paths inside a directory
     *
     * - returns list with single path entry if file name provided
     * - optionally filters by beginning of extension string (e.g., "pcap" matches "pcapX")
     */
    static std::vector<std::string> files_in_directory(const std::string& file_or_directory,
                                                const std::string& limit_ext_start = "") {

        const std::filesystem::path in_path{file_or_directory};

        std::vector<std::string> files;

        if (std::filesystem::is_regular_file(in_path)) {
            files.push_back(file_or_directory);
        } else if (std::filesystem::is_directory(in_path)) {

            for (auto const& dir_entry: std::filesystem::directory_iterator{in_path}) {

                const auto path_str = dir_entry.path().string();
                const auto extension_str = dir_entry.path().extension().string();
                const auto name_str = dir_entry.path().filename().string();

                // checks if path is regular file (no dir, links, ., .., etc.) and non-hidden
                if (dir_entry.is_regular_file() && name_str[0] != '.') {
                    if (!limit_ext_start.empty()) {
                        if (extension_str.find_first_of(limit_ext_start) != std::string::npos) {
                            files.push_back(path_str);
                        }
                    } else {
                        files.push_back(path_str);
                    }
                }
            }

            std::sort(files.begin(), files.end());

        } else {
            throw std::invalid_argument(file_or_directory +
                " is neither regular file nor directory");
        }

        return files;
    }


    /*!
     * compares numbers appended to a file extension
     *
     * - e.g., test.pcap2 < test.pcap10 (unlike lexicographical comparison)
     * - falls back to lexicographical ordering when no numeric ending found
     * - use with std::sort, e.g., std::sort(v.begin(), v.end(), util::compare_file_ext_seq)
     */
    static bool compare_file_ext_seq(const std::string& a, const std::string& b) {

        std::filesystem::path path_a{a}, path_b{b};
        auto ext_a = path_a.extension().string(), ext_b = path_b.extension().string();
        auto seq_pos_a = ext_a.find_first_of("0123456789", 0);
        auto seq_pos_b = ext_b.find_first_of("0123456789", 0);

        if (seq_pos_a != std::string::npos && seq_pos_b != std::string::npos) {
            auto seq_a = std::stoi(ext_a.substr(seq_pos_a));
            auto seq_b = std::stoi(ext_b.substr(seq_pos_b));
            return seq_a < seq_b;
        } else {
            return a < b;
        }
    };

    /*!
     * returns a reference to an unordered_map entry matching a key, inserts key if not present
     */
    template<typename KeyType, typename ValueType>
    static ValueType& get_or_add_map_entry(std::unordered_map<KeyType, ValueType>& map,
                                    const KeyType& key) {

        auto map_it = map.find(key);

        if (map_it != map.end()) {
            return map_it->second;
        } else {
            auto insert_result = map.insert({key, ValueType{}});
            return insert_result.first->second;
        }
    }

    /*!
     * Returns a string of bytes formatted as hexadecimal numbers
     * @param buf pointer to byte array
     * @param count number of bytes from beginning of buf
     */
    template<typename Byte>
    static std::string formatted_bytes(const Byte* buf, unsigned count, char delim = ' ') {

        std::stringstream ss;

        for (auto i = 0; i < count; i++)
            ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned) buf[i] << delim;

        return ss.str();
    }
}

#endif
