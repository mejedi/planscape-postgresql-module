#pragma once

#include <sys/types.h>
#include <vector>
#include <string>

class Symboliser
{
    Symboliser(const Symboliser &) = delete;
    void operator = (const Symboliser &) = delete;
public:
    Symboliser(const std::string &path, const void *base);
    ~Symboliser();

    // Extract debug info for the given address 
    void symbolise(const void *addr);

    // Access attributes filled by symbolise().
    const char *get_fn_name() const { return m_fn_name; }
    const char *get_src_file_name() const { return m_src_file_name; }
    int get_line_number() const { return m_line_number; }

    // Advance to next tuple describing the address produced by
    // symbolise(). Hint: inlining.
    bool next();

private:
    void reset_attrs();
    void launch_helper(const std::string &binary_path);
    void shutdown_helper();
    bool communicate(const void *addr);
    bool parse_next();

    const void * const m_base;
    pid_t              m_helper_pid;
    int                m_helper_socket;
    std::vector<char>  m_response_buffer;
    char *             m_parse;
    const char *       m_fn_name;
    const char *       m_src_file_name;
    int                m_line_number;
};
