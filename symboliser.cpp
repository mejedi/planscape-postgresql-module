#include "symboliser.h"

#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <spawn.h>
#include <inttypes.h>
#include <cstring>

void Symboliser::reset_attrs()
{
    m_fn_name = "??";
    m_src_file_name = "??";
    m_line_number = 0;
    m_parse = nullptr;
}

void Symboliser::launch_helper(const std::string &binary_path)
{
    static char                helper_cmd[] = "/usr/bin/addr2line";
    static char                helper_flags[] = "-aCfsie";
    // Flags breakdown:
    //  -a relay offset to describe back, see Symboliser::communicate()
    //     for rationale; 
    //  -C demangle C++ names;
    //  -f print function names;
    //  -s reduce source file path to a basename;
    //  -i produce info on inlined functions;
    //  -e <PATH>
    //     binary file path.

    int                        sockets[2];
    struct timeval             timeout = {};
    posix_spawn_file_actions_t file_actions;
    char *                     helper_argv[] =
    {
        helper_cmd,
        helper_flags,
        const_cast<char *>(binary_path.c_str()),
        nullptr
    };
    char *                     helper_env[] = { nullptr };
    pid_t                      helper_pid;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return;

    if (fcntl(sockets[0], F_SETFL, O_CLOEXEC) != 0
        || fcntl(sockets[1], F_SETFL, O_CLOEXEC) != 0)
        goto cleanup_sockets;

    // Set 200ms send/receive timeout.
    timeout.tv_usec = 200000;

    if (setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) != 0)
        goto cleanup_sockets;

    if (setsockopt(sockets[0], SOL_SOCKET, SO_SNDTIMEO,
                      &timeout, sizeof(timeout)) != 0)
        goto cleanup_sockets;

    // Init file_actions.
    if (posix_spawn_file_actions_init(&file_actions) != 0)
        goto cleanup_sockets;

    if (posix_spawn_file_actions_adddup2(&file_actions,
                                         sockets[1], STDIN_FILENO) != 0
        || posix_spawn_file_actions_adddup2(&file_actions,
                                            sockets[1], STDOUT_FILENO) != 0)
        goto cleanup;

    // Finally, spawn helper process.
    if (0 == posix_spawn(&helper_pid, helper_cmd,
                         &file_actions, nullptr, helper_argv, helper_env))
    {
        posix_spawn_file_actions_destroy(&file_actions);
        close(sockets[1]);
        m_helper_pid = helper_pid;
        m_helper_socket = sockets[0];
        return;
    }

cleanup:
    posix_spawn_file_actions_destroy(&file_actions);
cleanup_sockets:
    close(sockets[0]);
    close(sockets[1]);
}

void Symboliser::shutdown_helper()
{
    if (m_helper_pid != 0) {
        kill(m_helper_pid, SIGKILL);
        waitpid(m_helper_pid, nullptr, 0);
        m_helper_pid = 0;
    }

    if (m_helper_socket != -1) {
        close(m_helper_socket);
        m_helper_socket = -1;
    }

    reset_attrs();
}

bool Symboliser::communicate(const void *addr)
{
    // addr2line gets next offset to describe from STDIN.
    // The number of lines produced may vary depending on the inlined
    // functions.  To facilitate parsing, we submit 2 requests:
    // the offset we care about, followed by offset 0.
    //
    // We use the response to the second request, which is always the
    // same, as the separator to look for.  It is essential that the
    // offset to describe is relayed back.
    static const char terminator[] = {
        '0', 'x',
        '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0',
        '\n', '?', '?', '\n', '?', '?', ':', '0', '\n'
    };

    int request_len;
    char request_buf[32];

    request_len = sprintf(request_buf, "%" PRIxPTR"\n0\n",
                          reinterpret_cast<uintptr_t>(addr) -
                          reinterpret_cast<uintptr_t>(m_base));

    assert(request_len > 0);

    // Prevent SIGPIPE if the helper was terminated (someone kill-ed it
    // externally.)
    if (send(m_helper_socket, request_buf, request_len, MSG_NOSIGNAL)
        != request_len)
    {
        return false;
    }

    auto &response_buf = m_response_buffer;
    size_t response_size = 0;

    while (true) {

        ssize_t packet_size = 128;

        if (response_buf.size() < response_size + packet_size) {
            response_buf.resize(response_size + packet_size);
        }

        packet_size = recv(m_helper_socket,
                           &response_buf[response_size], packet_size,
                           0);

        if (packet_size < 0) {
            if (errno == EINTR) continue;
            return false;
        }

        response_size += packet_size;

        // Look for terminator.
        if (response_size >= sizeof(terminator) &&
            memcmp(&response_buf[response_size - sizeof terminator],
                   terminator, sizeof terminator) == 0)
        {
            response_buf[response_size - sizeof terminator] = '\0';
            // Skip the 'relayed offset' part.
            m_parse = strchr(&response_buf[0], '\n');
            if (m_parse)
                m_parse ++;
            return true;
        }

        // EOF
        if (packet_size == 0)
            return false;
    }
}

void Symboliser::symbolise(const void *addr)
{
    if (!communicate(addr) || !parse_next())
        shutdown_helper();
}

bool Symboliser::parse_next()
{
    if (!m_parse)
        return false;

    m_fn_name = m_parse;
    m_parse = strchr(m_parse, '\n');
    if (!m_parse)
        return false;

    *m_parse = 0;
    auto *src_file_name = m_parse + 1;
    m_parse = strchr(m_parse + 1, '\n');
    if (!m_parse)
        return false;

    *m_parse = 0; m_parse++;

    m_src_file_name = src_file_name;
    m_line_number = 0;
    char *p = strchr(src_file_name, ':');
    if (p) {
        *p = 0;
        sscanf(p+1, "%d", &m_line_number);
    }

    return true;
}

bool Symboliser::next()
{
    if (!parse_next()) {
        reset_attrs();
        return false;
    }
    return true;
}

Symboliser::Symboliser(const std::string &binary_path, const void *base) :
    m_base(base),
    m_helper_pid(0),
    m_helper_socket(-1)
{
    reset_attrs();
    launch_helper(binary_path);
}

Symboliser::~Symboliser()
{
    shutdown_helper();
}
