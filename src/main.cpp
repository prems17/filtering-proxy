// Filtering HTTP/HTTPS forward proxy
// Build: g++ -std=c++17 -pthread src/main.cpp -o proxy
// Run:   ./proxy [port] [blocklist file]     (defaults: 8888, blocklist.txt)

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

static const int    NUM_WORKERS      = 8;      // fixed-size thread pool
static const int    SOCKET_TIMEOUT_S = 10;     // recv/send/connect timeout
static const int    TUNNEL_IDLE_MS   = 30000;  // idle limit for CONNECT tunnels
static const size_t MAX_HEADER_BYTES = 16384;  // reject oversized headers

// ---------------------------------------------------------------- logging
static std::mutex g_log_mutex;
static std::ofstream g_log_file;

static void log_decision(const std::string& client_ip, const std::string& method,
                         const std::string& host, const std::string& decision) {
    char ts[32];
    time_t now = time(nullptr);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    std::lock_guard<std::mutex> lock(g_log_mutex);  // one line at a time across threads
    std::string line = std::string(ts) + " | " + client_ip + " | " + method + " | " + host + " | " + decision;
    std::cout << line << std::endl;
    if (g_log_file.is_open()) g_log_file << line << std::endl;
}

// ----------------------------------------------------------- policy engine
static std::set<std::string> g_blocklist;  // read-only after startup, so no lock needed

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static void load_blocklist(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        std::cerr << "Warning: could not open " << path << " (nothing will be blocked)\n";
        return;
    }
    std::string line;
    while (std::getline(in, line)) {
        // trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty() || line[0] == '#') continue;
        g_blocklist.insert(to_lower(line));
    }
    std::cout << "Loaded " << g_blocklist.size() << " blocked domains\n";
}

// Blocks "evil.com" and also any subdomain such as "www.evil.com".
static bool is_blocked(const std::string& host_in) {
    std::string host = to_lower(host_in);
    while (true) {
        if (g_blocklist.count(host)) return true;
        size_t dot = host.find('.');
        if (dot == std::string::npos) return false;
        host = host.substr(dot + 1);
    }
}

// ------------------------------------------------------------ socket helpers
static void set_timeouts(int fd, int seconds) {
    struct timeval tv{seconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// send() may write only part of the buffer, so loop until everything is sent.
static bool send_all(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;  // reset, timeout, or closed
        sent += (size_t)n;
    }
    return true;
}
static bool send_all(int fd, const std::string& s) { return send_all(fd, s.data(), s.size()); }

static void send_error(int fd, int code, const std::string& text) {
    std::string body = std::to_string(code) + " " + text + "\n";
    std::string resp = "HTTP/1.1 " + std::to_string(code) + " " + text +
                       "\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(body.size()) +
                       "\r\nConnection: close\r\n\r\n" + body;
    send_all(fd, resp);
}

static int connect_to_origin(const std::string& host, const std::string& port) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        set_timeouts(fd, SOCKET_TIMEOUT_S);  // SO_SNDTIMEO also bounds connect()
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// Reads until the blank line that ends the HTTP headers. TCP is a byte stream,
// so one recv() can return half a request; keep reading until "\r\n\r\n".
static bool read_headers(int fd, std::string& buf, size_t& header_end) {
    char tmp[4096];
    while (true) {
        size_t pos = buf.find("\r\n\r\n");
        if (pos != std::string::npos) { header_end = pos + 4; return true; }
        if (buf.size() > MAX_HEADER_BYTES) return false;
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;  // closed, reset, or timed out
        buf.append(tmp, (size_t)n);
    }
}

// ------------------------------------------------------------ request parsing
struct Request {
    std::string method, target, version;
    std::vector<std::pair<std::string, std::string>> headers;
};

static bool parse_request(const std::string& head, Request& req) {
    std::istringstream in(head);
    std::string line;
    if (!std::getline(in, line)) return false;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream rl(line);
    if (!(rl >> req.method >> req.target >> req.version)) return false;

    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        req.headers.push_back({name, value});
    }
    return true;
}

static std::string get_header(const Request& req, const std::string& name) {
    for (auto& h : req.headers)
        if (to_lower(h.first) == to_lower(name)) return h.second;
    return "";
}

// "host:port" -> host, port (handles [ipv6]:port too)
static void split_host_port(const std::string& hp, const std::string& default_port,
                            std::string& host, std::string& port) {
    if (!hp.empty() && hp[0] == '[') {
        size_t end = hp.find(']');
        host = hp.substr(1, end - 1);
        port = (end != std::string::npos && end + 2 <= hp.size() && hp[end + 1] == ':')
                   ? hp.substr(end + 2) : default_port;
        return;
    }
    size_t colon = hp.rfind(':');
    if (colon == std::string::npos) { host = hp; port = default_port; }
    else { host = hp.substr(0, colon); port = hp.substr(colon + 1); }
}

// ---------------------------------------------------------- CONNECT tunneling
// After "200 Connection Established" we just copy bytes both ways. The data is
// TLS-encrypted, so the proxy never sees the URL path or content.
static void tunnel(int client, int origin) {
    struct pollfd fds[2] = {{client, POLLIN, 0}, {origin, POLLIN, 0}};
    char buf[8192];
    while (true) {
        int r = poll(fds, 2, TUNNEL_IDLE_MS);
        if (r <= 0) return;  // idle timeout or error
        for (int i = 0; i < 2; i++) {
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t n = recv(fds[i].fd, buf, sizeof(buf), 0);
                if (n <= 0) return;
                if (!send_all(fds[1 - i].fd, buf, (size_t)n)) return;
            }
        }
    }
}

// ------------------------------------------------------------ client handler
static void handle_client(int client, const std::string& client_ip) {
    set_timeouts(client, SOCKET_TIMEOUT_S);

    std::string buf;
    size_t header_end = 0;
    if (!read_headers(client, buf, header_end)) { send_error(client, 400, "Bad Request"); return; }

    Request req;
    if (!parse_request(buf.substr(0, header_end), req)) { send_error(client, 400, "Bad Request"); return; }

    // ---- HTTPS: CONNECT host:port ----
    if (req.method == "CONNECT") {
        std::string host, port;
        split_host_port(req.target, "443", host, port);

        if (is_blocked(host)) {
            log_decision(client_ip, "CONNECT", host, "BLOCK");
            send_error(client, 403, "Forbidden");
            return;
        }
        int origin = connect_to_origin(host, port);
        if (origin < 0) {
            log_decision(client_ip, "CONNECT", host, "ALLOW (origin unreachable)");
            send_error(client, 502, "Bad Gateway");
            return;
        }
        log_decision(client_ip, "CONNECT", host, "ALLOW");
        send_all(client, "HTTP/1.1 200 Connection Established\r\n\r\n");
        tunnel(client, origin);
        close(origin);
        return;
    }

    // ---- Plain HTTP: request target is an absolute URL (http://host/path) ----
    std::string host, port, path;
    const std::string prefix = "http://";
    if (req.target.compare(0, prefix.size(), prefix) == 0) {
        std::string rest = req.target.substr(prefix.size());
        size_t slash = rest.find('/');
        std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
        path = (slash == std::string::npos) ? "/" : rest.substr(slash);
        split_host_port(hostport, "80", host, port);
    } else {
        // A real proxy client always sends an absolute URL. A bare path like "GET /" means
        // someone opened the proxy port directly (e.g. a browser or port-forwarding check).
        // Forwarding it would make the proxy connect to itself in a loop, so reject it.
        send_error(client, 400, "This is a proxy server. Configure your client to use it as an HTTP proxy.");
        return;
    }
    if (host.empty()) { send_error(client, 400, "Bad Request"); return; }

    if (is_blocked(host)) {
        log_decision(client_ip, req.method, host, "BLOCK");
        send_error(client, 403, "Forbidden");
        return;
    }

    int origin = connect_to_origin(host, port);
    if (origin < 0) {
        log_decision(client_ip, req.method, host, "ALLOW (origin unreachable)");
        send_error(client, 502, "Bad Gateway");
        return;
    }
    log_decision(client_ip, req.method, host, "ALLOW");

    // Rebuild the request: origin-form path, drop proxy-only headers, close after response.
    std::string out = req.method + " " + path + " HTTP/1.1\r\n";
    bool has_host = false;
    for (auto& h : req.headers) {
        std::string n = to_lower(h.first);
        if (n == "proxy-connection" || n == "connection" || n == "proxy-authorization") continue;
        if (n == "host") has_host = true;
        out += h.first + ": " + h.second + "\r\n";
    }
    if (!has_host) out += "Host: " + host + "\r\n";
    out += "Connection: close\r\n\r\n";
    if (!send_all(origin, out)) { send_error(client, 502, "Bad Gateway"); close(origin); return; }

    // Forward the request body (e.g. POST) using Content-Length.
    std::string cl = get_header(req, "Content-Length");
    if (!cl.empty()) {
        long total = std::strtol(cl.c_str(), nullptr, 10);
        std::string already = buf.substr(header_end);  // body bytes that arrived with the headers
        if (!already.empty() && !send_all(origin, already)) { close(origin); return; }
        long remaining = total - (long)already.size();
        char tmp[8192];
        while (remaining > 0) {
            ssize_t n = recv(client, tmp, std::min<long>(sizeof(tmp), remaining), 0);
            if (n <= 0) { close(origin); return; }
            if (!send_all(origin, tmp, (size_t)n)) { close(origin); return; }
            remaining -= n;
        }
    }

    // Relay the response until the origin closes. Because we sent "Connection: close",
    // EOF marks the end, so Content-Length and chunked encoding pass through untouched.
    char tmp[8192];
    while (true) {
        ssize_t n = recv(origin, tmp, sizeof(tmp), 0);
        if (n <= 0) break;  // EOF, reset, or timeout
        if (!send_all(client, tmp, (size_t)n)) break;
    }
    close(origin);
}

// --------------------------------------------------------------- thread pool
struct Job { int fd; std::string ip; };
static std::queue<Job> g_jobs;
static std::mutex g_jobs_mutex;
static std::condition_variable g_jobs_cv;

static void worker() {
    while (true) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(g_jobs_mutex);
            g_jobs_cv.wait(lock, [] { return !g_jobs.empty(); });
            job = g_jobs.front();
            g_jobs.pop();
        }
        handle_client(job.fd, job.ip);
        close(job.fd);
    }
}

// ---------------------------------------------------------------------- main
int main(int argc, char* argv[]) {
    int port = (argc > 1) ? std::atoi(argv[1]) : 8888;
    std::string blocklist_path = (argc > 2) ? argv[2] : "blocklist.txt";

    signal(SIGPIPE, SIG_IGN);  // writing to a closed socket must not kill the proxy
    load_blocklist(blocklist_path);
    g_log_file.open("proxy.log", std::ios::app);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(server, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server, 128) < 0) { perror("listen"); return 1; }

    std::vector<std::thread> pool;
    for (int i = 0; i < NUM_WORKERS; i++) pool.emplace_back(worker);
    std::cout << "Proxy listening on port " << port << " with " << NUM_WORKERS << " workers\n";

    while (true) {
        sockaddr_in caddr{};
        socklen_t clen = sizeof(caddr);
        int client = accept(server, (sockaddr*)&caddr, &clen);
        if (client < 0) continue;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));
        {
            std::lock_guard<std::mutex> lock(g_jobs_mutex);
            g_jobs.push({client, ip});
        }
        g_jobs_cv.notify_one();
    }
}
