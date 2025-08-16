// SPDX-License-Identifier: MIT
// thecube app-launcher: connect to CORE, fetch spec, apply Landlock, exec app.

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/landlock.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <optional>
#include <algorithm>

// Single-header JSON (vendor this file in your repo as external/json.hpp)
#include "nlohmann/json.hpp"
using nlohmann::json;

// ---------- Build-time knobs ----------
static constexpr const char* CORE_SOCK_PATH = "/run/thecube/core.sock";
static constexpr size_t MAX_MSG = 64 * 1024;

// ---------- Small utils ----------
[[noreturn]] static void die(const char* where) {
    std::perror(where);
    std::exit(1);
}
static void diex(const char* msg) {
    std::fprintf(stderr, "error: %s\n", msg);
    std::exit(1);
}
static bool path_exists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

// ---------- Landlock helpers (unprivileged) ----------
static int ll_sys_create_ruleset(const struct landlock_ruleset_attr* attr, size_t size, __u32 flags) {
#ifdef SYS_landlock_create_ruleset
    return (int)syscall(SYS_landlock_create_ruleset, attr, size, flags);
#else
    errno = ENOSYS; return -1;
#endif
}
static int ll_sys_add_rule(int ruleset_fd, enum landlock_rule_type type, const void* rule_attr, __u32 flags) {
#ifdef SYS_landlock_add_rule
    return (int)syscall(SYS_landlock_add_rule, ruleset_fd, type, rule_attr, flags);
#else
    errno = ENOSYS; return -1;
#endif
}
static int ll_sys_restrict_self(int ruleset_fd, __u32 flags) {
#ifdef SYS_landlock_restrict_self
    return (int)syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
#else
    errno = ENOSYS; return -1;
#endif
}

struct Landlock {
    bool supported = false;
    __u64 handled = 0;             // bitmask of actions we’ll enforce
    int ruleset_fd = -1;

    // Initialize a ruleset that covers common FS ops (RO/RW, dir create/remove, exec).
    void init() {
        // Probe ABI (optional: use LANDLOCK_CREATE_RULESET_VERSION to get ABI)
        struct landlock_ruleset_attr probe{};
        int fd = ll_sys_create_ruleset(&probe, sizeof(probe), LANDLOCK_CREATE_RULESET_VERSION);
        if (fd < 0 && errno == ENOSYS) { supported = false; return; }
        if (fd >= 0) close(fd); // only a probe

        // Choose the set of actions we intend to handle.
        handled =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_CHAR |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM |
            LANDLOCK_ACCESS_FS_TRUNCATE;

        struct landlock_ruleset_attr attr{};
        attr.handled_access_fs = handled;

        ruleset_fd = ll_sys_create_ruleset(&attr, sizeof(attr), 0);
        if (ruleset_fd < 0) { supported = false; return; }
        supported = true;
    }

    // Add a PATH_BENEATH rule for a directory with allowed mask.
    void allow_dir(const std::string& dir, __u64 allow_mask) {
        if (!supported) return;
        int dfd = open(dir.c_str(), O_PATH | O_CLOEXEC);
        if (dfd < 0) die(("open " + dir).c_str());

        struct landlock_path_beneath_attr pb{};
        pb.parent_fd = dfd;
        pb.allowed_access = allow_mask & handled; // intersect with handled actions
        if (ll_sys_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) {
            int e = errno;
            close(dfd);
            errno = e; die(("landlock_add_rule " + dir).c_str());
        }
        close(dfd);
    }

    void restrict_self() {
        if (!supported) return;
        if (ll_sys_restrict_self(ruleset_fd, 0) < 0) die("landlock_restrict_self");
        close(ruleset_fd);
        ruleset_fd = -1;
    }
};

// ---------- Core IPC (very small JSON over AF_UNIX) ----------
struct PeerCred {
    pid_t pid{};
    uid_t uid{};
    gid_t gid{};
};

// Very small line-oriented messaging (one JSON per send/recv).
static int connect_core() {
    int s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (s < 0) die("socket");
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CORE_SOCK_PATH);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) < 0) die("connect(core.sock)");
    return s;
}

static PeerCred get_peercred(int s) {
    PeerCred pc{};
    struct ucred cred{};
    socklen_t len = sizeof(cred);
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) die("getsockopt(SO_PEERCRED)");
    pc.pid = cred.pid; pc.uid = cred.uid; pc.gid = cred.gid;
    return pc;
}

static void send_json(int s, const json& j) {
    std::string bytes = j.dump();
    if (bytes.size() > MAX_MSG) diex("message too big");
    ssize_t n = send(s, bytes.data(), bytes.size(), 0);
    if (n < 0 || (size_t)n != bytes.size()) die("send(core)");
}

static json recv_json(int s) {
    char buf[MAX_MSG];
    ssize_t n = recv(s, buf, sizeof(buf), 0);
    if (n < 0) die("recv(core)");
    return json::parse(std::string(buf, buf + n));
}

// ---------- Spec (what launcher expects from CORE) ----------
struct Spec {
    std::string app_id;
    std::vector<std::string> exec;   // e.g. ["/usr/bin/python3", "/app/main.py"]
    std::vector<std::string> args;   // optional extra args
    std::string workdir = "/app";

    std::vector<std::string> ro_paths; // allow RO
    std::vector<std::string> rw_paths; // allow RW (/state should be here)

    std::vector<std::pair<std::string,std::string>> env; // name,value
};

// Parse CORE reply into Spec
static Spec parse_spec(const json& j) {
    Spec s;
    s.app_id = j.at("appId").get<std::string>();
    s.exec = j.at("entry").at("exec").get<std::vector<std::string>>();
    if (j.contains("entry") && j["entry"].contains("args"))
        s.args = j["entry"]["args"].get<std::vector<std::string>>();
    if (j.contains("entry") && j["entry"].contains("workingDir"))
        s.workdir = j["entry"]["workingDir"].get<std::string>();

    if (j.contains("files") && j["files"].contains("readOnly"))
        s.ro_paths = j["files"]["readOnly"].get<std::vector<std::string>>();
    if (j.contains("files") && j["files"].contains("readWrite"))
        s.rw_paths = j["files"]["readWrite"].get<std::vector<std::string>>();

    if (j.contains("entry") && j["entry"].contains("env")) {
        for (auto& e : j["entry"]["env"]) {
            s.env.emplace_back(e.at("name").get<std::string>(), e.at("value").get<std::string>());
        }
    }
    return s;
}

// ---------- Main ----------
static void usage(const char* argv0) {
    std::fprintf(stderr, "Usage: %s --app <id> [--no-landlock] [--trace]\n", argv0);
    std::exit(2);
}

int main(int argc, char** argv) {
    std::string app_id;
    bool no_landlock = false;
    bool trace = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--app" && i + 1 < argc) { app_id = argv[++i]; }
        else if (a == "--no-landlock") { no_landlock = true; }
        else if (a == "--trace") { trace = true; }
        else { usage(argv[0]); }
    }
    if (app_id.empty()) usage(argv[0]);

    if (geteuid() == 0) diex("launcher must not run as root (use systemd DynamicUser).");

    // Connect to CORE
    int s = connect_core();
    PeerCred corepc = get_peercred(s);
    if (trace) std::cerr << "[launcher] connected to CORE pid=" << corepc.pid
                         << " uid=" << corepc.uid << " gid=" << corepc.gid << "\n";

    // Send request (replace with your real protocol; this is a stub)
    json req = {
        {"type","GET_SPEC"},
        {"appId",app_id},
        // Optional: include launcher’s creds for CORE logs
        {"launcher", {{"pid", (int)getpid()}, {"uid", (int)geteuid()}, {"gid",(int)getegid()}}}
    };
    send_json(s, req);

    // Receive response
    json resp = recv_json(s);
    if (!resp.contains("ok") || !resp["ok"].get<bool>()) {
        std::string emsg = resp.value("error", "CORE rejected request");
        diex(emsg.c_str());
    }
    Spec spec = parse_spec(resp.at("spec"));

    if (trace) {
        std::cerr << "[launcher] got spec for " << spec.app_id << "\n";
        std::cerr << "  exec: ";
        for (auto& e : spec.exec) std::cerr << e << " ";
        for (auto& a : spec.args) std::cerr << a << " ";
        std::cerr << "\n";
    }

    // Apply Landlock if available and not disabled
    Landlock ll;
    if (!no_landlock) {
        ll.init();
        if (ll.supported) {
            // RO allows: READ_FILE + READ_DIR + EXECUTE (if you want to allow exec in RO trees)
            const __u64 RO = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
            // RW allows: RO + WRITE_FILE + TRUNCATE + MAKE_* + REMOVE_*
            const __u64 RW = RO |
                LANDLOCK_ACCESS_FS_WRITE_FILE |
                LANDLOCK_ACCESS_FS_TRUNCATE |
                LANDLOCK_ACCESS_FS_MAKE_REG |
                LANDLOCK_ACCESS_FS_MAKE_DIR |
                LANDLOCK_ACCESS_FS_MAKE_SYM |
                LANDLOCK_ACCESS_FS_MAKE_FIFO |
                LANDLOCK_ACCESS_FS_MAKE_SOCK |
                LANDLOCK_ACCESS_FS_MAKE_CHAR |
                LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                LANDLOCK_ACCESS_FS_REMOVE_FILE |
                LANDLOCK_ACCESS_FS_REMOVE_DIR;

            // Ensure /app always RO if it exists
            if (path_exists("/app")) ll.allow_dir("/app", RO);
            // Allow extra RO assets
            for (auto& p : spec.ro_paths) if (path_exists(p)) ll.allow_dir(p, RO);
            // Allow RW state and declared RW dirs
            for (auto& p : spec.rw_paths) {
                // CORE/systemd should have created/bound these already
                if (path_exists(p)) ll.allow_dir(p, RW);
            }

            // Lock it in
            ll.restrict_self();
            if (trace) std::cerr << "[launcher] Landlock enforced\n";
        } else if (trace) {
            std::cerr << "[launcher] Landlock not supported; continuing without\n";
        }
    }

    // Set environment
    for (auto& kv : spec.env) setenv(kv.first.c_str(), kv.second.c_str(), 1);

    // Working dir (systemd BindReadOnlyPaths mounts app pkg at /app)
    if (!spec.workdir.empty()) {
        if (chdir(spec.workdir.c_str()) < 0) die(("chdir " + spec.workdir).c_str());
    }

    // Build argv for execve
    std::vector<char*> argvv;
    for (auto& s : spec.exec) argvv.push_back(const_cast<char*>(s.c_str()));
    for (auto& a : spec.args) argvv.push_back(const_cast<char*>(a.c_str()));
    argvv.push_back(nullptr);

    // Close CORE socket before exec
    close(s);

    // Exec the app
    execve(argvv[0], argvv.data(), environ);
    die(("execve " + std::string(argvv[0])).c_str());
}
