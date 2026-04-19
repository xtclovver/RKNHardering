#include "native_signs_probe.h"

#include <jni.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cerrno>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <sys/system_properties.h>

#include <algorithm>
#include <map>
#include <sstream>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <sys/uio.h>
#include <poll.h>

namespace {

constexpr size_t kProcFileMaxBytes = 256 * 1024;
constexpr size_t kMapsFileMaxBytes = 2 * 1024 * 1024;

const char *const kAllowedProcPaths[] = {
    "/proc/net/route",
    "/proc/net/ipv6_route",
    "/proc/net/tcp",
    "/proc/net/tcp6",
    "/proc/net/udp",
    "/proc/net/udp6",
    "/proc/net/dev",
    "/proc/self/net/route",
    "/proc/self/net/ipv6_route",
    "/proc/self/net/tcp",
    "/proc/self/net/tcp6",
    "/proc/self/net/udp",
    "/proc/self/net/udp6",
    "/proc/self/net/dev",
    "/proc/self/maps",
    "/proc/self/status",
    "/proc/self/cmdline",
};

bool isPathAllowed(const char *path) {
    if (path == nullptr) return false;
    for (const char *allowed : kAllowedProcPaths) {
        if (std::strcmp(allowed, path) == 0) return true;
    }
    return false;
}

std::string ipToString(const sockaddr *sa) {
    if (sa == nullptr) return {};
    char buffer[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        const auto *in4 = reinterpret_cast<const sockaddr_in *>(sa);
        if (inet_ntop(AF_INET, &in4->sin_addr, buffer, sizeof(buffer)) == nullptr) {
            return {};
        }
    } else if (sa->sa_family == AF_INET6) {
        const auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
        if (inet_ntop(AF_INET6, &in6->sin6_addr, buffer, sizeof(buffer)) == nullptr) {
            return {};
        }
    } else {
        return {};
    }
    return std::string(buffer);
}

int fetchMtu(const char *name) {
    if (name == nullptr || name[0] == '\0') return -1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq req;
    std::memset(&req, 0, sizeof(req));
    std::strncpy(req.ifr_name, name, IFNAMSIZ - 1);
    int mtu = -1;
    if (ioctl(fd, SIOCGIFMTU, &req) == 0) {
        mtu = req.ifr_mtu;
    }
    close(fd);
    return mtu;
}

std::string familyName(int family) {
    switch (family) {
        case AF_INET: return "inet";
        case AF_INET6: return "inet6";
        case AF_PACKET: return "packet";
        default: return std::to_string(family);
    }
}

jobjectArray toStringArray(JNIEnv *env, const std::vector<std::string> &items) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(items.size()), stringClass, nullptr);
    if (arr == nullptr) {
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }
    for (jsize i = 0; i < static_cast<jsize>(items.size()); ++i) {
        jstring s = env->NewStringUTF(items[i].c_str());
        if (s == nullptr) continue;
        env->SetObjectArrayElement(arr, i, s);
        env->DeleteLocalRef(s);
    }
    env->DeleteLocalRef(stringClass);
    return arr;
}

jobjectArray nativeGetIfAddrs(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> rows;
    struct ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) {
        return toStringArray(env, rows);
    }

    for (struct ifaddrs *cur = head; cur != nullptr; cur = cur->ifa_next) {
        if (cur->ifa_name == nullptr) continue;
        const char *name = cur->ifa_name;
        unsigned int index = if_nametoindex(name);
        int mtu = fetchMtu(name);
        unsigned int flags = cur->ifa_flags;
        int family = cur->ifa_addr != nullptr ? cur->ifa_addr->sa_family : -1;
        std::string addr = ipToString(cur->ifa_addr);
        std::string netmask = ipToString(cur->ifa_netmask);

        std::string row;
        row.reserve(128);
        row.append(name);
        row.push_back('|');
        row.append(std::to_string(index));
        row.push_back('|');
        row.append(std::to_string(flags));
        row.push_back('|');
        row.append(familyName(family));
        row.push_back('|');
        row.append(addr);
        row.push_back('|');
        row.append(netmask);
        row.push_back('|');
        row.append(std::to_string(mtu));
        rows.push_back(row);
    }

    freeifaddrs(head);
    return toStringArray(env, rows);
}

jint nativeIfNameToIndex(JNIEnv *env, jclass /*clazz*/, jstring nameStr) {
    if (nameStr == nullptr) return 0;
    const char *name = env->GetStringUTFChars(nameStr, nullptr);
    if (name == nullptr) return 0;
    unsigned int idx = if_nametoindex(name);
    env->ReleaseStringUTFChars(nameStr, name);
    return static_cast<jint>(idx);
}

jstring nativeReadProcFile(JNIEnv *env, jclass /*clazz*/, jstring pathStr, jint maxBytes) {
    if (pathStr == nullptr) return nullptr;
    const char *path = env->GetStringUTFChars(pathStr, nullptr);
    if (path == nullptr) return nullptr;

    bool allowed = isPathAllowed(path);
    std::string pathCopy(path);
    env->ReleaseStringUTFChars(pathStr, path);
    if (!allowed) return nullptr;

    size_t limit = static_cast<size_t>(maxBytes > 0 ? maxBytes : 0);
    if (limit == 0 || limit > kMapsFileMaxBytes) {
        limit = (pathCopy == "/proc/self/maps") ? kMapsFileMaxBytes : kProcFileMaxBytes;
    }

    FILE *file = std::fopen(pathCopy.c_str(), "re");
    if (file == nullptr) return nullptr;

    std::string data;
    data.reserve(std::min<size_t>(limit, 64 * 1024));
    char buffer[4096];
    while (data.size() < limit) {
        size_t want = std::min<size_t>(sizeof(buffer), limit - data.size());
        size_t got = std::fread(buffer, 1, want, file);
        if (got == 0) break;
        data.append(buffer, got);
    }
    std::fclose(file);

    return env->NewStringUTF(data.c_str());
}

jobjectArray nativeReadSelfMapsSummary(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> findings;
    FILE *file = std::fopen("/proc/self/maps", "re");
    if (file == nullptr) {
        return toStringArray(env, findings);
    }

    static const char *const kSuspiciousMarkers[] = {
        "frida-agent",
        "frida-gadget",
        "libfrida",
        "libsubstrate",
        "com.saurik.substrate",
        "XposedBridge",
        "libxposed",
        "lspatch",
        "LSPosed",
        "libriru",
        "libzygisk",
    };

    char line[4096];
    size_t rwxLargeCount = 0;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        const char *perms = std::strchr(line, ' ');
        if (perms == nullptr) continue;
        ++perms;
        bool rwx = perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x';

        for (const char *marker : kSuspiciousMarkers) {
            if (std::strstr(line, marker) != nullptr) {
                std::string f = "marker|";
                f.append(marker);
                f.push_back('|');
                std::string raw(line);
                if (!raw.empty() && raw.back() == '\n') raw.pop_back();
                f.append(raw);
                findings.push_back(f);
                break;
            }
        }

        if (rwx) {
            unsigned long long start = 0, end = 0;
            if (std::sscanf(line, "%llx-%llx", &start, &end) == 2 && end > start) {
                unsigned long long size = end - start;
                if (size >= (256ULL * 1024ULL)) {
                    ++rwxLargeCount;
                }
            }
        }
    }
    std::fclose(file);

    if (rwxLargeCount > 0) {
        std::string f = "rwx_large|";
        f.append(std::to_string(rwxLargeCount));
        findings.push_back(f);
    }

    return toStringArray(env, findings);
}

jobjectArray nativeProbeFeatureFlags(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> rows;

    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get("ro.debuggable", value) > 0) {
        rows.push_back(std::string("ro.debuggable=") + value);
    }
    value[0] = '\0';
    if (__system_property_get("ro.build.version.sdk", value) > 0) {
        rows.push_back(std::string("ro.build.version.sdk=") + value);
    }
    value[0] = '\0';
    if (__system_property_get("ro.product.cpu.abi", value) > 0) {
        rows.push_back(std::string("ro.product.cpu.abi=") + value);
    }
    value[0] = '\0';
    if (__system_property_get("ro.build.type", value) > 0) {
        rows.push_back(std::string("ro.build.type=") + value);
    }

    struct utsname uts;
    if (uname(&uts) == 0) {
        rows.push_back(std::string("uname.sysname=") + uts.sysname);
        rows.push_back(std::string("uname.release=") + uts.release);
        rows.push_back(std::string("uname.machine=") + uts.machine);
    }

    return toStringArray(env, rows);
}

int readIntFromSysfs(const std::string &path, int fallback) {
    FILE *f = std::fopen(path.c_str(), "re");
    if (f == nullptr) return fallback;
    int value = fallback;
    if (std::fscanf(f, "%d", &value) != 1) {
        value = fallback;
    }
    std::fclose(f);
    return value;
}

std::string readLineFromSysfs(const std::string &path) {
    FILE *f = std::fopen(path.c_str(), "re");
    if (f == nullptr) return {};
    char buf[256] = {0};
    if (std::fgets(buf, sizeof(buf), f) == nullptr) {
        std::fclose(f);
        return {};
    }
    std::fclose(f);
    std::string s(buf);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    return s;
}

std::string flagNames(unsigned int flags) {
    std::string out;
    auto add = [&](const char *n) { if (!out.empty()) out += ','; out += n; };
    if (flags & IFF_UP) add("UP");
    if (flags & IFF_BROADCAST) add("BROADCAST");
    if (flags & IFF_LOOPBACK) add("LOOPBACK");
    if (flags & IFF_POINTOPOINT) add("POINTOPOINT");
    if (flags & IFF_RUNNING) add("RUNNING");
    if (flags & IFF_NOARP) add("NOARP");
    if (flags & IFF_PROMISC) add("PROMISC");
    if (flags & IFF_MULTICAST) add("MULTICAST");
    return out;
}

int ipv6PrefixLen(const sockaddr *sa) {
    if (sa == nullptr || sa->sa_family != AF_INET6) return -1;
    const auto *in6 = reinterpret_cast<const sockaddr_in6 *>(sa);
    int bits = 0;
    for (int i = 0; i < 16; ++i) {
        unsigned char b = in6->sin6_addr.s6_addr[i];
        if (b == 0xff) { bits += 8; continue; }
        for (int k = 7; k >= 0; --k) {
            if (b & (1u << k)) ++bits; else return bits;
        }
        return bits;
    }
    return bits;
}

jobjectArray nativeInterfaceDump(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> blocks;
    struct ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) {
        return toStringArray(env, blocks);
    }

    struct AddrLine {
        int family = 0;
        std::string addr;
        std::string mask;
        std::string peer;
        bool p2p = false;
        bool bc = false;
    };
    struct Iface {
        std::string name;
        unsigned int flags = 0;
        std::vector<AddrLine> addrs;
    };
    std::map<std::string, Iface> ifaces;

    for (struct ifaddrs *cur = head; cur != nullptr; cur = cur->ifa_next) {
        if (cur->ifa_name == nullptr) continue;
        std::string name = cur->ifa_name;
        auto &ent = ifaces[name];
        ent.name = name;
        ent.flags |= cur->ifa_flags;
        if (cur->ifa_addr == nullptr) continue;
        int fam = cur->ifa_addr->sa_family;
        if (fam != AF_INET && fam != AF_INET6) continue;
        AddrLine line;
        line.family = fam;
        line.addr = ipToString(cur->ifa_addr);
        line.p2p = (cur->ifa_flags & IFF_POINTOPOINT) != 0;
        line.bc = (cur->ifa_flags & IFF_BROADCAST) != 0;
        if (fam == AF_INET) {
            line.mask = ipToString(cur->ifa_netmask);
            if (line.p2p && cur->ifa_dstaddr != nullptr) {
                line.peer = ipToString(cur->ifa_dstaddr);
            } else if (line.bc && cur->ifa_ifu.ifu_broadaddr != nullptr) {
                line.peer = ipToString(cur->ifa_ifu.ifu_broadaddr);
            }
        } else {
            int pref = ipv6PrefixLen(cur->ifa_netmask);
            if (pref >= 0) line.mask = std::to_string(pref);
            if (line.p2p && cur->ifa_dstaddr != nullptr) {
                line.peer = ipToString(cur->ifa_dstaddr);
            }
        }
        ent.addrs.push_back(std::move(line));
    }
    freeifaddrs(head);

    for (const auto &kv : ifaces) {
        const Iface &iface = kv.second;
        std::ostringstream oss;
        unsigned int idx = if_nametoindex(iface.name.c_str());
        int mtu = readIntFromSysfs("/sys/class/net/" + iface.name + "/mtu", -1);
        int type = readIntFromSysfs("/sys/class/net/" + iface.name + "/type", -1);
        int txq = readIntFromSysfs("/sys/class/net/" + iface.name + "/tx_queue_len", -1);
        std::string opstate = readLineFromSysfs("/sys/class/net/" + iface.name + "/operstate");
        std::string carrier = readLineFromSysfs("/sys/class/net/" + iface.name + "/carrier");
        std::string addr = readLineFromSysfs("/sys/class/net/" + iface.name + "/address");

        oss << iface.name << ": flags=" << iface.flags << "<" << flagNames(iface.flags) << ">";
        oss << " index " << idx;
        if (mtu > 0) oss << " mtu " << mtu;
        if (type >= 0) oss << " type " << type;
        if (!opstate.empty()) oss << " operstate " << opstate;
        if (!carrier.empty()) oss << " carrier " << carrier;
        if (!addr.empty()) oss << " hwaddr " << addr;
        oss << "\n";

        std::vector<AddrLine> sorted = iface.addrs;
        std::sort(sorted.begin(), sorted.end(), [](const AddrLine &a, const AddrLine &b) {
            if (a.family != b.family) return a.family == AF_INET;
            return a.addr < b.addr;
        });
        for (const AddrLine &l : sorted) {
            if (l.family == AF_INET) {
                oss << "  inet " << (l.addr.empty() ? "-" : l.addr);
                if (!l.mask.empty()) oss << " netmask " << l.mask;
                if (!l.peer.empty()) {
                    oss << (l.p2p ? " destination " : " broadcast ") << l.peer;
                }
                oss << "\n";
            } else {
                oss << "  inet6 " << (l.addr.empty() ? "-" : l.addr);
                if (!l.mask.empty()) oss << " prefixlen " << l.mask;
                if (!l.peer.empty() && l.p2p) oss << " destination " << l.peer;
                oss << "\n";
            }
        }
        if (txq >= 0) oss << "  txqueuelen " << txq << "\n";
        blocks.push_back(oss.str());
    }
    return toStringArray(env, blocks);
}

std::string routeScopeName(int scope) {
    switch (scope) {
        case RT_SCOPE_UNIVERSE: return "global";
        case RT_SCOPE_SITE: return "site";
        case RT_SCOPE_LINK: return "link";
        case RT_SCOPE_HOST: return "host";
        case RT_SCOPE_NOWHERE: return "nowhere";
        default: return std::to_string(scope);
    }
}

std::string routeTypeName(int type) {
    switch (type) {
        case RTN_UNSPEC: return "unspec";
        case RTN_UNICAST: return "unicast";
        case RTN_LOCAL: return "local";
        case RTN_BROADCAST: return "broadcast";
        case RTN_ANYCAST: return "anycast";
        case RTN_MULTICAST: return "multicast";
        case RTN_BLACKHOLE: return "blackhole";
        case RTN_UNREACHABLE: return "unreachable";
        case RTN_PROHIBIT: return "prohibit";
        case RTN_THROW: return "throw";
        case RTN_NAT: return "nat";
        case RTN_XRESOLVE: return "xresolve";
        default: return std::to_string(type);
    }
}

std::vector<std::string> netlinkRouteDump(int family) {
    std::vector<std::string> out;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        out.push_back(std::string("error|socket|errno=") + std::to_string(errno));
        return out;
    }

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req;
    std::memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = 0;
    req.rtm.rtm_family = static_cast<unsigned char>(family);

    struct sockaddr_nl kernel;
    std::memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
               reinterpret_cast<struct sockaddr *>(&kernel), sizeof(kernel)) < 0) {
        out.push_back(std::string("error|sendto|errno=") + std::to_string(errno));
        close(fd);
        return out;
    }

    char buf[8192];
    while (true) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int pr = poll(&pfd, 1, 2000);
        if (pr <= 0) {
            if (pr == 0) out.push_back("error|poll|timeout");
            else out.push_back(std::string("error|poll|errno=") + std::to_string(errno));
            break;
        }
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0) {
            out.push_back(std::string("error|recv|errno=") + std::to_string(errno));
            break;
        }
        if (len == 0) break;

        bool done = false;
        for (struct nlmsghdr *nh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nh, static_cast<unsigned int>(len));
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                auto *err = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nh));
                out.push_back(std::string("error|nlmsg|errno=") + std::to_string(-err->error));
                done = true;
                break;
            }
            if (nh->nlmsg_type != RTM_NEWROUTE) continue;

            auto *rtm = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(nh));
            int rtaLen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
            struct rtattr *attr = RTM_RTA(rtm);

            std::string dst, gw, src, prefSrc;
            int oif = 0;
            unsigned int priority = 0;
            char iface[IF_NAMESIZE] = {0};

            for (; RTA_OK(attr, rtaLen); attr = RTA_NEXT(attr, rtaLen)) {
                void *data = RTA_DATA(attr);
                int alen = RTA_PAYLOAD(attr);
                switch (attr->rta_type) {
                    case RTA_DST: {
                        char b[INET6_ADDRSTRLEN] = {0};
                        if (inet_ntop(rtm->rtm_family, data, b, sizeof(b))) dst = b;
                        break;
                    }
                    case RTA_GATEWAY: {
                        char b[INET6_ADDRSTRLEN] = {0};
                        if (inet_ntop(rtm->rtm_family, data, b, sizeof(b))) gw = b;
                        break;
                    }
                    case RTA_SRC: {
                        char b[INET6_ADDRSTRLEN] = {0};
                        if (inet_ntop(rtm->rtm_family, data, b, sizeof(b))) src = b;
                        break;
                    }
                    case RTA_PREFSRC: {
                        char b[INET6_ADDRSTRLEN] = {0};
                        if (inet_ntop(rtm->rtm_family, data, b, sizeof(b))) prefSrc = b;
                        break;
                    }
                    case RTA_OIF: {
                        if (alen >= static_cast<int>(sizeof(int))) {
                            oif = *reinterpret_cast<int *>(data);
                            if_indextoname(oif, iface);
                        }
                        break;
                    }
                    case RTA_PRIORITY: {
                        if (alen >= static_cast<int>(sizeof(unsigned int))) {
                            priority = *reinterpret_cast<unsigned int *>(data);
                        }
                        break;
                    }
                    default: break;
                }
            }

            std::ostringstream oss;
            oss << "route|family=" << (rtm->rtm_family == AF_INET ? "inet" : rtm->rtm_family == AF_INET6 ? "inet6" : std::to_string(rtm->rtm_family));
            oss << "|dst=" << (dst.empty() ? "default" : dst) << "/" << static_cast<int>(rtm->rtm_dst_len);
            if (!gw.empty()) oss << "|via=" << gw;
            if (!src.empty()) oss << "|src=" << src;
            if (!prefSrc.empty()) oss << "|prefsrc=" << prefSrc;
            if (oif > 0) {
                oss << "|oif=" << oif;
                if (iface[0]) oss << "|dev=" << iface;
            }
            oss << "|table=" << static_cast<int>(rtm->rtm_table);
            oss << "|scope=" << routeScopeName(rtm->rtm_scope);
            oss << "|type=" << routeTypeName(rtm->rtm_type);
            oss << "|proto=" << static_cast<int>(rtm->rtm_protocol);
            if (priority) oss << "|metric=" << priority;
            out.push_back(oss.str());
        }
        if (done) break;
    }

    close(fd);
    return out;
}

jobjectArray nativeNetlinkRouteDump(JNIEnv *env, jclass /*clazz*/, jint family) {
    std::vector<std::string> items;
    if (family == 0 || family == AF_INET) {
        auto v4 = netlinkRouteDump(AF_INET);
        items.insert(items.end(), v4.begin(), v4.end());
    }
    if (family == 0 || family == AF_INET6) {
        auto v6 = netlinkRouteDump(AF_INET6);
        items.insert(items.end(), v6.begin(), v6.end());
    }
    return toStringArray(env, items);
}

std::string inetDiagStateName(unsigned int state) {
    switch (state) {
        case 1: return "ESTABLISHED";
        case 2: return "SYN_SENT";
        case 3: return "SYN_RECV";
        case 4: return "FIN_WAIT1";
        case 5: return "FIN_WAIT2";
        case 6: return "TIME_WAIT";
        case 7: return "CLOSE";
        case 8: return "CLOSE_WAIT";
        case 9: return "LAST_ACK";
        case 10: return "LISTEN";
        case 11: return "CLOSING";
        default: return std::to_string(state);
    }
}

std::vector<std::string> netlinkInetDiag(int family, int protocol) {
    std::vector<std::string> out;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        out.push_back(std::string("error|socket|errno=") + std::to_string(errno));
        return out;
    }

    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.req));
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.nlh.nlmsg_seq = 1;
    msg.req.sdiag_family = static_cast<unsigned char>(family);
    msg.req.sdiag_protocol = static_cast<unsigned char>(protocol);
    msg.req.idiag_states = 0xffffffff;

    struct sockaddr_nl kernel;
    std::memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    if (sendto(fd, &msg, msg.nlh.nlmsg_len, 0,
               reinterpret_cast<struct sockaddr *>(&kernel), sizeof(kernel)) < 0) {
        out.push_back(std::string("error|sendto|errno=") + std::to_string(errno));
        close(fd);
        return out;
    }

    char buf[16384];
    while (true) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int pr = poll(&pfd, 1, 2000);
        if (pr <= 0) {
            if (pr == 0) out.push_back("error|poll|timeout");
            else out.push_back(std::string("error|poll|errno=") + std::to_string(errno));
            break;
        }
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0) {
            out.push_back(std::string("error|recv|errno=") + std::to_string(errno));
            break;
        }
        if (len == 0) break;
        bool done = false;
        for (struct nlmsghdr *nh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nh, static_cast<unsigned int>(len));
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                auto *err = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nh));
                out.push_back(std::string("error|nlmsg|errno=") + std::to_string(-err->error));
                done = true;
                break;
            }
            if (nh->nlmsg_type != SOCK_DIAG_BY_FAMILY) continue;

            auto *diag = reinterpret_cast<struct inet_diag_msg *>(NLMSG_DATA(nh));
            char src[INET6_ADDRSTRLEN] = {0};
            char dst[INET6_ADDRSTRLEN] = {0};
            int af = diag->idiag_family;
            inet_ntop(af, diag->id.idiag_src, src, sizeof(src));
            inet_ntop(af, diag->id.idiag_dst, dst, sizeof(dst));
            unsigned short sport = ntohs(diag->id.idiag_sport);
            unsigned short dport = ntohs(diag->id.idiag_dport);
            std::ostringstream oss;
            oss << "socket|family=" << (af == AF_INET ? "inet" : "inet6");
            oss << "|proto=" << (protocol == IPPROTO_TCP ? "tcp" : protocol == IPPROTO_UDP ? "udp" : std::to_string(protocol));
            oss << "|state=" << inetDiagStateName(diag->idiag_state);
            oss << "|src=" << src << ":" << sport;
            oss << "|dst=" << dst << ":" << dport;
            oss << "|uid=" << diag->idiag_uid;
            oss << "|inode=" << diag->idiag_inode;
            oss << "|if=" << diag->id.idiag_if;
            out.push_back(oss.str());
        }
        if (done) break;
    }

    close(fd);
    return out;
}

jobjectArray nativeNetlinkSockDiag(JNIEnv *env, jclass /*clazz*/, jint family, jint protocol) {
    auto items = netlinkInetDiag(family, protocol);
    return toStringArray(env, items);
}

jobjectArray nativeLibraryIntegrity(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> rows;

    static const char *const kSymbols[] = {
        "getifaddrs",
        "if_nametoindex",
        "socket",
        "fopen",
        "inet_ntop",
        "ioctl",
    };

    for (const char *sym : kSymbols) {
        void *addr = dlsym(RTLD_DEFAULT, sym);
        if (addr == nullptr) {
            std::string row = sym;
            row.append("||missing");
            rows.push_back(row);
            continue;
        }
        Dl_info info;
        std::memset(&info, 0, sizeof(info));
        const char *lib = "";
        if (dladdr(addr, &info) != 0 && info.dli_fname != nullptr) {
            lib = info.dli_fname;
        }
        char addrBuf[32];
        std::snprintf(addrBuf, sizeof(addrBuf), "%p", addr);
        std::string row = sym;
        row.push_back('|');
        row.append(addrBuf);
        row.push_back('|');
        row.append(lib);
        rows.push_back(row);
    }

    return toStringArray(env, rows);
}

const JNINativeMethod kMethods[] = {
    {"nativeGetIfAddrs", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeGetIfAddrs)},
    {"nativeIfNameToIndex", "(Ljava/lang/String;)I", reinterpret_cast<void *>(nativeIfNameToIndex)},
    {"nativeReadProcFile", "(Ljava/lang/String;I)Ljava/lang/String;", reinterpret_cast<void *>(nativeReadProcFile)},
    {"nativeReadSelfMapsSummary", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeReadSelfMapsSummary)},
    {"nativeProbeFeatureFlags", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeProbeFeatureFlags)},
    {"nativeLibraryIntegrity", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeLibraryIntegrity)},
    {"nativeInterfaceDump", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeInterfaceDump)},
    {"nativeNetlinkRouteDump", "(I)[Ljava/lang/String;", reinterpret_cast<void *>(nativeNetlinkRouteDump)},
    {"nativeNetlinkSockDiag", "(II)[Ljava/lang/String;", reinterpret_cast<void *>(nativeNetlinkSockDiag)},
};

} // namespace

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass("com/notcvnt/rknhardering/probe/NativeSignsBridge");
    if (cls == nullptr) return JNI_ERR;
    jint rc = env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0]));
    env->DeleteLocalRef(cls);
    if (rc != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
