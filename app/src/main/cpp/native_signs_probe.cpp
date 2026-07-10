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
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <sys/system_properties.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <map>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <linux/fib_rules.h>
#include <linux/udp.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <sys/uio.h>
#include <poll.h>
#include <dlfcn.h>

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

int readIntFromSysfs(const std::string &path, int fallback);

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
        row.push_back('|');
        int iface_type = readIntFromSysfs("/sys/class/net/" + std::string(name) + "/type", -1);
        row.append(std::to_string(iface_type));
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

    auto limit = static_cast<size_t>(maxBytes > 0 ? maxBytes : 0);
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
            unsigned long long start = 0;
            unsigned long long end = 0;
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
    for (unsigned char b : in6->sin6_addr.s6_addr) {
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
            if (int pref = ipv6PrefixLen(cur->ifa_netmask); pref >= 0) line.mask = std::to_string(pref);
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
            if (pr == 0) out.emplace_back("error|poll|timeout");
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
        for (auto *nh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nh, static_cast<unsigned int>(len));
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const auto *err = reinterpret_cast<const struct nlmsgerr *>(NLMSG_DATA(nh));
                out.push_back(std::string("error|nlmsg|errno=") + std::to_string(-err->error));
                done = true;
                break;
            }
            if (nh->nlmsg_type != RTM_NEWROUTE) continue;

            auto *rtm = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(nh));
            int rtaLen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
            auto *attr = RTM_RTA(rtm);

            std::string dst;
            std::string gw;
            std::string src;
            std::string prefSrc;
            int oif = 0;
            unsigned int priority = 0;
            char iface[IF_NAMESIZE] = {0};

            for (; RTA_OK(attr, rtaLen); attr = RTA_NEXT(attr, rtaLen)) {
                auto *data = RTA_DATA(attr);
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
                const auto *err = reinterpret_cast<const struct nlmsgerr *>(NLMSG_DATA(nh));
                out.push_back(std::string("error|nlmsg|errno=") + std::to_string(-err->error));
                done = true;
                break;
            }
            if (nh->nlmsg_type != SOCK_DIAG_BY_FAMILY) continue;

            const auto *diag = reinterpret_cast<const struct inet_diag_msg *>(NLMSG_DATA(nh));
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

jobjectArray nativeDetectRoot(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> findings;

    static const char *const kSuPaths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/vendor/bin/su",
        "/product/bin/su",
        "/apex/com.android.runtime/bin/su",
    };
    for (const char *path : kSuPaths) {
        if (access(path, F_OK) == 0) {
            std::string f = "su_binary|";
            f.append(path);
            findings.push_back(f);
        }
    }

    struct PropCheck {
        const char *prop;
        const char *suspiciousValue;
    };
    static const PropCheck kRootProps[] = {
        {"ro.debuggable", "1"},
        {"ro.secure", "0"},
        {"ro.build.selinux", "0"},
        {"service.adb.root", "1"},
        {"ro.build.tags", "test-keys"},
    };
    for (const auto &check : kRootProps) {
        char val[PROP_VALUE_MAX] = {0};
        if (__system_property_get(check.prop, val) > 0) {
            if (std::strcmp(val, check.suspiciousValue) == 0) {
                std::string f = "root_prop|";
                f.append(check.prop);
                f.push_back('=');
                f.append(val);
                findings.push_back(f);
            }
        }
    }

    static const char *const kRootMgmtPaths[] = {
        "/data/adb/magisk",
        "/data/adb/modules",
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/SuperSU",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon",
    };
    for (const char *path : kRootMgmtPaths) {
        if (access(path, F_OK) == 0) {
            std::string f = "root_mgmt|";
            f.append(path);
            findings.push_back(f);
        }
    }

    if (access("/system", W_OK) == 0) {
        findings.emplace_back("system_rw|/system is writable");
    }

    FILE *mounts = std::fopen("/proc/self/mounts", "re");
    if (mounts != nullptr) {
        char line[1024];
        while (std::fgets(line, sizeof(line), mounts) != nullptr) {
            if (std::strstr(line, "magisk") != nullptr ||
                std::strstr(line, "core-only") != nullptr) {
                std::string raw(line);
                if (!raw.empty() && raw.back() == '\n') raw.pop_back();
                std::string f = "suspicious_mount|";
                f.append(raw);
                findings.push_back(f);
            }
            if (std::strstr(line, "overlay") != nullptr &&
                (std::strstr(line, "/system") != nullptr ||
                 std::strstr(line, "/vendor") != nullptr)) {
                std::string raw(line);
                if (!raw.empty() && raw.back() == '\n') raw.pop_back();
                std::string f = "overlay_mount|";
                f.append(raw);
                findings.push_back(f);
            }
        }
        std::fclose(mounts);
    }

    FILE *selinux = std::fopen("/sys/fs/selinux/enforce", "re");
    if (selinux != nullptr) {
        int enforce = -1;
        if (std::fscanf(selinux, "%d", &enforce) == 1 && enforce == 0) {
            findings.emplace_back("selinux|permissive");
        }
        std::fclose(selinux);
    } else {
        findings.emplace_back("selinux|absent");
    }

    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();
    if (uid == 0 || euid == 0 || gid == 0) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "uid=%d euid=%d gid=%d", uid, euid, gid);
        std::string f = "root_uid|";
        f.append(buf);
        findings.push_back(f);
    }

    static const char *const kMagiskProps[] = {
        "init.svc.magisk_daemon",
        "init.svc.magisk_pfs",
        "persist.magisk.hide",
    };
    for (const char *prop : kMagiskProps) {
        char val[PROP_VALUE_MAX] = {0};
        if (__system_property_get(prop, val) > 0 && val[0] != '\0') {
            std::string f = "magisk_prop|";
            f.append(prop);
            f.push_back('=');
            f.append(val);
            findings.push_back(f);
        }
    }

    return toStringArray(env, findings);
}

bool fileContains(const char *path, const char *needle) {
    FILE *f = std::fopen(path, "re");
    if (f == nullptr) return false;
    char line[1024];
    bool found = false;
    while (std::fgets(line, sizeof(line), f) != nullptr) {
        if (std::strstr(line, needle) != nullptr) { found = true; break; }
    }
    std::fclose(f);
    return found;
}

jobjectArray nativeDetectEmulator(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> findings;

    static const char *const kQemuProps[] = {
        "ro.kernel.qemu",
        "ro.kernel.qemu.gles",
        "ro.boot.qemu",
        "qemu.hw.mainkeys",
    };
    for (const char *prop : kQemuProps) {
        char val[PROP_VALUE_MAX] = {0};
        if (__system_property_get(prop, val) > 0 && val[0] != '\0') {
            std::string f = "qemu_prop|";
            f.append(prop);
            f.push_back('=');
            f.append(val);
            findings.push_back(f);
        }
    }

    static const char *const kHwProps[] = {
        "ro.hardware",
        "ro.product.board",
    };
    for (const char *prop : kHwProps) {
        char val[PROP_VALUE_MAX] = {0};
        if (__system_property_get(prop, val) > 0) {
            if (std::strstr(val, "goldfish") != nullptr ||
                std::strstr(val, "ranchu") != nullptr) {
                std::string f = "goldfish|";
                f.append(prop);
                f.push_back('=');
                f.append(val);
                findings.push_back(f);
            }
        }
    }

    static const char *const kPipePaths[] = {
        "/dev/qemu_pipe",
        "/dev/socket/qemud",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
    };
    for (const char *path : kPipePaths) {
        if (access(path, F_OK) == 0) {
            std::string f = "qemu_pipe|";
            f.append(path);
            findings.push_back(f);
        }
    }

    if (fileContains("/proc/tty/drivers", "goldfish")) {
        findings.emplace_back("qemu_driver|/proc/tty/drivers:goldfish");
    }

    static const char *const kBlueStacksPaths[] = {
        "/system/lib/libbstfolder_jni.so",
        "/data/bluestacks.prop",
    };
    for (const char *path : kBlueStacksPaths) {
        if (access(path, F_OK) == 0) {
            std::string f = "bluestacks|";
            f.append(path);
            findings.push_back(f);
        }
    }

    return toStringArray(env, findings);
}

}

static void detectVpnPropertiesAll(std::vector<std::string> &findings);
static void detectVpnFiles(std::vector<std::string> &findings);
static void detectVpnInterfaces(std::vector<std::string> &findings);
static void detectVpnRoutes(std::vector<std::string> &findings);
static void detectArpNeighbors(std::vector<std::string> &findings);
static void detectSysctl(std::vector<std::string> &findings);
static void detectEstablishedVpn(std::vector<std::string> &findings);
static void detectQdisc(std::vector<std::string> &findings);
static void detectMssAnomaly(std::vector<std::string> &findings);
static void detectBpfMaps(std::vector<std::string> &findings);
static void detectLoopbackConflicts(std::vector<std::string> &findings);
static void detectSocketLeaks(std::vector<std::string> &findings);
static void detectIpRecvErr(std::vector<std::string> &findings);
static jobjectArray nativeDetectVpnDetector(JNIEnv *env, jclass /*clazz*/, jobject cancellationSignal);
static void detectSysfsLeak(std::vector<std::string> &findings);
static void detectGetifaddrsVpn(std::vector<std::string> &findings);
static void detectSysclassnetVpn(std::vector<std::string> &findings);
static void detectRtmGetlinkVpn(std::vector<std::string> &findings);
static void detectProcIfInet6(std::vector<std::string> &findings);
static void detectProcIpv6RouteVpn(std::vector<std::string> &findings);
static void detectProcNetDevVpn(std::vector<std::string> &findings);
static void detectFibTrieAccess(std::vector<std::string> &findings);
static void detectSetsockoptBindToDevice(std::vector<std::string> &findings);
static void detectInetDiagAccess(std::vector<std::string> &findings);
static void detectGetsocknameLeak(std::vector<std::string> &findings);
static void detectVpnPolicyRules(std::vector<std::string> &findings);
static void detectRouteCount(std::vector<std::string> &findings);
static void detectUdpPortConflictPhysicalIp(std::vector<std::string> &findings);
static void detectTrimOracle(std::vector<std::string> &findings);
static void detectIfindexnameVpn(std::vector<std::string> &findings);
static void detectPmtuMssCombined(std::vector<std::string> &findings);
static void detectUdpPmtu(std::vector<std::string> &findings);
static void detectNormalPmtu(std::vector<std::string> &findings);
static void detectTraceroute(std::vector<std::string> &findings);
static void detectTimingOracle(std::vector<std::string> &findings);
static void detectBackpressure(
    JNIEnv *env,
    jobject cancellationSignal,
    jmethodID isCancelledMethod,
    std::vector<std::string> &findings
);
static void detectGsoLargeSend(std::vector<std::string> &findings);
static void detectHwTimestamp(std::vector<std::string> &findings);

jobjectArray nativeDetectVpnProperties(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> findings;

    detectVpnPropertiesAll(findings);
    detectVpnFiles(findings);

    return toStringArray(env, findings);
}

jobjectArray nativeDetectVpnLeaks(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> findings;

    detectVpnInterfaces(findings);
    detectVpnRoutes(findings);
    detectArpNeighbors(findings);

    return toStringArray(env, findings);
}

jobjectArray nativeDetectVpnAdvanced(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> findings;

    detectSysctl(findings);
    detectEstablishedVpn(findings);
    detectQdisc(findings);
    detectMssAnomaly(findings);
    detectBpfMaps(findings);

    return toStringArray(env, findings);
}

jobjectArray nativeDetectVpnSyscalls(JNIEnv *env, jclass /*clazz*/) {
    std::vector<std::string> findings;

    detectLoopbackConflicts(findings);
    detectSocketLeaks(findings);
    detectIpRecvErr(findings);

    return toStringArray(env, findings);
}

static void detectVpnPropertiesAll(std::vector<std::string> &findings) {
    const std::vector<std::string> vpnProps = {
        "net.vpn.dns1", "net.vpn.dns2",
        "dhcp.tun0.dns1", "dhcp.tun0.dns2",
        "net.interfaces.default.type", "net.interfaces.default.name",
        "net.vpn.dns3", "net.vpn.dns4",
    };
    for (const auto &prop : vpnProps) {
        char value[PROP_VALUE_MAX] = {0};
        if (__system_property_get(prop.c_str(), value) > 0 && value[0] != '\0') {
            findings.emplace_back("vpn_prop|" + prop + "=" + value);
        }
    }
    char devType[PROP_VALUE_MAX] = {0};
    if (__system_property_get("net.interfaces.default.type", devType) > 0) {
        std::string lower = devType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("tun") != std::string::npos || lower.find("vpn") != std::string::npos) {
            findings.emplace_back("vpn_prop|net.interfaces.default.type contains tun/vpn");
        }
    }
}

static void detectVpnFiles(std::vector<std::string> &findings) {
    const std::vector<std::pair<std::string, std::string>> pathGroups = {
        {"vpnhide", "/data/local/tmp/vpnhide"},
        {"vpnhide", "/data/data/com.vpnhide"},
        {"vpnhide", "/data/local/tmp/.vpnhide"},
        {"vpnhide", "/data/data/com.vpn.hide"},
        {"lsposed", "/data/adb/lspd"},
        {"lsposed", "/data/adb/modules/lsposed"},
        {"lsposed", "/data/misc/lspd"},
        {"lsposed", "/data/data/org.lsposed.manager"},
        {"zygisk", "/data/adb/modules/zygisk"},
        {"zygisk", "/data/adb/zygisk"},
        {"zygisk", "/data/local/tmp/zygisk"},
    };
    for (const auto &[prefix, path] : pathGroups) {
        struct stat st;
        if (stat(path.c_str(), &st) == 0) {
            findings.emplace_back(prefix + "|" + path);
        }
    }
    const std::vector<std::string> hookPropNames = {
        "persist.sys.lspd.hook", "ro.magisk.version",
        "init.svc.zygote_restart",
    };
    for (const auto &prop : hookPropNames) {
        char value[PROP_VALUE_MAX] = {0};
        if (__system_property_get(prop.c_str(), value) > 0 && value[0] != '\0') {
            findings.emplace_back("hook_prop|" + prop + "=" + value);
        }
    }
}

static bool ifaceExists(const char *name) {
    struct ifreq ifr{};
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    bool exists = (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0);
    close(fd);
    return exists;
}

static void detectVpnInterfaces(std::vector<std::string> &findings) {
    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "utun1", "wg0", "wg1", "ppp0", "xfrm0"};
    for (const auto &name : tunNames) {
        if (!ifaceExists(name.c_str())) continue;
        struct ifreq ifr{};
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name.c_str());
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
            findings.emplace_back("inet6_vpn_iface|" + name + "|flags=0x" + std::to_string(ifr.ifr_flags));
        }
        close(fd);
    }
}

static bool isVpnIface(const char *iface) {
    static const std::vector<std::string> vpnIfaces = {"tun0", "tun1", "utun0", "ppp0", "wg0", "wg1"};
    for (const auto &v : vpnIfaces) {
        if (v == iface) return true;
    }
    return false;
}

static void detectVpnRoutes(std::vector<std::string> &findings) {
    std::ifstream f("/proc/net/route");
    if (!f.is_open()) return;
    std::string line;
    int vpnRouteCount = 0;
    std::getline(f, line);
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string ifaceBuf;
        unsigned long dest = 0;
        unsigned long gateway = 0;
        if (!(iss >> ifaceBuf >> std::hex >> dest >> gateway)) continue;
        if (!isVpnIface(ifaceBuf.c_str())) continue;
        vpnRouteCount++;
        if (dest == 0 || dest == 0xFFFFFFFF) continue;
        std::ostringstream oss;
        oss << std::hex << std::setw(8) << std::setfill('0') << dest;
        findings.emplace_back("vpn_policy_rules|iface=" + ifaceBuf + " dest=" + oss.str());
    }
    if (vpnRouteCount > 0) {
        findings.emplace_back("route_vpn_iface|vpn_routes=" + std::to_string(vpnRouteCount));
    }
}

static void detectArpNeighbors(std::vector<std::string> &findings) {
    std::ifstream f("/proc/net/arp");
    if (!f.is_open()) return;
    std::string line;
    std::getline(f, line);
    int totalEntries = 0;
    int hiddenEntries = 0;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string ip, hwType, flags, mac, mask, iface;
        if (!(iss >> ip >> hwType >> flags >> mac >> mask >> iface)) continue;
        totalEntries++;
        if (mac == "00:00:00:00:00:00" || mac.find("ff:ff:ff:ff:ff:ff") != std::string::npos) {
            hiddenEntries++;
        }
    }
    if (hiddenEntries > 0) {
        findings.emplace_back("hidden_mac_neighbors|hidden=" + std::to_string(hiddenEntries) + " total=" + std::to_string(totalEntries));
    }
}

static void detectSysctl(std::vector<std::string> &findings) {
    auto readInt = [](const char *path) -> std::optional<int> {
        FILE *f = fopen(path, "r");
        if (!f) return std::nullopt;
        int val = 0;
        bool ok = (fscanf(f, "%d", &val) == 1);
        fclose(f);
        return ok ? std::optional(val) : std::nullopt;
    };
    if (auto val = readInt("/proc/sys/net/ipv4/ip_forward"); val && *val != 0) {
        findings.emplace_back("sysctl_forwarding|ip_forward=1");
    }
    if (auto val = readInt("/proc/sys/net/ipv4/conf/all/rp_filter"); val && *val == 0) {
        findings.emplace_back("sysctl_rp_filter|rp_filter=0");
    }
}

static bool isVpnPort(int port) {
    return port == 51820 || port == 1194 || port == 1195 || port == 443 || port == 8443;
}

static void detectEstablishedVpn(std::vector<std::string> &findings) {
    std::ifstream f("/proc/net/tcp");
    if (!f.is_open()) return;
    std::string line;
    std::getline(f, line);
    while (std::getline(f, line)) {
        unsigned long localAddr = 0;
        unsigned long remoteAddr = 0;
        int localPort = 0;
        int remotePort = 0;
        int state = 0;
        if (sscanf(line.c_str(), " %lx:%x %lx:%x %x", &localAddr, &localPort, &remoteAddr, &remotePort, &state) < 5) continue;
        if (state != 1) continue;
        if (!isVpnPort(remotePort)) continue;
        findings.emplace_back("established_vpn|remote_port=" + std::to_string(remotePort));
    }
}

static void detectQdisc(std::vector<std::string> &findings) {
    std::ifstream f("/proc/net/dev");
    if (!f.is_open()) return;
    std::string line;
    std::getline(f, line);
    std::getline(f, line);
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string iface;
        std::getline(iss >> std::ws, iface, ':');
        unsigned long rxBytes = 0;
        unsigned long rxPackets = 0;
        iss >> rxBytes >> rxPackets;
        for (int i = 0; i < 6; ++i) { unsigned long tmp = 0; iss >> tmp; }
        unsigned long txBytes = 0;
        unsigned long txPackets = 0;
        iss >> txBytes >> txPackets;
        if (iface != "tun0" && iface != "wg0") continue;
        findings.emplace_back("vpn_qdisc|iface=" + iface + " rx=" + std::to_string(rxBytes) + " tx=" + std::to_string(txBytes));
    }
}

static void detectMssAnomaly(std::vector<std::string> &findings) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) { close(fd); return; }
    struct tcp_info info{};
    socklen_t infoLen = sizeof(info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &infoLen) == 0 && info.tcpi_snd_mss > 0 && info.tcpi_snd_mss < 500) {
        findings.emplace_back("tcp_mss_low|snd_mss=" + std::to_string(info.tcpi_snd_mss) + "|rcv_mss=" + std::to_string(info.tcpi_rcv_mss));
    }
    close(fd);
}

static void detectBpfMaps(std::vector<std::string> &findings) {
    const std::vector<std::string> paths = {
        "/sys/fs/bpf/map_netd_iface_index_name_map",
        "/sys/fs/bpf/netd_shared/map_netd_iface_index_name_map",
        "/sys/fs/bpf/netd_iface_index_name_map",
    };
    for (const auto &path : paths) {
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) continue;
        close(fd);
        findings.emplace_back("bpf_map_accessible|" + path);
    }
}

static void detectIpRecvErr(std::vector<std::string> &findings) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    int opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &opt, sizeof(opt)) < 0) {
        if (errno == EACCES || errno == EPERM) {
            findings.emplace_back("unavailable|ip_recverr|denied");
        } else if (errno == ENOPROTOOPT) {
            findings.emplace_back("unavailable|ip_recverr|not_supported");
        }
    }
    close(fd);
}

// --- n08/n04/n30: sysfs VPN interface leak ---
static void detectSysfsLeak(std::vector<std::string> &findings) {
    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    const std::vector<std::string> sysfsBases = {"/sys/class/net", "/sys/devices/virtual/net"};
    std::vector<std::string> leaked;
    for (const auto &base : sysfsBases) {
        for (const auto &name : tunNames) {
            std::string path = base + "/" + name;
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                leaked.emplace_back(base + ": leaked " + name);
            }
        }
    }
    const std::vector<std::string> procSysBases = {
        "/proc/sys/net/ipv4/conf", "/proc/sys/net/ipv6/conf",
        "/proc/sys/net/ipv4/neigh", "/proc/sys/net/ipv6/neigh",
    };
    for (const auto &base : procSysBases) {
        for (const auto &name : tunNames) {
            std::string path = base + "/" + name;
            struct stat st;
            if (stat(path.c_str(), &st) == 0) {
                leaked.emplace_back(base + ": leaked " + name);
            }
        }
    }
    if (!leaked.empty()) {
        std::string r = "sysfs_vpn_leak|";
        for (size_t i = 0; i < leaked.size(); ++i) {
            if (i > 0) r += ", ";
            r += leaked[i];
        }
        findings.push_back(r);
    }
}

// --- n03: getifaddrs VPN interfaces ---
static void detectGetifaddrsVpn(std::vector<std::string> &findings) {
    struct ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) return;
    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    std::vector<std::string> found;
    for (struct ifaddrs *cur = head; cur != nullptr; cur = cur->ifa_next) {
        if (cur->ifa_name == nullptr) continue;
        for (const auto &name : tunNames) {
            if (cur->ifa_name == name) {
                found.push_back(name);
                break;
            }
        }
    }
    freeifaddrs(head);
    if (!found.empty()) {
        std::string r = "getifaddrs_vpn|";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i > 0) r += ", ";
            r += found[i];
        }
        findings.push_back(r);
    }
}

// --- n04: /sys/class/net VPN interfaces ---
static void detectSysclassnetVpn(std::vector<std::string> &findings) {
    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    std::vector<std::string> found;
    for (const auto &name : tunNames) {
        std::string path = std::string("/sys/class/net/") + name;
        struct stat st;
        if (stat(path.c_str(), &st) == 0) {
            found.push_back(name);
        }
    }
    if (!found.empty()) {
        std::string r = "sysclassnet_vpn|";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i > 0) r += ", ";
            r += found[i];
        }
        findings.push_back(r);
    }
}

// --- n05: RTM_GETLINK VPN interfaces ---
static std::string extractRtattrString(const struct rtattr *attr) {
    auto *data = reinterpret_cast<char *>(RTA_DATA(attr));
    if (data == nullptr || data[0] == '\0') return {};
    return {data};
}

static bool isVpnName(const std::string &name, const std::vector<std::string> &tunNames) {
    for (const auto &t : tunNames) {
        if (t == name) return true;
    }
    return false;
}

static void processNetlinkMsg(
    const struct nlmsghdr *nh,
    const std::vector<std::string> &tunNames,
    std::vector<std::string> &found
) {
    if (nh->nlmsg_type != RTM_NEWLINK) return;
    auto *ifi = reinterpret_cast<struct ifinfomsg *>(NLMSG_DATA(nh));
    int rtaLen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
    auto *attr = reinterpret_cast<struct rtattr *>(ifi + 1);
    std::string ifname;
    for (; RTA_OK(attr, rtaLen); attr = RTA_NEXT(attr, rtaLen)) {
        if (attr->rta_type == IFLA_IFNAME) {
            ifname = extractRtattrString(attr);
            break;
        }
    }
    if (!ifname.empty() && isVpnName(ifname, tunNames)) {
        found.push_back(ifname);
    }
}

static void detectRtmGetlinkVpn(std::vector<std::string> &findings) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return;

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req{};
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;

    struct sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;

    if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
               reinterpret_cast<struct sockaddr *>(&kernel), sizeof(kernel)) < 0) {
        close(fd);
        return;
    }

    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    std::vector<std::string> found;
    char buf[8192];
    bool done = false;
    while (!done) {
        struct pollfd pfd = {fd, POLLIN, 0};
        if (poll(&pfd, 1, 2000) <= 0) break;
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len <= 0) break;
        for (auto *nh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nh, static_cast<unsigned int>(len));
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }
            processNetlinkMsg(nh, tunNames, found);
        }
    }
    close(fd);
    if (!found.empty()) {
        std::string r = "rtm_getlink_vpn|";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i > 0) r += ", ";
            r += found[i];
        }
        findings.push_back(r);
    }
}

// --- n10: /proc/net/if_inet6 VPN entries ---
static void detectProcIfInet6(std::vector<std::string> &findings) {
    const std::vector<std::string> paths = {"/proc/net/if_inet6", "/proc/self/net/if_inet6"};
    const std::vector<std::string> vpnIfaces = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    for (const auto &path : paths) {
        std::ifstream f(path);
        if (!f) continue;
        int vpnCount = 0;
        std::string vpnIfacesStr;
        std::string line;
        while (std::getline(f, line)) {
            std::istringstream iss(line);
            std::string tokens[6];
            for (int i = 0; i < 6 && iss >> tokens[i]; ++i) {}
            if (tokens[5].empty()) continue;
            const auto &iface = tokens[5];
            bool match = false;
            for (const auto &v : vpnIfaces) { if (v == iface) { match = true; break; } }
            if (!match) continue;
            vpnCount++;
            if (!vpnIfacesStr.empty()) vpnIfacesStr += ", ";
            vpnIfacesStr += iface;
        }
        if (vpnCount > 0) {
            findings.emplace_back("proc_if_inet6_vpn|count=" + std::to_string(vpnCount) + " ifaces=" + vpnIfacesStr);
            return;
        }
    }
}

// --- n11: /proc/net/ipv6_route VPN entries ---
static void detectProcIpv6RouteVpn(std::vector<std::string> &findings) {
    const std::vector<std::string> paths = {"/proc/net/ipv6_route", "/proc/self/net/ipv6_route"};
    const std::vector<std::string> vpnIfaces = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    for (const auto &path : paths) {
        std::ifstream f(path);
        if (!f) continue;
        int vpnCount = 0;
        std::string line;
        while (std::getline(f, line)) {
            std::istringstream iss(line);
            std::string tokens[10];
            for (int i = 0; i < 10 && iss >> tokens[i]; ++i) {}
            if (tokens[9].empty()) continue;
            const auto &iface = tokens[9];
            bool match = false;
            for (const auto &v : vpnIfaces) { if (v == iface) { match = true; break; } }
            if (match) vpnCount++;
        }
        if (vpnCount > 0) {
            findings.emplace_back("proc_ipv6_route_vpn|count=" + std::to_string(vpnCount));
            return;
        }
    }
}

// --- n16: /proc/net/dev VPN interface traffic ---
static void detectProcNetDevVpn(std::vector<std::string> &findings) {
    const std::vector<std::string> paths = {"/proc/net/dev", "/proc/self/net/dev"};
    const std::vector<std::string> vpnIfaces = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    for (const auto &path : paths) {
        std::ifstream f(path);
        if (!f) continue;
        std::string line;
        std::getline(f, line); // skip header 1
        std::getline(f, line); // skip header 2
        while (std::getline(f, line)) {
            auto colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string iface = line.substr(0, colon);
            // trim leading whitespace
            auto start = iface.find_first_not_of(" \t");
            if (start != std::string::npos) iface = iface.substr(start);
            bool match = false;
            for (const auto &v : vpnIfaces) { if (v == iface) { match = true; break; } }
            if (!match) continue;
            std::istringstream iss(line.substr(colon + 1));
            unsigned long rxBytes = 0, rxPackets = 0, txBytes = 0, txPackets = 0;
            iss >> rxBytes >> rxPackets;
            for (int i = 0; i < 6; ++i) { unsigned long tmp; iss >> tmp; }
            iss >> txBytes >> txPackets;
            findings.emplace_back("proc_net_dev_vpn|iface=" + iface + " rx=" + std::to_string(rxBytes) + " tx=" + std::to_string(txBytes));
            return;
        }
    }
}

// --- n17: /proc/net/fib_trie SELinux access check ---
static void detectFibTrieAccess(std::vector<std::string> &findings) {
    FILE *f = fopen("/proc/net/fib_trie", "re");
    if (f) {
        fclose(f);
    } else {
        if (errno == EACCES || errno == EPERM) {
            findings.push_back("fib_trie_denied|SELinux denies /proc/net/fib_trie");
        } else if (errno == ENOENT) {
            // not available on this kernel, neutral
        } else {
            std::string r = "fib_trie_denied|errno=" + std::to_string(errno);
            findings.push_back(r);
        }
    }
}

// --- n18: SO_BINDTODEVICE setsockopt ---
static void detectSetsockoptBindToDevice(std::vector<std::string> &findings) {
    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "wg0", "ppp0"};
    for (const auto &name : tunNames) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        int rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name.c_str(), static_cast<socklen_t>(name.size() + 1));
        if (rc == 0) {
            char devName[256] = {0};
            socklen_t devLen = sizeof(devName);
            if (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, devName, &devLen) == 0) {
                std::string devStr(devName);
                if (devStr.find(name) != std::string::npos) {
                    findings.emplace_back("bindtodevice_leak|setsockopt(" + name + ") succeeded, getsockopt confirmed");
                }
            }
        }
        close(fd);
    }
}

// --- n19: inet_diag netlink access check ---
static void detectInetDiagAccess(std::vector<std::string> &findings) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            findings.push_back("inet_diag_denied|SELinux denies inet_diag netlink");
        }
        return;
    }
    close(fd);
}

// --- n20: getsockname() VPN IP leak ---
static void detectGetsocknameLeak(std::vector<std::string> &findings) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct sockaddr_in localAddr;
    socklen_t addrLen = sizeof(localAddr);
    std::memset(&localAddr, 0, sizeof(localAddr));
    if (getsockname(fd, reinterpret_cast<struct sockaddr *>(&localAddr), &addrLen) == 0) {
        if (localAddr.sin_addr.s_addr != 0) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &localAddr.sin_addr, ip, sizeof(ip));
            // Check if it's a private IP that could be VPN
            unsigned int addr = ntohl(localAddr.sin_addr.s_addr);
            bool isPrivate = ((addr >> 24) == 10) ||
                             ((addr >> 20) == 0xAC1) || // 172.16.0.0/12
                             ((addr >> 16) == 0xC0A8);  // 192.168.0.0/16
            if (isPrivate) {
                std::string r = "getsockname_leak|local_ip=" + std::string(ip);
                findings.push_back(r);
            }
        }
    }
    close(fd);
}

// --- n21: VPN routing policy rules via netlink ---
static void detectVpnPolicyRules(std::vector<std::string> &findings) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return;

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req;
    std::memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETRULE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.rtm.rtm_family = AF_INET;

    struct sockaddr_nl kernel;
    std::memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
               reinterpret_cast<struct sockaddr *>(&kernel), sizeof(kernel)) < 0) {
        close(fd);
        return;
    }

    int vpnRuleCount = 0;
    std::string ruleSummary;
    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};

    char buf[8192];
    while (true) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int pr = poll(&pfd, 1, 2000);
        if (pr <= 0) break;
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len <= 0) break;
        bool done = false;
        for (auto *nh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nh, static_cast<unsigned int>(len));
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (nh->nlmsg_type == NLMSG_ERROR) { done = true; break; }
            if (nh->nlmsg_type != RTM_NEWRULE) continue;

            auto *rtm = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(nh));
            int rtaLen = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
            auto *attr = reinterpret_cast<struct rtattr *>(rtm + 1);

            int table = rtm->rtm_table;
            unsigned int fwMark = 0;
            int oif = 0;
            char iface[IF_NAMESIZE] = {0};

            for (; RTA_OK(attr, rtaLen); attr = RTA_NEXT(attr, rtaLen)) {
                auto *data = RTA_DATA(attr);
                int alen = RTA_PAYLOAD(attr);
                switch (attr->rta_type) {
                    case RTA_TABLE: {
                        if (alen >= static_cast<int>(sizeof(int))) {
                            table = *reinterpret_cast<int *>(data);
                        }
                        break;
                    }
                    case RTA_OIF: {
                        if (alen >= static_cast<int>(sizeof(int))) {
                            oif = *reinterpret_cast<int *>(data);
                            if_indextoname(oif, iface);
                        }
                        break;
                    }
                    case RTA_FLOW: {
                        if (alen >= static_cast<int>(sizeof(unsigned int))) {
                            fwMark = *reinterpret_cast<unsigned int *>(data);
                        }
                        break;
                    }
                    default: break;
                }
            }

            if (table >= 100 && table <= 200) {
                // High table numbers are often VPN policy routing tables
                bool isVpnIface = false;
                for (const auto &name : tunNames) {
                    if (iface[0] && name == iface) {
                        isVpnIface = true;
                        break;
                    }
                }
                if (isVpnIface || (table >= 100 && table <= 110)) {
                    vpnRuleCount++;
                    if (!ruleSummary.empty()) ruleSummary += "; ";
                    ruleSummary += "table=" + std::to_string(table);
                    if (iface[0]) ruleSummary += " iface=" + std::string(iface);
                    if (fwMark) ruleSummary += " fwmark=0x" + std::to_string(fwMark);
                }
            }

        }
        if (done) break;
    }
    close(fd);

    if (vpnRuleCount > 0) {
        std::string r = "vpn_policy_rules_netlink|count=" + std::to_string(vpnRuleCount);
        if (!ruleSummary.empty()) r += " " + ruleSummary;
        findings.push_back(r);
    }
}

// --- n07: Route count / anonymous interfaces ---
static void detectRouteCount(std::vector<std::string> &findings) {
    auto routes = netlinkRouteDump(0);
    int totalRoutes = 0;
    for (const auto &r : routes) {
        if (r.find("route|") == 0) totalRoutes++;
    }
    // Count unique interfaces
    std::map<std::string, int> ifaceCounts;
    for (const auto &r : routes) {
        auto devPos = r.find("|dev=");
        if (devPos != std::string::npos) {
            auto devEnd = r.find('|', devPos + 5);
            std::string dev = (devEnd != std::string::npos)
                ? r.substr(devPos + 5, devEnd - devPos - 5)
                : r.substr(devPos + 5);
            ifaceCounts[dev]++;
        }
    }
    std::string r = "route_count|total=" + std::to_string(totalRoutes);
    r += " interfaces=" + std::to_string(ifaceCounts.size());
    findings.push_back(r);
}

// --- n41: UDP port conflict on physical interface IP ---
static void detectUdpPortConflictPhysicalIp(std::vector<std::string> &findings) {
    // Get physical interface IP via getifaddrs
    struct ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) return;

    std::string physicalIp;
    for (struct ifaddrs *cur = head; cur != nullptr; cur = cur->ifa_next) {
        if (cur->ifa_name == nullptr || cur->ifa_addr == nullptr) continue;
        if (cur->ifa_addr->sa_family != AF_INET) continue;
        const char *name = cur->ifa_name;
        // Skip tunnel/VPN interfaces
        if (strstr(name, "tun") || strstr(name, "wg") || strstr(name, "ppp") ||
            strstr(name, "xfrm") || strstr(name, "utun")) continue;
        if (strcmp(name, "lo") == 0) continue;
        char ip[INET_ADDRSTRLEN];
        auto *in4 = reinterpret_cast<sockaddr_in *>(cur->ifa_addr);
        inet_ntop(AF_INET, &in4->sin_addr, ip, sizeof(ip));
        physicalIp = ip;
        break; // take the first physical IP
    }
    freeifaddrs(head);

    if (physicalIp.empty()) return;

    static const int kVpnPorts[] = {500, 4500, 1194, 1701, 51820};
    std::vector<int> conflicts;
    for (int port : kVpnPorts) {
        int testFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (testFd < 0) continue;
        int opt = 1;
        setsockopt(testFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, physicalIp.c_str(), &addr.sin_addr);
        if (bind(testFd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
            if (errno == EADDRINUSE) {
                conflicts.push_back(port);
            }
        }
        close(testFd);
    }
    if (!conflicts.empty()) {
        std::string r = "udp_port_conflict_physical|ip=" + physicalIp + " ports=";
        for (size_t i = 0; i < conflicts.size(); ++i) {
            if (i > 0) r += ",";
            r += std::to_string(conflicts[i]);
        }
        findings.push_back(r);
    }
}

// --- n42: Trim oracle (bind probe vs RTM_GETLINK) ---
static void detectTrimOracle(std::vector<std::string> &findings) {
    // Count interfaces via bind probe
    int bindCount = 0;
    for (int ifindex = 1; ifindex < 128; ++ifindex) {
        char name[IF_NAMESIZE] = {0};
        if (if_indextoname(static_cast<unsigned int>(ifindex), name) != nullptr) {
            bindCount++;
        }
    }
    // Count interfaces via RTM_GETLINK
    int rtmCount = 0;
    {
        int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd >= 0) {
            struct {
                struct nlmsghdr nlh;
                struct ifinfomsg ifi;
            } req;
            std::memset(&req, 0, sizeof(req));
            req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
            req.nlh.nlmsg_type = RTM_GETLINK;
            req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.nlh.nlmsg_seq = 1;
            struct sockaddr_nl kernel;
            std::memset(&kernel, 0, sizeof(kernel));
            kernel.nl_family = AF_NETLINK;
            if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
                       reinterpret_cast<struct sockaddr *>(&kernel), sizeof(kernel)) >= 0) {
                char buf[8192];
                while (true) {
                    struct pollfd pfd = {fd, POLLIN, 0};
                    int pr = poll(&pfd, 1, 2000);
                    if (pr <= 0) break;
                    ssize_t len = recv(fd, buf, sizeof(buf), 0);
                    if (len <= 0) break;
                    bool done = false;
                    for (auto *nh = reinterpret_cast<struct nlmsghdr *>(buf);
                         NLMSG_OK(nh, static_cast<unsigned int>(len));
                         nh = NLMSG_NEXT(nh, len)) {
                        if (nh->nlmsg_type == NLMSG_DONE) { done = true; break; }
                        if (nh->nlmsg_type == NLMSG_ERROR) { done = true; break; }
                        if (nh->nlmsg_type == RTM_NEWLINK) rtmCount++;
                    }
                    if (done) break;
                }
            }
            close(fd);
        }
    }
    if (bindCount != rtmCount) {
        std::string r = "trim_oracle|bind_probe=" + std::to_string(bindCount) +
                        " rtm_getlink=" + std::to_string(rtmCount) + " MISMATCH";
        findings.push_back(r);
    }
}

// --- n38: if_indexname VPN leak ---
static void detectIfindexnameVpn(std::vector<std::string> &findings) {
    const std::vector<std::string> tunNames = {"tun0", "tun1", "utun0", "wg0", "ppp0", "xfrm0"};
    std::vector<std::string> found;
    for (int ifindex = 1; ifindex < 128; ++ifindex) {
        char name[IF_NAMESIZE] = {0};
        if (if_indextoname(static_cast<unsigned int>(ifindex), name) == nullptr) continue;
        for (const auto &tun : tunNames) {
            if (tun == name) {
                found.push_back(std::string(name) + "(idx=" + std::to_string(ifindex) + ")");
                break;
            }
        }
    }
    if (!found.empty()) {
        std::string r = "ifindexname_vpn|";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i > 0) r += ", ";
            r += found[i];
        }
        findings.push_back(r);
    }
}

// --- n22: UDP PMTU + TCP MSS combined ---
static void detectPmtuMssCombined(std::vector<std::string> &findings) {
    // Check TCP MSS
    int tcpFd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpFd >= 0) {
        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(443);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(tcpFd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == 0) {
            struct tcp_info info;
            socklen_t infoLen = sizeof(info);
            if (getsockopt(tcpFd, IPPROTO_TCP, TCP_INFO, &info, &infoLen) == 0) {
                unsigned int sndMss = info.tcpi_snd_mss;
                unsigned int rcvMss = info.tcpi_rcv_mss;
                std::string r = "pmtu_mss_combined|tcp_snd_mss=" + std::to_string(sndMss) +
                                " tcp_rcv_mss=" + std::to_string(rcvMss);
                findings.push_back(r);
            }
        }
        close(tcpFd);
    }
}

// --- n24: UDP send PMTU ---
static void detectUdpPmtu(std::vector<std::string> &findings) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // Try sending 1500 bytes (typical MTU)
    char buf[1500];
    std::memset(buf, 0, sizeof(buf));
    ssize_t sent = sendto(fd, buf, sizeof(buf), 0,
                          reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    if (sent > 0) {
        std::string r = "udp_pmtu_ok|sent=" + std::to_string(sent) + " bytes";
        findings.push_back(r);
    } else {
        std::string r = "udp_pmtu_fail|errno=" + std::to_string(errno);
        findings.push_back(r);
    }
    close(fd);
}

// --- n40: Normal path MTU ---
static void detectNormalPmtu(std::vector<std::string> &findings) {
    // Get MTU from primary interface
    struct ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) return;
    for (struct ifaddrs *cur = head; cur != nullptr; cur = cur->ifa_next) {
        if (cur->ifa_name == nullptr) continue;
        if (strcmp(cur->ifa_name, "lo") == 0) continue;
        if (strstr(cur->ifa_name, "tun") || strstr(cur->ifa_name, "wg") ||
            strstr(cur->ifa_name, "ppp")) continue;
        int mtu = fetchMtu(cur->ifa_name);
        if (mtu > 0) {
            std::string r = "normal_pmtu|iface=" + std::string(cur->ifa_name) +
                            " mtu=" + std::to_string(mtu);
            findings.push_back(r);
            break;
        }
    }
    freeifaddrs(head);
}

// --- n33: Traceroute probe ---
static void detectTraceroute(std::vector<std::string> &findings) {
    // Try a raw UDP traceroute-like probe to detect VPN encapsulation
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    // Set low TTL
    int ttl = 1;
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(33434); // standard traceroute port
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char buf[64];
    std::memset(buf, 0, sizeof(buf));
    // Non-blocking send to detect errors
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ssize_t sent = sendto(fd, buf, sizeof(buf), 0,
                          reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    if (sent < 0 && errno == EACCES) {
        findings.push_back("traceroute_denied|sendto denied");
    }
    close(fd);
}

// --- n34: Timing oracle (CNTVCT) ---
static void detectTimingOracle(std::vector<std::string> &findings) {
#if defined(__aarch64__)
    // Measure ARM cycle counter for socket operations
    auto readCycleCounter = []() -> uint64_t {
        uint64_t val;
        asm volatile("mrs %0, cntvct_el0" : "=r"(val));
        return val;
    };
    const int iterations = 10;
    uint64_t totalCycles = 0;
    uint64_t minCycles = UINT64_MAX;
    uint64_t maxCycles = 0;
    for (int i = 0; i < iterations; ++i) {
        uint64_t start = readCycleCounter();
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct sockaddr_in addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(53);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            char buf[64] = {0};
            sendto(fd, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
            close(fd);
        }
        uint64_t end = readCycleCounter();
        uint64_t elapsed = end - start;
        totalCycles += elapsed;
        if (elapsed < minCycles) minCycles = elapsed;
        if (elapsed > maxCycles) maxCycles = elapsed;
    }
    uint64_t avgCycles = totalCycles / static_cast<uint64_t>(iterations);
    std::string r = "timing_oracle|min=" + std::to_string(minCycles) +
                    " max=" + std::to_string(maxCycles) +
                    " avg=" + std::to_string(avgCycles);
    findings.push_back(r);
#else
    findings.push_back("timing_oracle|not_arm64");
#endif
}

// --- n35: Backpressure flood test ---
static bool isScanCancelled(JNIEnv *env, jobject cancellationSignal, jmethodID isCancelledMethod) {
    if (cancellationSignal == nullptr || isCancelledMethod == nullptr) return true;
    jboolean cancelled = env->CallBooleanMethod(cancellationSignal, isCancelledMethod);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return true;
    }
    return cancelled == JNI_TRUE;
}

static void detectBackpressure(
    JNIEnv *env,
    jobject cancellationSignal,
    jmethodID isCancelledMethod,
    std::vector<std::string> &findings
) {
    if (isScanCancelled(env, cancellationSignal, isCancelledMethod)) return;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int pktCount = 50000;
    const int pktSize = 1400;
    char buf[pktSize];
    std::memset(buf, 0, sizeof(buf));
    int sent = 0;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < pktCount; ++i) {
        if ((i & 63) == 0 && isScanCancelled(env, cancellationSignal, isCancelledMethod)) {
            close(fd);
            return;
        }
        ssize_t rc = sendto(fd, buf, sizeof(buf), MSG_DONTWAIT,
                            reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
        if (rc < 0) break;
        sent++;
    }
    auto end = std::chrono::steady_clock::now();
    close(fd);
    if (isScanCancelled(env, cancellationSignal, isCancelledMethod)) return;
    double elapsedMs = std::chrono::duration<double, std::milli>(end - start).count();
    double throughputMB = (static_cast<double>(sent) * pktSize) / (1024.0 * 1024.0) / (elapsedMs / 1000.0);
    std::string r = "backpressure|" + std::to_string(sent) + "/" + std::to_string(pktCount) +
                    " pkts sent in " + std::to_string(static_cast<int>(elapsedMs)) + "ms (" +
                    std::to_string(static_cast<int>(throughputMB)) + " MB/s)";
    findings.push_back(r);
}

// --- n36: GSO large send test ---
static void detectGsoLargeSend(std::vector<std::string> &findings) {
#if defined(__linux__)
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    // Use a segment size that fits a normal path MTU. GSO availability is
    // diagnostic only; lack of support is not VPN evidence.
    int gsoSize = 1200;
    int rc = setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &gsoSize, sizeof(gsoSize));
    if (rc < 0) {
        std::string r = "gso_failed|errno=" + std::to_string(errno);
        findings.push_back(r);
    } else {
        // GSO accepted, try sending
        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        char buf[4800];
        std::memset(buf, 0, sizeof(buf));
        ssize_t sent = sendto(fd, buf, sizeof(buf), 0,
                              reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
        if (sent < 0) {
            std::string r = "gso_send_failed|errno=" + std::to_string(errno);
            findings.push_back(r);
        } else {
            findings.push_back("gso_ok");
        }
    }
    close(fd);
#endif
}

// --- n37: Hardware timestamping check ---
static void detectHwTimestamp(std::vector<std::string> &findings) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct hwtstamp_config hwconfig;
    std::memset(&hwconfig, 0, sizeof(hwconfig));
    hwconfig.tx_type = HWTSTAMP_TX_ON;
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    ifr.ifr_data = reinterpret_cast<caddr_t>(&hwconfig);
    int rc = ioctl(fd, SIOCSHWTSTAMP, &ifr);
    if (rc == 0) {
        findings.push_back("hw_timestamp|lo configured");
    }
    // Also check for SCM_TIMESTAMPING
    int tsFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tsFd >= 0) {
        int tsFlags = SOF_TIMESTAMPING_SOFTWARE;
        setsockopt(tsFd, SOL_SOCKET, SO_TIMESTAMPING, &tsFlags, sizeof(tsFlags));
        close(tsFd);
    }
    close(fd);
}

// --- n33: Traceroute (already defined above, skipping duplicate) ---

static void detectLoopbackConflicts(std::vector<std::string> &findings) {
    static const int kVpnPorts[] = {51820, 1194, 443, 8443};
    for (int port : kVpnPorts) {
        int testFd = socket(AF_INET, SOCK_STREAM, 0);
        if (testFd < 0) continue;
        int opt = 1;
        setsockopt(testFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(testFd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            if (errno == EADDRINUSE) {
                std::string r = "loopback_port_conflict|port="; r.append(std::to_string(port));
                findings.push_back(r);
            }
        }
        close(testFd);
    }
}

static void detectSocketLeaks(std::vector<std::string> &findings) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct sockaddr_in localAddr;
        socklen_t addrLen = sizeof(localAddr);
        memset(&localAddr, 0, sizeof(localAddr));
        if (getsockname(fd, (struct sockaddr *)&localAddr, &addrLen) == 0) {
            if (localAddr.sin_addr.s_addr != 0) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &localAddr.sin_addr, ip, sizeof(ip));
                std::string r = "so_bindtodevice|local_ip="; r.append(ip);
                findings.push_back(r);
            }
        }
        close(fd);
    }
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
    {"nativeDetectRoot", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeDetectRoot)},
    {"nativeDetectEmulator", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeDetectEmulator)},
    {"nativeDetectVpnProperties", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeDetectVpnProperties)},
    {"nativeDetectVpnLeaks", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeDetectVpnLeaks)},
    {"nativeDetectVpnAdvanced", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeDetectVpnAdvanced)},
    {"nativeDetectVpnSyscalls", "()[Ljava/lang/String;", reinterpret_cast<void *>(nativeDetectVpnSyscalls)},
    {"nativeDetectVpnDetector", "(Lcom/notcvnt/rknhardering/ScanCancellationSignal;)[Ljava/lang/String;", reinterpret_cast<void *>(nativeDetectVpnDetector)},
};

// New consolidated VPN detector: returns ONLY the new deep checks (prefixed
// with "vdet|") so they can live in their own UI category, separate from the
// legacy NativeSignsChecker output.
jobjectArray nativeDetectVpnDetector(JNIEnv *env, jclass /*clazz*/, jobject cancellationSignal) {
    std::vector<std::string> raw;
    jmethodID isCancelledMethod = nullptr;
    if (cancellationSignal != nullptr) {
        jclass cancellationClass = env->GetObjectClass(cancellationSignal);
        if (cancellationClass != nullptr) {
            isCancelledMethod = env->GetMethodID(cancellationClass, "isCancelled", "()Z");
            env->DeleteLocalRef(cancellationClass);
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            isCancelledMethod = nullptr;
        }
    }
    detectSysfsLeak(raw);
    detectGetifaddrsVpn(raw);
    detectSysclassnetVpn(raw);
    detectRtmGetlinkVpn(raw);
    detectProcIfInet6(raw);
    detectProcIpv6RouteVpn(raw);
    detectProcNetDevVpn(raw);
    detectIfindexnameVpn(raw);
    detectRouteCount(raw);
    detectNormalPmtu(raw);
    detectFibTrieAccess(raw);
    detectInetDiagAccess(raw);
    detectVpnPolicyRules(raw);
    detectTrimOracle(raw);
    detectPmtuMssCombined(raw);
    detectUdpPmtu(raw);
    detectTraceroute(raw);
    detectTimingOracle(raw);
    detectBackpressure(env, cancellationSignal, isCancelledMethod, raw);
    detectGsoLargeSend(raw);
    detectHwTimestamp(raw);
    detectSetsockoptBindToDevice(raw);
    detectGetsocknameLeak(raw);
    detectUdpPortConflictPhysicalIp(raw);

    std::vector<std::string> prefixed;
    prefixed.reserve(raw.size());
    for (const auto &line : raw) {
        prefixed.push_back("vdet|" + line);
    }
    return toStringArray(env, prefixed);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass("com/notcvnt/rknhardering/probe/NativeSignsBridge");
    if (cls == nullptr) return JNI_ERR;
    jint rc = env->RegisterNatives(cls, kMethods, static_cast<jint>(std::size(kMethods)));
    env->DeleteLocalRef(cls);
    if (rc != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
