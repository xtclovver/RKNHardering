#include "beta_local_probe.h"

#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netlink.h>
#include <linux/nexthop.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr size_t kBufferSize = 32 * 1024;
constexpr size_t kMaxResponseBytes = 256 * 1024;
constexpr size_t kMaxMessages = 2048;
constexpr int kPollSliceMs = 50;
constexpr int kNetlinkDeadlineMs = 1500;
constexpr int kMaxMonitorMs = 5000;

class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) : fd_(fd) {}
    ~ScopedFd() { if (fd_ >= 0) close(fd_); }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    int get() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
private:
    int fd_;
};

bool isCancelled(JNIEnv *env, jobject signal) {
    if (signal == nullptr) return false;
    jclass signalClass = env->GetObjectClass(signal);
    if (signalClass == nullptr) return false;
    jmethodID method = env->GetMethodID(signalClass, "isCancelled", "()Z");
    env->DeleteLocalRef(signalClass);
    if (method == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    const bool result = env->CallBooleanMethod(signal, method) == JNI_TRUE;
    if (env->ExceptionCheck()) env->ExceptionClear();
    return result;
}

jobjectArray toArray(JNIEnv *env, const std::vector<std::string> &items) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray array = env->NewObjectArray(static_cast<jsize>(items.size()), stringClass, nullptr);
    if (array == nullptr) {
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }
    for (jsize i = 0; i < static_cast<jsize>(items.size()); ++i) {
        jstring value = env->NewStringUTF(items[static_cast<size_t>(i)].c_str());
        if (value == nullptr) break;
        env->SetObjectArrayElement(array, i, value);
        env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(stringClass);
    return array;
}

const char *statusForError(int error) {
    if (error == EACCES || error == EPERM) return "permission_denied";
    if (error == ENOENT || error == ENOSYS || error == ENOPROTOOPT ||
        error == EPROTONOSUPPORT || error == EOPNOTSUPP || error == EAFNOSUPPORT) return "unsupported";
    if (error == ECANCELED) return "skipped";
    if (error == EMSGSIZE || error == ENOBUFS) return "truncated";
    return "error";
}

std::string errorRow(const char *check, int error, const char *stage) {
    std::ostringstream row;
    row << "beta_v1|check=" << check << "|status=" << statusForError(error)
        << "|errno=" << error << "|stage=" << stage;
    return row.str();
}

std::string simpleRow(const char *check, const char *status, const char *stage = nullptr) {
    std::string row = std::string("beta_v1|check=") + check + "|status=" + status;
    if (stage != nullptr) row += std::string("|stage=") + stage;
    return row;
}

bool messageOk(const nlmsghdr *header, int remaining) {
    return remaining >= static_cast<int>(sizeof(nlmsghdr)) &&
        header->nlmsg_len >= sizeof(nlmsghdr) &&
        header->nlmsg_len <= static_cast<uint32_t>(remaining);
}

bool sendNetlink(int fd, const void *data, size_t size) {
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    return sendto(fd, data, size, 0, reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) >= 0;
}

ssize_t receiveNetlink(JNIEnv *env, jobject signal, int fd, void *buffer, size_t capacity,
                       sockaddr_nl *sender, int *messageFlags, int deadlineMs = kNetlinkDeadlineMs) {
    int waited = 0;
    while (waited < deadlineMs) {
        if (isCancelled(env, signal)) {
            errno = ECANCELED;
            return -1;
        }
        pollfd descriptor{fd, POLLIN, 0};
        const int slice = std::min(kPollSliceMs, deadlineMs - waited);
        const int result = poll(&descriptor, 1, slice);
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        waited += slice;
        if (result == 0) continue;
        if ((descriptor.revents & POLLIN) == 0) {
            errno = EIO;
            return -1;
        }
        iovec io{buffer, capacity};
        msghdr message{};
        message.msg_name = sender;
        message.msg_namelen = sizeof(*sender);
        message.msg_iov = &io;
        message.msg_iovlen = 1;
        const ssize_t length = recvmsg(fd, &message, MSG_TRUNC);
        *messageFlags = message.msg_flags;
        return length;
    }
    errno = ETIMEDOUT;
    return -1;
}

bool parseNetlinkError(const nlmsghdr *header, int *error) {
    if (header->nlmsg_type != NLMSG_ERROR) return false;
    if (header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
        *error = EPROTO;
    } else {
        const auto *message = reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
        *error = message->error == 0 ? 0 : -message->error;
    }
    return true;
}

std::string sanitizeUnixName(const void *data, size_t size) {
    const auto *bytes = reinterpret_cast<const unsigned char *>(data);
    std::string result;
    result.reserve(std::min<size_t>(size, 96));
    for (size_t i = 0; i < size && result.size() < 96; ++i) {
        const unsigned char value = bytes[i];
        if (i == 0 && value == 0) {
            result.push_back('@');
        } else if (value == 0) {
            break;
        } else if (std::isalnum(value) != 0 || value == '-' || value == '_' || value == '.' || value == '/') {
            result.push_back(static_cast<char>(std::tolower(value)));
        } else {
            result.push_back('_');
        }
    }
    return result;
}

const char *candidateMarker(const std::string &name) {
    static const char *const markers[] = {
        "xray", "v2ray", "clash", "mihomo", "sing-box", "wireguard", "openvpn",
        "tor", "redsocks", "tun2socks", "dnscrypt", "shadowsocks", "hysteria", "naive", "brook",
    };
    for (const char *marker : markers) {
        if (name.find(marker) != std::string::npos) return marker;
    }
    return nullptr;
}

std::vector<std::string> unixDiagProbe(JNIEnv *env, jobject signal) {
    const char *check = "unix_diag";
    ScopedFd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG));
    if (!fd.valid()) return {errorRow(check, errno, "socket")};
    constexpr uint32_t sequence = 0x42554431;
    struct Request { nlmsghdr header; unix_diag_req request; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(unix_diag_req));
    request.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    request.request.sdiag_family = AF_UNIX;
    request.request.sdiag_protocol = 0;
    request.request.udiag_states = UINT32_MAX;
    request.request.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER | UDIAG_SHOW_RQLEN | UDIAG_SHOW_UID;
    request.request.udiag_cookie[0] = UINT32_MAX;
    request.request.udiag_cookie[1] = UINT32_MAX;
    if (!sendNetlink(fd.get(), &request, request.header.nlmsg_len)) return {errorRow(check, errno, "send")};

    std::vector<char> buffer(kBufferSize);
    size_t totalBytes = 0;
    size_t messages = 0;
    size_t matched = 0;
    size_t ownUidMatches = 0;
    size_t peerLinks = 0;
    size_t queuedMatches = 0;
    std::vector<std::string> markers;
    bool done = false;
    while (!done && messages < kMaxMessages) {
        sockaddr_nl sender{};
        int flags = 0;
        const ssize_t length = receiveNetlink(env, signal, fd.get(), buffer.data(), buffer.size(), &sender, &flags);
        if (length < 0) return {errorRow(check, errno, "recv")};
        if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) return {simpleRow(check, "truncated", "recv")};
        totalBytes += static_cast<size_t>(length);
        if (totalBytes > kMaxResponseBytes) return {simpleRow(check, "truncated", "cap")};
        int remaining = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); messageOk(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            ++messages;
            if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) return {simpleRow(check, "malformed_response", "identity")};
            if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) return {simpleRow(check, "truncated", "dump_interrupted")};
            if (header->nlmsg_type == NLMSG_DONE) { done = true; remaining = 0; break; }
            int error = 0;
            if (parseNetlinkError(header, &error)) {
                if (error != 0) return {errorRow(check, error, "nlmsg")};
                continue;
            }
            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(unix_diag_msg))) continue;
            const auto *message = reinterpret_cast<const unix_diag_msg *>(NLMSG_DATA(header));
            int bytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(unix_diag_msg)));
            auto *attribute = reinterpret_cast<const rtattr *>(
                reinterpret_cast<const char *>(message) + NLMSG_ALIGN(sizeof(*message)));
            const char *marker = nullptr;
            bool hasPeer = false;
            bool ownUid = false;
            bool queued = false;
            for (; RTA_OK(attribute, bytes); attribute = RTA_NEXT(attribute, bytes)) {
                if (attribute->rta_type == UNIX_DIAG_NAME && RTA_PAYLOAD(attribute) > 0) {
                    const std::string name = sanitizeUnixName(RTA_DATA(attribute), RTA_PAYLOAD(attribute));
                    marker = candidateMarker(name);
                } else if (attribute->rta_type == UNIX_DIAG_PEER && RTA_PAYLOAD(attribute) >= sizeof(uint32_t)) {
                    hasPeer = true;
                } else if (attribute->rta_type == UNIX_DIAG_UID && RTA_PAYLOAD(attribute) >= sizeof(uint32_t)) {
                    uint32_t uid = 0;
                    std::memcpy(&uid, RTA_DATA(attribute), sizeof(uid));
                    ownUid = uid == static_cast<uint32_t>(getuid());
                } else if (attribute->rta_type == UNIX_DIAG_RQLEN && RTA_PAYLOAD(attribute) >= sizeof(unix_diag_rqlen)) {
                    unix_diag_rqlen queues{};
                    std::memcpy(&queues, RTA_DATA(attribute), sizeof(queues));
                    queued = queues.udiag_rqueue > 0 || queues.udiag_wqueue > 0;
                }
            }
            if (bytes != 0) return {simpleRow(check, "malformed_response", "attributes")};
            if (marker != nullptr) {
                ++matched;
                if (ownUid) ++ownUidMatches;
                if (hasPeer) ++peerLinks;
                if (queued) ++queuedMatches;
                const std::string markerValue(marker);
                if (std::find(markers.begin(), markers.end(), markerValue) == markers.end() && markers.size() < 16) {
                    markers.push_back(markerValue);
                }
            }
        }
        if (remaining != 0) return {simpleRow(check, "malformed_response", "alignment")};
    }
    if (!done || messages >= kMaxMessages) return {simpleRow(check, "truncated", "message_cap")};
    std::ostringstream row;
    row << "beta_v1|check=unix_diag|status=available|matched=" << matched
        << "|own_uid_matches=" << ownUidMatches << "|peer_links=" << peerLinks
        << "|queued_matches=" << queuedMatches;
    if (!markers.empty()) {
        row << "|markers=";
        for (size_t i = 0; i < markers.size(); ++i) {
            if (i > 0) row << ',';
            row << markers[i];
        }
    }
    return {row.str()};
}

bool sockaddrEqual(const sockaddr_storage &first, socklen_t firstLength,
                   const sockaddr_storage &second, socklen_t secondLength) {
    if (first.ss_family != second.ss_family) return false;
    if (first.ss_family == AF_INET && firstLength >= static_cast<socklen_t>(sizeof(sockaddr_in)) &&
        secondLength >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *left = reinterpret_cast<const sockaddr_in *>(&first);
        const auto *right = reinterpret_cast<const sockaddr_in *>(&second);
        return left->sin_port == right->sin_port && left->sin_addr.s_addr == right->sin_addr.s_addr;
    }
    if (first.ss_family == AF_INET6 && firstLength >= static_cast<socklen_t>(sizeof(sockaddr_in6)) &&
        secondLength >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto *left = reinterpret_cast<const sockaddr_in6 *>(&first);
        const auto *right = reinterpret_cast<const sockaddr_in6 *>(&second);
        return left->sin6_port == right->sin6_port &&
            std::memcmp(&left->sin6_addr, &right->sin6_addr, sizeof(in6_addr)) == 0;
    }
    return false;
}

bool sockaddrLoopback(const sockaddr_storage &address) {
    if (address.ss_family == AF_INET) {
        const auto *value = reinterpret_cast<const sockaddr_in *>(&address);
        return (ntohl(value->sin_addr.s_addr) >> 24) == 127;
    }
    if (address.ss_family == AF_INET6) {
        const auto *value = reinterpret_cast<const sockaddr_in6 *>(&address);
        return IN6_IS_ADDR_LOOPBACK(&value->sin6_addr);
    }
    return false;
}

std::vector<std::string> originalDestinationProbe(int fd) {
    const char *check = "original_destination";
    sockaddr_storage peer{};
    socklen_t peerLength = sizeof(peer);
    if (getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &peerLength) != 0) {
        return {errorRow(check, errno, "getpeername")};
    }
    sockaddr_storage original{};
    socklen_t originalLength = sizeof(original);
    int level = 0;
    int option = 0;
    if (peer.ss_family == AF_INET) {
        level = SOL_IP;
        option = SO_ORIGINAL_DST;
    } else if (peer.ss_family == AF_INET6) {
        level = SOL_IPV6;
        option = IP6T_SO_ORIGINAL_DST;
    } else {
        return {errorRow(check, EAFNOSUPPORT, "family")};
    }
    if (getsockopt(fd, level, option, &original, &originalLength) != 0) {
        return {errorRow(check, errno, "getsockopt")};
    }
    std::ostringstream row;
    row << "beta_v1|check=original_destination|status=available|family=" << peer.ss_family
        << "|matches_peer=" << (sockaddrEqual(peer, peerLength, original, originalLength) ? "true" : "false")
        << "|peer_loopback=" << (sockaddrLoopback(peer) ? "true" : "false")
        << "|original_loopback=" << (sockaddrLoopback(original) ? "true" : "false");
    return {row.str()};
}

std::vector<std::string> unixPeerIdentityProbe(int fd) {
    const char *check = "unix_peer_identity";
    sockaddr_storage peerAddress{};
    socklen_t peerAddressLength = sizeof(peerAddress);
    if (getpeername(fd, reinterpret_cast<sockaddr *>(&peerAddress), &peerAddressLength) != 0) {
        return {errorRow(check, errno, "getpeername")};
    }
    if (peerAddress.ss_family != AF_UNIX) return {errorRow(check, EAFNOSUPPORT, "family")};
    ucred credentials{};
    socklen_t credentialsLength = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialsLength) != 0 ||
        credentialsLength < static_cast<socklen_t>(sizeof(credentials))) {
        return {errorRow(check, errno == 0 ? EPROTO : errno, "peercred")};
    }
    char securityContext[256]{};
    socklen_t securityLength = sizeof(securityContext);
    const bool securityAvailable = getsockopt(fd, SOL_SOCKET, SO_PEERSEC,
        securityContext, &securityLength) == 0;
    const int securityError = securityAvailable ? 0 : errno;
    std::ostringstream row;
    row << "beta_v1|check=unix_peer_identity|status=available"
        << "|peer_uid_is_self=" << (credentials.uid == getuid() ? "true" : "false")
        << "|peer_pid_is_self=" << (credentials.pid == getpid() ? "true" : "false")
        << "|peersec_available=" << (securityAvailable ? "true" : "false");
    if (securityAvailable) {
        // Return only the SELinux type/domain component, never the full MLS range.
        std::string context(securityContext, strnlen(securityContext, sizeof(securityContext)));
        const size_t first = context.find(':');
        const size_t second = first == std::string::npos ? std::string::npos : context.find(':', first + 1);
        const size_t third = second == std::string::npos ? std::string::npos : context.find(':', second + 1);
        if (second != std::string::npos) {
            std::string domain = context.substr(second + 1,
                third == std::string::npos ? std::string::npos : third - second - 1);
            domain.erase(std::remove_if(domain.begin(), domain.end(), [](unsigned char value) {
                return std::isalnum(value) == 0 && value != '_' && value != '-';
            }), domain.end());
            const char *domainClass = "other";
            if (domain.find("isolated") != std::string::npos) domainClass = "isolated_app";
            else if (domain.find("untrusted") != std::string::npos) domainClass = "app";
            else if (domain == "netd" || domain.find("vpn") != std::string::npos) domainClass = "network_service";
            else if (domain == "system_server") domainClass = "system";
            if (!domain.empty()) row << "|peer_domain_class=" << domainClass;
        }
    } else if (securityError == EACCES || securityError == EPERM) {
        row << "|peersec_status=permission_denied";
    } else {
        row << "|peersec_status=unsupported";
    }
    return {row.str()};
}

std::vector<std::string> pktInfoProbe(int fd) {
    const char *check = "pktinfo";
    sockaddr_storage local{};
    socklen_t localLength = sizeof(local);
    if (getsockname(fd, reinterpret_cast<sockaddr *>(&local), &localLength) != 0) {
        return {errorRow(check, errno, "getsockname")};
    }
    int enabled = 0;
    socklen_t enabledLength = sizeof(enabled);
    int level = 0;
    int option = 0;
    if (local.ss_family == AF_INET) {
        level = SOL_IP;
        option = IP_PKTINFO;
    } else if (local.ss_family == AF_INET6) {
        level = SOL_IPV6;
        option = IPV6_RECVPKTINFO;
    } else {
        return {errorRow(check, EAFNOSUPPORT, "family")};
    }
    if (getsockopt(fd, level, option, &enabled, &enabledLength) != 0) {
        return {errorRow(check, errno, "getsockopt")};
    }
    std::ostringstream row;
    row << "beta_v1|check=pktinfo|status=available|family=" << local.ss_family
        << "|supported=true|enabled=" << (enabled != 0 ? "true" : "false")
        << "|ancillary_observed=false";
    return {row.str()};
}

std::vector<std::string> transitionMonitor(JNIEnv *env, jobject signal, int requestedDurationMs) {
    const char *check = "netlink_transitions";
    const int durationMs = std::max(0, std::min(requestedDurationMs, kMaxMonitorMs));
    ScopedFd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (!fd.valid()) return {errorRow(check, errno, "socket")};
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (bind(fd.get(), reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
        return {errorRow(check, errno, "bind")};
    }
    static const int groups[] = {
        RTNLGRP_LINK, RTNLGRP_TC, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR,
        RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE, RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE,
        RTNLGRP_NEXTHOP,
    };
    size_t joined = 0;
    size_t denied = 0;
    size_t unsupported = 0;
    for (const int group : groups) {
        if (setsockopt(fd.get(), SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) == 0) {
            ++joined;
        } else if (errno == EACCES || errno == EPERM) {
            ++denied;
        } else {
            ++unsupported;
        }
    }
    if (joined == 0) {
        return {simpleRow(check, denied > 0 ? "permission_denied" : "unsupported", "membership")};
    }

    size_t link = 0;
    size_t address = 0;
    size_t route = 0;
    size_t rule = 0;
    size_t qdisc = 0;
    size_t nexthop = 0;
    size_t messages = 0;
    size_t totalBytes = 0;
    int elapsed = 0;
    std::vector<char> buffer(kBufferSize);
    while (elapsed < durationMs && messages < kMaxMessages) {
        if (isCancelled(env, signal)) return {errorRow(check, ECANCELED, "cancelled")};
        pollfd descriptor{fd.get(), POLLIN, 0};
        const int slice = std::min(kPollSliceMs, durationMs - elapsed);
        const int result = poll(&descriptor, 1, slice);
        if (result < 0) {
            if (errno == EINTR) continue;
            return {errorRow(check, errno, "poll")};
        }
        elapsed += slice;
        if (result == 0) continue;
        if ((descriptor.revents & POLLIN) == 0) return {errorRow(check, EIO, "poll_events")};
        sockaddr_nl sender{};
        iovec io{buffer.data(), buffer.size()};
        msghdr message{};
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &io;
        message.msg_iovlen = 1;
        const ssize_t length = recvmsg(fd.get(), &message, MSG_TRUNC);
        if (length < 0) return {errorRow(check, errno, "recv")};
        if ((message.msg_flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) {
            return {simpleRow(check, "truncated", "recv")};
        }
        totalBytes += static_cast<size_t>(length);
        if (totalBytes > kMaxResponseBytes) return {simpleRow(check, "truncated", "cap")};
        int remaining = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); messageOk(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            ++messages;
            if (sender.nl_pid != 0) return {simpleRow(check, "malformed_response", "sender")};
            switch (header->nlmsg_type) {
                case RTM_NEWLINK: case RTM_DELLINK: ++link; break;
                case RTM_NEWADDR: case RTM_DELADDR: ++address; break;
                case RTM_NEWROUTE: case RTM_DELROUTE: ++route; break;
                case RTM_NEWRULE: case RTM_DELRULE: ++rule; break;
                case RTM_NEWQDISC: case RTM_DELQDISC: ++qdisc; break;
                case RTM_NEWNEXTHOP: case RTM_DELNEXTHOP: ++nexthop; break;
                default: break;
            }
        }
        if (remaining != 0) return {simpleRow(check, "malformed_response", "alignment")};
    }
    if (messages >= kMaxMessages) return {simpleRow(check, "truncated", "message_cap")};
    std::ostringstream row;
    row << "beta_v1|check=netlink_transitions|status=available|duration_ms=" << durationMs
        << "|joined_groups=" << joined << "|denied_groups=" << denied
        << "|unsupported_groups=" << unsupported << "|link=" << link
        << "|address=" << address << "|route=" << route << "|rule=" << rule
        << "|qdisc=" << qdisc << "|nexthop=" << nexthop;
    return {row.str()};
}

bool addRouteAttribute(nlmsghdr *header, size_t capacity, uint16_t type,
                       const void *data, size_t size) {
    const size_t length = RTA_LENGTH(size);
    const size_t next = NLMSG_ALIGN(header->nlmsg_len) + RTA_ALIGN(length);
    if (next > capacity || length > UINT16_MAX) return false;
    auto *attribute = reinterpret_cast<rtattr *>(reinterpret_cast<char *>(header) + NLMSG_ALIGN(header->nlmsg_len));
    attribute->rta_type = type;
    attribute->rta_len = static_cast<uint16_t>(length);
    std::memcpy(RTA_DATA(attribute), data, size);
    header->nlmsg_len = static_cast<uint32_t>(next);
    return true;
}

std::string queryNexthop(JNIEnv *env, jobject signal, uint32_t id) {
    ScopedFd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (!fd.valid()) return statusForError(errno);
    constexpr uint32_t sequence = 0x424e4831;
    struct Request { nlmsghdr header; nhmsg message; char attributes[32]; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(nhmsg));
    request.header.nlmsg_type = RTM_GETNEXTHOP;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = sequence;
    request.message.nh_family = AF_UNSPEC;
    if (!addRouteAttribute(&request.header, sizeof(request), NHA_ID, &id, sizeof(id)) ||
        !sendNetlink(fd.get(), &request, request.header.nlmsg_len)) return statusForError(errno == 0 ? EMSGSIZE : errno);
    alignas(nlmsghdr) char buffer[8192];
    sockaddr_nl sender{};
    int flags = 0;
    const ssize_t length = receiveNetlink(env, signal, fd.get(), buffer, sizeof(buffer), &sender, &flags);
    if (length < 0) return statusForError(errno);
    if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > sizeof(buffer)) return "truncated";
    int remaining = static_cast<int>(length);
    for (auto *header = reinterpret_cast<nlmsghdr *>(buffer); messageOk(header, remaining);
         header = NLMSG_NEXT(header, remaining)) {
        if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) return "malformed_response";
        int error = 0;
        if (parseNetlinkError(header, &error)) return error == 0 ? "malformed_response" : statusForError(error);
        if (header->nlmsg_type == RTM_NEWNEXTHOP && header->nlmsg_len >= NLMSG_LENGTH(sizeof(nhmsg))) return "available";
    }
    return "malformed_response";
}

std::vector<std::string> extendedRouteProbe(JNIEnv *env, jobject signal, int socketFd, int uid) {
    const char *check = "extended_rtnetlink";
    sockaddr_storage local{};
    sockaddr_storage remote{};
    socklen_t localLength = sizeof(local);
    socklen_t remoteLength = sizeof(remote);
    if (getsockname(socketFd, reinterpret_cast<sockaddr *>(&local), &localLength) != 0 ||
        getpeername(socketFd, reinterpret_cast<sockaddr *>(&remote), &remoteLength) != 0) {
        return {errorRow(check, errno, "socket_tuple")};
    }
    if (local.ss_family != remote.ss_family || (local.ss_family != AF_INET && local.ss_family != AF_INET6)) {
        return {errorRow(check, EAFNOSUPPORT, "family")};
    }
    constexpr uint32_t sequence = 0x42455231;
    struct Request { nlmsghdr header; rtmsg route; char attributes[256]; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = sequence;
    request.route.rtm_family = static_cast<uint8_t>(local.ss_family);
    request.route.rtm_dst_len = local.ss_family == AF_INET ? 32 : 128;
    request.route.rtm_src_len = local.ss_family == AF_INET ? 32 : 128;
    if (local.ss_family == AF_INET) {
        const auto *source = reinterpret_cast<const sockaddr_in *>(&local);
        const auto *destination = reinterpret_cast<const sockaddr_in *>(&remote);
        addRouteAttribute(&request.header, sizeof(request), RTA_SRC, &source->sin_addr, sizeof(source->sin_addr));
        addRouteAttribute(&request.header, sizeof(request), RTA_DST, &destination->sin_addr, sizeof(destination->sin_addr));
    } else {
        const auto *source = reinterpret_cast<const sockaddr_in6 *>(&local);
        const auto *destination = reinterpret_cast<const sockaddr_in6 *>(&remote);
        addRouteAttribute(&request.header, sizeof(request), RTA_SRC, &source->sin6_addr, sizeof(source->sin6_addr));
        addRouteAttribute(&request.header, sizeof(request), RTA_DST, &destination->sin6_addr, sizeof(destination->sin6_addr));
    }
    const uint32_t requestUid = static_cast<uint32_t>(uid);
    addRouteAttribute(&request.header, sizeof(request), RTA_UID, &requestUid, sizeof(requestUid));
    ScopedFd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (!fd.valid()) return {errorRow(check, errno, "socket")};
    if (!sendNetlink(fd.get(), &request, request.header.nlmsg_len)) return {errorRow(check, errno, "send")};
    alignas(nlmsghdr) char buffer[8192];
    sockaddr_nl sender{};
    int flags = 0;
    const ssize_t length = receiveNetlink(env, signal, fd.get(), buffer, sizeof(buffer), &sender, &flags);
    if (length < 0) return {errorRow(check, errno, "recv")};
    if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > sizeof(buffer)) return {simpleRow(check, "truncated", "recv")};
    int remaining = static_cast<int>(length);
    for (auto *header = reinterpret_cast<nlmsghdr *>(buffer); messageOk(header, remaining);
         header = NLMSG_NEXT(header, remaining)) {
        if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) return {simpleRow(check, "malformed_response", "identity")};
        int error = 0;
        if (parseNetlinkError(header, &error)) {
            if (error != 0) return {errorRow(check, error, "nlmsg")};
            continue;
        }
        if (header->nlmsg_type != RTM_NEWROUTE || header->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) continue;
        const auto *route = reinterpret_cast<const rtmsg *>(NLMSG_DATA(header));
        int bytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(rtmsg)));
        auto *attribute = RTM_RTA(route);
        uint32_t table = route->rtm_table;
        uint32_t output = 0;
        uint32_t routeUid = 0;
        uint32_t nexthopId = 0;
        uint32_t mtu = 0;
        uint32_t advmss = 0;
        uint16_t encapType = 0;
        size_t multipathHops = 0;
        bool hasRouteUid = false;
        bool hasEncap = false;
        bool hasVia = false;
        for (; RTA_OK(attribute, bytes); attribute = RTA_NEXT(attribute, bytes)) {
            const int payload = RTA_PAYLOAD(attribute);
            if (attribute->rta_type == RTA_TABLE && payload >= static_cast<int>(sizeof(table))) std::memcpy(&table, RTA_DATA(attribute), sizeof(table));
            else if (attribute->rta_type == RTA_OIF && payload >= static_cast<int>(sizeof(output))) std::memcpy(&output, RTA_DATA(attribute), sizeof(output));
            else if (attribute->rta_type == RTA_UID && payload >= static_cast<int>(sizeof(routeUid))) { std::memcpy(&routeUid, RTA_DATA(attribute), sizeof(routeUid)); hasRouteUid = true; }
            else if (attribute->rta_type == RTA_NH_ID && payload >= static_cast<int>(sizeof(nexthopId))) std::memcpy(&nexthopId, RTA_DATA(attribute), sizeof(nexthopId));
            else if (attribute->rta_type == RTA_ENCAP_TYPE && payload >= static_cast<int>(sizeof(encapType))) std::memcpy(&encapType, RTA_DATA(attribute), sizeof(encapType));
            else if (attribute->rta_type == RTA_ENCAP) hasEncap = true;
            else if (attribute->rta_type == RTA_VIA) hasVia = true;
            else if (attribute->rta_type == RTA_MULTIPATH) {
                int hopBytes = payload;
                auto *hop = reinterpret_cast<const rtnexthop *>(RTA_DATA(attribute));
                while (RTNH_OK(hop, hopBytes)) { ++multipathHops; hopBytes -= RTNH_ALIGN(hop->rtnh_len); hop = RTNH_NEXT(hop); }
                if (hopBytes != 0) return {simpleRow(check, "malformed_response", "multipath")};
            } else if (attribute->rta_type == RTA_METRICS) {
                int metricBytes = payload;
                auto *metric = reinterpret_cast<const rtattr *>(RTA_DATA(attribute));
                for (; RTA_OK(metric, metricBytes); metric = RTA_NEXT(metric, metricBytes)) {
                    uint32_t value = 0;
                    if (RTA_PAYLOAD(metric) < static_cast<int>(sizeof(value))) continue;
                    std::memcpy(&value, RTA_DATA(metric), sizeof(value));
                    if (metric->rta_type == RTAX_MTU) mtu = value;
                    else if (metric->rta_type == RTAX_ADVMSS) advmss = value;
                }
                if (metricBytes != 0) return {simpleRow(check, "malformed_response", "metrics")};
            }
        }
        if (bytes != 0) return {simpleRow(check, "malformed_response", "attributes")};
        const std::string nexthopStatus = nexthopId == 0 ? "not_referenced" : queryNexthop(env, signal, nexthopId);
        std::ostringstream row;
        row << "beta_v1|check=extended_rtnetlink|status=available|family=" << static_cast<int>(route->rtm_family)
            << "|table=" << table << "|oif=" << output << "|multipath_hops=" << multipathHops
            << "|encap=" << (hasEncap ? "true" : "false") << "|encap_type=" << encapType
            << "|via=" << (hasVia ? "true" : "false") << "|route_uid_present=" << (hasRouteUid ? "true" : "false")
            << "|route_uid_matches=" << (hasRouteUid && routeUid == requestUid ? "true" : "false")
            << "|mtu=" << mtu << "|advmss=" << advmss << "|nh_id=" << nexthopId
            << "|nh_query=" << nexthopStatus;
        return {row.str()};
    }
    return {simpleRow(check, "malformed_response", "no_route")};
}

}  // namespace

jobjectArray nativeBetaUnixDiagProbe(JNIEnv *env, jclass, jobject cancellationSignal) {
    return toArray(env, unixDiagProbe(env, cancellationSignal));
}

jobjectArray nativeBetaOriginalDestinationProbe(JNIEnv *env, jclass, jint fd) {
    return toArray(env, originalDestinationProbe(fd));
}

jobjectArray nativeBetaUnixPeerIdentityProbe(JNIEnv *env, jclass, jint fd) {
    return toArray(env, unixPeerIdentityProbe(fd));
}

jobjectArray nativeBetaPktInfoProbe(JNIEnv *env, jclass, jint fd) {
    return toArray(env, pktInfoProbe(fd));
}

jobjectArray nativeBetaTransitionMonitor(JNIEnv *env, jclass, jint durationMs, jobject cancellationSignal) {
    return toArray(env, transitionMonitor(env, cancellationSignal, durationMs));
}

jobjectArray nativeBetaExtendedRouteProbe(JNIEnv *env, jclass, jint fd, jint uid, jobject cancellationSignal) {
    return toArray(env, extendedRouteProbe(env, cancellationSignal, fd, uid));
}
