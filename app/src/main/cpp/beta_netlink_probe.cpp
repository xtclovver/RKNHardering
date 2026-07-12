#include "beta_netlink_probe.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <linux/fib_rules.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr uint32_t kRouteSequence = 0x42545231;
constexpr uint32_t kRuleSequence = 0x42545232;
constexpr uint32_t kAddressSequence = 0x42545233;
constexpr size_t kBufferSize = 64 * 1024;
constexpr size_t kMaxMessages = 2048;
constexpr size_t kMaxResponseBytes = 256 * 1024;

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
    return env->CallBooleanMethod(signal, method) == JNI_TRUE;
}

jobjectArray toArray(JNIEnv *env, const std::vector<std::string> &items) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(items.size()), stringClass, nullptr);
    for (jsize i = 0; i < static_cast<jsize>(items.size()); ++i) {
        jstring value = env->NewStringUTF(items[static_cast<size_t>(i)].c_str());
        env->SetObjectArrayElement(result, i, value);
        env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(stringClass);
    return result;
}

std::string statusForError(int error) {
    if (error == EACCES || error == EPERM) return "permission_denied";
    if (error == EOPNOTSUPP || error == ENOPROTOOPT || error == ENOSYS) return "unsupported";
    return "error";
}

std::string errorRow(const char *check, int error, const char *stage) {
    std::ostringstream row;
    row << "beta_v1|check=" << check << "|status=" << statusForError(error)
        << "|errno=" << error << "|stage=" << stage;
    return row.str();
}

bool addAttribute(nlmsghdr *header, size_t capacity, uint16_t type, const void *data, size_t size) {
    const size_t attributeLength = RTA_LENGTH(size);
    const size_t nextLength = NLMSG_ALIGN(header->nlmsg_len) + RTA_ALIGN(attributeLength);
    if (nextLength > capacity) return false;
    auto *attribute = reinterpret_cast<rtattr *>(reinterpret_cast<char *>(header) + NLMSG_ALIGN(header->nlmsg_len));
    attribute->rta_type = type;
    attribute->rta_len = static_cast<uint16_t>(attributeLength);
    std::memcpy(RTA_DATA(attribute), data, size);
    header->nlmsg_len = static_cast<uint32_t>(nextLength);
    return true;
}

int openRouteSocket() {
    return socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
}

bool sendRequest(int fd, const void *data, size_t size) {
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    return sendto(fd, data, size, 0, reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) >= 0;
}

ssize_t receivePacket(JNIEnv *env, jobject signal, int fd, char *buffer, size_t capacity,
                      sockaddr_nl *sender, int *flags) {
    pollfd descriptor{fd, POLLIN, 0};
    int waitedMs = 0;
    while (descriptor.revents == 0 && waitedMs < 1500) {
        if (isCancelled(env, signal)) {
            errno = ECANCELED;
            return -1;
        }
        const int result = poll(&descriptor, 1, 50);
        if (result < 0) return -1;
        waitedMs += 50;
    }
    if (descriptor.revents == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    iovec iov{buffer, capacity};
    msghdr message{};
    message.msg_name = sender;
    message.msg_namelen = sizeof(*sender);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    const ssize_t length = recvmsg(fd, &message, MSG_TRUNC);
    *flags = message.msg_flags;
    return length;
}

bool socketTuple(int fd, sockaddr_storage *local, socklen_t *localLength,
                 sockaddr_storage *remote, socklen_t *remoteLength) {
    return getsockname(fd, reinterpret_cast<sockaddr *>(local), localLength) == 0 &&
        getpeername(fd, reinterpret_cast<sockaddr *>(remote), remoteLength) == 0 &&
        local->ss_family == remote->ss_family;
}

std::string routeLookup(JNIEnv *env, jobject signal, int fd, int uid, int *selectedIfIndex, int *family) {
    sockaddr_storage local{};
    sockaddr_storage remote{};
    socklen_t localLength = sizeof(local);
    socklen_t remoteLength = sizeof(remote);
    if (!socketTuple(fd, &local, &localLength, &remote, &remoteLength)) {
        return errorRow("route_lookup", errno == 0 ? EINVAL : errno, "socket_tuple");
    }
    *family = local.ss_family;
    struct Request {
        nlmsghdr header;
        rtmsg route;
        char attributes[256];
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = kRouteSequence;
    request.route.rtm_family = static_cast<uint8_t>(*family);
    request.route.rtm_dst_len = *family == AF_INET ? 32 : 128;
    request.route.rtm_src_len = *family == AF_INET ? 32 : 128;
    if (*family == AF_INET) {
        const auto *src = reinterpret_cast<const sockaddr_in *>(&local);
        const auto *dst = reinterpret_cast<const sockaddr_in *>(&remote);
        addAttribute(&request.header, sizeof(request), RTA_SRC, &src->sin_addr, sizeof(src->sin_addr));
        addAttribute(&request.header, sizeof(request), RTA_DST, &dst->sin_addr, sizeof(dst->sin_addr));
    } else if (*family == AF_INET6) {
        const auto *src = reinterpret_cast<const sockaddr_in6 *>(&local);
        const auto *dst = reinterpret_cast<const sockaddr_in6 *>(&remote);
        addAttribute(&request.header, sizeof(request), RTA_SRC, &src->sin6_addr, sizeof(src->sin6_addr));
        addAttribute(&request.header, sizeof(request), RTA_DST, &dst->sin6_addr, sizeof(dst->sin6_addr));
    } else {
        return errorRow("route_lookup", EAFNOSUPPORT, "family");
    }
    const uint32_t requestUid = static_cast<uint32_t>(uid);
    addAttribute(&request.header, sizeof(request), RTA_UID, &requestUid, sizeof(requestUid));

    const int netlink = openRouteSocket();
    if (netlink < 0) return errorRow("route_lookup", errno, "socket");
    if (!sendRequest(netlink, &request, request.header.nlmsg_len)) {
        const int error = errno;
        close(netlink);
        return errorRow("route_lookup", error, "send");
    }
    alignas(nlmsghdr) char buffer[8192];
    sockaddr_nl sender{};
    int messageFlags = 0;
    const ssize_t length = receivePacket(env, signal, netlink, buffer, sizeof(buffer), &sender, &messageFlags);
    close(netlink);
    if (length < 0) return errno == ECANCELED
        ? "beta_v1|check=route_lookup|status=skipped|stage=cancelled"
        : errorRow("route_lookup", errno == 0 ? ETIMEDOUT : errno, "recv");
    if ((messageFlags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > sizeof(buffer)) {
        return "beta_v1|check=route_lookup|status=truncated";
    }
    int remaining = static_cast<int>(length);
    for (auto *header = reinterpret_cast<nlmsghdr *>(buffer); NLMSG_OK(header, remaining);
         header = NLMSG_NEXT(header, remaining)) {
        if (header->nlmsg_seq != kRouteSequence || sender.nl_pid != 0) {
            return "beta_v1|check=route_lookup|status=malformed_response|stage=identity";
        }
        if (header->nlmsg_type == NLMSG_ERROR) {
            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                return "beta_v1|check=route_lookup|status=malformed_response|stage=error_length";
            }
            const auto *error = reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
            return error->error == 0
                ? "beta_v1|check=route_lookup|status=malformed_response|stage=empty_ack"
                : errorRow("route_lookup", -error->error, "nlmsg");
        }
        if (header->nlmsg_type != RTM_NEWROUTE || header->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) continue;
        const auto *route = reinterpret_cast<const rtmsg *>(NLMSG_DATA(header));
        int attributeBytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(rtmsg)));
        auto *attribute = RTM_RTA(route);
        uint32_t table = route->rtm_table;
        uint32_t output = 0;
        for (; RTA_OK(attribute, attributeBytes); attribute = RTA_NEXT(attribute, attributeBytes)) {
            if (RTA_PAYLOAD(attribute) < sizeof(uint32_t)) continue;
            if (attribute->rta_type == RTA_TABLE) std::memcpy(&table, RTA_DATA(attribute), sizeof(table));
            if (attribute->rta_type == RTA_OIF) std::memcpy(&output, RTA_DATA(attribute), sizeof(output));
        }
        if (attributeBytes != 0) return "beta_v1|check=route_lookup|status=malformed_response|stage=attribute";
        *selectedIfIndex = static_cast<int>(output);
        std::ostringstream row;
        row << "beta_v1|check=route_lookup|status=available|family=" << static_cast<int>(route->rtm_family)
            << "|table=" << table << "|oif=" << output << "|type=" << static_cast<int>(route->rtm_type)
            << "|protocol=" << static_cast<int>(route->rtm_protocol) << "|scope=" << static_cast<int>(route->rtm_scope);
        return row.str();
    }
    return "beta_v1|check=route_lookup|status=malformed_response|stage=no_route";
}

std::string matchingRules(JNIEnv *env, jobject signal, int family, int uid) {
    struct Request { nlmsghdr header; fib_rule_hdr rule; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(fib_rule_hdr));
    request.header.nlmsg_type = RTM_GETRULE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = kRuleSequence;
    request.rule.family = static_cast<uint8_t>(family);
    const int netlink = openRouteSocket();
    if (netlink < 0) return errorRow("policy_rules", errno, "socket");
    if (!sendRequest(netlink, &request, request.header.nlmsg_len)) {
        const int error = errno; close(netlink); return errorRow("policy_rules", error, "send");
    }
    std::vector<char> buffer(kBufferSize);
    size_t messages = 0;
    size_t totalBytes = 0;
    size_t matched = 0;
    bool done = false;
    while (!done && messages < kMaxMessages) {
        sockaddr_nl sender{};
        int flags = 0;
        const ssize_t length = receivePacket(env, signal, netlink, buffer.data(), buffer.size(), &sender, &flags);
        if (length < 0) {
            const int error = errno;
            close(netlink);
            return error == ECANCELED
                ? "beta_v1|check=policy_rules|status=skipped|stage=cancelled"
                : errorRow("policy_rules", error == 0 ? ETIMEDOUT : error, "recv");
        }
        if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) {
            close(netlink); return "beta_v1|check=policy_rules|status=truncated";
        }
        totalBytes += static_cast<size_t>(length);
        if (totalBytes > kMaxResponseBytes) { close(netlink); return "beta_v1|check=policy_rules|status=truncated"; }
        int remaining = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            ++messages;
            if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) { close(netlink); return "beta_v1|check=policy_rules|status=truncated"; }
            if (header->nlmsg_seq != kRuleSequence || sender.nl_pid != 0) { close(netlink); return "beta_v1|check=policy_rules|status=malformed_response|stage=identity"; }
            if (header->nlmsg_type == NLMSG_DONE) {
                if (header->nlmsg_len < NLMSG_LENGTH(sizeof(int))) { close(netlink); return "beta_v1|check=policy_rules|status=malformed_response|stage=done_length"; }
                int completion = 0;
                std::memcpy(&completion, NLMSG_DATA(header), sizeof(completion));
                if (completion != 0) { close(netlink); return errorRow("policy_rules", completion < 0 ? -completion : completion, "done"); }
                done = true; remaining = 0; break;
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                if (header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) { close(netlink); return "beta_v1|check=policy_rules|status=malformed_response|stage=error_length"; }
                const auto *error = reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
                if (error->error != 0) { close(netlink); return errorRow("policy_rules", -error->error, "nlmsg"); }
                continue;
            }
            if (header->nlmsg_type != RTM_NEWRULE || header->nlmsg_len < NLMSG_LENGTH(sizeof(fib_rule_hdr))) continue;
            const auto *rule = reinterpret_cast<const fib_rule_hdr *>(NLMSG_DATA(header));
            int attributeBytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(fib_rule_hdr)));
            auto *attribute = reinterpret_cast<const rtattr *>(reinterpret_cast<const char *>(rule) + NLMSG_ALIGN(sizeof(*rule)));
            bool applies = true;
            for (; RTA_OK(attribute, attributeBytes); attribute = RTA_NEXT(attribute, attributeBytes)) {
                if (attribute->rta_type == FRA_UID_RANGE) {
                    if (RTA_PAYLOAD(attribute) < sizeof(fib_rule_uid_range)) { close(netlink); return "beta_v1|check=policy_rules|status=malformed_response|stage=uid_range"; }
                    fib_rule_uid_range range{};
                    std::memcpy(&range, RTA_DATA(attribute), sizeof(range));
                    applies = uid >= static_cast<int>(range.start) && uid <= static_cast<int>(range.end);
                }
            }
            if (attributeBytes != 0) { close(netlink); return "beta_v1|check=policy_rules|status=malformed_response|stage=attribute"; }
            if (applies) ++matched;
        }
        if (remaining != 0) { close(netlink); return "beta_v1|check=policy_rules|status=malformed_response|stage=alignment"; }
    }
    close(netlink);
    if (!done || messages >= kMaxMessages) return "beta_v1|check=policy_rules|status=truncated";
    std::ostringstream row;
    row << "beta_v1|check=policy_rules|status=available|matching_uid_rules=" << matched;
    return row.str();
}

std::string addressSnapshot(JNIEnv *env, jobject signal, int family, int selectedIfIndex) {
    struct Request { nlmsghdr header; ifaddrmsg address; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
    request.header.nlmsg_type = RTM_GETADDR;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = kAddressSequence;
    request.address.ifa_family = static_cast<uint8_t>(family);
    const int netlink = openRouteSocket();
    if (netlink < 0) return errorRow("rtnl_address", errno, "socket");
    if (!sendRequest(netlink, &request, request.header.nlmsg_len)) {
        const int error = errno; close(netlink); return errorRow("rtnl_address", error, "send");
    }
    std::vector<char> buffer(kBufferSize);
    size_t messages = 0;
    size_t totalBytes = 0;
    size_t matched = 0;
    bool done = false;
    while (!done && messages < kMaxMessages) {
        sockaddr_nl sender{};
        int flags = 0;
        const ssize_t length = receivePacket(env, signal, netlink, buffer.data(), buffer.size(), &sender, &flags);
        if (length < 0) {
            const int error = errno;
            close(netlink);
            return error == ECANCELED
                ? "beta_v1|check=rtnl_address|status=skipped|stage=cancelled"
                : errorRow("rtnl_address", error == 0 ? ETIMEDOUT : error, "recv");
        }
        if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) { close(netlink); return "beta_v1|check=rtnl_address|status=truncated"; }
        totalBytes += static_cast<size_t>(length);
        if (totalBytes > kMaxResponseBytes) { close(netlink); return "beta_v1|check=rtnl_address|status=truncated"; }
        int remaining = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            ++messages;
            if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) { close(netlink); return "beta_v1|check=rtnl_address|status=truncated"; }
            if (header->nlmsg_seq != kAddressSequence || sender.nl_pid != 0) { close(netlink); return "beta_v1|check=rtnl_address|status=malformed_response|stage=identity"; }
            if (header->nlmsg_type == NLMSG_DONE) {
                if (header->nlmsg_len < NLMSG_LENGTH(sizeof(int))) { close(netlink); return "beta_v1|check=rtnl_address|status=malformed_response|stage=done_length"; }
                int completion = 0;
                std::memcpy(&completion, NLMSG_DATA(header), sizeof(completion));
                if (completion != 0) { close(netlink); return errorRow("rtnl_address", completion < 0 ? -completion : completion, "done"); }
                done = true; remaining = 0; break;
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                if (header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) { close(netlink); return "beta_v1|check=rtnl_address|status=malformed_response|stage=error_length"; }
                const auto *error = reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
                if (error->error != 0) { close(netlink); return errorRow("rtnl_address", -error->error, "nlmsg"); }
                continue;
            }
            if (header->nlmsg_type != RTM_NEWADDR || header->nlmsg_len < NLMSG_LENGTH(sizeof(ifaddrmsg))) continue;
            const auto *address = reinterpret_cast<const ifaddrmsg *>(NLMSG_DATA(header));
            if (selectedIfIndex <= 0 || address->ifa_index == static_cast<uint32_t>(selectedIfIndex)) ++matched;
        }
        if (remaining != 0) { close(netlink); return "beta_v1|check=rtnl_address|status=malformed_response|stage=alignment"; }
    }
    close(netlink);
    if (!done || messages >= kMaxMessages) return "beta_v1|check=rtnl_address|status=truncated";
    std::ostringstream row;
    row << "beta_v1|check=rtnl_address|status=available|selected_ifindex=" << selectedIfIndex
        << "|address_count=" << matched;
    return row.str();
}

}  // namespace

jobjectArray nativeBetaRoutingSnapshot(JNIEnv *env, jclass, jint fd, jint uid, jobject cancellationSignal) {
    int selectedIfIndex = 0;
    int family = AF_UNSPEC;
    std::vector<std::string> rows;
    rows.push_back(routeLookup(env, cancellationSignal, fd, uid, &selectedIfIndex, &family));
    if (isCancelled(env, cancellationSignal)) return toArray(env, rows);
    if (family == AF_INET || family == AF_INET6) {
        rows.push_back(matchingRules(env, cancellationSignal, family, uid));
        if (isCancelled(env, cancellationSignal)) return toArray(env, rows);
        rows.push_back(addressSnapshot(env, cancellationSignal, family, selectedIfIndex));
    } else {
        rows.push_back("beta_v1|check=policy_rules|status=unsupported");
        rows.push_back("beta_v1|check=rtnl_address|status=unsupported");
    }
    return toArray(env, rows);
}
