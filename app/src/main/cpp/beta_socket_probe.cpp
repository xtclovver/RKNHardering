#include "beta_socket_probe.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr uint32_t kSequence = 0x42544131;
constexpr int kPollTimeoutMs = 1500;

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

jobjectArray toStringArray(JNIEnv *env, const std::vector<std::string> &items) {
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

std::string statusForErrno(int error) {
    switch (error) {
        case EACCES:
        case EPERM: return "permission_denied";
        case ENOPROTOOPT:
        case EOPNOTSUPP:
        case ENOSYS: return "unsupported";
        default: return "error";
    }
}

std::string errorRow(const char *check, int error, const char *stage) {
    std::ostringstream out;
    out << "beta_v1|check=" << check << "|status=" << statusForErrno(error)
        << "|errno=" << error << "|stage=" << stage;
    return out.str();
}

bool readIntOption(int fd, int option, int *value, int *error) {
    socklen_t length = sizeof(*value);
    if (getsockopt(fd, SOL_SOCKET, option, value, &length) == 0 && length >= sizeof(*value)) return true;
    *error = errno;
    return false;
}

bool readU64Option(int fd, int option, uint64_t *value, int *error) {
    socklen_t length = sizeof(*value);
    if (getsockopt(fd, SOL_SOCKET, option, value, &length) == 0 && length >= sizeof(*value)) return true;
    *error = errno;
    return false;
}

std::string socketHost(const sockaddr_storage &storage, socklen_t length) {
    if (length < sizeof(sa_family_t)) return {};
    char address[INET6_ADDRSTRLEN] = {0};
    if (storage.ss_family == AF_INET && length >= sizeof(sockaddr_in)) {
        const auto *value = reinterpret_cast<const sockaddr_in *>(&storage);
        if (inet_ntop(AF_INET, &value->sin_addr, address, sizeof(address)) == nullptr) return {};
    } else if (storage.ss_family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        const auto *value = reinterpret_cast<const sockaddr_in6 *>(&storage);
        if (inet_ntop(AF_INET6, &value->sin6_addr, address, sizeof(address)) == nullptr) return {};
    } else {
        return {};
    }
    return address;
}

uint16_t socketPort(const sockaddr_storage &storage, socklen_t length) {
    if (storage.ss_family == AF_INET && length >= sizeof(sockaddr_in)) {
        return ntohs(reinterpret_cast<const sockaddr_in *>(&storage)->sin_port);
    }
    if (storage.ss_family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
        return ntohs(reinterpret_cast<const sockaddr_in6 *>(&storage)->sin6_port);
    }
    return 0;
}

bool fillDiagId(int fd, inet_diag_req_v2 *request, uint64_t cookie) {
    sockaddr_storage local{};
    sockaddr_storage remote{};
    socklen_t localLength = sizeof(local);
    socklen_t remoteLength = sizeof(remote);
    if (getsockname(fd, reinterpret_cast<sockaddr *>(&local), &localLength) != 0 ||
        getpeername(fd, reinterpret_cast<sockaddr *>(&remote), &remoteLength) != 0 ||
        local.ss_family != remote.ss_family) {
        return false;
    }
    request->sdiag_family = static_cast<uint8_t>(local.ss_family);
    if (local.ss_family == AF_INET) {
        const auto *src = reinterpret_cast<const sockaddr_in *>(&local);
        const auto *dst = reinterpret_cast<const sockaddr_in *>(&remote);
        request->id.idiag_sport = src->sin_port;
        request->id.idiag_dport = dst->sin_port;
        std::memcpy(request->id.idiag_src, &src->sin_addr, sizeof(src->sin_addr));
        std::memcpy(request->id.idiag_dst, &dst->sin_addr, sizeof(dst->sin_addr));
    } else if (local.ss_family == AF_INET6) {
        const auto *src = reinterpret_cast<const sockaddr_in6 *>(&local);
        const auto *dst = reinterpret_cast<const sockaddr_in6 *>(&remote);
        request->id.idiag_sport = src->sin6_port;
        request->id.idiag_dport = dst->sin6_port;
        std::memcpy(request->id.idiag_src, &src->sin6_addr, sizeof(src->sin6_addr));
        std::memcpy(request->id.idiag_dst, &dst->sin6_addr, sizeof(dst->sin6_addr));
        request->id.idiag_if = src->sin6_scope_id;
    } else {
        return false;
    }
    request->id.idiag_cookie[0] = static_cast<uint32_t>(cookie);
    request->id.idiag_cookie[1] = static_cast<uint32_t>(cookie >> 32U);
    return true;
}

}  // namespace

jobjectArray nativeBetaSocketIdentity(JNIEnv *env, jclass, jint fd) {
    std::vector<std::string> rows;
    if (fd < 0) return toStringArray(env, {errorRow("socket_identity", EBADF, "fd")});

    uint64_t cookie = 0;
    uint64_t netnsCookie = 0;
    int mark = 0;
    int boundIfIndex = 0;
    int cookieError = 0;
    int markError = 0;
    int netnsError = 0;
    int ifIndexError = 0;
    const bool hasCookie = readU64Option(fd, SO_COOKIE, &cookie, &cookieError);
    const bool hasMark = readIntOption(fd, SO_MARK, &mark, &markError);
    const bool hasNetns = readU64Option(fd, SO_NETNS_COOKIE, &netnsCookie, &netnsError);
    const bool hasIfIndex = readIntOption(fd, SO_BINDTOIFINDEX, &boundIfIndex, &ifIndexError);

    char boundDevice[IF_NAMESIZE] = {0};
    socklen_t deviceLength = sizeof(boundDevice);
    const bool hasDevice = getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, boundDevice, &deviceLength) == 0;
    const int deviceError = hasDevice ? 0 : errno;

    sockaddr_storage local{};
    sockaddr_storage remote{};
    socklen_t localLength = sizeof(local);
    socklen_t remoteLength = sizeof(remote);
    const bool hasLocal = getsockname(fd, reinterpret_cast<sockaddr *>(&local), &localLength) == 0;
    const bool hasRemote = getpeername(fd, reinterpret_cast<sockaddr *>(&remote), &remoteLength) == 0;
    const bool hasKernelIdentity = hasCookie || hasMark || hasNetns || hasIfIndex;
    const bool identityComplete = hasCookie && hasLocal && hasRemote;

    std::ostringstream row;
    row << "beta_v1|check=socket_identity|status=" << (hasKernelIdentity ? "available" : "unavailable");
    row << "|identity_complete=" << (identityComplete ? "true" : "false");
    if (hasCookie) row << "|cookie=" << cookie; else row << "|cookie_errno=" << cookieError;
    if (hasMark) row << "|mark=" << static_cast<uint32_t>(mark); else row << "|mark_errno=" << markError;
    if (hasNetns) row << "|netns_cookie=" << netnsCookie; else row << "|netns_errno=" << netnsError;
    if (hasIfIndex) row << "|bound_ifindex=" << boundIfIndex; else row << "|ifindex_errno=" << ifIndexError;
    if (hasDevice && deviceLength > 0 && boundDevice[0] != '\0') row << "|bound_device=" << boundDevice;
    else if (!hasDevice) row << "|device_errno=" << deviceError;
    if (hasLocal) row << "|local_address=" << socketHost(local, localLength) << "|local_port=" << socketPort(local, localLength);
    if (hasRemote) row << "|remote_address=" << socketHost(remote, remoteLength) << "|remote_port=" << socketPort(remote, remoteLength);
    rows.push_back(row.str());
    return toStringArray(env, rows);
}

jobjectArray nativeBetaInetDiagByCookie(JNIEnv *env, jclass, jint fd, jobject cancellationSignal) {
    std::vector<std::string> rows;
    if (fd < 0) return toStringArray(env, {errorRow("inet_diag_cookie", EBADF, "fd")});
    uint64_t cookie = 0;
    int optionError = 0;
    if (!readU64Option(fd, SO_COOKIE, &cookie, &optionError)) {
        return toStringArray(env, {errorRow("inet_diag_cookie", optionError, "so_cookie")});
    }
    int protocol = 0;
    if (!readIntOption(fd, SO_PROTOCOL, &protocol, &optionError)) {
        return toStringArray(env, {errorRow("inet_diag_cookie", optionError, "so_protocol")});
    }

    struct Request {
        nlmsghdr header;
        inet_diag_req_v2 request;
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(inet_diag_req_v2));
    request.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = kSequence;
    request.request.sdiag_protocol = static_cast<uint8_t>(protocol);
    request.request.idiag_states = 0xffffffffU;
    if (!fillDiagId(fd, &request.request, cookie)) {
        return toStringArray(env, {errorRow("inet_diag_cookie", EINVAL, "socket_tuple")});
    }

    int netlink = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (netlink < 0) return toStringArray(env, {errorRow("inet_diag_cookie", errno, "socket")});
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(netlink, &request, request.header.nlmsg_len, 0,
               reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) < 0) {
        const int error = errno;
        close(netlink);
        return toStringArray(env, {errorRow("inet_diag_cookie", error, "send")});
    }
    pollfd descriptor{netlink, POLLIN, 0};
    int waitedMs = 0;
    while (descriptor.revents == 0 && waitedMs < kPollTimeoutMs) {
        if (isCancelled(env, cancellationSignal)) {
            close(netlink);
            return toStringArray(env, {"beta_v1|check=inet_diag_cookie|status=skipped|stage=cancelled"});
        }
        const int result = poll(&descriptor, 1, 50);
        if (result < 0) {
            const int error = errno;
            close(netlink);
            return toStringArray(env, {errorRow("inet_diag_cookie", error, "poll")});
        }
        waitedMs += 50;
    }
    if (descriptor.revents == 0) {
        close(netlink);
        return toStringArray(env, {errorRow("inet_diag_cookie", ETIMEDOUT, "poll")});
    }
    alignas(nlmsghdr) char buffer[8192];
    iovec iov{buffer, sizeof(buffer)};
    sockaddr_nl sender{};
    msghdr message{};
    message.msg_name = &sender;
    message.msg_namelen = sizeof(sender);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    const ssize_t length = recvmsg(netlink, &message, MSG_TRUNC);
    close(netlink);
    if (length < 0) return toStringArray(env, {errorRow("inet_diag_cookie", errno, "recv")});
    if ((message.msg_flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > sizeof(buffer)) {
        return toStringArray(env, {"beta_v1|check=inet_diag_cookie|status=truncated"});
    }

    int remaining = static_cast<int>(length);
    bool found = false;
    for (auto *header = reinterpret_cast<nlmsghdr *>(buffer); NLMSG_OK(header, remaining);
         header = NLMSG_NEXT(header, remaining)) {
        if (header->nlmsg_seq != kSequence || sender.nl_pid != 0) {
            return toStringArray(env, {"beta_v1|check=inet_diag_cookie|status=malformed_response|stage=identity"});
        }
        if (header->nlmsg_type == NLMSG_ERROR) {
            if (header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                return toStringArray(env, {"beta_v1|check=inet_diag_cookie|status=malformed_response|stage=nlmsg_error"});
            }
            const auto *error = reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
            if (error->error == 0) continue;
            return toStringArray(env, {errorRow("inet_diag_cookie", -error->error, "nlmsg")});
        }
        if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
            header->nlmsg_len < NLMSG_LENGTH(sizeof(inet_diag_msg))) {
            continue;
        }
        const auto *diag = reinterpret_cast<const inet_diag_msg *>(NLMSG_DATA(header));
        const uint64_t responseCookie = static_cast<uint64_t>(diag->id.idiag_cookie[0]) |
            (static_cast<uint64_t>(diag->id.idiag_cookie[1]) << 32U);
        if (responseCookie != cookie) continue;
        const bool uidMatches = diag->idiag_uid == static_cast<uint32_t>(getuid());
        std::ostringstream row;
        row << "beta_v1|check=inet_diag_cookie|status=available|matched=true"
            << "|cookie_match=true|uid=" << diag->idiag_uid
            << "|uid_match=" << (uidMatches ? "true" : "false")
            << "|critical_mismatch=" << (uidMatches ? "false" : "true")
            << "|ifindex=" << diag->id.idiag_if << "|inode=" << diag->idiag_inode;
        rows.push_back(row.str());
        found = true;
    }
    if (remaining != 0) {
        return toStringArray(env, {"beta_v1|check=inet_diag_cookie|status=malformed_response|stage=alignment"});
    }
    if (!found) rows.push_back("beta_v1|check=inet_diag_cookie|status=available|matched=false");
    return toStringArray(env, rows);
}

jobjectArray nativeBetaNetdIdentity(JNIEnv *env, jclass, jint fd) {
    void *library = dlopen("libnetd_client.so", RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) {
        return toStringArray(env, {"beta_v1|check=netd_netid|status=unavailable|stage=dlopen"});
    }
    using GetSocket = int (*)(unsigned *, int);
    using GetProcess = unsigned (*)();
    auto getSocket = reinterpret_cast<GetSocket>(dlsym(library, "getNetworkForSocket"));
    auto getProcess = reinterpret_cast<GetProcess>(dlsym(library, "getNetworkForProcess"));
    if (getSocket == nullptr || getProcess == nullptr) {
        dlclose(library);
        return toStringArray(env, {"beta_v1|check=netd_netid|status=unavailable|stage=dlsym"});
    }
    unsigned socketNetId = 0;
    const int socketResult = getSocket(&socketNetId, fd);
    if (socketResult != 0) {
        dlclose(library);
        return toStringArray(env, {errorRow("netd_netid", -socketResult, "get_socket")});
    }
    const unsigned processNetId = getProcess();
    std::ostringstream row;
    row << "beta_v1|check=netd_netid|status=available|socket_netid=" << socketNetId
        << "|process_netid=" << processNetId;
    dlclose(library);
    return toStringArray(env, {row.str()});
}
