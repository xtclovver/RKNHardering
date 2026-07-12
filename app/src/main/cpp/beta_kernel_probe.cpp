#include "beta_kernel_probe.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/genetlink.h>
#include <linux/if_tun.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
#include <linux/xfrm.h>
#include <net/if.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr size_t kBufferSize = 32 * 1024;
constexpr size_t kMaxResponseBytes = 256 * 1024;
constexpr size_t kMaxMessages = 1024;
constexpr size_t kMaxRows = 128;
constexpr int kPollSliceMs = 50;
constexpr int kDeadlineMs = 1500;

// linux/ovpn.h is newer than the NDK 28 UAPI snapshot. These values come from
// the generated Linux UAPI (Documentation/netlink/specs/ovpn.yaml). Family
// resolution supplies the runtime family version; an incompatible kernel reply
// is reported as unsupported/malformed rather than interpreted.
constexpr uint8_t kOvpnCmdPeerGet = 3;
constexpr uint16_t kOvpnAttrIfindex = 1;
constexpr uint16_t kOvpnAttrPeer = 2;

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

uint64_t readInterfaceCounter(unsigned int ifindex, const char *counter) {
    char interfaceName[IF_NAMESIZE]{};
    if (if_indextoname(ifindex, interfaceName) == nullptr) return 0;
    const std::string path = std::string("/sys/class/net/") + interfaceName + "/statistics/" + counter;
    ScopedFd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd.valid()) return 0;
    char value[32]{};
    const ssize_t length = read(fd.get(), value, sizeof(value) - 1);
    if (length <= 0) return 0;
    char *end = nullptr;
    const unsigned long long parsed = strtoull(value, &end, 10);
    return end == value ? 0 : static_cast<uint64_t>(parsed);
}

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
    const bool cancelled = env->CallBooleanMethod(signal, method) == JNI_TRUE;
    if (env->ExceptionCheck()) env->ExceptionClear();
    return cancelled;
}

jobjectArray toArray(JNIEnv *env, const std::vector<std::string> &items) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(items.size()), stringClass, nullptr);
    if (result == nullptr) {
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }
    for (jsize i = 0; i < static_cast<jsize>(items.size()); ++i) {
        jstring value = env->NewStringUTF(items[static_cast<size_t>(i)].c_str());
        if (value == nullptr) break;
        env->SetObjectArrayElement(result, i, value);
        env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(stringClass);
    return result;
}

const char *statusForError(int error) {
    if (error == EACCES || error == EPERM) return "permission_denied";
    if (error == ENOENT || error == ENOSYS || error == ENOPROTOOPT || error == EPROTONOSUPPORT ||
        error == EOPNOTSUPP || error == EAFNOSUPPORT) return "unsupported";
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

uint16_t attributeType(const nlattr *attribute) {
    return static_cast<uint16_t>(attribute->nla_type & NLA_TYPE_MASK);
}

bool attributeOk(const nlattr *attribute, int remaining) {
    return remaining >= static_cast<int>(sizeof(nlattr)) &&
        attribute->nla_len >= sizeof(nlattr) &&
        attribute->nla_len <= remaining;
}

bool netlinkMessageOk(const nlmsghdr *header, int remaining) {
    return remaining >= static_cast<int>(sizeof(nlmsghdr)) &&
        header->nlmsg_len >= sizeof(nlmsghdr) &&
        header->nlmsg_len <= static_cast<uint32_t>(remaining);
}

const nlattr *nextAttribute(const nlattr *attribute, int *remaining) {
    const int length = NLA_ALIGN(attribute->nla_len);
    *remaining -= length;
    return reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(attribute) + length);
}

const void *attributeData(const nlattr *attribute) {
    return reinterpret_cast<const char *>(attribute) + NLA_HDRLEN;
}

int attributePayload(const nlattr *attribute) {
    return static_cast<int>(attribute->nla_len) - NLA_HDRLEN;
}

template <typename T>
bool readAttribute(const nlattr *attribute, T *value) {
    if (attributePayload(attribute) < static_cast<int>(sizeof(T))) return false;
    std::memcpy(value, attributeData(attribute), sizeof(T));
    return true;
}

bool addAttribute(nlmsghdr *header, size_t capacity, uint16_t type,
                  const void *data, size_t size) {
    const size_t length = NLA_HDRLEN + size;
    const size_t next = NLMSG_ALIGN(header->nlmsg_len) + NLA_ALIGN(length);
    if (next > capacity || length > UINT16_MAX) return false;
    auto *attribute = reinterpret_cast<nlattr *>(
        reinterpret_cast<char *>(header) + NLMSG_ALIGN(header->nlmsg_len));
    attribute->nla_type = type;
    attribute->nla_len = static_cast<uint16_t>(length);
    if (size > 0) std::memcpy(reinterpret_cast<char *>(attribute) + NLA_HDRLEN, data, size);
    const size_t padding = NLA_ALIGN(length) - length;
    if (padding > 0) std::memset(reinterpret_cast<char *>(attribute) + length, 0, padding);
    header->nlmsg_len = static_cast<uint32_t>(next);
    return true;
}

bool sendNetlink(int fd, const void *data, size_t size) {
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    return sendto(fd, data, size, 0, reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) >= 0;
}

ssize_t receiveNetlink(JNIEnv *env, jobject signal, int fd, void *buffer,
                       size_t capacity, sockaddr_nl *sender, int *messageFlags) {
    pollfd descriptor{fd, POLLIN, 0};
    int waited = 0;
    while (waited < kDeadlineMs) {
        if (isCancelled(env, signal)) {
            errno = ECANCELED;
            return -1;
        }
        const int result = poll(&descriptor, 1, kPollSliceMs);
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (result > 0) break;
        waited += kPollSliceMs;
    }
    if (descriptor.revents == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
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

struct GenericFamily {
    int id = -1;
    uint8_t version = 1;
};

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

GenericFamily resolveFamily(JNIEnv *env, jobject signal, int fd, const char *name,
                            const char *check, std::string *failure) {
    constexpr uint32_t sequence = 0x42474631;
    struct Request {
        nlmsghdr header;
        genlmsghdr generic;
        char attributes[128];
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(genlmsghdr));
    request.header.nlmsg_type = GENL_ID_CTRL;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = sequence;
    request.generic.cmd = CTRL_CMD_GETFAMILY;
    request.generic.version = 1;
    if (!addAttribute(&request.header, sizeof(request), CTRL_ATTR_FAMILY_NAME,
                      name, std::strlen(name) + 1)) {
        *failure = errorRow(check, EMSGSIZE, "family_request");
        return {};
    }
    if (!sendNetlink(fd, &request, request.header.nlmsg_len)) {
        *failure = errorRow(check, errno, "family_send");
        return {};
    }
    alignas(nlmsghdr) char buffer[8192];
    sockaddr_nl sender{};
    int flags = 0;
    const ssize_t length = receiveNetlink(env, signal, fd, buffer, sizeof(buffer), &sender, &flags);
    if (length < 0) {
        *failure = errorRow(check, errno, "family_recv");
        return {};
    }
    if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > sizeof(buffer)) {
        *failure = simpleRow(check, "truncated", "family_recv");
        return {};
    }
    int remaining = static_cast<int>(length);
    for (auto *header = reinterpret_cast<nlmsghdr *>(buffer); netlinkMessageOk(header, remaining);
         header = NLMSG_NEXT(header, remaining)) {
        if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) {
            *failure = simpleRow(check, "malformed_response", "family_identity");
            return {};
        }
        int error = 0;
        if (parseNetlinkError(header, &error)) {
            if (error != 0) *failure = errorRow(check, error, "family_nlmsg");
            continue;
        }
        if (header->nlmsg_type != GENL_ID_CTRL ||
            header->nlmsg_len < NLMSG_LENGTH(sizeof(genlmsghdr))) continue;
        const auto *generic = reinterpret_cast<const genlmsghdr *>(NLMSG_DATA(header));
        int bytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(genlmsghdr)));
        auto *attribute = reinterpret_cast<const nlattr *>(
            reinterpret_cast<const char *>(generic) + GENL_HDRLEN);
        GenericFamily family;
        for (; attributeOk(attribute, bytes); attribute = nextAttribute(attribute, &bytes)) {
            if (attributeType(attribute) == CTRL_ATTR_FAMILY_ID) {
                uint16_t id = 0;
                if (!readAttribute(attribute, &id)) {
                    *failure = simpleRow(check, "malformed_response", "family_id");
                    return {};
                }
                family.id = id;
            } else if (attributeType(attribute) == CTRL_ATTR_VERSION) {
                uint32_t version = 1;
                if (readAttribute(attribute, &version)) family.version = static_cast<uint8_t>(version);
            }
        }
        if (bytes != 0 || family.id < 0) {
            *failure = simpleRow(check, "malformed_response", "family_attributes");
            return {};
        }
        return family;
    }
    if (failure->empty()) *failure = simpleRow(check, "unsupported", "family_absent");
    return {};
}

std::string safeInterfaceName(const char *data, size_t length) {
    size_t actual = 0;
    while (actual < length && data[actual] != '\0') ++actual;
    std::string result;
    result.reserve(actual);
    for (size_t i = 0; i < actual && result.size() < IFNAMSIZ - 1; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
            result.push_back(static_cast<char>(c));
        }
    }
    return result;
}

void countWireGuardPeers(const nlattr *peers, size_t *peerCount, size_t *activeCount,
                         uint64_t *rxBytes, uint64_t *txBytes) {
    int peerBytes = attributePayload(peers);
    auto *peer = reinterpret_cast<const nlattr *>(attributeData(peers));
    for (; attributeOk(peer, peerBytes); peer = nextAttribute(peer, &peerBytes)) {
        ++*peerCount;
        bool active = false;
        int bytes = attributePayload(peer);
        auto *attribute = reinterpret_cast<const nlattr *>(attributeData(peer));
        for (; attributeOk(attribute, bytes); attribute = nextAttribute(attribute, &bytes)) {
            const uint16_t type = attributeType(attribute);
            if (type == WGPEER_A_RX_BYTES || type == WGPEER_A_TX_BYTES) {
                uint64_t value = 0;
                if (!readAttribute(attribute, &value)) continue;
                if (type == WGPEER_A_RX_BYTES) *rxBytes += value; else *txBytes += value;
                if (value > 0) active = true;
            } else if (type == WGPEER_A_LAST_HANDSHAKE_TIME &&
                       attributePayload(attribute) >= static_cast<int>(sizeof(int64_t))) {
                int64_t seconds = 0;
                std::memcpy(&seconds, attributeData(attribute), sizeof(seconds));
                if (seconds > 0) active = true;
            }
        }
        if (active) ++*activeCount;
    }
}

std::vector<std::string> wireGuardProbe(JNIEnv *env, jobject signal) {
    const char *check = "wireguard_genl";
    ScopedFd socketFd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC));
    if (!socketFd.valid()) return {errorRow(check, errno, "socket")};
    std::string failure;
    const GenericFamily family = resolveFamily(env, signal, socketFd.get(), WG_GENL_NAME, check, &failure);
    if (family.id < 0) return {failure};
    constexpr uint32_t sequence = 0x42574731;
    struct Request { nlmsghdr header; genlmsghdr generic; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(genlmsghdr));
    request.header.nlmsg_type = static_cast<uint16_t>(family.id);
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    request.generic.cmd = WG_CMD_GET_DEVICE;
    request.generic.version = family.version;
    if (!sendNetlink(socketFd.get(), &request, request.header.nlmsg_len)) {
        return {errorRow(check, errno, "send")};
    }
    std::vector<char> buffer(kBufferSize);
    size_t totalBytes = 0;
    size_t messages = 0;
    size_t devices = 0;
    size_t peers = 0;
    size_t peersWithHistory = 0;
    uint64_t rxBytes = 0;
    uint64_t txBytes = 0;
    std::vector<std::string> interfaceNames;
    bool done = false;
    while (!done && messages < kMaxMessages) {
        sockaddr_nl sender{};
        int flags = 0;
        const ssize_t length = receiveNetlink(env, signal, socketFd.get(), buffer.data(), buffer.size(), &sender, &flags);
        if (length < 0) return {errorRow(check, errno, "recv")};
        if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) {
            return {simpleRow(check, "truncated", "recv")};
        }
        totalBytes += static_cast<size_t>(length);
        if (totalBytes > kMaxResponseBytes) return {simpleRow(check, "truncated", "cap")};
        int remaining = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); netlinkMessageOk(header, remaining);
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
            if (header->nlmsg_type != family.id || header->nlmsg_len < NLMSG_LENGTH(sizeof(genlmsghdr))) continue;
            ++devices;
            const auto *generic = reinterpret_cast<const genlmsghdr *>(NLMSG_DATA(header));
            int bytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(genlmsghdr)));
            auto *attribute = reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(generic) + GENL_HDRLEN);
            for (; attributeOk(attribute, bytes); attribute = nextAttribute(attribute, &bytes)) {
                const uint16_t type = attributeType(attribute);
                if (type == WGDEVICE_A_IFNAME && attributePayload(attribute) > 0 && interfaceNames.size() < 16) {
                    const std::string name = safeInterfaceName(
                        reinterpret_cast<const char *>(attributeData(attribute)),
                        static_cast<size_t>(attributePayload(attribute)));
                    if (!name.empty()) interfaceNames.push_back(name);
                } else if (type == WGDEVICE_A_PEERS) {
                    countWireGuardPeers(attribute, &peers, &peersWithHistory, &rxBytes, &txBytes);
                }
                // Private/public/preshared key attributes are intentionally ignored.
            }
            if (bytes != 0) return {simpleRow(check, "malformed_response", "attributes")};
        }
        if (remaining != 0) return {simpleRow(check, "malformed_response", "alignment")};
    }
    if (!done || messages >= kMaxMessages) return {simpleRow(check, "truncated", "message_cap")};
    std::ostringstream row;
    row << "beta_v1|check=" << check << "|status=available|devices=" << devices
        << "|peers=" << peers << "|peers_with_handshake_or_counters=" << peersWithHistory
        << "|rx_bytes=" << rxBytes << "|tx_bytes=" << txBytes;
    if (!interfaceNames.empty()) {
        row << "|interfaces=";
        for (size_t i = 0; i < interfaceNames.size(); ++i) {
            if (i > 0) row << ',';
            row << interfaceNames[i];
        }
    }
    std::vector<unsigned int> interfaceIndexes;
    for (const std::string &name : interfaceNames) {
        const unsigned int index = if_nametoindex(name.c_str());
        if (index != 0) interfaceIndexes.push_back(index);
    }
    if (!interfaceIndexes.empty()) {
        row << "|interface_indexes=";
        for (size_t i = 0; i < interfaceIndexes.size(); ++i) {
            if (i > 0) row << ',';
            row << interfaceIndexes[i];
        }
    }
    return {row.str()};
}

std::vector<unsigned int> linkKindInterfaces(JNIEnv *env, jobject signal, const char *kind,
                                             std::string *failure) {
    ScopedFd socketFd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (!socketFd.valid()) {
        *failure = errorRow("ovpn_genl", errno, "link_socket");
        return {};
    }
    constexpr uint32_t sequence = 0x424c4b31;
    struct Request { nlmsghdr header; ifinfomsg info; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
    request.header.nlmsg_type = RTM_GETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    request.info.ifi_family = AF_UNSPEC;
    if (!sendNetlink(socketFd.get(), &request, request.header.nlmsg_len)) {
        *failure = errorRow("ovpn_genl", errno, "link_send");
        return {};
    }
    std::vector<unsigned int> interfaces;
    std::vector<char> buffer(kBufferSize);
    size_t totalBytes = 0;
    size_t messages = 0;
    bool done = false;
    while (!done && messages < kMaxMessages) {
        sockaddr_nl sender{};
        int flags = 0;
        const ssize_t length = receiveNetlink(env, signal, socketFd.get(), buffer.data(), buffer.size(), &sender, &flags);
        if (length < 0) {
            *failure = errorRow("ovpn_genl", errno, "link_recv");
            return {};
        }
        if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) {
            *failure = simpleRow("ovpn_genl", "truncated", "link_recv");
            return {};
        }
        totalBytes += static_cast<size_t>(length);
        if (totalBytes > kMaxResponseBytes) {
            *failure = simpleRow("ovpn_genl", "truncated", "link_cap");
            return {};
        }
        int remaining = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); netlinkMessageOk(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            ++messages;
            if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) {
                *failure = simpleRow("ovpn_genl", "malformed_response", "link_identity");
                return {};
            }
            if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) {
                *failure = simpleRow("ovpn_genl", "truncated", "link_dump_interrupted");
                return {};
            }
            if (header->nlmsg_type == NLMSG_DONE) { done = true; remaining = 0; break; }
            int error = 0;
            if (parseNetlinkError(header, &error)) {
                if (error != 0) {
                    *failure = errorRow("ovpn_genl", error, "link_nlmsg");
                    return {};
                }
                continue;
            }
            if (header->nlmsg_type != RTM_NEWLINK || header->nlmsg_len < NLMSG_LENGTH(sizeof(ifinfomsg))) continue;
            const auto *info = reinterpret_cast<const ifinfomsg *>(NLMSG_DATA(header));
            int bytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(ifinfomsg)));
            auto *attribute = reinterpret_cast<const rtattr *>(IFLA_RTA(info));
            bool matched = false;
            for (; RTA_OK(attribute, bytes); attribute = RTA_NEXT(attribute, bytes)) {
                if (attribute->rta_type != IFLA_LINKINFO) continue;
                int nestedBytes = RTA_PAYLOAD(attribute);
                auto *nested = reinterpret_cast<const rtattr *>(RTA_DATA(attribute));
                for (; RTA_OK(nested, nestedBytes); nested = RTA_NEXT(nested, nestedBytes)) {
                    if (nested->rta_type != IFLA_INFO_KIND || RTA_PAYLOAD(nested) <= 0) continue;
                    const std::string value = safeInterfaceName(
                        reinterpret_cast<const char *>(RTA_DATA(nested)),
                        static_cast<size_t>(RTA_PAYLOAD(nested)));
                    if (value == kind) matched = true;
                }
                if (nestedBytes != 0) {
                    *failure = simpleRow("ovpn_genl", "malformed_response", "linkinfo_attributes");
                    return {};
                }
            }
            if (bytes != 0) {
                *failure = simpleRow("ovpn_genl", "malformed_response", "link_attributes");
                return {};
            }
            if (matched && info->ifi_index > 0 && interfaces.size() < 32) {
                interfaces.push_back(static_cast<unsigned int>(info->ifi_index));
            }
        }
        if (remaining != 0) {
            *failure = simpleRow("ovpn_genl", "malformed_response", "link_alignment");
            return {};
        }
    }
    if (!done) *failure = simpleRow("ovpn_genl", "truncated", "link_message_cap");
    return interfaces;
}

std::vector<std::string> ovpnProbe(JNIEnv *env, jobject signal) {
    const char *check = "ovpn_genl";
    ScopedFd socketFd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC));
    if (!socketFd.valid()) return {errorRow(check, errno, "socket")};
    std::string failure;
    const GenericFamily family = resolveFamily(env, signal, socketFd.get(), "ovpn", check, &failure);
    if (family.id < 0) return {failure};

    std::string linkFailure;
    const std::vector<unsigned int> candidates = linkKindInterfaces(env, signal, "ovpn", &linkFailure);
    if (!linkFailure.empty()) return {linkFailure};
    if (candidates.empty()) {
        return {"beta_v1|check=ovpn_genl|status=available|family=present|interfaces=0|peers=0"};
    }

    size_t peers = 0;
    size_t queried = 0;
    uint64_t rxBytes = 0;
    uint64_t txBytes = 0;
    uint32_t sequence = 0x424f5600;
    for (const unsigned int ifindex : candidates) {
        if (isCancelled(env, signal)) return {errorRow(check, ECANCELED, "cancelled")};
        struct Request { nlmsghdr header; genlmsghdr generic; char attributes[32]; } request{};
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(genlmsghdr));
        request.header.nlmsg_type = static_cast<uint16_t>(family.id);
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.header.nlmsg_seq = ++sequence;
        request.generic.cmd = kOvpnCmdPeerGet;
        request.generic.version = family.version;
        if (!addAttribute(&request.header, sizeof(request), kOvpnAttrIfindex, &ifindex, sizeof(ifindex))) {
            return {errorRow(check, EMSGSIZE, "request")};
        }
        if (!sendNetlink(socketFd.get(), &request, request.header.nlmsg_len)) return {errorRow(check, errno, "send")};
        std::vector<char> buffer(kBufferSize);
        size_t totalBytes = 0;
        size_t messages = 0;
        bool done = false;
        while (!done && messages < kMaxMessages) {
            sockaddr_nl sender{};
            int flags = 0;
            const ssize_t length = receiveNetlink(env, signal, socketFd.get(), buffer.data(), buffer.size(), &sender, &flags);
            if (length < 0) return {errorRow(check, errno, "recv")};
            if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) return {simpleRow(check, "truncated", "recv")};
            totalBytes += static_cast<size_t>(length);
            if (totalBytes > kMaxResponseBytes) return {simpleRow(check, "truncated", "cap")};
            int remaining = static_cast<int>(length);
            for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); netlinkMessageOk(header, remaining); header = NLMSG_NEXT(header, remaining)) {
                ++messages;
                if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) return {simpleRow(check, "malformed_response", "identity")};
                if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) return {simpleRow(check, "truncated", "dump_interrupted")};
                if (header->nlmsg_type == NLMSG_DONE) { done = true; remaining = 0; break; }
                int error = 0;
                if (parseNetlinkError(header, &error)) {
                    if (error != 0) return {errorRow(check, error, "nlmsg")};
                    continue;
                }
                if (header->nlmsg_type != family.id || header->nlmsg_len < NLMSG_LENGTH(sizeof(genlmsghdr))) continue;
                const auto *generic = reinterpret_cast<const genlmsghdr *>(NLMSG_DATA(header));
                int bytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(genlmsghdr)));
                auto *attribute = reinterpret_cast<const nlattr *>(reinterpret_cast<const char *>(generic) + GENL_HDRLEN);
                bool hasPeer = false;
                for (; attributeOk(attribute, bytes); attribute = nextAttribute(attribute, &bytes)) {
                    if (attributeType(attribute) == kOvpnAttrPeer) hasPeer = true;
                }
                if (bytes != 0) return {simpleRow(check, "malformed_response", "attributes")};
                if (hasPeer) ++peers;
            }
            if (remaining != 0) return {simpleRow(check, "malformed_response", "alignment")};
        }
        if (!done) return {simpleRow(check, "truncated", "message_cap")};
        ++queried;
        rxBytes += readInterfaceCounter(ifindex, "rx_bytes");
        txBytes += readInterfaceCounter(ifindex, "tx_bytes");
    }
    std::ostringstream row;
    row << "beta_v1|check=ovpn_genl|status=available|family=present|interfaces="
        << queried << "|peers=" << peers << "|rx_bytes=" << rxBytes << "|tx_bytes=" << txBytes
        << "|interface_indexes=";
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (i > 0) row << ',';
        row << candidates[i];
    }
    return {row.str()};
}

std::vector<std::string> xfrmProbe(JNIEnv *env, jobject signal, bool imsContext) {
    const char *check = "xfrm";
    ScopedFd socketFd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM));
    if (!socketFd.valid()) return {errorRow(check, errno, "socket")};
    constexpr uint32_t sequence = 0x42584631;
    struct Request { nlmsghdr header; xfrm_usersa_id id; } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(xfrm_usersa_id));
    request.header.nlmsg_type = XFRM_MSG_GETSA;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    request.id.family = AF_UNSPEC;
    if (!sendNetlink(socketFd.get(), &request, request.header.nlmsg_len)) return {errorRow(check, errno, "send")};
    std::vector<char> buffer(kBufferSize);
    size_t totalBytes = 0;
    size_t messages = 0;
    size_t states = 0;
    size_t tunnelStates = 0;
    size_t statesWithTraffic = 0;
    size_t natTraversalStates = 0;
    bool done = false;
    while (!done && messages < kMaxMessages) {
        sockaddr_nl sender{};
        int flags = 0;
        const ssize_t length = receiveNetlink(env, signal, socketFd.get(), buffer.data(), buffer.size(), &sender, &flags);
        if (length < 0) return {errorRow(check, errno, "recv")};
        if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > buffer.size()) return {simpleRow(check, "truncated", "recv")};
        totalBytes += static_cast<size_t>(length);
        if (totalBytes > kMaxResponseBytes) return {simpleRow(check, "truncated", "cap")};
        int remaining = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data()); netlinkMessageOk(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            ++messages;
            if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) return {simpleRow(check, "malformed_response", "identity")};
            if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) return {simpleRow(check, "truncated", "dump_interrupted")};
            if (header->nlmsg_type == NLMSG_DONE) { done = true; remaining = 0; break; }
            int error = 0;
            if (parseNetlinkError(header, &error)) {
                if (error != 0) return {errorRow(check, error, "nlmsg")};
                continue;
            }
            if (header->nlmsg_type != XFRM_MSG_NEWSA || header->nlmsg_len < NLMSG_LENGTH(sizeof(xfrm_usersa_info))) continue;
            const auto *state = reinterpret_cast<const xfrm_usersa_info *>(NLMSG_DATA(header));
            ++states;
            if (state->mode == XFRM_MODE_TUNNEL) ++tunnelStates;
            if (state->curlft.bytes > 0 || state->curlft.packets > 0) ++statesWithTraffic;
            int bytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(xfrm_usersa_info)));
            auto *attribute = reinterpret_cast<const nlattr *>(
                reinterpret_cast<const char *>(state) + NLMSG_ALIGN(sizeof(*state)));
            for (; attributeOk(attribute, bytes); attribute = nextAttribute(attribute, &bytes)) {
                if (attributeType(attribute) != XFRMA_ENCAP) continue;
                xfrm_encap_tmpl encapsulation{};
                if (!readAttribute(attribute, &encapsulation)) return {simpleRow(check, "malformed_response", "encap")};
                const uint16_t sourcePort = ntohs(encapsulation.encap_sport);
                const uint16_t destinationPort = ntohs(encapsulation.encap_dport);
                if (sourcePort == 4500 || destinationPort == 4500 || sourcePort == 500 || destinationPort == 500) {
                    ++natTraversalStates;
                }
            }
            if (bytes != 0) return {simpleRow(check, "malformed_response", "attributes")};
        }
        if (remaining != 0) return {simpleRow(check, "malformed_response", "alignment")};
    }
    if (!done || messages >= kMaxMessages) return {simpleRow(check, "truncated", "message_cap")};
    const char *classification = states == 0 ? "none" :
        (imsContext ? "system_ims" : "unknown_ipsec");
    std::ostringstream row;
    row << "beta_v1|check=xfrm|status=available|states=" << states
        << "|tunnel_states=" << tunnelStates << "|states_with_traffic=" << statesWithTraffic
        << "|nat_t_states=" << natTraversalStates << "|classification=" << classification;
    return {row.str()};
}

std::vector<std::string> tunFdProbe(JNIEnv *env, jobject signal) {
    const char *check = "tun_fd";
    DIR *directory = opendir("/proc/self/fd");
    if (directory == nullptr) return {errorRow(check, errno, "open_fd_dir")};
    const int directoryFd = dirfd(directory);
    size_t inspected = 0;
    size_t tunCount = 0;
    std::vector<std::string> names;
    int readError = 0;
    while (true) {
        errno = 0;
        dirent *entry = readdir(directory);
        if (entry == nullptr) {
            readError = errno;
            break;
        }
        if (isCancelled(env, signal)) {
            closedir(directory);
            return {errorRow(check, ECANCELED, "cancelled")};
        }
        char *end = nullptr;
        const long value = std::strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || value < 0 || value > INT32_MAX || value == directoryFd) continue;
        if (++inspected > 512) {
            closedir(directory);
            return {simpleRow(check, "truncated", "fd_cap")};
        }
        ScopedFd duplicate(fcntl(static_cast<int>(value), F_DUPFD_CLOEXEC, 0));
        if (!duplicate.valid()) continue;
        ifreq interface{};
        if (ioctl(duplicate.get(), TUNGETIFF, &interface) == 0) {
            ++tunCount;
            const std::string name = safeInterfaceName(interface.ifr_name, IFNAMSIZ);
            if (!name.empty() && names.size() < 16) names.push_back(name);
        } else if (errno != ENOTTY && errno != EINVAL && errno != EBADF && errno != EOPNOTSUPP) {
            if (errno == EACCES || errno == EPERM) {
                closedir(directory);
                return {errorRow(check, errno, "tungetiff")};
            }
        }
    }
    closedir(directory);
    if (readError != 0) return {errorRow(check, readError, "read_fd_dir")};
    std::ostringstream row;
    row << "beta_v1|check=tun_fd|status=available|inspected=" << inspected << "|tun_fds=" << tunCount;
    if (!names.empty()) {
        row << "|interfaces=";
        for (size_t i = 0; i < names.size(); ++i) {
            if (i > 0) row << ',';
            row << names[i];
        }
    }
    return {row.str()};
}

int bpfCall(bpf_cmd command, bpf_attr *attribute) {
#if defined(__NR_bpf)
    return static_cast<int>(syscall(__NR_bpf, command, attribute, sizeof(*attribute)));
#else
    (void)command;
    (void)attribute;
    errno = ENOSYS;
    return -1;
#endif
}

std::string currentCgroupPath() {
    ScopedFd fd(open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC));
    if (!fd.valid()) return {};
    char buffer[4096];
    const ssize_t length = read(fd.get(), buffer, sizeof(buffer) - 1);
    if (length <= 0) return {};
    buffer[length] = '\0';
    std::string content(buffer);
    const size_t marker = content.find("0::");
    if (marker == std::string::npos) return {};
    const size_t begin = marker + 3;
    const size_t end = content.find('\n', begin);
    std::string relative = content.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
    if (relative.empty() || relative[0] != '/' || relative.find("..") != std::string::npos) return {};
    return "/sys/fs/cgroup" + relative;
}

std::vector<std::string> bpfNetfilterProbe(JNIEnv *env, jobject signal, bool aggressive) {
    const char *check = "bpf_netfilter";
    std::vector<std::string> rows;
    const std::string cgroupPath = currentCgroupPath();
    if (cgroupPath.empty()) {
        rows.push_back(simpleRow("cgroup_bpf", "unavailable", "cgroup_path"));
    } else {
        ScopedFd cgroup(open(cgroupPath.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
        if (!cgroup.valid()) {
            rows.push_back(errorRow("cgroup_bpf", errno, "cgroup_open"));
        } else {
            const bpf_attach_type types[] = {
                BPF_CGROUP_INET_INGRESS,
                BPF_CGROUP_INET_EGRESS,
                BPF_CGROUP_INET_SOCK_CREATE,
            };
            size_t queried = 0;
            size_t programs = 0;
            for (const bpf_attach_type type : types) {
                if (isCancelled(env, signal)) return {errorRow(check, ECANCELED, "cancelled")};
                uint32_t ids[64]{};
                bpf_attr attribute{};
                attribute.query.target_fd = static_cast<uint32_t>(cgroup.get());
                attribute.query.attach_type = static_cast<uint32_t>(type);
                attribute.query.prog_cnt = 64;
                attribute.query.prog_ids = reinterpret_cast<uint64_t>(ids);
                if (bpfCall(BPF_PROG_QUERY, &attribute) == 0) {
                    ++queried;
                    programs += attribute.query.prog_cnt;
                } else if (errno != EINVAL && errno != EOPNOTSUPP && errno != ENOSYS) {
                    rows.push_back(errorRow("cgroup_bpf", errno, "prog_query"));
                    break;
                }
            }
            if (rows.empty()) {
                std::ostringstream row;
                row << "beta_v1|check=cgroup_bpf|status=" << (queried > 0 ? "available" : "unsupported")
                    << "|attach_types=" << queried
                    << "|programs=" << programs;
                rows.push_back(row.str());
            }
        }
    }

    if (aggressive) {
        static const char *const paths[] = {
            "/sys/fs/bpf/netd_shared/map_netd_uid_owner_map",
            "/sys/fs/bpf/netd_shared/map_netd_cookie_tag_map",
            "/sys/fs/bpf/netd_shared/map_netd_iface_index_name_map",
            "/sys/fs/bpf/map_netd_uid_owner_map",
        };
        size_t opened = 0;
        size_t denied = 0;
        size_t missing = 0;
        for (const char *path : paths) {
            if (isCancelled(env, signal)) return {errorRow(check, ECANCELED, "cancelled")};
            bpf_attr attribute{};
            attribute.pathname = reinterpret_cast<uint64_t>(path);
            ScopedFd map(bpfCall(BPF_OBJ_GET, &attribute));
            if (map.valid()) ++opened;
            else if (errno == EACCES || errno == EPERM) ++denied;
            else if (errno == ENOENT) ++missing;
            else {
                rows.push_back(errorRow("bpf_netd", errno, "obj_get"));
                break;
            }
        }
        std::ostringstream row;
        row << "beta_v1|check=bpf_netd|status="
            << (opened > 0 ? "available" : (denied > 0 ? "permission_denied" : "unsupported"))
            << "|opened=" << opened << "|denied=" << denied << "|missing=" << missing;
        rows.push_back(row.str());
    } else {
        rows.push_back(simpleRow("bpf_netd", "skipped", "aggressive_disabled"));
    }

    // A ruleset query is capability-only: no global rule bodies are retained.
    ScopedFd netfilter(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER));
    if (!netfilter.valid()) {
        rows.push_back(errorRow("netfilter_path", errno, "socket"));
    } else {
        constexpr uint32_t sequence = 0x424e4601;
        struct Request { nlmsghdr header; nfgenmsg generic; } request{};
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(nfgenmsg));
        request.header.nlmsg_type = static_cast<uint16_t>((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE);
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.header.nlmsg_seq = sequence;
        request.generic.nfgen_family = AF_UNSPEC;
        request.generic.version = NFNETLINK_V0;
        request.generic.res_id = 0;
        if (!sendNetlink(netfilter.get(), &request, request.header.nlmsg_len)) {
            rows.push_back(errorRow("netfilter_path", errno, "send"));
        } else {
            alignas(nlmsghdr) char buffer[8192];
            size_t tables = 0;
            size_t messages = 0;
            size_t totalBytes = 0;
            bool done = false;
            std::string failure;
            while (!done && messages < kMaxMessages && failure.empty()) {
                sockaddr_nl sender{};
                int flags = 0;
                const ssize_t length = receiveNetlink(env, signal, netfilter.get(), buffer, sizeof(buffer), &sender, &flags);
                if (length < 0) {
                    failure = errorRow("netfilter_path", errno, "recv");
                    break;
                }
                if ((flags & MSG_TRUNC) != 0 || static_cast<size_t>(length) > sizeof(buffer)) {
                    failure = simpleRow("netfilter_path", "truncated", "recv");
                    break;
                }
                totalBytes += static_cast<size_t>(length);
                if (totalBytes > kMaxResponseBytes) {
                    failure = simpleRow("netfilter_path", "truncated", "cap");
                    break;
                }
                int remaining = static_cast<int>(length);
                for (auto *header = reinterpret_cast<nlmsghdr *>(buffer); netlinkMessageOk(header, remaining); header = NLMSG_NEXT(header, remaining)) {
                    ++messages;
                    if (sender.nl_pid != 0 || header->nlmsg_seq != sequence) {
                        failure = simpleRow("netfilter_path", "malformed_response", "identity");
                        break;
                    }
                    if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) {
                        failure = simpleRow("netfilter_path", "truncated", "dump_interrupted");
                        break;
                    }
                    int error = 0;
                    if (parseNetlinkError(header, &error)) {
                        if (error != 0) failure = errorRow("netfilter_path", error, "nlmsg");
                    } else if (header->nlmsg_type == NLMSG_DONE) {
                        done = true;
                        remaining = 0;
                        break;
                    } else {
                        ++tables;
                    }
                }
                if (remaining != 0 && failure.empty()) {
                    failure = simpleRow("netfilter_path", "malformed_response", "alignment");
                }
            }
            if (!done && failure.empty()) failure = simpleRow("netfilter_path", "truncated", "message_cap");
            if (!failure.empty()) rows.push_back(failure);
            else {
                std::ostringstream row;
                row << "beta_v1|check=netfilter_path|status=available|table_messages=" << tables
                    << "|scope=capability_only";
                rows.push_back(row.str());
            }
        }
    }
    if (rows.size() > kMaxRows) rows.resize(kMaxRows);
    return rows;
}

}  // namespace

jobjectArray nativeBetaWireGuardProbe(JNIEnv *env, jclass, jobject cancellationSignal) {
    return toArray(env, wireGuardProbe(env, cancellationSignal));
}

jobjectArray nativeBetaOvpnProbe(JNIEnv *env, jclass, jobject cancellationSignal) {
    return toArray(env, ovpnProbe(env, cancellationSignal));
}

jobjectArray nativeBetaXfrmProbe(JNIEnv *env, jclass, jboolean imsContext, jobject cancellationSignal) {
    return toArray(env, xfrmProbe(env, cancellationSignal, imsContext == JNI_TRUE));
}

jobjectArray nativeBetaTunFdProbe(JNIEnv *env, jclass, jobject cancellationSignal) {
    return toArray(env, tunFdProbe(env, cancellationSignal));
}

jobjectArray nativeBetaBpfNetfilterProbe(JNIEnv *env, jclass, jboolean aggressive, jobject cancellationSignal) {
    return toArray(env, bpfNetfilterProbe(env, cancellationSignal, aggressive == JNI_TRUE));
}
