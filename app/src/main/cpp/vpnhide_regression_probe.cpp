#include "vpnhide_regression_probe.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <utility>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace vpnhide_regression {
namespace {

constexpr std::size_t kIfconfCapacity = 128;
constexpr std::size_t kMaxFindingSamples = 12;

char asciiLower(char value) {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<char>(value + ('a' - 'A'));
    }
    return value;
}

bool startsWithAsciiCaseInsensitive(std::string_view value, std::string_view prefix) {
    if (value.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (asciiLower(value[i]) != asciiLower(prefix[i])) return false;
    }
    return true;
}

bool containsAsciiCaseInsensitive(std::string_view value, std::string_view needle) {
    if (needle.empty() || value.size() < needle.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= value.size(); ++i) {
        if (startsWithAsciiCaseInsensitive(value.substr(i), needle)) return true;
    }
    return false;
}

bool isAsciiDigits(std::string_view value) {
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](char c) {
        return c >= '0' && c <= '9';
    });
}

bool isPlausibleInterfaceName(std::string_view name) {
    if (name.empty() || name.size() >= IFNAMSIZ) return false;
    return std::all_of(name.begin(), name.end(), [](char raw) {
        const unsigned char c = static_cast<unsigned char>(raw);
        return (c >= 'a' && c <= 'z') ||
               (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') ||
               c == '_' || c == '-' || c == '.' || c == ':' || c == '@';
    });
}

std::string readIfreqName(const ifreq &entry) {
    const std::size_t length = strnlen(entry.ifr_name, IFNAMSIZ);
    if (length == 0 || length >= IFNAMSIZ) return {};
    return std::string(entry.ifr_name, length);
}

bool writeIfreqName(ifreq &entry, std::string_view name) {
    if (name.empty() || name.size() >= IFNAMSIZ) return false;
    std::memset(&entry, 0, sizeof(entry));
    std::memcpy(entry.ifr_name, name.data(), name.size());
    entry.ifr_name[name.size()] = '\0';
    return true;
}

void appendUnique(std::vector<std::string> &out, std::string value) {
    if (std::find(out.begin(), out.end(), value) == out.end()) {
        out.push_back(std::move(value));
    }
}

void appendNumbered(
    std::vector<std::string> &out,
    std::string_view prefix,
    int maximum,
    bool includeBare
) {
    if (includeBare) appendUnique(out, std::string(prefix));
    for (int index = 0; index <= maximum; ++index) {
        appendUnique(out, std::string(prefix) + std::to_string(index));
    }
}

bool isConcealmentErrno(int value) {
    return value == ENODEV || value == ENXIO || value == ENOENT;
}

std::uint32_t queryIfindex(int fd, std::string_view name) {
    ifreq request{};
    if (!writeIfreqName(request, name)) return 0;

    errno = 0;
    if (ioctl(fd, SIOCGIFINDEX, &request) != 0) return 0;
    if (request.ifr_ifindex <= 0) return 0;
    return static_cast<std::uint32_t>(request.ifr_ifindex);
}

int reverseIfindex(int fd, std::uint32_t index, int &savedErrno) {
    ifreq request{};
    request.ifr_ifindex = static_cast<int>(index);

    errno = 0;
    const int result = ioctl(fd, SIOCGIFNAME, &request);
    savedErrno = errno;
    return result;
}

void detectIfindexAsymmetry(std::vector<std::string> &findings) {
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        findings.emplace_back(
            "vpnhide_ifindex_unavailable|stage=socket errno=" +
            std::to_string(errno)
        );
        return;
    }

    const auto candidates = buildIfNameCandidates();
    std::vector<std::string> samples;
    std::size_t total = 0;

    for (const auto &name : candidates) {
        const std::uint32_t firstIndex = queryIfindex(fd, name);
        if (firstIndex == 0) continue;

        int reverseErrno = 0;
        const int reverseResult = reverseIfindex(fd, firstIndex, reverseErrno);
        const std::uint32_t secondIndex = queryIfindex(fd, name);
        const IfindexObservation observation{
            firstIndex,
            reverseResult,
            reverseErrno,
            secondIndex,
        };
        if (!isStableIfindexConcealment(observation)) continue;

        ++total;
        if (samples.size() < kMaxFindingSamples) {
            std::ostringstream sample;
            sample << name << ':' << firstIndex
                   << "(reverse_errno=" << reverseErrno << ')';
            samples.push_back(sample.str());
        }
    }

    close(fd);
    if (total == 0) {
        findings.emplace_back("vpnhide_ifindex_clean|completed");
        return;
    }

    std::ostringstream detail;
    detail << "stable_asymmetries=" << total << " samples=";
    for (std::size_t i = 0; i < samples.size(); ++i) {
        if (i != 0) detail << ',';
        detail << samples[i];
    }
    if (total > samples.size()) detail << ",...+" << (total - samples.size());
    findings.emplace_back("vpnhide_ifindex_oracle|" + detail.str());
}

void detectIfconfTail(std::vector<std::string> &findings) {
    std::array<ifreq, kIfconfCapacity> buffer{};

    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        findings.emplace_back(
            "vpnhide_ifconf_unavailable|stage=socket errno=" +
            std::to_string(errno)
        );
        return;
    }

    ifconf request{};
    request.ifc_len = static_cast<int>(sizeof(buffer));
    request.ifc_req = buffer.data();

    errno = 0;
    const int result = ioctl(fd, SIOCGIFCONF, &request);
    const int savedErrno = errno;
    close(fd);
    if (result != 0 || request.ifc_len < 0) {
        findings.emplace_back(
            "vpnhide_ifconf_unavailable|stage=ioctl errno=" +
            std::to_string(savedErrno)
        );
        return;
    }

    const std::size_t returnedBytes = std::min<std::size_t>(
        static_cast<std::size_t>(request.ifc_len),
        sizeof(buffer)
    );
    if (returnedBytes == sizeof(buffer)) {
        findings.emplace_back(
            "vpnhide_ifconf_unavailable|stage=buffer_full returned_bytes=" +
            std::to_string(returnedBytes)
        );
        return;
    }
    const auto inspection = inspectIfconfTail(
        buffer.data(),
        buffer.size(),
        returnedBytes
    );
    if (inspection.staleSlots == 0) {
        findings.emplace_back(
            "vpnhide_ifconf_clean|returned_bytes=" +
            std::to_string(returnedBytes)
        );
        return;
    }

    std::ostringstream detail;
    detail << "returned_bytes=" << returnedBytes
           << " entry_size=" << sizeof(ifreq)
           << " stale_slots=" << inspection.staleSlots
           << " vpn_like=" << inspection.vpnLikeSlots
           << " names=";
    for (std::size_t i = 0; i < inspection.names.size(); ++i) {
        if (i != 0) detail << ',';
        detail << inspection.names[i];
    }

    const char *kind = inspection.vpnLikeSlots > 0
        ? "vpnhide_ifconf_tail_vpn|"
        : "vpnhide_ifconf_tail_oracle|";
    findings.emplace_back(std::string(kind) + detail.str());
}

}  // namespace

bool matchesVpnhideInterfaceName(std::string_view name) {
    if (name.empty()) return false;

    constexpr std::array<std::string_view, 9> prefixes = {
        "tun", "tap", "wg", "ppp", "ipsec", "xfrm", "utun", "l2tp", "gre",
    };
    for (const auto prefix : prefixes) {
        if (startsWithAsciiCaseInsensitive(name, prefix)) return true;
    }

    if (containsAsciiCaseInsensitive(name, "vpn")) return true;

    return name.size() > 2 &&
           asciiLower(name[0]) == 'i' &&
           asciiLower(name[1]) == 'f' &&
           isAsciiDigits(name.substr(2));
}

std::vector<std::string> buildIfNameCandidates() {
    std::vector<std::string> candidates;
    candidates.reserve(900);

    appendNumbered(candidates, "tun", 63, true);
    appendNumbered(candidates, "tap", 31, true);
    appendNumbered(candidates, "wg", 63, true);
    appendNumbered(candidates, "ppp", 31, true);
    appendNumbered(candidates, "ipsec", 31, true);
    appendNumbered(candidates, "xfrm", 31, true);
    appendNumbered(candidates, "utun", 31, true);
    appendNumbered(candidates, "l2tp", 31, true);
    appendNumbered(candidates, "gre", 31, true);

    appendNumbered(candidates, "if", 255, false);

    appendNumbered(candidates, "vpn", 63, true);
    for (const char *name : {
             "myvpn0", "xvpn1", "svpn0", "vpn-client", "custom_vpn_42",
             "TUN0", "WG0", "VPN",
         }) {
        appendUnique(candidates, name);
    }

    return candidates;
}

bool isStableIfindexConcealment(const IfindexObservation &observation) {
    return observation.firstIndex > 0 &&
           observation.reverseResult < 0 &&
           isConcealmentErrno(observation.reverseErrno) &&
           observation.secondIndex == observation.firstIndex;
}

IfconfTailInspection inspectIfconfTail(
    const ifreq *buffer,
    std::size_t capacity,
    std::size_t returnedBytes
) {
    IfconfTailInspection inspection;
    if (buffer == nullptr || capacity == 0) return inspection;

    const std::size_t totalBytes = capacity * sizeof(ifreq);
    const std::size_t boundedBytes = std::min(returnedBytes, totalBytes);
    const std::size_t firstTailSlot = std::min(
        capacity,
        (boundedBytes + sizeof(ifreq) - 1) / sizeof(ifreq)
    );

    for (std::size_t index = firstTailSlot; index < capacity; ++index) {
        const std::string name = readIfreqName(buffer[index]);
        if (!isPlausibleInterfaceName(name)) continue;

        ++inspection.staleSlots;
        if (matchesVpnhideInterfaceName(name)) ++inspection.vpnLikeSlots;
        if (inspection.names.size() < kMaxFindingSamples &&
            std::find(inspection.names.begin(), inspection.names.end(), name) ==
                inspection.names.end()) {
            inspection.names.push_back(name);
        }
    }
    return inspection;
}

void collectFindings(std::vector<std::string> &findings) {
    detectIfindexAsymmetry(findings);
    detectIfconfTail(findings);
}

}  // namespace vpnhide_regression
