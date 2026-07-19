#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <net/if.h>

namespace vpnhide_regression {

struct IfindexObservation {
    std::uint32_t firstIndex = 0;
    int reverseResult = -1;
    int reverseErrno = 0;
    std::uint32_t secondIndex = 0;
};

struct IfconfTailInspection {
    std::size_t staleSlots = 0;
    std::size_t vpnLikeSlots = 0;
    std::vector<std::string> names;
};

bool matchesVpnhideInterfaceName(std::string_view name);
std::vector<std::string> buildIfNameCandidates();
bool isStableIfindexConcealment(const IfindexObservation &observation);
IfconfTailInspection inspectIfconfTail(
    const ifreq *buffer,
    std::size_t capacity,
    std::size_t returnedBytes
);
void collectFindings(std::vector<std::string> &findings);

}  // namespace vpnhide_regression
