#include "vpnhide_regression_probe.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <iostream>

namespace {

void setName(ifreq &entry, const char *name) {
    std::memset(&entry, 0, sizeof(entry));
    std::strncpy(entry.ifr_name, name, IFNAMSIZ - 1);
}

bool contains(const std::vector<std::string> &values, const char *value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

}  // namespace

int main() {
    using namespace vpnhide_regression;

    assert(matchesVpnhideInterfaceName("tun"));
    assert(matchesVpnhideInterfaceName("tun0"));
    assert(matchesVpnhideInterfaceName("Wg99"));
    assert(matchesVpnhideInterfaceName("custom_VPN_42"));
    assert(matchesVpnhideInterfaceName("if33"));
    assert(!matchesVpnhideInterfaceName("if"));
    assert(!matchesVpnhideInterfaceName("ifb0"));
    assert(!matchesVpnhideInterfaceName("wlan0"));

    const auto candidates = buildIfNameCandidates();
    assert(contains(candidates, "tun"));
    assert(contains(candidates, "tun0"));
    assert(contains(candidates, "if0"));
    assert(contains(candidates, "if255"));
    assert(!contains(candidates, "if"));

    assert(isStableIfindexConcealment({33, -1, ENODEV, 33}));
    assert(isStableIfindexConcealment({33, -1, ENXIO, 33}));
    assert(isStableIfindexConcealment({33, -1, ENOENT, 33}));
    assert(!isStableIfindexConcealment({33, 0, 0, 33}));
    assert(!isStableIfindexConcealment({33, -1, EACCES, 33}));
    assert(!isStableIfindexConcealment({33, -1, ENODEV, 34}));
    assert(!isStableIfindexConcealment({0, -1, ENODEV, 0}));

    std::array<ifreq, 4> stale{};
    setName(stale[0], "lo");
    setName(stale[1], "wlan0");
    setName(stale[2], "rmnet_data0");
    setName(stale[3], "tun0");
    const auto inspected = inspectIfconfTail(
        stale.data(), stale.size(), 2 * sizeof(ifreq)
    );
    assert(inspected.staleSlots == 2);
    assert(inspected.vpnLikeSlots == 1);
    assert(contains(inspected.names, "rmnet_data0"));
    assert(contains(inspected.names, "tun0"));

    const auto partialInspection = inspectIfconfTail(
        stale.data(), stale.size(), sizeof(ifreq) + 1
    );
    assert(partialInspection.staleSlots == 2);
    assert(partialInspection.vpnLikeSlots == 1);

    const auto clampedInspection = inspectIfconfTail(
        stale.data(), stale.size(), stale.size() * sizeof(ifreq) + 1
    );
    assert(clampedInspection.staleSlots == 0);
    assert(clampedInspection.vpnLikeSlots == 0);

    std::array<ifreq, 4> clean{};
    setName(clean[0], "lo");
    setName(clean[1], "wlan0");
    const auto cleanInspection = inspectIfconfTail(
        clean.data(), clean.size(), 2 * sizeof(ifreq)
    );
    assert(cleanInspection.staleSlots == 0);
    assert(cleanInspection.vpnLikeSlots == 0);

    std::vector<std::string> terminalOutcomes;
    collectFindings(terminalOutcomes);
    const auto ifindexOutcomes = std::count_if(
        terminalOutcomes.begin(), terminalOutcomes.end(),
        [](const std::string &value) { return value.rfind("vpnhide_ifindex_", 0) == 0; }
    );
    const auto ifconfOutcomes = std::count_if(
        terminalOutcomes.begin(), terminalOutcomes.end(),
        [](const std::string &value) { return value.rfind("vpnhide_ifconf_", 0) == 0; }
    );
    assert(ifindexOutcomes == 1);
    assert(ifconfOutcomes == 1);

    std::cout << "vpnhide regression probe core tests passed\n";
    return 0;
}
