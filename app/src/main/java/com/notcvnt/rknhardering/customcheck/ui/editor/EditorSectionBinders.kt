package com.notcvnt.rknhardering.customcheck.ui.editor

/** All twelve section binders of the custom-check editor, in visual order. */
internal class EditorSectionBinders(host: SectionBinder.Host) {
    val geoIp = GeoIpSectionBinder(host)
    val ipComparison = IpComparisonSectionBinder(host)
    val cdnPulling = CdnPullingSectionBinder(host)
    val directSigns = DirectSignsSectionBinder(host)
    val indirectSigns = IndirectSignsSectionBinder(host)
    val nativeSigns = NativeSignsSectionBinder(host)
    val locationSignals = LocationSignalsSectionBinder(host)
    val icmpSpoofing = IcmpSpoofingSectionBinder(host)
    val rttTriangulation = RttTriangulationSectionBinder(host)
    val callTransport = CallTransportSectionBinder(host)
    val splitTunnel = SplitTunnelSectionBinder(host)
    val domainReachability = DomainReachabilitySectionBinder(host)

    val ordered: List<SectionBinder<*>> = listOf(
        geoIp, ipComparison, cdnPulling, directSigns, indirectSigns, nativeSigns,
        locationSignals, icmpSpoofing, rttTriangulation, callTransport, splitTunnel,
        domainReachability,
    )
}
