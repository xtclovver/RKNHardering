package com.notcvnt.rknhardering.ui.main

import androidx.annotation.DrawableRes
import androidx.annotation.IdRes
import androidx.annotation.StringRes
import com.notcvnt.rknhardering.R

internal data class TileViewIds(
    @param:IdRes val card: Int,
    @param:IdRes val header: Int,
    @param:IdRes val dot: Int,
    @param:IdRes val icon: Int,
    @param:IdRes val title: Int,
    @param:IdRes val hint: Int,
    @param:IdRes val chevron: Int,
    @param:IdRes val body: Int,
)

internal data class TileSpec(
    val id: String,
    @param:StringRes val titleRes: Int,
    @param:DrawableRes val iconRes: Int,
    val views: TileViewIds,
)

/**
 * Static table of the main-screen category tiles: ids, header resources and
 * per-tile view ids, in accordion order. Replaces the per-view when-mappers
 * that previously lived in MainActivity.
 *
 * Note: [IPS] (IP channels) is a category id without a tile of its own — it
 * is deliberately absent from [ALL].
 */
internal object CategoryTiles {

    const val GEO = "geo"
    const val IPC = "ipc"
    const val CDN = "cdn"
    const val IPS = "ip_channels"
    const val DIR = "dir"
    const val IND = "ind"
    const val STN = "stn"
    const val ICM = "icmp"
    const val RTT = "rtt"
    const val LOC = "loc"
    const val BYP = "byp"
    const val NAT = "nat"
    const val REA = "rea"

    val ALL: List<TileSpec> = listOf(
        TileSpec(
            id = GEO,
            titleRes = R.string.main_card_geo_ip,
            iconRes = R.drawable.ic_public,
            views = TileViewIds(
                card = R.id.cardGeoIp,
                header = R.id.headerGeoIp,
                dot = R.id.headerDotGeoIp,
                icon = R.id.headerIconGeoIp,
                title = R.id.headerTitleGeoIp,
                hint = R.id.headerHintGeoIp,
                chevron = R.id.chevronGeoIp,
                body = R.id.bodyGeoIp,
            ),
        ),
        TileSpec(
            id = IPC,
            titleRes = R.string.main_card_ip_comparison,
            iconRes = R.drawable.ic_compare_arrows,
            views = TileViewIds(
                card = R.id.cardIpComparison,
                header = R.id.headerIpComparison,
                dot = R.id.headerDotIpComparison,
                icon = R.id.headerIconIpComparison,
                title = R.id.headerTitleIpComparison,
                hint = R.id.headerHintIpComparison,
                chevron = R.id.chevronIpComparison,
                body = R.id.bodyIpComparison,
            ),
        ),
        TileSpec(
            id = CDN,
            titleRes = R.string.main_card_cdn_pulling,
            iconRes = R.drawable.ic_cloud,
            views = TileViewIds(
                card = R.id.cardCdnPulling,
                header = R.id.headerCdnPulling,
                dot = R.id.headerDotCdnPulling,
                icon = R.id.headerIconCdnPulling,
                title = R.id.headerTitleCdnPulling,
                hint = R.id.headerHintCdnPulling,
                chevron = R.id.chevronCdnPulling,
                body = R.id.bodyCdnPulling,
            ),
        ),
        TileSpec(
            id = DIR,
            titleRes = R.string.main_card_direct_signs,
            iconRes = R.drawable.ic_security,
            views = TileViewIds(
                card = R.id.cardDirect,
                header = R.id.headerDirect,
                dot = R.id.headerDotDirect,
                icon = R.id.headerIconDirect,
                title = R.id.headerTitleDirect,
                hint = R.id.headerHintDirect,
                chevron = R.id.chevronDirect,
                body = R.id.bodyDirect,
            ),
        ),
        TileSpec(
            id = IND,
            titleRes = R.string.main_card_indirect_signs,
            iconRes = R.drawable.ic_lan,
            views = TileViewIds(
                card = R.id.cardIndirect,
                header = R.id.headerIndirect,
                dot = R.id.headerDotIndirect,
                icon = R.id.headerIconIndirect,
                title = R.id.headerTitleIndirect,
                hint = R.id.headerHintIndirect,
                chevron = R.id.chevronIndirect,
                body = R.id.bodyIndirect,
            ),
        ),
        TileSpec(
            id = NAT,
            titleRes = R.string.main_card_native_signs,
            iconRes = R.drawable.ic_lock,
            views = TileViewIds(
                card = R.id.cardNativeSigns,
                header = R.id.headerNativeSigns,
                dot = R.id.headerDotNativeSigns,
                icon = R.id.headerIconNativeSigns,
                title = R.id.headerTitleNativeSigns,
                hint = R.id.headerHintNativeSigns,
                chevron = R.id.chevronNativeSigns,
                body = R.id.bodyNativeSigns,
            ),
        ),
        TileSpec(
            id = STN,
            titleRes = R.string.main_card_call_transport,
            iconRes = R.drawable.ic_call,
            views = TileViewIds(
                card = R.id.cardCallTransport,
                header = R.id.headerCallTransport,
                dot = R.id.headerDotCallTransport,
                icon = R.id.headerIconCallTransport,
                title = R.id.headerTitleCallTransport,
                hint = R.id.headerHintCallTransport,
                chevron = R.id.chevronCallTransport,
                body = R.id.bodyCallTransport,
            ),
        ),
        TileSpec(
            id = ICM,
            titleRes = R.string.main_card_icmp_spoofing,
            iconRes = R.drawable.ic_network,
            views = TileViewIds(
                card = R.id.cardIcmpSpoofing,
                header = R.id.headerIcmpSpoofing,
                dot = R.id.headerDotIcmpSpoofing,
                icon = R.id.headerIconIcmpSpoofing,
                title = R.id.headerTitleIcmpSpoofing,
                hint = R.id.headerHintIcmpSpoofing,
                chevron = R.id.chevronIcmpSpoofing,
                body = R.id.bodyIcmpSpoofing,
            ),
        ),
        TileSpec(
            id = RTT,
            titleRes = R.string.main_card_rtt_triangulation,
            iconRes = R.drawable.ic_pin,
            views = TileViewIds(
                card = R.id.cardRttTriangulation,
                header = R.id.headerRttTriangulation,
                dot = R.id.headerDotRttTriangulation,
                icon = R.id.headerIconRttTriangulation,
                title = R.id.headerTitleRttTriangulation,
                hint = R.id.headerHintRttTriangulation,
                chevron = R.id.chevronRttTriangulation,
                body = R.id.bodyRttTriangulation,
            ),
        ),
        TileSpec(
            id = LOC,
            titleRes = R.string.main_card_location_signals,
            iconRes = R.drawable.ic_location_on,
            views = TileViewIds(
                card = R.id.cardLocation,
                header = R.id.headerLocation,
                dot = R.id.headerDotLocation,
                icon = R.id.headerIconLocation,
                title = R.id.headerTitleLocation,
                hint = R.id.headerHintLocation,
                chevron = R.id.chevronLocation,
                body = R.id.bodyLocation,
            ),
        ),
        TileSpec(
            id = BYP,
            titleRes = R.string.settings_split_tunnel,
            iconRes = R.drawable.ic_call_split,
            views = TileViewIds(
                card = R.id.cardBypass,
                header = R.id.headerBypass,
                dot = R.id.headerDotBypass,
                icon = R.id.headerIconBypass,
                title = R.id.headerTitleBypass,
                hint = R.id.headerHintBypass,
                chevron = R.id.chevronBypass,
                body = R.id.bodyBypass,
            ),
        ),
        TileSpec(
            id = REA,
            titleRes = R.string.main_card_domain_reachability,
            iconRes = R.drawable.ic_globe,
            views = TileViewIds(
                card = R.id.cardDomainReachability,
                header = R.id.headerDomainReachability,
                dot = R.id.headerDotDomainReachability,
                icon = R.id.headerIconDomainReachability,
                title = R.id.headerTitleDomainReachability,
                hint = R.id.headerHintDomainReachability,
                chevron = R.id.chevronDomainReachability,
                body = R.id.bodyDomainReachability,
            ),
        ),
    )
}
