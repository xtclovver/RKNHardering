package com.notcvnt.rknhardering.probe

import java.io.IOException
import java.net.URL

internal enum class IpEndpointFamilyHint {
    GENERIC,
    IPV4,
    IPV6,
}

internal data class IpEndpointSpec(
    val url: String,
    val familyHint: IpEndpointFamilyHint = familyHintForUrl(url),
)

internal suspend fun fetchFirstSuccessfulIp(
    endpoints: List<IpEndpointSpec>,
    attempt: suspend (IpEndpointSpec) -> Result<String>,
): Result<String> {
    var preferredFailure: EndpointFailure? = null

    for (endpoint in endpoints) {
        val result = attempt(endpoint)
        if (result.isSuccess) return result

        val error = result.exceptionOrNull() as? Exception ?: IOException("Unknown IP fetch error")
        val candidate = EndpointFailure(endpoint.familyHint, error)
        preferredFailure = selectPreferredFailure(preferredFailure, candidate)
    }

    return Result.failure(preferredFailure?.error ?: IOException("All IP endpoints failed"))
}

private data class EndpointFailure(
    val familyHint: IpEndpointFamilyHint,
    val error: Exception,
)

private fun selectPreferredFailure(
    current: EndpointFailure?,
    candidate: EndpointFailure,
): EndpointFailure {
    if (current == null) return candidate
    return if (failurePriority(candidate.familyHint) > failurePriority(current.familyHint)) {
        candidate
    } else {
        current
    }
}

private fun failurePriority(familyHint: IpEndpointFamilyHint): Int {
    return when (familyHint) {
        IpEndpointFamilyHint.GENERIC -> 3
        IpEndpointFamilyHint.IPV4 -> 2
        IpEndpointFamilyHint.IPV6 -> 1
    }
}

private fun familyHintForUrl(url: String): IpEndpointFamilyHint {
    val host = runCatching { URL(url).host.lowercase() }.getOrDefault("")
    return when {
        host.startsWith("ipv4-") || host.startsWith("api-ipv4.") -> IpEndpointFamilyHint.IPV4
        host.startsWith("ipv6-") || host.startsWith("api-ipv6.") -> IpEndpointFamilyHint.IPV6
        else -> IpEndpointFamilyHint.GENERIC
    }
}
