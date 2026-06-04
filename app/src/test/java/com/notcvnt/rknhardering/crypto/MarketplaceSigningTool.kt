package com.notcvnt.rknhardering.crypto

import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom

// Maintainer-only utility, not a real test.
// keygen:
//   ./gradlew :app:testDebugUnitTest --tests "*MarketplaceSigningTool.keygen" \
//       -Dmarketplace.out=path/to/dir
//
// sign current marketplace/catalog.json:
//   ./gradlew :app:testDebugUnitTest --tests "*MarketplaceSigningTool.signCatalog" \
//       -Dmarketplace.privkey=path/to/marketplace_privkey.hex
//
// Without the -D properties both methods are skipped (assumeTrue), so a normal
// test run never touches them.
class MarketplaceSigningTool {

    @Test
    fun keygen() {
        val out = System.getProperty("marketplace.out")
        assumeTrue("set -Dmarketplace.out=<dir> to run", out != null)
        val sk = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val pk = Ed25519.derivePublicKey(sk)
        val dir = File(out!!).also { it.mkdirs() }
        File(dir, "marketplace_privkey.hex").writeText(bytesToHex(sk))
        File(dir, "marketplace_pubkey.hex").writeText(bytesToHex(pk))
        println("priv -> ${dir.resolve("marketplace_privkey.hex").absolutePath} (KEEP SECRET)")
        println("pub  -> ${dir.resolve("marketplace_pubkey.hex").absolutePath}")
    }

    @Test
    fun signCatalog() {
        val privPath = System.getProperty("marketplace.privkey")
        assumeTrue("set -Dmarketplace.privkey=<path> to run", privPath != null)
        val repoRoot = findRepoRoot()
        val catalog = File(repoRoot, "marketplace/catalog.json").also { check(it.isFile) { "no catalog: $it" } }
        val sigOut = File(repoRoot, "marketplace/catalog.sig")
        val sk = hexToBytes(File(privPath!!).readText())
        val pk = Ed25519.derivePublicKey(sk)
        val sig = Ed25519.sign(sk, pk, catalog.readBytes())
        sigOut.writeText(bytesToHex(sig))
        println("signed ${catalog.length()} bytes -> ${sigOut.absolutePath}")
    }

    private fun findRepoRoot(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            if (File(dir, "marketplace/catalog.json").isFile) return dir
            dir = dir.parentFile
        }
        error("could not find marketplace/catalog.json above ${System.getProperty("user.dir")}")
    }

    companion object {
        fun bytesToHex(b: ByteArray): String {
            val sb = StringBuilder(b.size * 2)
            for (x in b) sb.append("%02x".format(x.toInt() and 0xFF))
            return sb.toString()
        }

        fun hexToBytes(hex: String): ByteArray {
            val clean = hex.trim().lowercase()
            require(clean.length % 2 == 0)
            val out = ByteArray(clean.length / 2)
            for (i in out.indices) out[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            return out
        }
    }
}
