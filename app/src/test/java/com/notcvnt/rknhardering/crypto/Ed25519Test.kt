package com.notcvnt.rknhardering.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Ed25519Test {

    private fun hex(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    // RFC 8032 §7.1 — TEST 1
    @Test
    fun `rfc8032 test1 empty message`() {
        val sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val sig = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555" +
                "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        assertArrayEquals(pk, Ed25519.derivePublicKey(sk))
        assertArrayEquals(sig, Ed25519.sign(sk, pk, ByteArray(0)))
        assertTrue(Ed25519.verify(pk, ByteArray(0), sig))
    }

    // RFC 8032 §7.1 — TEST 2
    @Test
    fun `rfc8032 test2 one byte`() {
        val sk = hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        val pk = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        val msg = hex("72")
        val sig = hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        assertArrayEquals(pk, Ed25519.derivePublicKey(sk))
        assertArrayEquals(sig, Ed25519.sign(sk, pk, msg))
        assertTrue(Ed25519.verify(pk, msg, sig))
    }

    @Test
    fun `verify rejects tampered message`() {
        val sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pk = Ed25519.derivePublicKey(sk)
        val msg = "hello".toByteArray()
        val sig = Ed25519.sign(sk, pk, msg)
        assertFalse(Ed25519.verify(pk, "hellp".toByteArray(), sig))
    }

    @Test
    fun `verify rejects flipped bit in signature`() {
        val sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pk = Ed25519.derivePublicKey(sk)
        val msg = "hello".toByteArray()
        val sig = Ed25519.sign(sk, pk, msg).copyOf()
        sig[0] = (sig[0].toInt() xor 1).toByte()
        assertFalse(Ed25519.verify(pk, msg, sig))
    }

    @Test
    fun `verify rejects wrong public key`() {
        val sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pk = Ed25519.derivePublicKey(sk)
        val msg = "hello".toByteArray()
        val sig = Ed25519.sign(sk, pk, msg)
        val otherPk = Ed25519.derivePublicKey(hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
        assertFalse(Ed25519.verify(otherPk, msg, sig))
    }

    @Test
    fun `verify rejects wrong length inputs`() {
        assertFalse(Ed25519.verify(ByteArray(31), "x".toByteArray(), ByteArray(64)))
        assertFalse(Ed25519.verify(ByteArray(32), "x".toByteArray(), ByteArray(63)))
    }
}
