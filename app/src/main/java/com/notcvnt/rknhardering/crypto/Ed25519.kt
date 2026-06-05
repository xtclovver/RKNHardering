package com.notcvnt.rknhardering.crypto

import java.math.BigInteger
import java.security.MessageDigest

// RFC 8032 Ed25519 — verify only. Pure Kotlin, no third-party deps.
// Constant-time is not a goal (verification has no secret input). Sign is provided
// for the offline signing CLI under :app:src/test (host-only path).
object Ed25519 {

    private val P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val L = BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")
    private val D = BigInteger("-121665").mod(P)
        .multiply(BigInteger("121666").modInverse(P)).mod(P)
    private val I = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)
    private val B: Point = run {
        val by = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P)
        val bx = recoverX(by, false)
        Point(bx, by)
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        val a = runCatching { decodePoint(publicKey) }.getOrNull() ?: return false
        val r = signature.copyOfRange(0, 32)
        val s = decodeScalarLE(signature.copyOfRange(32, 64))
        if (s >= L) return false
        val rPoint = runCatching { decodePoint(r) }.getOrNull() ?: return false
        val md = MessageDigest.getInstance("SHA-512")
        md.update(r)
        md.update(publicKey)
        md.update(message)
        val k = decodeScalarLE(md.digest()).mod(L)
        val left = scalarMul(B, s)
        val right = add(rPoint, scalarMul(a, k))
        return left.x == right.x && left.y == right.y
    }

    fun sign(privateKey: ByteArray, publicKey: ByteArray, message: ByteArray): ByteArray {
        require(privateKey.size == 32 && publicKey.size == 32)
        val md = MessageDigest.getInstance("SHA-512")
        val h = md.digest(privateKey)
        val a = clampScalar(h.copyOfRange(0, 32))
        val prefix = h.copyOfRange(32, 64)

        md.reset(); md.update(prefix); md.update(message)
        val r = decodeScalarLE(md.digest()).mod(L)
        val rEnc = encodePoint(scalarMul(B, r))

        md.reset(); md.update(rEnc); md.update(publicKey); md.update(message)
        val k = decodeScalarLE(md.digest()).mod(L)
        val s = r.add(k.multiply(a)).mod(L)
        return rEnc + encodeScalarLE(s)
    }

    fun derivePublicKey(privateKey: ByteArray): ByteArray {
        require(privateKey.size == 32)
        val h = MessageDigest.getInstance("SHA-512").digest(privateKey)
        val a = clampScalar(h.copyOfRange(0, 32))
        return encodePoint(scalarMul(B, a))
    }

    private fun clampScalar(bytes: ByteArray): BigInteger {
        val c = bytes.copyOf()
        c[0] = (c[0].toInt() and 248).toByte()
        c[31] = (c[31].toInt() and 127 or 64).toByte()
        return decodeScalarLE(c)
    }

    private fun decodeScalarLE(bytes: ByteArray): BigInteger {
        val be = ByteArray(bytes.size + 1)
        for (i in bytes.indices) be[bytes.size - i] = bytes[i]
        return BigInteger(be)
    }

    private fun encodeScalarLE(s: BigInteger): ByteArray {
        val be = s.toByteArray()
        val out = ByteArray(32)
        val take = minOf(be.size, 32)
        for (i in 0 until take) out[i] = be[be.size - 1 - i]
        return out
    }

    private data class Point(val x: BigInteger, val y: BigInteger)

    private fun recoverX(y: BigInteger, sign: Boolean): BigInteger {
        val y2 = y.multiply(y).mod(P)
        val num = y2.subtract(BigInteger.ONE).mod(P)
        val den = D.multiply(y2).add(BigInteger.ONE).mod(P)
        val xx = num.multiply(den.modInverse(P)).mod(P)
        var x = xx.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
        if (x.multiply(x).subtract(xx).mod(P) != BigInteger.ZERO) {
            x = x.multiply(I).mod(P)
        }
        if (x.multiply(x).subtract(xx).mod(P) != BigInteger.ZERO) {
            throw IllegalArgumentException("no sqrt")
        }
        if ((x.testBit(0)) != sign) x = P.subtract(x).mod(P)
        return x
    }

    private fun decodePoint(bytes: ByteArray): Point {
        require(bytes.size == 32)
        val raw = bytes.copyOf()
        val sign = (raw[31].toInt() and 0x80) != 0
        raw[31] = (raw[31].toInt() and 0x7F).toByte()
        val y = decodeScalarLE(raw)
        if (y >= P) throw IllegalArgumentException("y out of range")
        val x = recoverX(y, sign)
        val p = Point(x, y)
        if (!onCurve(p)) throw IllegalArgumentException("not on curve")
        return p
    }

    private fun encodePoint(p: Point): ByteArray {
        val out = encodeScalarLE(p.y.mod(P))
        if (p.x.testBit(0)) out[31] = (out[31].toInt() or 0x80).toByte()
        return out
    }

    private fun onCurve(p: Point): Boolean {
        val x2 = p.x.multiply(p.x).mod(P)
        val y2 = p.y.multiply(p.y).mod(P)
        val lhs = y2.subtract(x2).mod(P)
        val rhs = BigInteger.ONE.add(D.multiply(x2).mod(P).multiply(y2).mod(P)).mod(P)
        return lhs == rhs
    }

    private fun add(p1: Point, p2: Point): Point {
        val xy = p1.x.multiply(p2.y).mod(P)
        val yx = p1.y.multiply(p2.x).mod(P)
        val xxyy = D.multiply(p1.x).mod(P).multiply(p2.x).mod(P)
            .multiply(p1.y).mod(P).multiply(p2.y).mod(P)
        val x3num = xy.add(yx).mod(P)
        val x3den = BigInteger.ONE.add(xxyy).mod(P)
        val y3num = p1.y.multiply(p2.y).mod(P).add(p1.x.multiply(p2.x).mod(P)).mod(P)
        val y3den = BigInteger.ONE.subtract(xxyy).mod(P)
        return Point(
            x3num.multiply(x3den.modInverse(P)).mod(P),
            y3num.multiply(y3den.modInverse(P)).mod(P),
        )
    }

    private fun scalarMul(p: Point, scalar: BigInteger): Point {
        var result = Point(BigInteger.ZERO, BigInteger.ONE)
        var addend = p
        var s = scalar.mod(L)
        while (s > BigInteger.ZERO) {
            if (s.testBit(0)) result = add(result, addend)
            addend = add(addend, addend)
            s = s.shiftRight(1)
        }
        return result
    }
}
