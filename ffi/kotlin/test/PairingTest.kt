// JVM smoke test for the generated Kotlin bindings. No test framework, no Gradle:
// compiled with kotlinc next to the generated sources and run with `java`.
// Run via ffi/kotlin/run-tests.ps1 or ffi/kotlin/run-tests.sh.

import kotlin.system.exitProcess
import ro.codai.devicepairing.CodeExchange
import ro.codai.devicepairing.PairingException
import ro.codai.devicepairing.PairingWindow
import ro.codai.devicepairing.TrustStore
import ro.codai.devicepairing.TrustedPeerRecord
import ro.codai.devicepairing.codeAlphabet
import ro.codai.devicepairing.codeLength
import ro.codai.devicepairing.normaliseCode
import ro.codai.devicepairing.sasDigits

private var checks = 0

private fun check(cond: Boolean, what: String) {
    if (!cond) throw AssertionError("FAILED: $what")
    checks++
}

private inline fun <reified E : Throwable> expectThrows(what: String, block: () -> Unit) {
    try {
        block()
    } catch (e: Throwable) {
        if (e is E) {
            checks++
            return
        }
        throw AssertionError("FAILED: $what threw ${e::class.qualifiedName}: ${e.message}", e)
    }
    throw AssertionError("FAILED: $what did not throw ${E::class.simpleName}")
}

private fun id(fill: Int) = ByteArray(32) { fill.toByte() }

/** Both sides of a code exchange; returns each side's verify_peer outcome. */
private fun exchange(hostCode: String, joinerCode: String): Pair<Result<ByteArray>, Result<ByteArray>> {
    val host = id(1)
    val joiner = id(2)
    val xh = CodeExchange.start(hostCode, host, joiner)
    val xj = CodeExchange.start(joinerCode, joiner, host)
    check(xh.message().size == 33, "PAKE message is 33 bytes")
    val ch = xh.finish(xj.message())
    val cj = xj.finish(xh.message())
    check(ch.tag().size == 32, "confirmation tag is 32 bytes")
    return runCatching { ch.verifyPeer(cj.tag()) } to runCatching { cj.verifyPeer(ch.tag()) }
}

fun pairsEndToEnd() {
    val window = PairingWindow()
    val shown = window.code()
    check(shown.length == codeLength().toInt(), "code length")
    check(shown.all { it in codeAlphabet() }, "code alphabet")
    val code = window.beginAttempt()
    check(code == shown, "begin_attempt returns the shown code")
    check(window.isConsumed(), "window consumed")

    // The joiner types it lower-case with a dash.
    val typed = (shown.substring(0, 4) + "-" + shown.substring(4)).lowercase()
    check(normaliseCode(typed) == shown, "normalise_code")
    val (kh, kj) = exchange(code, typed)
    val keyH = kh.getOrThrow()
    val keyJ = kj.getOrThrow()
    check(keyH.size == 32, "session key is 32 bytes")
    check(keyH.contentEquals(keyJ), "both sides derive the same session key")

    expectThrows<PairingException.Consumed>("second begin_attempt") { window.beginAttempt() }
}

fun wrongCodeFailsBothSides() {
    val (kh, kj) = exchange("ABCDEFGH", "ABCDEFGJ")
    check(kh.exceptionOrNull() is PairingException.Mismatch, "host sees Mismatch")
    check(kj.exceptionOrNull() is PairingException.Mismatch, "joiner sees Mismatch")
}

fun oneShotAndInputValidation() {
    val xa = CodeExchange.start("ABCDEFGH", id(1), id(2))
    val xb = CodeExchange.start("ABCDEFGH", id(2), id(1))
    val c = xa.finish(xb.message())
    expectThrows<PairingException.Consumed>("second finish") { xa.finish(xb.message()) }
    runCatching { c.verifyPeer(ByteArray(32)) }
    expectThrows<PairingException.Consumed>("second verify_peer") { c.verifyPeer(ByteArray(32)) }
    expectThrows<PairingException.InvalidInput>("31-byte id") { CodeExchange.start("X", ByteArray(31), id(2)) }
    expectThrows<PairingException.Protocol>("short PAKE message") { xb.finish(ByteArray(5)) }
}

fun windowTokenAndCode() {
    val qr = PairingWindow()
    qr.verifyToken("  " + qr.token().lowercase() + "\n") // throws on failure
    check(qr.isConsumed(), "token accepted case-insensitively, window consumed")
    expectThrows<PairingException.Consumed>("token is one-shot") { qr.verifyToken(qr.token()) }

    val wrong = PairingWindow.withTtlSecs(60uL)
    val t = wrong.token()
    val bad = (if (t[0] == 'A') "B" else "A") + t.substring(1)
    expectThrows<PairingException.Mismatch>("wrong token") { wrong.verifyToken(bad) }
    expectThrows<PairingException.Consumed>("wrong token burnt the window") { wrong.verifyToken(t) }

    val typed = PairingWindow()
    typed.verifyCode(typed.code().lowercase())
    check(typed.isConsumed(), "verify_code consumes")
    check(!typed.isExpired(), "fresh window not expired")
}

fun sasIsSymmetric() {
    val window = PairingWindow()
    val nonce = window.nonce()
    check(nonce.size == 16, "nonce is 16 bytes")
    val ab = sasDigits(nonce, id(1), id(2))
    val ba = sasDigits(nonce, id(2), id(1))
    check(ab == ba && ab.length == 6 && ab.all { it.isDigit() }, "SAS symmetric, 6 digits")
    expectThrows<PairingException.InvalidInput>("bad nonce length") { sasDigits(ByteArray(15), id(1), id(2)) }
    expectThrows<PairingException.InvalidInput>("bad id length in verify_sas") { window.verifySas(ab, ByteArray(3), id(2)) }
    check(!window.isConsumed(), "invalid input does not consume")
    window.verifySas(ab, id(2), id(1))
    check(window.isConsumed(), "verify_sas consumes")
}

fun trustStoreRoundTrip() {
    val secret = ByteArray(32) { 9 }
    val store = TrustStore()
    store.insert(
        TrustedPeerRecord(
            id = "abc",
            name = "Living room TV",
            method = "code",
            pairedAtMs = 1_780_000_000_000uL,
            lastSeenMs = null,
            metaJson = """{"platform":"android-tv"}""",
            revoked = false,
        ),
    )
    val sealed = store.seal(secret)
    val back = TrustStore.open(sealed, secret)
    check(back.peers() == store.peers(), "peers round-trip")
    check(back.isTrusted("abc"), "trusted after open")
    check(back.revoke("abc") && !back.isTrusted("abc"), "revoke")

    val tampered = sealed.copyOf()
    tampered[40] = (tampered[40].toInt() xor 1).toByte()
    expectThrows<PairingException.BadTrustStore>("flipped byte") { TrustStore.open(tampered, secret) }
    expectThrows<PairingException.BadTrustStore>("wrong secret") { TrustStore.open(sealed, ByteArray(32) { 8 }) }
}

fun main() {
    try {
        pairsEndToEnd()
        wrongCodeFailsBothSides()
        oneShotAndInputValidation()
        windowTokenAndCode()
        sasIsSymmetric()
        trustStoreRoundTrip()
    } catch (e: Throwable) {
        System.err.println(e.message)
        e.printStackTrace()
        exitProcess(1)
    }
    println("kotlin ok $checks checks")
}
