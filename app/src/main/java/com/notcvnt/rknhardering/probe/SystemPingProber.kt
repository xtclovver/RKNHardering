package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanExecutionContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import kotlin.math.roundToInt
import kotlin.concurrent.thread

object SystemPingProber {
    private const val DEFAULT_COUNT = 3
    private const val DEFAULT_REPLY_TIMEOUT_SECONDS = 4
    private const val OUTPUT_PREVIEW_LIMIT = 400
    private val SUMMARY_REGEX = Regex("""(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received""")
    private val RTT_REGEX = Regex(
        """(?:round-trip|rtt)\s+min/avg/max(?:/[a-z]+)?\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)""",
        RegexOption.IGNORE_CASE,
    )
    private val REPLY_TIME_REGEX = Regex("""time[=<]([0-9.]+)\s*ms""", RegexOption.IGNORE_CASE)

    internal data class CommandResult(
        val exitCode: Int,
        val output: String,
        val stderr: String = "",
    )

    data class PingResult(
        val address: String,
        val sent: Int,
        val received: Int,
        val minRttMs: Double? = null,
        val avgRttMs: Double? = null,
        val maxRttMs: Double? = null,
        val exitCode: Int,
        val rawOutput: String,
    ) {
        val hasReplies: Boolean
            get() = received > 0

        fun compactSummary(): String {
            val stats = if (minRttMs != null && avgRttMs != null && maxRttMs != null) {
                "min ${formatMs(minRttMs)}, avg ${formatMs(avgRttMs)}, max ${formatMs(maxRttMs)}"
            } else {
                "RTT unavailable"
            }
            return "$received/$sent replies, $stats"
        }
    }

    @Volatile
    internal var runCommandOverride: ((List<String>) -> CommandResult)? = null

    suspend fun probe(
        address: String,
        count: Int = DEFAULT_COUNT,
        replyTimeoutSeconds: Int = DEFAULT_REPLY_TIMEOUT_SECONDS,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): PingResult = withContext(Dispatchers.IO) {
        executionContext.throwIfCancelled()
        val commands = listOf(
            buildCommand(binary = "ping", forceIpv4 = true, count = count, replyTimeoutSeconds = replyTimeoutSeconds, address = address),
            buildCommand(binary = "ping", forceIpv4 = false, count = count, replyTimeoutSeconds = replyTimeoutSeconds, address = address),
            buildCommand(binary = "/system/bin/ping", forceIpv4 = true, count = count, replyTimeoutSeconds = replyTimeoutSeconds, address = address),
            buildCommand(binary = "/system/bin/ping", forceIpv4 = false, count = count, replyTimeoutSeconds = replyTimeoutSeconds, address = address),
        )

        var lastError: Throwable? = null
        for (command in commands) {
            executionContext.throwIfCancelled()
            try {
                val startedAt = System.nanoTime()
                val commandResult = runCommand(command, executionContext)
                executionContext.diagnosticCollector?.record(
                    category = "icmp",
                    source = "ping",
                    target = address,
                    status = "exit ${commandResult.exitCode}",
                    durationMs = (System.nanoTime() - startedAt) / 1_000_000,
                    body = buildString {
                        appendLine("command=${command.joinToString(" ")}")
                        appendLine("exitCode=${commandResult.exitCode}")
                        appendLine("stdout:")
                        appendLine(commandResult.output)
                        appendLine("stderr:")
                        append(commandResult.stderr)
                    },
                )
                return@withContext try {
                    parse(address, commandResult)
                } catch (error: IOException) {
                    throw IOException(
                        buildParseFailureMessage(
                            command = command,
                            commandResult = commandResult,
                        ),
                        error,
                    )
                }
            } catch (error: Throwable) {
                lastError = error
            }
        }
        throw IOException(lastError?.message ?: "System ping is unavailable", lastError)
    }

    internal fun parse(
        address: String,
        commandResult: CommandResult,
    ): PingResult {
        val summaryMatch = SUMMARY_REGEX.find(commandResult.output)
        val sent = summaryMatch?.groupValues?.getOrNull(1)?.toIntOrNull()
        val received = summaryMatch?.groupValues?.getOrNull(2)?.toIntOrNull()

        val rttMatch = RTT_REGEX.find(commandResult.output)
        val minFromSummary = rttMatch?.groupValues?.getOrNull(1)?.toDoubleOrNull()
        val avgFromSummary = rttMatch?.groupValues?.getOrNull(2)?.toDoubleOrNull()
        val maxFromSummary = rttMatch?.groupValues?.getOrNull(3)?.toDoubleOrNull()

        val replySamples = REPLY_TIME_REGEX.findAll(commandResult.output)
            .mapNotNull { it.groupValues.getOrNull(1)?.toDoubleOrNull() }
            .toList()

        val effectiveSent = sent ?: if (replySamples.isNotEmpty()) DEFAULT_COUNT else null
        val effectiveReceived = received ?: replySamples.size.takeIf { it > 0 }

        if (effectiveSent == null || effectiveReceived == null) {
            throw IOException("Failed to parse ping output")
        }

        val minRtt = minFromSummary ?: replySamples.minOrNull()
        val avgRtt = avgFromSummary ?: replySamples.takeIf { it.isNotEmpty() }?.average()
        val maxRtt = maxFromSummary ?: replySamples.maxOrNull()

        return PingResult(
            address = address,
            sent = effectiveSent,
            received = effectiveReceived,
            minRttMs = minRtt,
            avgRttMs = avgRtt,
            maxRttMs = maxRtt,
            exitCode = commandResult.exitCode,
            rawOutput = commandResult.output,
        )
    }

    private fun runCommand(
        command: List<String>,
        executionContext: ScanExecutionContext,
    ): CommandResult {
        runCommandOverride?.let { return it(command) }

        val process = ProcessBuilder(command).start()
        val registration = executionContext.cancellationSignal.register {
            runCatching { process.destroyForcibly() }
        }
        try {
            var output = ""
            var stderr = ""
            val stdoutReader = thread(name = "rkn-ping-stdout") {
                output = runCatching { process.inputStream.bufferedReader().use { it.readText() } }.getOrDefault("")
            }
            val stderrReader = thread(name = "rkn-ping-stderr") {
                stderr = runCatching { process.errorStream.bufferedReader().use { it.readText() } }.getOrDefault("")
            }
            val exitCode = process.waitFor()
            stdoutReader.join()
            stderrReader.join()
            executionContext.throwIfCancelled()
            return CommandResult(
                exitCode = exitCode,
                output = output,
                stderr = stderr,
            )
        } finally {
            registration.dispose()
            runCatching { process.destroy() }
        }
    }

    private fun formatMs(value: Double): String {
        val rounded = (value * 10).roundToInt() / 10.0
        return if (rounded % 1.0 == 0.0) "${rounded.toInt()} ms" else "$rounded ms"
    }

    private fun buildCommand(
        binary: String,
        forceIpv4: Boolean,
        count: Int,
        replyTimeoutSeconds: Int,
        address: String,
    ): List<String> {
        return buildList {
            add(binary)
            if (forceIpv4) add("-4")
            add("-n")
            add("-c")
            add(count.toString())
            add("-W")
            add(replyTimeoutSeconds.toString())
            add(address)
        }
    }

    private fun buildParseFailureMessage(
        command: List<String>,
        commandResult: CommandResult,
    ): String {
        val commandName = command.firstOrNull() ?: "ping"
        val outputPreview = commandResult.output
            .replace("\r", "")
            .replace("\n", "\\n")
            .ifBlank { "<empty>" }
            .let { preview ->
                if (preview.length <= OUTPUT_PREVIEW_LIMIT) {
                    preview
                } else {
                    preview.take(OUTPUT_PREVIEW_LIMIT) + "..."
                }
            }
        return "Failed to parse ping output (command=$commandName, exitCode=${commandResult.exitCode}, output=$outputPreview)"
    }
}
