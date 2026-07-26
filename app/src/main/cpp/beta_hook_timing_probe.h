#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace beta_hook_timing {

constexpr std::size_t kWarmupPairs = 32;
constexpr std::size_t kPairsPerBatch = 128;
constexpr std::size_t kMinimumFullBatches = 3;
constexpr std::size_t kMaximumBatches = 5;
constexpr std::size_t kMinimumValidPairs = 384;
constexpr std::int64_t kMinimumMedianTicks = 8;
constexpr std::int64_t kMadMultiplier = 6;
constexpr std::uint32_t kMinimumRatioMilli = 1250;

enum class PairOrder {
    AB,
    BA,
};

struct TimedPair {
    std::uint64_t suspectTicks = 0;
    std::uint64_t baselineTicks = 0;
    bool cpuStable = true;
};

struct BatchAnalysis {
    std::size_t validPairs = 0;
    std::size_t droppedMigrations = 0;
    std::int64_t correctedMedianTicks = 0;
    std::int64_t combinedMadTicks = 0;
    std::uint32_t normalizedRatioMilli = 0;
    bool anomalous = false;
};

enum class CompletionStatus {
    COMPLETE,
    TRUNCATED,
    CANCELLED,
};

enum class OutcomeConsistency {
    UNAVAILABLE,
    CONSISTENT,
    MISMATCH,
};

struct RawInterfaceRecord {
    std::uint32_t index = 0;
    std::string name;
};

struct InterfaceIdentity {
    std::uint32_t index = 0;
    std::uint64_t nameHash = 0;

    bool operator==(const InterfaceIdentity &other) const {
        return index == other.index && nameHash == other.nameHash;
    }
};

PairOrder pairOrderFor(std::size_t index);
TimedPair orderedPair(
    std::uint64_t firstTicks,
    std::uint64_t secondTicks,
    PairOrder order,
    unsigned int startCpu,
    unsigned int endCpu
);
std::int64_t median(std::vector<std::int64_t> values);
std::int64_t medianAbsoluteDeviation(
    const std::vector<std::int64_t> &values,
    std::int64_t center
);
BatchAnalysis analyzeBatch(
    const std::vector<TimedPair> &operation,
    const std::vector<TimedPair> &control
);
bool hasStableAnomaly(const std::vector<BatchAnalysis> &batches);
CompletionStatus completionStatus(
    std::size_t fullBatches,
    std::size_t validPairs,
    bool cancelled,
    bool deadlineReached
);
OutcomeConsistency compareProbeOutcomes(
    int firstResult,
    int firstError,
    bool firstPayloadUsable,
    int secondResult,
    int secondError,
    bool secondPayloadUsable
);
std::uint64_t ticksToNanoseconds(std::uint64_t ticks, std::uint64_t counterFrequency);
std::vector<InterfaceIdentity> normalizeInterfaces(
    const std::vector<RawInterfaceRecord> &records
);

}  // namespace beta_hook_timing

#if defined(__ANDROID__) && !defined(BETA_HOOK_TIMING_HOST_TEST)
#include <jni.h>

jobjectArray nativeBetaHookTimingProbe(
    JNIEnv *env,
    jclass clazz,
    jobject cancellationSignal
);
#endif
