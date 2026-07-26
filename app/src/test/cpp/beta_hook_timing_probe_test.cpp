#include "beta_hook_timing_probe.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<beta_hook_timing::TimedPair> repeatedPairs(
    std::size_t count,
    std::uint64_t suspect,
    std::uint64_t baseline
) {
    return std::vector<beta_hook_timing::TimedPair>(
        count,
        beta_hook_timing::TimedPair{suspect, baseline, true}
    );
}

beta_hook_timing::BatchAnalysis batch(bool anomalous) {
    beta_hook_timing::BatchAnalysis value;
    value.validPairs = beta_hook_timing::kPairsPerBatch;
    value.anomalous = anomalous;
    return value;
}

}  // namespace

int main() {
    using namespace beta_hook_timing;

    assert(median({1, 9, 3}) == 3);
    assert(median({1, 9, 3, 5}) == 4);
    assert(medianAbsoluteDeviation({1, 3, 5, 7, 9}, 5) == 2);

    assert(pairOrderFor(0) == PairOrder::AB);
    assert(pairOrderFor(1) == PairOrder::BA);
    const TimedPair ab = orderedPair(125, 100, PairOrder::AB, 2, 2);
    const TimedPair ba = orderedPair(100, 125, PairOrder::BA, 3, 3);
    assert(ab.suspectTicks == ba.suspectTicks);
    assert(ab.baselineTicks == ba.baselineTicks);

    const auto neutralControl = repeatedPairs(kPairsPerBatch, 100, 100);
    const BatchAnalysis exactTickBoundary = analyzeBatch(
        repeatedPairs(kPairsPerBatch, 108, 100),
        neutralControl
    );
    assert(!exactTickBoundary.anomalous);
    const BatchAnalysis exactRatioBoundary = analyzeBatch(
        repeatedPairs(kPairsPerBatch, 125, 100),
        neutralControl
    );
    assert(exactRatioBoundary.correctedMedianTicks == 25);
    assert(exactRatioBoundary.normalizedRatioMilli == 1250);
    assert(exactRatioBoundary.anomalous);
    const BatchAnalysis belowRatioBoundary = analyzeBatch(
        repeatedPairs(kPairsPerBatch, 124, 100),
        neutralControl
    );
    assert(!belowRatioBoundary.anomalous);

    std::vector<TimedPair> migrated = repeatedPairs(kPairsPerBatch, 125, 100);
    migrated.push_back(orderedPair(125, 100, PairOrder::AB, 1, 2));
    const BatchAnalysis migrationAnalysis = analyzeBatch(migrated, neutralControl);
    assert(migrationAnalysis.validPairs == kPairsPerBatch);
    assert(migrationAnalysis.droppedMigrations == 1);

    assert(hasStableAnomaly({batch(true), batch(false), batch(true), batch(false), batch(true)}));
    assert(!hasStableAnomaly({batch(true), batch(false), batch(true), batch(false), batch(false)}));

    assert(completionStatus(3, 384, false, false) == CompletionStatus::COMPLETE);
    assert(completionStatus(3, 384, false, true) == CompletionStatus::COMPLETE);
    assert(completionStatus(2, 383, false, true) == CompletionStatus::TRUNCATED);
    assert(completionStatus(5, 640, true, false) == CompletionStatus::CANCELLED);

    assert(compareProbeOutcomes(-1, 19, false, -1, 19, false) ==
        OutcomeConsistency::UNAVAILABLE);
    assert(compareProbeOutcomes(-1, 19, false, 0, 0, true) ==
        OutcomeConsistency::MISMATCH);
    assert(compareProbeOutcomes(-1, 19, false, -1, 6, false) ==
        OutcomeConsistency::MISMATCH);
    assert(compareProbeOutcomes(0, 0, true, 0, 0, true) ==
        OutcomeConsistency::CONSISTENT);
    assert(compareProbeOutcomes(0, 0, true, 0, 0, false) ==
        OutcomeConsistency::MISMATCH);

    assert(ticksToNanoseconds(10, 1000000000ULL) == 10);
    assert(ticksToNanoseconds(100, 100000000ULL) == 1000);
    assert(ticksToNanoseconds(100, 0) == 0);

    const std::vector<InterfaceIdentity> normalized = normalizeInterfaces({
        {2, "tun0"},
        {1, "lo"},
        {2, "tun0"},
    });
    assert(normalized.size() == 2);
    for (const InterfaceIdentity &identity : normalized) {
        assert(identity.nameHash != 0);
    }

    std::cout << "beta hook timing pure tests passed\n";
    return 0;
}
