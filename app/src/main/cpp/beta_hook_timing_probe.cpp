#include "beta_hook_timing_probe.h"

#include <algorithm>
#include <limits>

namespace beta_hook_timing {
namespace {

std::uint64_t interfaceNameHash(const std::string &name) {
    std::uint64_t value = 1469598103934665603ULL;
    for (const unsigned char byte : name) {
        value ^= byte;
        value *= 1099511628211ULL;
    }
    return value;
}

std::uint32_t normalizedRatioMilli(
    std::uint64_t suspect,
    std::uint64_t baseline,
    std::uint64_t controlSuspect,
    std::uint64_t controlBaseline
) {
    if (baseline == 0 || controlSuspect == 0) return 0;
#if defined(__SIZEOF_INT128__)
    const unsigned __int128 numerator =
        static_cast<unsigned __int128>(suspect) * controlBaseline * 1000U;
    const unsigned __int128 denominator =
        static_cast<unsigned __int128>(baseline) * controlSuspect;
    if (denominator == 0) return 0;
    const unsigned __int128 ratio = numerator / denominator;
    return ratio > std::numeric_limits<std::uint32_t>::max()
        ? std::numeric_limits<std::uint32_t>::max()
        : static_cast<std::uint32_t>(ratio);
#else
    const long double ratio =
        static_cast<long double>(suspect) * static_cast<long double>(controlBaseline) * 1000.0L /
        (static_cast<long double>(baseline) * static_cast<long double>(controlSuspect));
    if (ratio >= static_cast<long double>(std::numeric_limits<std::uint32_t>::max())) {
        return std::numeric_limits<std::uint32_t>::max();
    }
    return ratio <= 0.0L ? 0U : static_cast<std::uint32_t>(ratio);
#endif
}

std::uint64_t nonNegativeMedian(const std::vector<std::int64_t> &values) {
    return static_cast<std::uint64_t>(std::max<std::int64_t>(0, median(values)));
}

}  // namespace

PairOrder pairOrderFor(std::size_t index) {
    return (index & 1U) == 0U ? PairOrder::AB : PairOrder::BA;
}

TimedPair orderedPair(
    std::uint64_t firstTicks,
    std::uint64_t secondTicks,
    PairOrder order,
    unsigned int startCpu,
    unsigned int endCpu
) {
    return order == PairOrder::AB
        ? TimedPair{firstTicks, secondTicks, startCpu == endCpu}
        : TimedPair{secondTicks, firstTicks, startCpu == endCpu};
}

std::int64_t median(std::vector<std::int64_t> values) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const std::size_t middle = values.size() / 2;
    if ((values.size() & 1U) != 0U) return values[middle];
    const std::int64_t lower = values[middle - 1];
    const std::int64_t upper = values[middle];
    return lower + (upper - lower) / 2;
}

std::int64_t medianAbsoluteDeviation(
    const std::vector<std::int64_t> &values,
    std::int64_t center
) {
    std::vector<std::int64_t> deviations;
    deviations.reserve(values.size());
    for (const std::int64_t value : values) {
        const std::uint64_t distance = value >= center
            ? static_cast<std::uint64_t>(value - center)
            : static_cast<std::uint64_t>(center - value);
        deviations.push_back(distance > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
            ? std::numeric_limits<std::int64_t>::max()
            : static_cast<std::int64_t>(distance));
    }
    return median(std::move(deviations));
}

BatchAnalysis analyzeBatch(
    const std::vector<TimedPair> &operation,
    const std::vector<TimedPair> &control
) {
    BatchAnalysis result;
    std::vector<std::int64_t> operationDeltas;
    std::vector<std::int64_t> controlDeltas;
    std::vector<std::int64_t> operationSuspect;
    std::vector<std::int64_t> operationBaseline;
    std::vector<std::int64_t> controlSuspect;
    std::vector<std::int64_t> controlBaseline;
    operationDeltas.reserve(operation.size());
    controlDeltas.reserve(control.size());
    operationSuspect.reserve(operation.size());
    operationBaseline.reserve(operation.size());
    controlSuspect.reserve(control.size());
    controlBaseline.reserve(control.size());

    const auto append = [&result](
        const std::vector<TimedPair> &source,
        std::vector<std::int64_t> *deltas,
        std::vector<std::int64_t> *suspect,
        std::vector<std::int64_t> *baseline
    ) {
        for (const TimedPair &pair : source) {
            if (!pair.cpuStable) {
                ++result.droppedMigrations;
                continue;
            }
            const std::uint64_t boundedSuspect = std::min<std::uint64_t>(
                pair.suspectTicks,
                static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
            );
            const std::uint64_t boundedBaseline = std::min<std::uint64_t>(
                pair.baselineTicks,
                static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
            );
            suspect->push_back(static_cast<std::int64_t>(boundedSuspect));
            baseline->push_back(static_cast<std::int64_t>(boundedBaseline));
            deltas->push_back(
                static_cast<std::int64_t>(boundedSuspect) -
                    static_cast<std::int64_t>(boundedBaseline)
            );
        }
    };
    append(operation, &operationDeltas, &operationSuspect, &operationBaseline);
    append(control, &controlDeltas, &controlSuspect, &controlBaseline);
    result.validPairs = std::min(operationDeltas.size(), controlDeltas.size());
    if (result.validPairs == 0) return result;

    const std::int64_t operationMedian = median(operationDeltas);
    const std::int64_t controlMedian = median(controlDeltas);
    result.correctedMedianTicks = operationMedian - controlMedian;
    result.combinedMadTicks =
        medianAbsoluteDeviation(operationDeltas, operationMedian) +
        medianAbsoluteDeviation(controlDeltas, controlMedian);
    result.normalizedRatioMilli = normalizedRatioMilli(
        nonNegativeMedian(operationSuspect),
        nonNegativeMedian(operationBaseline),
        nonNegativeMedian(controlSuspect),
        nonNegativeMedian(controlBaseline)
    );
    const std::int64_t scaledMad = result.combinedMadTicks >
            std::numeric_limits<std::int64_t>::max() / kMadMultiplier
        ? std::numeric_limits<std::int64_t>::max()
        : kMadMultiplier * result.combinedMadTicks;
    const std::int64_t timingThreshold = std::max(kMinimumMedianTicks, scaledMad);
    result.anomalous =
        result.correctedMedianTicks > timingThreshold &&
        result.normalizedRatioMilli >= kMinimumRatioMilli;
    return result;
}

bool hasStableAnomaly(const std::vector<BatchAnalysis> &batches) {
    return std::count_if(batches.begin(), batches.end(), [](const BatchAnalysis &batch) {
        return batch.validPairs >= kPairsPerBatch && batch.anomalous;
    }) >= static_cast<std::ptrdiff_t>(kMinimumFullBatches);
}

CompletionStatus completionStatus(
    std::size_t fullBatches,
    std::size_t validPairs,
    bool cancelled,
    bool deadlineReached
) {
    if (cancelled) return CompletionStatus::CANCELLED;
    if (fullBatches < kMinimumFullBatches || validPairs < kMinimumValidPairs) {
        return CompletionStatus::TRUNCATED;
    }
    (void) deadlineReached;
    return CompletionStatus::COMPLETE;
}

OutcomeConsistency compareProbeOutcomes(
    int firstResult,
    int firstError,
    bool firstPayloadUsable,
    int secondResult,
    int secondError,
    bool secondPayloadUsable
) {
    if (firstResult != secondResult || firstError != secondError) {
        return OutcomeConsistency::MISMATCH;
    }
    if (firstResult != 0) return OutcomeConsistency::UNAVAILABLE;
    if (firstPayloadUsable != secondPayloadUsable) return OutcomeConsistency::MISMATCH;
    return firstPayloadUsable ? OutcomeConsistency::CONSISTENT : OutcomeConsistency::UNAVAILABLE;
}

std::uint64_t ticksToNanoseconds(std::uint64_t ticks, std::uint64_t counterFrequency) {
    if (counterFrequency == 0) return 0;
#if defined(__SIZEOF_INT128__)
    const unsigned __int128 scaled = static_cast<unsigned __int128>(ticks) * 1000000000ULL;
    return static_cast<std::uint64_t>(scaled / counterFrequency);
#else
    const long double converted = static_cast<long double>(ticks) * 1000000000.0L /
        static_cast<long double>(counterFrequency);
    if (converted >= static_cast<long double>(std::numeric_limits<std::uint64_t>::max())) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return converted <= 0.0L ? 0ULL : static_cast<std::uint64_t>(converted);
#endif
}

std::vector<InterfaceIdentity> normalizeInterfaces(
    const std::vector<RawInterfaceRecord> &records
) {
    std::vector<InterfaceIdentity> normalized;
    normalized.reserve(records.size());
    for (const RawInterfaceRecord &record : records) {
        if (record.name.empty()) continue;
        normalized.push_back({record.index, interfaceNameHash(record.name)});
    }
    std::sort(normalized.begin(), normalized.end(), [](const InterfaceIdentity &left,
                                                        const InterfaceIdentity &right) {
        if (left.nameHash != right.nameHash) return left.nameHash < right.nameHash;
        return left.index < right.index;
    });
    normalized.erase(std::unique(normalized.begin(), normalized.end()), normalized.end());
    return normalized;
}

}  // namespace beta_hook_timing

#if defined(__ANDROID__) && !defined(BETA_HOOK_TIMING_HOST_TEST)

#include "vpnhide_regression_probe.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sstream>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

using beta_hook_timing::BatchAnalysis;
using beta_hook_timing::CompletionStatus;
using beta_hook_timing::PairOrder;
using beta_hook_timing::TimedPair;

[[maybe_unused]] constexpr auto kNativeHardDeadline = std::chrono::milliseconds(900);
[[maybe_unused]] constexpr auto kMeasurementDeadline = std::chrono::milliseconds(850);
constexpr std::size_t kIfconfCapacity = 128;
constexpr std::size_t kMaximumSnapshotNames = 256;
constexpr std::size_t kStrongKernelCandidates = 3;
constexpr std::size_t kMaximumPairAttempts = 192;

class ScopedFd {
public:
    explicit ScopedFd(int value = -1) : value_(value) {}
    ~ScopedFd() { if (value_ >= 0) close(value_); }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    int get() const { return value_; }
    bool valid() const { return value_ >= 0; }
private:
    int value_;
};

class CancellationProbe {
public:
    CancellationProbe(JNIEnv *env, jobject signal) : env_(env), signal_(signal) {
        if (signal_ == nullptr) return;
        jclass signalClass = env_->GetObjectClass(signal_);
        if (signalClass == nullptr) return;
        method_ = env_->GetMethodID(signalClass, "isCancelled", "()Z");
        env_->DeleteLocalRef(signalClass);
        if (env_->ExceptionCheck()) {
            env_->ExceptionClear();
            method_ = nullptr;
        }
    }

    bool cancelled() const {
        if (signal_ == nullptr || method_ == nullptr) return false;
        const bool result = env_->CallBooleanMethod(signal_, method_) == JNI_TRUE;
        if (env_->ExceptionCheck()) {
            env_->ExceptionClear();
            return true;
        }
        return result;
    }

private:
    JNIEnv *env_;
    jobject signal_;
    jmethodID method_ = nullptr;
};

bool shouldStop(
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline
) {
    return cancellation.cancelled() || std::chrono::steady_clock::now() >= deadline;
}

enum class MeasuredOperation {
    IFCONF,
    IFINDEX,
    CONTROL_READ,
};

struct InvocationStorage {
    std::array<ifreq, kIfconfCapacity> entries{};
    ifconf configuration{};
    ifreq interfaceRequest{};
    int availableBytes = 0;
};

struct CallOutcome {
    int result = -1;
    int error = 0;
};

struct IfconfSnapshot {
    bool available = false;
    CallOutcome outcome{};
    int returnedBytes = 0;
    std::vector<std::string> names;
    std::vector<beta_hook_timing::InterfaceIdentity> normalized;
};

struct SemanticPass {
    bool available = false;
    bool mismatch = false;
    bool interrupted = false;
    std::string timingName = "lo";
};

SemanticPass interruptedSemanticPass() {
    SemanticPass result;
    result.interrupted = true;
    return result;
}

struct KernelSources {
    bool available = false;
    const char *failureReason = "unavailable";
    std::vector<std::string> ifconf;
    std::vector<std::string> netlink;
    std::vector<std::string> proc;
};

struct AggregateResult {
    const char *check = nullptr;
    const char *status = "available";
    const char *reason = "no_corroboration";
    std::uint64_t counterFrequency = 0;
    std::size_t measurements = 0;
    std::size_t fullBatches = 0;
    std::size_t droppedMigrations = 0;
    std::int64_t medianTicks = 0;
    std::int64_t madTicks = 0;
    std::uint32_t ratioMilli = 0;
    bool timingAnomaly = false;
    bool semanticMismatch = false;
    bool corroborated = false;
};

#if defined(__aarch64__)
inline std::uint64_t readCounter() {
    std::uint64_t value = 0;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

inline std::uint64_t readCounterFrequency() {
    std::uint64_t value = 0;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return value;
}

inline long rawSystemCall3(long number, long first, long second, long third) {
    register long x0 asm("x0") = first;
    register long x1 asm("x1") = second;
    register long x2 asm("x2") = third;
    register long x8 asm("x8") = number;
    asm volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

CallOutcome rawIoctl(int fd, unsigned long request, void *argument) {
    const long result = rawSystemCall3(
        __NR_ioctl,
        fd,
        static_cast<long>(request),
        reinterpret_cast<long>(argument)
    );
    if (result < 0 && result >= -4095) return {-1, static_cast<int>(-result)};
    return {static_cast<int>(result), 0};
}

bool currentCpu(unsigned int *cpu) {
#if defined(__NR_getcpu)
    unsigned int node = 0;
    const long result = rawSystemCall3(
        __NR_getcpu,
        reinterpret_cast<long>(cpu),
        reinterpret_cast<long>(&node),
        0
    );
    return result == 0;
#else
    (void) cpu;
    return false;
#endif
}
#endif

CallOutcome libcIoctl(int fd, unsigned long request, void *argument) {
    errno = 0;
    const int result = ioctl(fd, request, argument);
    return {result, result < 0 ? errno : 0};
}

void prepareInvocation(
    InvocationStorage *storage,
    MeasuredOperation operation,
    std::string_view name
) {
    std::memset(storage, 0, sizeof(*storage));
    if (operation == MeasuredOperation::IFCONF) {
        storage->configuration.ifc_len = static_cast<int>(sizeof(storage->entries));
        storage->configuration.ifc_req = storage->entries.data();
    } else if (operation == MeasuredOperation::IFINDEX) {
        const std::size_t length = std::min(name.size(), static_cast<std::size_t>(IFNAMSIZ - 1));
        std::memcpy(storage->interfaceRequest.ifr_name, name.data(), length);
        storage->interfaceRequest.ifr_name[length] = '\0';
    }
}

[[maybe_unused]] void *invocationArgument(InvocationStorage *storage, MeasuredOperation operation) {
    switch (operation) {
        case MeasuredOperation::IFCONF: return &storage->configuration;
        case MeasuredOperation::IFINDEX: return &storage->interfaceRequest;
        case MeasuredOperation::CONTROL_READ: return &storage->availableBytes;
    }
    return nullptr;
}

[[maybe_unused]] unsigned long requestFor(MeasuredOperation operation) {
    switch (operation) {
        case MeasuredOperation::IFCONF: return SIOCGIFCONF;
        case MeasuredOperation::IFINDEX: return SIOCGIFINDEX;
        case MeasuredOperation::CONTROL_READ: return FIONREAD;
    }
    return 0;
}

#if defined(__aarch64__)
TimedPair measureLibcRawPair(
    int fd,
    MeasuredOperation operation,
    std::string_view name,
    PairOrder order
) {
    InvocationStorage first{};
    InvocationStorage second{};
    prepareInvocation(&first, operation, name);
    prepareInvocation(&second, operation, name);
    unsigned int startCpu = 0;
    unsigned int endCpu = 0;
    const bool startCpuKnown = currentCpu(&startCpu);
    std::uint64_t firstStart = 0;
    std::uint64_t firstEnd = 0;
    std::uint64_t secondStart = 0;
    std::uint64_t secondEnd = 0;
    if (order == PairOrder::AB) {
        firstStart = readCounter();
        (void) libcIoctl(fd, requestFor(operation), invocationArgument(&first, operation));
        firstEnd = readCounter();
        secondStart = readCounter();
        (void) rawIoctl(fd, requestFor(operation), invocationArgument(&second, operation));
        secondEnd = readCounter();
    } else {
        firstStart = readCounter();
        (void) rawIoctl(fd, requestFor(operation), invocationArgument(&first, operation));
        firstEnd = readCounter();
        secondStart = readCounter();
        (void) libcIoctl(fd, requestFor(operation), invocationArgument(&second, operation));
        secondEnd = readCounter();
    }
    const bool endCpuKnown = currentCpu(&endCpu);
    if (!startCpuKnown || !endCpuKnown) endCpu = startCpu + 1U;
    return beta_hook_timing::orderedPair(
        firstEnd - firstStart,
        secondEnd - secondStart,
        order,
        startCpu,
        endCpu
    );
}

TimedPair measureRawNamesPair(
    int fd,
    std::string_view candidate,
    std::string_view control,
    PairOrder order
) {
    InvocationStorage first{};
    InvocationStorage second{};
    const std::string_view firstName = order == PairOrder::AB ? candidate : control;
    const std::string_view secondName = order == PairOrder::AB ? control : candidate;
    prepareInvocation(&first, MeasuredOperation::IFINDEX, firstName);
    prepareInvocation(&second, MeasuredOperation::IFINDEX, secondName);
    unsigned int startCpu = 0;
    unsigned int endCpu = 0;
    const bool startCpuKnown = currentCpu(&startCpu);
    const std::uint64_t firstStart = readCounter();
    (void) rawIoctl(fd, SIOCGIFINDEX, &first.interfaceRequest);
    const std::uint64_t firstEnd = readCounter();
    const std::uint64_t secondStart = readCounter();
    (void) rawIoctl(fd, SIOCGIFINDEX, &second.interfaceRequest);
    const std::uint64_t secondEnd = readCounter();
    const bool endCpuKnown = currentCpu(&endCpu);
    if (!startCpuKnown || !endCpuKnown) endCpu = startCpu + 1U;
    return beta_hook_timing::orderedPair(
        firstEnd - firstStart,
        secondEnd - secondStart,
        order,
        startCpu,
        endCpu
    );
}

TimedPair measureRawControlPair(int fd, PairOrder order) {
    InvocationStorage first{};
    InvocationStorage second{};
    prepareInvocation(&first, MeasuredOperation::CONTROL_READ, {});
    prepareInvocation(&second, MeasuredOperation::CONTROL_READ, {});
    unsigned int startCpu = 0;
    unsigned int endCpu = 0;
    const bool startCpuKnown = currentCpu(&startCpu);
    const std::uint64_t firstStart = readCounter();
    (void) rawIoctl(fd, FIONREAD, &first.availableBytes);
    const std::uint64_t firstEnd = readCounter();
    const std::uint64_t secondStart = readCounter();
    (void) rawIoctl(fd, FIONREAD, &second.availableBytes);
    const std::uint64_t secondEnd = readCounter();
    const bool endCpuKnown = currentCpu(&endCpu);
    if (!startCpuKnown || !endCpuKnown) endCpu = startCpu + 1U;
    return beta_hook_timing::orderedPair(
        firstEnd - firstStart,
        secondEnd - secondStart,
        order,
        startCpu,
        endCpu
    );
}
#endif

bool sameOutcome(const CallOutcome &left, const CallOutcome &right) {
    return left.result == right.result && left.error == right.error;
}

std::vector<beta_hook_timing::RawInterfaceRecord> recordsFromIfconf(
    const std::array<ifreq, kIfconfCapacity> &entries,
    int returnedBytes
) {
    std::vector<beta_hook_timing::RawInterfaceRecord> records;
    if (returnedBytes < 0 || returnedBytes > static_cast<int>(sizeof(entries)) ||
        returnedBytes % static_cast<int>(sizeof(ifreq)) != 0) {
        return records;
    }
    const std::size_t count = static_cast<std::size_t>(returnedBytes) / sizeof(ifreq);
    records.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const std::size_t length = strnlen(entries[index].ifr_name, IFNAMSIZ);
        if (length == 0 || length >= IFNAMSIZ) continue;
        records.push_back({
            0,
            std::string(entries[index].ifr_name, length),
        });
    }
    return records;
}

IfconfSnapshot readIfconf(int fd, bool raw) {
    InvocationStorage storage{};
    prepareInvocation(&storage, MeasuredOperation::IFCONF, {});
    const CallOutcome outcome = raw
#if defined(__aarch64__)
        ? rawIoctl(fd, SIOCGIFCONF, &storage.configuration)
#else
        ? CallOutcome{-1, ENOTSUP}
#endif
        : libcIoctl(fd, SIOCGIFCONF, &storage.configuration);
    IfconfSnapshot snapshot;
    snapshot.outcome = outcome;
    if (outcome.result != 0 || storage.configuration.ifc_len < 0 ||
        storage.configuration.ifc_len >= static_cast<int>(sizeof(storage.entries))) {
        return snapshot;
    }
    const auto records = recordsFromIfconf(storage.entries, storage.configuration.ifc_len);
    if (storage.configuration.ifc_len != 0 && records.empty()) return snapshot;
    snapshot.available = true;
    snapshot.returnedBytes = storage.configuration.ifc_len;
    snapshot.normalized = beta_hook_timing::normalizeInterfaces(records);
    snapshot.names.reserve(records.size());
    for (const auto &record : records) snapshot.names.push_back(record.name);
    std::sort(snapshot.names.begin(), snapshot.names.end());
    snapshot.names.erase(std::unique(snapshot.names.begin(), snapshot.names.end()), snapshot.names.end());
    return snapshot;
}

bool containsName(const std::vector<std::string> &names, std::string_view target) {
    return std::find(names.begin(), names.end(), target) != names.end();
}

std::size_t migrationCount(const std::vector<TimedPair> &values) {
    return static_cast<std::size_t>(std::count_if(values.begin(), values.end(), [](const TimedPair &value) {
        return !value.cpuStable;
    }));
}

CallOutcome queryIndex(int fd, std::string_view name, bool raw, int *index) {
    InvocationStorage storage{};
    prepareInvocation(&storage, MeasuredOperation::IFINDEX, name);
    const CallOutcome outcome = raw
#if defined(__aarch64__)
        ? rawIoctl(fd, SIOCGIFINDEX, &storage.interfaceRequest)
#else
        ? CallOutcome{-1, ENOTSUP}
#endif
        : libcIoctl(fd, SIOCGIFINDEX, &storage.interfaceRequest);
    *index = outcome.result == 0 ? storage.interfaceRequest.ifr_ifindex : 0;
    return outcome;
}

CallOutcome queryName(int fd, int index, bool raw, std::string *name) {
    InvocationStorage storage{};
    storage.interfaceRequest.ifr_ifindex = index;
    const CallOutcome outcome = raw
#if defined(__aarch64__)
        ? rawIoctl(fd, SIOCGIFNAME, &storage.interfaceRequest)
#else
        ? CallOutcome{-1, ENOTSUP}
#endif
        : libcIoctl(fd, SIOCGIFNAME, &storage.interfaceRequest);
    if (outcome.result == 0) {
        const std::size_t length = strnlen(storage.interfaceRequest.ifr_name, IFNAMSIZ);
        if (length > 0 && length < IFNAMSIZ) name->assign(storage.interfaceRequest.ifr_name, length);
    }
    return outcome;
}

SemanticPass libcSemanticPass(
    int fd,
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline
) {
    if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
    const IfconfSnapshot libcSnapshot = readIfconf(fd, false);
    if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
    const IfconfSnapshot rawSnapshot = readIfconf(fd, true);
    if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
    const beta_hook_timing::OutcomeConsistency outcomeConsistency =
        beta_hook_timing::compareProbeOutcomes(
            libcSnapshot.outcome.result,
            libcSnapshot.outcome.error,
            libcSnapshot.available,
            rawSnapshot.outcome.result,
            rawSnapshot.outcome.error,
            rawSnapshot.available
        );
    if (outcomeConsistency == beta_hook_timing::OutcomeConsistency::UNAVAILABLE) return {};
    SemanticPass result;
    result.available = true;
    result.mismatch = outcomeConsistency == beta_hook_timing::OutcomeConsistency::MISMATCH;
    if (libcSnapshot.available && rawSnapshot.available) {
        result.mismatch = result.mismatch ||
            libcSnapshot.returnedBytes != rawSnapshot.returnedBytes ||
            libcSnapshot.normalized != rawSnapshot.normalized;
    }
    std::vector<std::string> unionNames = libcSnapshot.names;
    unionNames.insert(unionNames.end(), rawSnapshot.names.begin(), rawSnapshot.names.end());
    std::sort(unionNames.begin(), unionNames.end());
    unionNames.erase(std::unique(unionNames.begin(), unionNames.end()), unionNames.end());
    for (const std::string &name : unionNames) {
        if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
        int libcIndex = 0;
        int rawIndex = 0;
        const CallOutcome libcIndexOutcome = queryIndex(fd, name, false, &libcIndex);
        if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
        const CallOutcome rawIndexOutcome = queryIndex(fd, name, true, &rawIndex);
        if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
        if (!sameOutcome(libcIndexOutcome, rawIndexOutcome) || libcIndex != rawIndex) {
            result.mismatch = true;
        }
        if (rawIndex > 0) {
            std::string libcName;
            std::string rawName;
            const CallOutcome libcNameOutcome = queryName(fd, rawIndex, false, &libcName);
            if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
            const CallOutcome rawNameOutcome = queryName(fd, rawIndex, true, &rawName);
            if (shouldStop(cancellation, deadline)) return interruptedSemanticPass();
            if (!sameOutcome(libcNameOutcome, rawNameOutcome) || libcName != rawName || rawName != name) {
                result.mismatch = true;
            }
        }
        if (result.timingName == "lo" && vpnhide_regression::matchesVpnhideInterfaceName(name)) {
            result.timingName = name;
        }
    }
    return result;
}

bool parseProcNetDev(std::vector<std::string> *names) {
    ScopedFd fd(open("/proc/net/dev", O_RDONLY | O_CLOEXEC));
    if (!fd.valid()) return false;
    std::array<char, 32768> buffer{};
    const ssize_t length = read(fd.get(), buffer.data(), buffer.size() - 1);
    if (length <= 0 || static_cast<std::size_t>(length) >= buffer.size() - 1) return false;
    buffer[static_cast<std::size_t>(length)] = '\0';
    const char *cursor = buffer.data();
    const char *end = cursor + length;
    while (cursor < end) {
        const char *lineEnd = static_cast<const char *>(std::memchr(cursor, '\n', static_cast<std::size_t>(end - cursor)));
        if (lineEnd == nullptr) lineEnd = end;
        const char *separator = static_cast<const char *>(std::memchr(cursor, ':', static_cast<std::size_t>(lineEnd - cursor)));
        if (separator != nullptr) {
            const char *start = cursor;
            while (start < separator && std::isspace(static_cast<unsigned char>(*start))) ++start;
            const char *finish = separator;
            while (finish > start && std::isspace(static_cast<unsigned char>(finish[-1]))) --finish;
            if (finish > start && static_cast<std::size_t>(finish - start) < IFNAMSIZ) {
                names->emplace_back(start, finish);
                if (names->size() >= kMaximumSnapshotNames) return false;
            }
        }
        cursor = lineEnd < end ? lineEnd + 1 : end;
    }
    std::sort(names->begin(), names->end());
    names->erase(std::unique(names->begin(), names->end()), names->end());
    return !names->empty();
}

bool readRtmGetlink(
    std::vector<std::string> *names,
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline
) {
    if (shouldStop(cancellation, deadline)) return false;
    ScopedFd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE));
    if (!fd.valid()) return false;
    constexpr std::uint32_t sequence = 0x42544854;
    struct Request {
        nlmsghdr header;
        ifinfomsg info;
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
    request.header.nlmsg_type = RTM_GETLINK;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    request.info.ifi_family = AF_UNSPEC;
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd.get(), &request, request.header.nlmsg_len, 0,
               reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) < 0) {
        return false;
    }
    std::array<char, 32768> buffer{};
    bool done = false;
    std::size_t messages = 0;
    while (!done && !shouldStop(cancellation, deadline) && messages < 1024) {
        pollfd descriptor{fd.get(), POLLIN, 0};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()
        );
        const int timeout = static_cast<int>(std::max<std::int64_t>(0, std::min<std::int64_t>(20, remaining.count())));
        const int pollResult = poll(&descriptor, 1, timeout);
        if (pollResult < 0) return false;
        if (pollResult == 0) continue;
        sockaddr_nl sender{};
        iovec iov{buffer.data(), buffer.size()};
        msghdr message{};
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        const ssize_t length = recvmsg(fd.get(), &message, MSG_TRUNC);
        if (length <= 0 || (message.msg_flags & MSG_TRUNC) != 0 ||
            static_cast<std::size_t>(length) > buffer.size() || sender.nl_pid != 0) {
            return false;
        }
        int remainingBytes = static_cast<int>(length);
        for (auto *header = reinterpret_cast<nlmsghdr *>(buffer.data());
             remainingBytes >= static_cast<int>(sizeof(nlmsghdr)) &&
                 header->nlmsg_len >= sizeof(nlmsghdr) &&
                 header->nlmsg_len <= static_cast<std::uint32_t>(remainingBytes);
             header = NLMSG_NEXT(header, remainingBytes)) {
            if (shouldStop(cancellation, deadline)) return false;
            ++messages;
            if (header->nlmsg_seq != sequence || (header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) return false;
            if (header->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (header->nlmsg_type == NLMSG_ERROR || header->nlmsg_type != RTM_NEWLINK ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(ifinfomsg))) {
                if (header->nlmsg_type == NLMSG_ERROR) return false;
                continue;
            }
            const auto *info = reinterpret_cast<const ifinfomsg *>(NLMSG_DATA(header));
            int attributeBytes = static_cast<int>(header->nlmsg_len - NLMSG_LENGTH(sizeof(ifinfomsg)));
            auto *attribute = reinterpret_cast<const rtattr *>(IFLA_RTA(info));
            for (; RTA_OK(attribute, attributeBytes); attribute = RTA_NEXT(attribute, attributeBytes)) {
                if (attribute->rta_type != IFLA_IFNAME || RTA_PAYLOAD(attribute) <= 0) continue;
                const char *value = reinterpret_cast<const char *>(RTA_DATA(attribute));
                const std::size_t maximum = static_cast<std::size_t>(RTA_PAYLOAD(attribute));
                const std::size_t nameLength = strnlen(value, maximum);
                if (nameLength > 0 && nameLength < maximum && nameLength < IFNAMSIZ) {
                    names->emplace_back(value, nameLength);
                    if (names->size() >= kMaximumSnapshotNames) return false;
                }
            }
            if (attributeBytes != 0) return false;
        }
        if (remainingBytes != 0) return false;
    }
    if (!done) return false;
    std::sort(names->begin(), names->end());
    names->erase(std::unique(names->begin(), names->end()), names->end());
    return !names->empty();
}

KernelSources kernelSources(
    int fd,
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline
) {
    KernelSources sources;
    if (shouldStop(cancellation, deadline)) {
        sources.failureReason = cancellation.cancelled() ? "cancelled" : "deadline";
        return sources;
    }
    const IfconfSnapshot ifconf = readIfconf(fd, true);
    if (shouldStop(cancellation, deadline)) {
        sources.failureReason = cancellation.cancelled() ? "cancelled" : "deadline";
        return sources;
    }
    if (!ifconf.available) {
        sources.failureReason = "ifconf_unavailable";
        return sources;
    }
    sources.ifconf = ifconf.names;
    if (!readRtmGetlink(&sources.netlink, cancellation, deadline)) {
        sources.failureReason = shouldStop(cancellation, deadline)
            ? (cancellation.cancelled() ? "cancelled" : "deadline")
            : "netlink_unavailable";
        return sources;
    }
    if (shouldStop(cancellation, deadline)) {
        sources.failureReason = cancellation.cancelled() ? "cancelled" : "deadline";
        return sources;
    }
    if (!parseProcNetDev(&sources.proc)) {
        sources.failureReason = "proc_unavailable";
        return sources;
    }
    if (shouldStop(cancellation, deadline)) {
        sources.failureReason = cancellation.cancelled() ? "cancelled" : "deadline";
        return sources;
    }
    sources.available = true;
    sources.failureReason = "none";
    return sources;
}

bool sourceMismatch(int fd, std::string_view name, const KernelSources &sources) {
    int index = 0;
    const CallOutcome indexOutcome = queryIndex(fd, name, true, &index);
    const bool byIndex = indexOutcome.result == 0 && index > 0;
    const bool byIfconf = containsName(sources.ifconf, name);
    const bool byNetlink = containsName(sources.netlink, name);
    const bool byProc = containsName(sources.proc, name);
    const unsigned int present = static_cast<unsigned int>(byIndex) +
        static_cast<unsigned int>(byIfconf) + static_cast<unsigned int>(byNetlink) +
        static_cast<unsigned int>(byProc);
    return present != 0U && present != 4U;
}

std::string controlName(std::size_t length, unsigned int salt) {
    if (length == 0 || length >= IFNAMSIZ) return {};
    static constexpr char alphabet[] = "qzjxkvb0123456789";
    std::string value(length, 'q');
    for (std::size_t index = 0; index < length; ++index) {
        value[index] = alphabet[(salt + static_cast<unsigned int>(index * 7U)) % (sizeof(alphabet) - 1U)];
        salt = salt * 1103515245U + 12345U;
    }
    return value;
}

std::array<std::string, IFNAMSIZ> buildAbsentControls(
    int fd,
    const KernelSources &sources,
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline,
    bool *interrupted
) {
    std::array<std::string, IFNAMSIZ> controls{};
    for (std::size_t length = 1; length < controls.size(); ++length) {
        for (unsigned int salt = 1; salt < 128; ++salt) {
            if (shouldStop(cancellation, deadline)) {
                *interrupted = true;
                return controls;
            }
            const std::string candidate = controlName(length, salt);
            if (candidate.empty() || containsName(sources.ifconf, candidate) ||
                containsName(sources.netlink, candidate) || containsName(sources.proc, candidate)) {
                continue;
            }
            int index = 0;
            const CallOutcome outcome = queryIndex(fd, candidate, true, &index);
            if (shouldStop(cancellation, deadline)) {
                *interrupted = true;
                return controls;
            }
            if (outcome.result < 0 &&
                (outcome.error == ENODEV || outcome.error == ENXIO || outcome.error == ENOENT)) {
                controls[length] = candidate;
                break;
            }
        }
    }
    return controls;
}

template <typename Measure>
bool fillBatch(
    std::vector<TimedPair> *values,
    std::size_t wanted,
    std::chrono::steady_clock::time_point deadline,
    const CancellationProbe &cancellation,
    Measure measure
) {
    values->clear();
    values->reserve(kMaximumPairAttempts);
    std::size_t valid = 0;
    for (std::size_t attempt = 0; attempt < kMaximumPairAttempts && valid < wanted; ++attempt) {
        if (shouldStop(cancellation, deadline)) return false;
        TimedPair value = measure(beta_hook_timing::pairOrderFor(attempt));
        if (shouldStop(cancellation, deadline)) return false;
        if (value.cpuStable) ++valid;
        values->push_back(value);
    }
    return valid == wanted;
}

bool warmupLibc(
    int fd,
    std::string_view timingName,
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline
) {
#if defined(__aarch64__)
    for (std::size_t index = 0; index < beta_hook_timing::kWarmupPairs; ++index) {
        if (shouldStop(cancellation, deadline)) return false;
        const PairOrder order = beta_hook_timing::pairOrderFor(index);
        (void) measureLibcRawPair(fd, MeasuredOperation::IFCONF, {}, order);
        if (shouldStop(cancellation, deadline)) return false;
        (void) measureLibcRawPair(fd, MeasuredOperation::IFINDEX, timingName, order);
        if (shouldStop(cancellation, deadline)) return false;
        (void) measureLibcRawPair(fd, MeasuredOperation::CONTROL_READ, {}, order);
    }
#else
    (void) fd;
    (void) timingName;
    (void) cancellation;
    (void) deadline;
#endif
    return true;
}

void updateConservativeAggregate(
    AggregateResult *aggregate,
    const BatchAnalysis &first,
    const BatchAnalysis &second
) {
    const std::int64_t medianValue = std::min(first.correctedMedianTicks, second.correctedMedianTicks);
    const std::int64_t madValue = std::max(first.combinedMadTicks, second.combinedMadTicks);
    const std::uint32_t ratioValue = std::min(first.normalizedRatioMilli, second.normalizedRatioMilli);
    if (aggregate->fullBatches == 1 || medianValue < aggregate->medianTicks) aggregate->medianTicks = medianValue;
    aggregate->madTicks = std::max(aggregate->madTicks, madValue);
    if (aggregate->ratioMilli == 0 || ratioValue < aggregate->ratioMilli) aggregate->ratioMilli = ratioValue;
}

[[maybe_unused]] AggregateResult runLibcBranch(
    int fd,
    std::uint64_t frequency,
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline
) {
    AggregateResult result;
    result.check = "vpnhide_hook_timing.libc";
    result.counterFrequency = frequency;
    if (cancellation.cancelled()) {
        result.status = "skipped";
        result.reason = "cancelled";
        return result;
    }
    const SemanticPass before = libcSemanticPass(fd, cancellation, deadline);
    if (before.interrupted) {
        result.status = cancellation.cancelled() ? "skipped" : "truncated";
        result.reason = cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data";
        return result;
    }
    if (!before.available) {
        result.status = "unavailable";
        result.reason = "semantic_unavailable";
        return result;
    }
    if (!warmupLibc(fd, before.timingName, cancellation, deadline)) {
        result.status = cancellation.cancelled() ? "skipped" : "truncated";
        result.reason = cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data";
        return result;
    }
    std::vector<BatchAnalysis> ifconfBatches;
    std::vector<BatchAnalysis> ifindexBatches;
    std::vector<TimedPair> ifconf;
    std::vector<TimedPair> ifindex;
    std::vector<TimedPair> control;
    bool cancelled = false;
    bool deadlineReached = false;
    for (std::size_t batch = 0; batch < beta_hook_timing::kMaximumBatches; ++batch) {
        cancelled = cancellation.cancelled();
        deadlineReached = std::chrono::steady_clock::now() >= deadline;
        if (cancelled || deadlineReached) break;
#if defined(__aarch64__)
        const bool ifconfFull = fillBatch(
            &ifconf,
            beta_hook_timing::kPairsPerBatch,
            deadline,
            cancellation,
            [fd](PairOrder order) { return measureLibcRawPair(fd, MeasuredOperation::IFCONF, {}, order); }
        );
        const bool ifindexFull = fillBatch(
            &ifindex,
            beta_hook_timing::kPairsPerBatch,
            deadline,
            cancellation,
            [fd, &before](PairOrder order) {
                return measureLibcRawPair(fd, MeasuredOperation::IFINDEX, before.timingName, order);
            }
        );
        const bool controlFull = fillBatch(
            &control,
            beta_hook_timing::kPairsPerBatch,
            deadline,
            cancellation,
            [fd](PairOrder order) { return measureLibcRawPair(fd, MeasuredOperation::CONTROL_READ, {}, order); }
        );
        if (!ifconfFull || !ifindexFull || !controlFull) break;
#endif
        const BatchAnalysis ifconfAnalysis = beta_hook_timing::analyzeBatch(ifconf, control);
        const BatchAnalysis ifindexAnalysis = beta_hook_timing::analyzeBatch(ifindex, control);
        if (ifconfAnalysis.validPairs < beta_hook_timing::kPairsPerBatch ||
            ifindexAnalysis.validPairs < beta_hook_timing::kPairsPerBatch) {
            break;
        }
        ifconfBatches.push_back(ifconfAnalysis);
        ifindexBatches.push_back(ifindexAnalysis);
        ++result.fullBatches;
        result.measurements += beta_hook_timing::kPairsPerBatch;
        result.droppedMigrations +=
            migrationCount(ifconf) + migrationCount(ifindex) + migrationCount(control);
        updateConservativeAggregate(&result, ifconfAnalysis, ifindexAnalysis);
    }
    const SemanticPass after = libcSemanticPass(fd, cancellation, deadline);
    if (after.interrupted) {
        result.status = cancellation.cancelled() ? "skipped" : "truncated";
        result.reason = cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data";
        result.corroborated = false;
        return result;
    }
    if (!after.available) {
        result.status = "unavailable";
        result.reason = "semantic_unavailable";
        result.corroborated = false;
        return result;
    }
    result.semanticMismatch = before.mismatch && after.available && after.mismatch;
    result.timingAnomaly = beta_hook_timing::hasStableAnomaly(ifconfBatches) &&
        beta_hook_timing::hasStableAnomaly(ifindexBatches);
    const CompletionStatus completion = beta_hook_timing::completionStatus(
        result.fullBatches,
        result.measurements,
        cancelled || cancellation.cancelled(),
        deadlineReached || std::chrono::steady_clock::now() >= deadline
    );
    if (completion == CompletionStatus::CANCELLED) {
        result.status = "skipped";
        result.reason = "cancelled";
    } else if (completion == CompletionStatus::TRUNCATED) {
        result.status = "truncated";
        result.reason = "deadline_or_insufficient_data";
    } else {
        result.corroborated = result.timingAnomaly && result.semanticMismatch;
        result.reason = result.corroborated ? "corroborated"
            : result.timingAnomaly ? "timing_only"
            : result.semanticMismatch ? "semantic_only"
            : "no_corroboration";
    }
    return result;
}

struct KernelCandidate {
    std::string name;
    std::string control;
    std::int64_t sweepDelta = std::numeric_limits<std::int64_t>::min();
};

[[maybe_unused]] AggregateResult runKernelBranch(
    int fd,
    std::uint64_t frequency,
    const CancellationProbe &cancellation,
    std::chrono::steady_clock::time_point deadline
) {
    AggregateResult result;
    result.check = "vpnhide_hook_timing.kernel";
    result.counterFrequency = frequency;
    if (cancellation.cancelled()) {
        result.status = "skipped";
        result.reason = "cancelled";
        return result;
    }
    const KernelSources before = kernelSources(fd, cancellation, deadline);
    if (!before.available) {
        const bool interrupted = shouldStop(cancellation, deadline);
        result.status = interrupted ? (cancellation.cancelled() ? "skipped" : "truncated") : "unavailable";
        result.reason = interrupted
            ? (cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data")
            : before.failureReason;
        return result;
    }
    bool controlsInterrupted = false;
    const auto controls = buildAbsentControls(fd, before, cancellation, deadline, &controlsInterrupted);
    if (controlsInterrupted) {
        result.status = cancellation.cancelled() ? "skipped" : "truncated";
        result.reason = cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data";
        return result;
    }
    const auto candidates = vpnhide_regression::buildIfNameCandidates();
    std::vector<KernelCandidate> strongest;
    strongest.reserve(kStrongKernelCandidates);
#if defined(__aarch64__)
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        if (shouldStop(cancellation, deadline)) break;
        const std::string &name = candidates[index];
        if (name.empty() || name.size() >= controls.size() || controls[name.size()].empty()) continue;
        const TimedPair sample = measureRawNamesPair(
            fd,
            name,
            controls[name.size()],
            beta_hook_timing::pairOrderFor(index)
        );
        if (shouldStop(cancellation, deadline)) break;
        if (!sample.cpuStable) {
            ++result.droppedMigrations;
            continue;
        }
        const std::int64_t suspect = static_cast<std::int64_t>(std::min<std::uint64_t>(
            sample.suspectTicks,
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        ));
        const std::int64_t baseline = static_cast<std::int64_t>(std::min<std::uint64_t>(
            sample.baselineTicks,
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        ));
        KernelCandidate candidate{name, controls[name.size()], suspect - baseline};
        strongest.push_back(std::move(candidate));
        std::sort(strongest.begin(), strongest.end(), [](const KernelCandidate &left,
                                                          const KernelCandidate &right) {
            return left.sweepDelta > right.sweepDelta;
        });
        if (strongest.size() > kStrongKernelCandidates) strongest.pop_back();
    }
#endif
    if (strongest.empty()) {
        result.status = "truncated";
        result.reason = "no_candidate_data";
        return result;
    }
#if defined(__aarch64__)
    for (std::size_t warmup = 0; warmup < beta_hook_timing::kWarmupPairs; ++warmup) {
        if (shouldStop(cancellation, deadline)) {
            result.status = cancellation.cancelled() ? "skipped" : "truncated";
            result.reason = cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data";
            return result;
        }
        const PairOrder order = beta_hook_timing::pairOrderFor(warmup);
        for (const KernelCandidate &candidate : strongest) {
            (void) measureRawNamesPair(fd, candidate.name, candidate.control, order);
            if (shouldStop(cancellation, deadline)) {
                result.status = cancellation.cancelled() ? "skipped" : "truncated";
                result.reason = cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data";
                return result;
            }
        }
        (void) measureRawControlPair(fd, order);
    }
#endif
    std::array<std::vector<BatchAnalysis>, kStrongKernelCandidates> analyses;
    std::array<std::int64_t, kStrongKernelCandidates> minimumMedian{};
    std::array<std::int64_t, kStrongKernelCandidates> maximumMad{};
    std::array<std::uint32_t, kStrongKernelCandidates> minimumRatio{};
    minimumMedian.fill(std::numeric_limits<std::int64_t>::max());
    minimumRatio.fill(std::numeric_limits<std::uint32_t>::max());
    std::vector<TimedPair> operation;
    std::vector<TimedPair> control;
    bool cancelled = false;
    bool deadlineReached = false;
    for (std::size_t batch = 0; batch < beta_hook_timing::kMaximumBatches; ++batch) {
        cancelled = cancellation.cancelled();
        deadlineReached = std::chrono::steady_clock::now() >= deadline;
        if (cancelled || deadlineReached) break;
#if defined(__aarch64__)
        const bool controlFull = fillBatch(
            &control,
            beta_hook_timing::kPairsPerBatch,
            deadline,
            cancellation,
            [fd](PairOrder order) { return measureRawControlPair(fd, order); }
        );
        if (!controlFull) break;
        bool batchFull = true;
        std::size_t batchMigrations = migrationCount(control);
        std::array<BatchAnalysis, kStrongKernelCandidates> batchAnalyses{};
        for (std::size_t index = 0; index < strongest.size(); ++index) {
            const bool operationFull = fillBatch(
                &operation,
                beta_hook_timing::kPairsPerBatch,
                deadline,
                cancellation,
                [fd, &strongest, index](PairOrder order) {
                    return measureRawNamesPair(
                        fd,
                        strongest[index].name,
                        strongest[index].control,
                        order
                    );
                }
            );
            if (!operationFull) {
                batchFull = false;
                break;
            }
            batchAnalyses[index] = beta_hook_timing::analyzeBatch(operation, control);
            batchMigrations += migrationCount(operation);
            if (batchAnalyses[index].validPairs < beta_hook_timing::kPairsPerBatch) {
                batchFull = false;
                break;
            }
        }
        if (!batchFull) break;
        ++result.fullBatches;
        result.measurements += beta_hook_timing::kPairsPerBatch;
        result.droppedMigrations += batchMigrations;
        for (std::size_t index = 0; index < strongest.size(); ++index) {
            analyses[index].push_back(batchAnalyses[index]);
            minimumMedian[index] = std::min(minimumMedian[index], batchAnalyses[index].correctedMedianTicks);
            maximumMad[index] = std::max(maximumMad[index], batchAnalyses[index].combinedMadTicks);
            minimumRatio[index] = std::min(minimumRatio[index], batchAnalyses[index].normalizedRatioMilli);
        }
#endif
    }
    if (cancellation.cancelled()) {
        result.status = "skipped";
        result.reason = "cancelled";
        result.corroborated = false;
        return result;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        result.status = "truncated";
        result.reason = "deadline_or_insufficient_data";
        result.corroborated = false;
        return result;
    }
    const KernelSources after = kernelSources(fd, cancellation, deadline);
    if (!after.available) {
        const bool interrupted = shouldStop(cancellation, deadline);
        result.status = interrupted ? (cancellation.cancelled() ? "skipped" : "truncated") : "unavailable";
        result.reason = interrupted
            ? (cancellation.cancelled() ? "cancelled" : "deadline_or_insufficient_data")
            : after.failureReason;
        return result;
    }
    std::size_t representative = 0;
    std::size_t representativeAnomalies = 0;
    bool anyTiming = false;
    bool anySemantic = false;
    bool anyCorroborated = false;
    bool semanticSweepComplete = true;
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        if (shouldStop(cancellation, deadline)) {
            cancelled = cancellation.cancelled();
            deadlineReached = !cancelled;
            semanticSweepComplete = false;
            break;
        }
        const bool beforeMismatch = sourceMismatch(fd, candidates[index], before);
        if (shouldStop(cancellation, deadline)) {
            cancelled = cancellation.cancelled();
            deadlineReached = !cancelled;
            semanticSweepComplete = false;
            break;
        }
        const bool afterMismatch = sourceMismatch(fd, candidates[index], after);
        anySemantic = anySemantic || (beforeMismatch && afterMismatch);
    }
    for (std::size_t index = 0; index < strongest.size(); ++index) {
        if (shouldStop(cancellation, deadline)) {
            cancelled = cancellation.cancelled();
            deadlineReached = !cancelled;
            semanticSweepComplete = false;
            break;
        }
        const std::size_t anomalyCount = static_cast<std::size_t>(std::count_if(
            analyses[index].begin(), analyses[index].end(), [](const BatchAnalysis &batchAnalysis) {
                return batchAnalysis.anomalous;
            }
        ));
        const bool stable = beta_hook_timing::hasStableAnomaly(analyses[index]);
        const bool beforeMismatch = sourceMismatch(fd, strongest[index].name, before);
        if (shouldStop(cancellation, deadline)) {
            cancelled = cancellation.cancelled();
            deadlineReached = !cancelled;
            semanticSweepComplete = false;
            break;
        }
        const bool semantic = beforeMismatch && sourceMismatch(fd, strongest[index].name, after);
        anyTiming = anyTiming || stable;
        anySemantic = anySemantic || semantic;
        anyCorroborated = anyCorroborated || (stable && semantic);
        if (anomalyCount > representativeAnomalies) {
            representativeAnomalies = anomalyCount;
            representative = index;
        }
    }
    result.corroborated = anyCorroborated;
    result.timingAnomaly = anyCorroborated || anyTiming;
    result.semanticMismatch = anySemantic;
    if (!strongest.empty() && minimumMedian[representative] != std::numeric_limits<std::int64_t>::max()) {
        result.medianTicks = minimumMedian[representative];
        result.madTicks = maximumMad[representative];
        result.ratioMilli = minimumRatio[representative] == std::numeric_limits<std::uint32_t>::max()
            ? 0
            : minimumRatio[representative];
    }
    const CompletionStatus completion = beta_hook_timing::completionStatus(
        result.fullBatches,
        result.measurements,
        cancelled || cancellation.cancelled(),
        deadlineReached || std::chrono::steady_clock::now() >= deadline
    );
    if (completion == CompletionStatus::CANCELLED) {
        result.status = "skipped";
        result.reason = "cancelled";
        result.corroborated = false;
    } else if (completion == CompletionStatus::TRUNCATED || !semanticSweepComplete) {
        result.status = "truncated";
        result.reason = "deadline_or_insufficient_data";
        result.corroborated = false;
    } else {
        result.reason = result.corroborated ? "corroborated"
            : result.timingAnomaly && result.semanticMismatch ? "uncorrelated_signals"
            : result.timingAnomaly ? "timing_only"
            : result.semanticMismatch ? "semantic_only"
            : "no_corroboration";
    }
    return result;
}

std::string aggregateRow(const AggregateResult &result) {
    const std::uint64_t medianTicks = static_cast<std::uint64_t>(std::max<std::int64_t>(0, result.medianTicks));
    const std::uint64_t madTicks = static_cast<std::uint64_t>(std::max<std::int64_t>(0, result.madTicks));
    std::ostringstream row;
    row << "beta_v1|check=" << result.check
        << "|status=" << result.status
        << "|reason=" << result.reason
        << "|counter_hz=" << result.counterFrequency
        << "|valid_pairs=" << result.measurements
        << "|full_batches=" << result.fullBatches
        << "|cpu_migrations=" << result.droppedMigrations
        << "|median_ticks=" << medianTicks
        << "|mad_ticks=" << madTicks
        << "|ratio_milli=" << result.ratioMilli
        << "|timing_anomaly=" << (result.timingAnomaly ? "true" : "false")
        << "|semantic_mismatch=" << (result.semanticMismatch ? "true" : "false")
        << "|corroborated=" << (result.corroborated ? "true" : "false");
    return row.str();
}

[[maybe_unused]] std::string unsupportedRow(const char *check) {
    AggregateResult result;
    result.check = check;
    result.status = "unsupported";
    result.reason = "unsupported_arch";
    return aggregateRow(result);
}

[[maybe_unused]] std::string counterUnavailableRow(const char *check) {
    AggregateResult result;
    result.check = check;
    result.status = "unavailable";
    result.reason = "counter_unavailable";
    return aggregateRow(result);
}

jobjectArray toArray(JNIEnv *env, const std::array<std::string, 2> &rows) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray result = env->NewObjectArray(2, stringClass, nullptr);
    if (result == nullptr) {
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }
    for (jsize index = 0; index < 2; ++index) {
        jstring value = env->NewStringUTF(rows[static_cast<std::size_t>(index)].c_str());
        if (value == nullptr) break;
        env->SetObjectArrayElement(result, index, value);
        env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(stringClass);
    return result;
}

}  // namespace

jobjectArray nativeBetaHookTimingProbe(JNIEnv *env, jclass, jobject cancellationSignal) {
#if !defined(__aarch64__)
    (void) cancellationSignal;
    return toArray(env, {
        unsupportedRow("vpnhide_hook_timing.libc"),
        unsupportedRow("vpnhide_hook_timing.kernel"),
    });
#else
    const auto startedAt = std::chrono::steady_clock::now();
    const auto measurementDeadline = startedAt + kMeasurementDeadline;
    const auto hardDeadline = startedAt + kNativeHardDeadline;
    const CancellationProbe cancellation(env, cancellationSignal);
    const std::uint64_t frequency = readCounterFrequency();
    if (frequency == 0) {
        return toArray(env, {
            counterUnavailableRow("vpnhide_hook_timing.libc"),
            counterUnavailableRow("vpnhide_hook_timing.kernel"),
        });
    }
    ScopedFd fd(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (!fd.valid()) {
        AggregateResult libc;
        libc.check = "vpnhide_hook_timing.libc";
        libc.status = "unavailable";
        libc.reason = "socket_unavailable";
        libc.counterFrequency = frequency;
        AggregateResult kernel = libc;
        kernel.check = "vpnhide_hook_timing.kernel";
        return toArray(env, {aggregateRow(libc), aggregateRow(kernel)});
    }
    AggregateResult libc = runLibcBranch(
        fd.get(),
        frequency,
        cancellation,
        measurementDeadline
    );
    AggregateResult kernel;
    if (std::chrono::steady_clock::now() >= measurementDeadline) {
        kernel.check = "vpnhide_hook_timing.kernel";
        kernel.status = "truncated";
        kernel.reason = "deadline_or_insufficient_data";
        kernel.counterFrequency = frequency;
    } else {
        kernel = runKernelBranch(
            fd.get(),
            frequency,
            cancellation,
            measurementDeadline
        );
    }
    if (std::chrono::steady_clock::now() >= hardDeadline) {
        if (std::string_view(libc.status) != "skipped") {
            libc.status = "truncated";
            libc.reason = "hard_deadline";
            libc.corroborated = false;
        }
        if (std::string_view(kernel.status) != "skipped") {
            kernel.status = "truncated";
            kernel.reason = "hard_deadline";
            kernel.corroborated = false;
        }
    }
    return toArray(env, {aggregateRow(libc), aggregateRow(kernel)});
#endif
}

#endif
