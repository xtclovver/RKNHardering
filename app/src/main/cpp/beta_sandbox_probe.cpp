#include "beta_sandbox_probe.h"

#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/stat.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr size_t kMaxPaths = 12;
constexpr size_t kMaxPathBytes = 4096;
constexpr size_t kMaxProcBytes = 512 * 1024;
constexpr size_t kMaxProcLines = 4096;

struct ScopedFd {
    explicit ScopedFd(int value = -1) : value(value) {}
    ~ScopedFd() { if (value >= 0) close(value); }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    int release() { const int result = value; value = -1; return result; }
    int value;
};

struct LabeledPath {
    std::string label;
    std::string path;
};

struct ModuleRange {
    std::string name;
    uintptr_t start;
    uintptr_t end;
};

jobjectArray toStringArray(JNIEnv *env, const std::vector<std::string> &items) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(items.size()), stringClass, nullptr);
    if (result == nullptr) {
        env->DeleteLocalRef(stringClass);
        return nullptr;
    }
    for (jsize i = 0; i < static_cast<jsize>(items.size()); ++i) {
        jstring value = env->NewStringUTF(items[static_cast<size_t>(i)].c_str());
        if (value == nullptr) break;
        env->SetObjectArrayElement(result, i, value);
        env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(stringClass);
    return result;
}

std::string basenameOf(const std::string &path) {
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool readBoundedFile(const char *path, std::string *out, size_t maxBytes) {
    ScopedFd fd(open(path, O_RDONLY | O_CLOEXEC));
    if (fd.value < 0) return false;
    char buffer[4096];
    while (out->size() < maxBytes) {
        const size_t remaining = maxBytes - out->size();
        const ssize_t count = read(fd.value, buffer, remaining < sizeof(buffer) ? remaining : sizeof(buffer));
        if (count == 0) return true;
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        out->append(buffer, static_cast<size_t>(count));
    }
    return true;
}

bool parseStatusValue(const std::string &status, const char *key, int *value) {
    const std::string prefix = std::string(key) + ":";
    size_t start = 0;
    while (start < status.size()) {
        const size_t end = status.find('\n', start);
        const size_t length = (end == std::string::npos ? status.size() : end) - start;
        if (length >= prefix.size() && status.compare(start, prefix.size(), prefix) == 0) {
            const char *number = status.c_str() + start + prefix.size();
            while (*number == ' ' || *number == '\t') ++number;
            char *tail = nullptr;
            const long parsed = strtol(number, &tail, 10);
            if (tail == number) return false;
            *value = static_cast<int>(parsed);
            return true;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}

bool hasSeccompFilter() {
    std::string status;
    int seccomp = -1;
    return readBoundedFile("/proc/self/status", &status, 64 * 1024) &&
        parseStatusValue(status, "Seccomp", &seccomp) && seccomp == 2;
}

std::string processRow() {
    std::string status;
    const bool statusReadable = readBoundedFile("/proc/self/status", &status, 64 * 1024);
    int tracerPid = -1;
    int seccomp = -1;
    int noNewPrivs = -1;
    if (statusReadable) {
        parseStatusValue(status, "TracerPid", &tracerPid);
        parseStatusValue(status, "Seccomp", &seccomp);
        parseStatusValue(status, "NoNewPrivs", &noNewPrivs);
    }
    std::string cgroup;
    const bool cgroupReadable = readBoundedFile("/proc/self/cgroup", &cgroup, 64 * 1024);
    size_t cgroupLines = 0;
    for (char value : cgroup) if (value == '\n') ++cgroupLines;

    std::ostringstream row;
    row << "beta_v1|check=sandbox_identity.process|status=available"
        << "|uid=" << static_cast<uint32_t>(getuid())
        << "|gid=" << static_cast<uint32_t>(getgid())
        << "|status_readable=" << (statusReadable ? "true" : "false")
        << "|cgroup_readable=" << (cgroupReadable ? "true" : "false")
        << "|cgroup_lines=" << cgroupLines
        << "|tracer_pid=" << tracerPid
        << "|seccomp=" << seccomp
        << "|no_new_privs=" << noNewPrivs
        << "|dumpable=" << prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    return row.str();
}

bool readLinkValue(const char *path, std::string *value) {
    char buffer[256];
    const ssize_t count = readlink(path, buffer, sizeof(buffer) - 1);
    if (count < 0) return false;
    buffer[count] = '\0';
    *value = buffer;
    return true;
}

std::string namespaceRow() {
    const char *names[] = {"mnt", "user", "pid", "net"};
    size_t available = 0;
    for (const char *name : names) {
        std::string value;
        const std::string path = std::string("/proc/self/ns/") + name;
        if (readLinkValue(path.c_str(), &value) && !value.empty()) ++available;
    }
    std::string mountInfo;
    const bool mountInfoReadable = readBoundedFile("/proc/self/mountinfo", &mountInfo, kMaxProcBytes);
    size_t mountLines = 0;
    for (char value : mountInfo) if (value == '\n' && mountLines < kMaxProcLines) ++mountLines;
    std::ostringstream row;
    row << "beta_v1|check=sandbox_identity.namespace|status="
        << (available > 0 || mountInfoReadable ? "available" : "unavailable")
        << "|namespace_count=" << available
        << "|mountinfo_readable=" << (mountInfoReadable ? "true" : "false")
        << "|mount_count=" << mountLines;
    return row.str();
}

bool statxPath(const std::string &path, struct statx *value, int *error) {
#if defined(__NR_statx)
    std::memset(value, 0, sizeof(*value));
    unsigned int mask = STATX_BASIC_STATS;
#if defined(STATX_MNT_ID)
    mask |= STATX_MNT_ID;
#endif
    if (syscall(__NR_statx, AT_FDCWD, path.c_str(), AT_SYMLINK_NOFOLLOW,
                mask, value) == 0) return true;
    *error = errno;
#else
    (void) path;
    (void) value;
    *error = ENOSYS;
#endif
    return false;
}

std::string filesystemRow(const std::vector<LabeledPath> &paths, const char *checkId) {
    size_t existing = 0;
    size_t statxSuccess = 0;
    size_t statfsSuccess = 0;
    size_t fscryptKnown = 0;
    size_t uidMismatch = 0;
    size_t directMismatch = 0;
    int firstError = 0;

    for (const auto &item : paths) {
        struct stat libcStat{};
        const bool libcOk = lstat(item.path.c_str(), &libcStat) == 0;
        if (libcOk) {
            ++existing;
            if (libcStat.st_uid != getuid() &&
                (item.label == "ce" || item.label == "de" || item.label == "files" || item.label == "cache")) {
                ++uidMismatch;
            }
        }
        struct statx directStat{};
        int statxError = 0;
        const bool directOk = statxPath(item.path, &directStat, &statxError);
        if (directOk) {
            ++statxSuccess;
            if (libcOk && (static_cast<uint64_t>(libcStat.st_ino) != directStat.stx_ino ||
                           static_cast<uint32_t>(libcStat.st_mode) != directStat.stx_mode ||
                           static_cast<uint32_t>(libcStat.st_uid) != directStat.stx_uid)) {
                ++directMismatch;
            }
        } else if (firstError == 0) {
            firstError = statxError;
        }
        struct statfs fs{};
        if (statfs(item.path.c_str(), &fs) == 0) ++statfsSuccess;

        if (libcOk && S_ISDIR(libcStat.st_mode) &&
            (item.label == "ce" || item.label == "de" || item.label == "files" || item.label == "cache")) {
            ScopedFd fd(open(item.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            if (fd.value >= 0) {
#if defined(FS_IOC_GET_ENCRYPTION_POLICY_EX)
                struct fscrypt_get_policy_ex_arg policy{};
                policy.policy_size = sizeof(policy.policy);
                if (ioctl(fd.value, FS_IOC_GET_ENCRYPTION_POLICY_EX, &policy) == 0) ++fscryptKnown;
#endif
                unsigned long flags = 0;
                (void) ioctl(fd.value, FS_IOC_GETFLAGS, &flags);
            }
        }
    }
    const bool contradiction = directMismatch > 0 || uidMismatch >= 2;
    std::ostringstream row;
    row << "beta_v1|check=" << checkId << "|status=" << (existing > 0 ? "available" : "unavailable")
        << "|path_count=" << paths.size()
        << "|existing_count=" << existing
        << "|statx_count=" << statxSuccess
        << "|statfs_count=" << statfsSuccess
        << "|fscrypt_known_count=" << fscryptKnown
        << "|uid_mismatch_count=" << uidMismatch
        << "|direct_mismatch_count=" << directMismatch
        << "|critical_mismatch=" << (contradiction ? "true" : "false");
    if (firstError != 0) row << "|statx_errno=" << firstError;
    return row.str();
}

std::string directSyscallRow(const std::vector<LabeledPath> &paths) {
    size_t compared = 0;
    size_t mismatches = 0;
    for (const auto &item : paths) {
        struct stat libcStat{};
        if (lstat(item.path.c_str(), &libcStat) != 0) continue;
        struct statx directStat{};
        int error = 0;
        if (!statxPath(item.path, &directStat, &error)) continue;
        ++compared;
        if (static_cast<uint64_t>(libcStat.st_ino) != directStat.stx_ino ||
            static_cast<uint32_t>(libcStat.st_mode) != directStat.stx_mode ||
            static_cast<uint32_t>(libcStat.st_uid) != directStat.stx_uid) ++mismatches;
    }
    std::string libcTarget;
    std::string directTarget;
    const bool libcRead = readLinkValue("/proc/self/exe", &libcTarget);
#if defined(__NR_readlinkat)
    char buffer[4096];
    const ssize_t count = syscall(__NR_readlinkat, AT_FDCWD, "/proc/self/exe", buffer, sizeof(buffer) - 1);
    const bool directRead = count >= 0;
    if (directRead) {
        buffer[count] = '\0';
        directTarget = buffer;
    }
#else
    const bool directRead = false;
#endif
    if (libcRead && directRead) {
        ++compared;
        if (libcTarget != directTarget) ++mismatches;
    }
    std::ostringstream row;
    row << "beta_v1|check=direct_syscall_consistency|status=" << (compared > 0 ? "available" : "unsupported")
        << "|compared_count=" << compared
        << "|mismatch_count=" << mismatches
        << "|critical_mismatch=" << (mismatches > 0 ? "true" : "false");
    return row.str();
}

std::string fdIdentityRow() {
    int pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        return "beta_v1|check=fd_identity|status=error|stage=socketpair";
    }
    ScopedFd first(pair[0]);
    ScopedFd peer(pair[1]);
    ScopedFd duplicate(dup(first.value));
    if (duplicate.value < 0) return "beta_v1|check=fd_identity|status=error|stage=dup";
    struct stat firstStat{};
    struct stat duplicateStat{};
    const bool firstOk = fstat(first.value, &firstStat) == 0;
    const bool duplicateOk = fstat(duplicate.value, &duplicateStat) == 0;
    const bool fstatMismatch = firstOk && duplicateOk &&
        (firstStat.st_dev != duplicateStat.st_dev || firstStat.st_ino != duplicateStat.st_ino ||
         firstStat.st_mode != duplicateStat.st_mode);

    int kcmpResult = -1;
    int kcmpError = ENOSYS;
#if defined(__NR_kcmp)
    if (!hasSeccompFilter()) {
        errno = 0;
        kcmpResult = static_cast<int>(syscall(__NR_kcmp, getpid(), getpid(), 0, first.value, duplicate.value));
        kcmpError = kcmpResult < 0 ? errno : 0;
    }
#endif
    bool pidfdCompared = false;
    bool pidfdMismatch = false;
    int pidfdError = ENOSYS;
#if defined(__NR_pidfd_open) && defined(__NR_pidfd_getfd)
    if (!hasSeccompFilter()) {
        ScopedFd pidfd(static_cast<int>(syscall(__NR_pidfd_open, getpid(), 0)));
        if (pidfd.value >= 0) {
            ScopedFd copied(static_cast<int>(syscall(__NR_pidfd_getfd, pidfd.value, first.value, 0)));
            if (copied.value >= 0) {
                struct stat copiedStat{};
                if (fstat(copied.value, &copiedStat) == 0 && firstOk) {
                    pidfdCompared = true;
                    pidfdMismatch = firstStat.st_dev != copiedStat.st_dev || firstStat.st_ino != copiedStat.st_ino;
                }
            } else {
                pidfdError = errno;
            }
        } else {
            pidfdError = errno;
        }
    }
#endif
    const bool kcmpMismatch = kcmpResult > 0;
    const bool contradiction = fstatMismatch || kcmpMismatch || pidfdMismatch;
    std::ostringstream row;
    row << "beta_v1|check=fd_identity|status=" << (firstOk && duplicateOk ? "available" : "error")
        << "|fstat_match=" << (fstatMismatch ? "false" : "true")
        << "|kcmp_result=" << kcmpResult
        << "|kcmp_errno=" << kcmpError
        << "|pidfd_compared=" << (pidfdCompared ? "true" : "false")
        << "|pidfd_errno=" << pidfdError
        << "|critical_mismatch=" << (contradiction ? "true" : "false");
    return row.str();
}

int collectModule(struct dl_phdr_info *info, size_t, void *opaque) {
    auto *ranges = static_cast<std::vector<ModuleRange> *>(opaque);
    const std::string name = info->dlpi_name == nullptr || info->dlpi_name[0] == '\0'
        ? "/proc/self/exe" : info->dlpi_name;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &header = info->dlpi_phdr[i];
        if (header.p_type != PT_LOAD || (header.p_flags & PF_X) == 0) continue;
        const uintptr_t start = static_cast<uintptr_t>(info->dlpi_addr + header.p_vaddr);
        ranges->push_back({name, start, start + static_cast<uintptr_t>(header.p_memsz)});
    }
    return ranges->size() >= 512 ? 1 : 0;
}

std::string linkerRow() {
    std::vector<ModuleRange> ranges;
    dl_iterate_phdr(collectModule, &ranges);
    std::string maps;
    const bool mapsReadable = readBoundedFile("/proc/self/maps", &maps, kMaxProcBytes);
    size_t executableFileMaps = 0;
    size_t start = 0;
    while (start < maps.size() && executableFileMaps < kMaxProcLines) {
        const size_t end = maps.find('\n', start);
        const std::string line = maps.substr(start, (end == std::string::npos ? maps.size() : end) - start);
        const size_t permissions = line.find(' ');
        if (permissions != std::string::npos && permissions + 3 < line.size() &&
            line[permissions + 3] == 'x' && line.find('/') != std::string::npos) ++executableFileMaps;
        if (end == std::string::npos) break;
        start = end + 1;
    }

    void *symbol = dlsym(RTLD_DEFAULT, "connect");
    Dl_info owner{};
    const bool ownerKnown = symbol != nullptr && dladdr(symbol, &owner) != 0 && owner.dli_fname != nullptr;
    bool symbolInOwner = false;
    if (ownerKnown) {
        const std::string ownerBase = basenameOf(owner.dli_fname);
        const uintptr_t address = reinterpret_cast<uintptr_t>(symbol);
        for (const auto &range : ranges) {
            if (basenameOf(range.name) == ownerBase && address >= range.start && address < range.end) {
                symbolInOwner = true;
                break;
            }
        }
    }
    const bool contradiction = ownerKnown && !symbolInOwner;
    std::ostringstream row;
    row << "beta_v1|check=linker_integrity|status=" << (!ranges.empty() ? "available" : "unavailable")
        << "|loader_exec_segments=" << ranges.size()
        << "|maps_readable=" << (mapsReadable ? "true" : "false")
        << "|mapped_exec_files=" << executableFileMaps
        << "|symbol_owner_known=" << (ownerKnown ? "true" : "false")
        << "|symbol_in_owner=" << (symbolInOwner ? "true" : "false")
        << "|critical_mismatch=" << (contradiction ? "true" : "false");
    return row.str();
}

std::vector<LabeledPath> readPaths(JNIEnv *env, jobjectArray values) {
    std::vector<LabeledPath> result;
    if (values == nullptr) return result;
    const jsize count = env->GetArrayLength(values);
    const jsize capped = count < static_cast<jsize>(kMaxPaths) ? count : static_cast<jsize>(kMaxPaths);
    for (jsize i = 0; i < capped; ++i) {
        auto value = static_cast<jstring>(env->GetObjectArrayElement(values, i));
        if (value == nullptr) continue;
        const char *utf = env->GetStringUTFChars(value, nullptr);
        if (utf != nullptr) {
            const std::string item(utf);
            const size_t separator = item.find('=');
            if (separator > 0 && separator < 32 && item.size() - separator - 1 <= kMaxPathBytes) {
                result.push_back({item.substr(0, separator), item.substr(separator + 1)});
            }
            env->ReleaseStringUTFChars(value, utf);
        }
        env->DeleteLocalRef(value);
    }
    return result;
}

}  // namespace

jobjectArray nativeBetaSandboxSnapshot(JNIEnv *env, jclass, jobjectArray paths, jboolean aggressive) {
    const std::vector<LabeledPath> parsedPaths = readPaths(env, paths);
    std::vector<std::string> rows;
    rows.reserve(7);
    rows.push_back(processRow());
    rows.push_back(namespaceRow());
    rows.push_back(filesystemRow(parsedPaths, "sandbox_identity.filesystem"));
    rows.push_back(directSyscallRow(parsedPaths));
    if (aggressive == JNI_TRUE) {
        rows.push_back(filesystemRow(parsedPaths, "fscrypt_identity"));
        rows.push_back(fdIdentityRow());
        rows.push_back(linkerRow());
    }
    return toStringArray(env, rows);
}
