/* SDK-typed A guest process observations. Compile ONLY inside admitted OMEN
 * macOS with its actual SDK: cc -dynamiclib -o omen_source_darwin.dylib ... -lproc
 * No signal, source selection, VM control or host privilege API is exported. */
#if !defined(__APPLE__)
#error This bridge requires the actual macOS SDK inside the OMEN macOS guest
#endif
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

int opemos_source_process(int pid, uint64_t out[3]) {
    struct proc_bsdinfo b;
    if (pid <= 0 || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &b, sizeof b) != (int)sizeof b)
        return -1;
    /* Public SDK fields, not a guessed private PROC_PIDUNIQIDENTIFIER ABI. */
    if (!b.pbi_start_tvsec || b.pbi_start_tvusec >= 1000000 ||
        b.pbi_start_tvsec > UINT64_MAX / 1000000 || b.pbi_pid != (uint32_t)pid) {
        errno = EINVAL; return -1;
    }
    out[0] = b.pbi_start_tvsec * 1000000 + b.pbi_start_tvusec;
    out[1] = b.pbi_uid; out[2] = b.pbi_pgid;
    return 0;
}
int opemos_source_pids(int *out, int capacity) {
    if (capacity != 65536) { errno = EINVAL; return -1; }
    int n = proc_listallpids(out, capacity * sizeof *out);
    if (n <= 0 || n >= capacity) { errno = EOVERFLOW; return -1; }
    return n;
}
int opemos_source_child_exited(int pid) {
    siginfo_t info = {0};
    if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT) != 0) return -1;
    return info.si_pid == pid ? 1 : 0;
}
