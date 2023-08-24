#ifndef _HELPERS_H_
#define _HELPERS_H_

typedef long (*sched_setaffinity_t)(pid_t pid, const struct cpumask *in_mask);

static sched_setaffinity_t _sched_setaffinity = NULL;

static long kvmrk_sched_setaffinity(pid_t pid, const struct cpumask *in_mask) {
    if (!_sched_setaffinity) {
        _sched_setaffinity = rk_kallsyms_lookup_name("sched_setaffinity");
    }

    return _sched_setaffinity(pid, in_mask);
}

// https://elixir.bootlin.com/linux/v5.15/source/arch/arm64/include/asm/kvm_host.h#L708
static inline void kvmrk_init_host_cpu_context(struct kvm_cpu_context *cpu_ctxt)
{
	/* The host's MPIDR is immutable, so let's set it up at boot time */
	ctxt_sys_reg(cpu_ctxt, MPIDR_EL1) = read_cpuid_mpidr();
}


static void *make_contig(void *old, unsigned long size) {
    return memcpy(kmalloc(ALIGN(size, PAGE_SIZE), GFP_KERNEL), old, size);
}

#endif
