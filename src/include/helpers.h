#ifndef _HELPERS_H_
#define _HELPERS_H_

typedef long (*sched_setaffinity_t)(pid_t pid, const struct cpumask *in_mask);

static sched_setaffinity_t _helper_sched_setaffinity = NULL;

static long helper_sched_setaffinity(pid_t pid, const struct cpumask *in_mask) {
    if (!_helper_sched_setaffinity) {
        _helper_sched_setaffinity = rk_kallsyms_lookup_name("sched_setaffinity");
    }

    return _helper_sched_setaffinity(pid, in_mask);
}

// https://elixir.bootlin.com/linux/v5.15/source/arch/arm64/include/asm/kvm_host.h#L708
static inline void helper_init_host_cpu_context(struct kvm_cpu_context *cpu_ctxt)
{
	/* The host's MPIDR is immutable, so let's set it up at boot time */
	ctxt_sys_reg(cpu_ctxt, MPIDR_EL1) = read_cpuid_mpidr();
}


#define helper_make_contig(src, size)     \
    memcpy(kmalloc(ALIGN(size, PAGE_SIZE), GFP_KERNEL), src, size)


// !! cant be in a func idk why
#define helper_flush_virt(addr)       \
    flush_cache_mm(init_mm_ptr);      \
    flush_tlb_all();                  \
    _helper_flush_virt(addr);         \


#define helper_for_each_cpu(f)        \
    flush_cache_mm(init_mm_ptr);      \
    do {                              \
        int i;                        \
        for (i = 0; i < num_online_cpus(); i++) {             \
            helper_sched_setaffinity(0, get_cpu_mask(i));     \
            f                         \
        }                             \
    } while (0);


#endif
