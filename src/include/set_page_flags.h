#ifndef _SET_PAGE_FLAGS_H_
#define _SET_PAGE_FLAGS_H_

#include <asm/pgtable.h>
#include <linux/align.h>
#include "resolve_kallsyms.h"

static struct mm_struct *init_mm_ptr = NULL;

static void init_init_mm_ptr(void) {
    if (!init_mm_ptr) {
        init_mm_ptr = rk_kallsyms_lookup_name("init_mm");
    }
}

void *virt_to_ptep(uintptr_t addr) {
    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp;
    pmd_t *pmdp;
    pte_t *ptep;

    pgdp = pgd_offset(init_mm_ptr, addr);
    if (pgd_none(*pgdp)) {
        return NULL;
    }

    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(*p4dp)) {
        return NULL;
    }

    pudp = pud_offset(p4dp, addr);
    if (pud_none(*pudp)) {
        return NULL;
    }
    if (pud_sect(*pudp)) {
        printk(KERN_INFO "debug: virt_to_ptep success, virt (%pK), ptep @ %pK", addr, pudp);
        return pudp;
    }

    pmdp = pmd_offset(pudp, addr);
    if (pmd_none(*pmdp)) {
        return NULL;
    }
    if (pmd_sect(*pmdp)) {
        printk(KERN_INFO "debug: virt_to_ptep success, virt (%pK), ptep @ %pK", addr, pmdp);
        return pmdp;
    }

    ptep = pte_offset_kernel(pmdp, addr);
    if (!ptep) {
        return NULL;
    }

    printk(KERN_INFO "debug: virt_to_ptep success, virt (%pK), ptep @ %pK", addr, ptep);
    return ptep;
}

void pte_flip_write_protect(pte_t *ptep) {
    if (!pte_write(*ptep)) {
        *ptep = pte_mkwrite(pte_mkdirty(*ptep));
        *ptep = clear_pte_bit(*ptep, __pgprot((_AT(pteval_t, 1) << 7)));

        return;
    }

    *ptep = pte_wrprotect(*ptep);
    *ptep = set_pte_bit(*ptep, __pgprot((_AT(pteval_t, 1) << 7)));
}

static unsigned long highmem_pte_to_phys(pte_t *ptep) {
    struct page *p = pte_page(*ptep);
    return page_to_phys(p);
}

static unsigned long highmem_virt_to_phys(unsigned long addr) {
    unsigned long off = addr & ~PAGE_MASK;
    unsigned long r = highmem_pte_to_phys(virt_to_ptep(addr)) + off;
    // printk(KERN_INFO "debug: highmem_virt_to_phys on addr %lx, off %lx -> %lx\n", addr, off, r);
    return r;
}


#endif
