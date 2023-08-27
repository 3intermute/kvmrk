                                .------..------..------..------..------.
                                |K.--. ||V.--. ||M.--. ||R.--. ||K.--. |
                                | :/\: || :(): || (\/) || :(): || :/\: |
                                | :\/: || ()() || :\/: || ()() || :\/: |
                                | '--'K|| '--'V|| '--'M|| '--'R|| '--'K|
                                `------'`------'`------'`------'`------'
                                bluepill for arm64 linux via hijacking kvm


why:
    there are a lot of research bluepill hypervisors for x86 but not many for
    arm. the goal of this project is to provide a simple and small foundation
    to build a thin hypervisor for arm64 linux.

exploit:
    to replace kvm's el2 exception vector table, kvmrk uses a technique-
    demonstrated at blackhat 2018 by [1].

    host el1                                        el2
                                                   ┌──────────────────────────────────────────────────┐
                                                   │                                                  │
                                                   │ ┌──────────┐                                     │
                                                   │ │ vbar_el2 ├───────────►  __kvm_hyp_host_vector  │
                                                   │ └──────────┘                                     │
     x0                                            │                                                  │
    ┌────────────────────────┐              hvc    │                                                  │
    │ HVC_RESET_VECTORS      ├──────────────────►  │                                                  │
    └────────────────────────┘                     │ ┌──────────┐                                     │
                                                   │ │ vbar_el2 ├───────────►  __hyp_stub_vectors     │
                                                   │ └──────────┘                                     │
     x0                                            │                                                  │
    ┌────────────────────────┐              hvc    │                                                  │
    │ HVC_SET_VECTORS        ├──────────────────►  │                                                  │
    └────────────────────────┘                     │ ┌──────────┐                                     │
     x1 = virt_to_phys(_kvmrk_stub_vectors)        │ │ vbar_el2 ├───────────►  _kvmrk_stub_vectors    │
                                                   │ └──────────┘                                     │
     x0                                            │                                                  │
    ┌────────────────────────┐              hvc    │                                                  │
    │ KVMRK_HVC_INIT_VECTORS ├──────────────────►  │                                                  │
    └────────────────────────┘                     │ ┌──────────┐                                     │
     x1 = virt_to_phys(_kvmrk_vectors)             │ │ vbar_el2 ├───────────►  _kvmrk_vectors         │
     x2 = top of newly allocated hyp stack         │ └──────────┘                                     │
                                                   │                                                  │
                                                   └──────────────────────────────────────────────────┘


    1. from host el1, kvmrk makes a HVC_RESET_VECTORS hypercall, kvm's host-
       vector handles this by resetting vbar_el2 to __hyp_stub_vectors.

    2. from host el1, kvmrk makes a HVC_SET_VECTORS hypercall-
       __hyp_stub_vectors handles this by setting vbar_el2 to the physical
       address of __kvmrk_stub_vectors.
       note:
           __kvmrk_stub_vectors is needed as without a hypervisor stack it is
           impossible to temporarily save registers so as not to clobber them.

    3. kvmrk then allocates a hypervisor stack and struct kvm_host_data for
       each cpu and makes a KVMRK_INIT_VECTORS hypercall which initializes
       sp_el2 and sets vbar_el2 to the real vector table for kvmrk-
       (_kvmrk_vectors).

usage:
    modify the source ! here are some important functions:


    __kvmrk_handle_trap(struct kvm_cpu_context *host_ctxt)
        description:
            called by kvmrk's synchronous exception from el1 handler
        args:
            host_ctxt - host context, modify this to do stuff idk

todo:
    -> enable mmu in el2 so hypervisor code will be able to
       directly call kernel functions via their virtual address.
    -> demo hooking el1 accesses of debug registers and pidr_el1

references:
    [1] https://i.blackhat.com/us-18/Wed-August-8/us-18-SINGH-BACK-TO-THE-FUTURE-A-RADICAL-INSECURE-DESIGN-OF-KVM-ON-ARM-wp.pdf
