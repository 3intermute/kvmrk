#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x23384f17, "module_layout" },
	{ 0x10e834a5, "kmalloc_caches" },
	{ 0xeb78b1ed, "unregister_kprobe" },
	{ 0x472cf3b, "register_kprobe" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0xe4bbc1dd, "kimage_voffset" },
	{ 0xa38c1436, "cpu_bit_bitmap" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x92997ed8, "_printk" },
	{ 0xa512cebd, "kmem_cache_alloc_trace" },
	{ 0x4829a47e, "memcpy" },
	{ 0xc60d0620, "__num_online_cpus" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "0626214181C0516F794B52B");
