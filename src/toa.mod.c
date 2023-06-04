#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
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
__used
__attribute__((section("__versions"))) = {
	{ 0xb5852678, "module_layout" },
	{ 0x5c8aaeca, "param_ops_ulong" },
	{ 0xa5f006da, "single_release" },
	{ 0x55f9f154, "seq_read" },
	{ 0x1e64f671, "seq_lseek" },
	{ 0x609f1c7e, "synchronize_net" },
	{ 0xc9ec4e21, "free_percpu" },
	{ 0xd05eab8, "remove_proc_entry" },
	{ 0x38293a22, "ipv4_specific" },
	{ 0x420ddf95, "inet_stream_ops" },
	{ 0xe007de41, "kallsyms_lookup_name" },
	{ 0x5b8fd723, "proc_create" },
	{ 0xd11f2aa2, "init_net" },
	{ 0x949f7342, "__alloc_percpu" },
	{ 0xa58e3cf4, "cpu_hwcaps" },
	{ 0xf2733ece, "cpu_hwcap_keys" },
	{ 0xe4bbc1dd, "kimage_voffset" },
	{ 0x52da2b65, "arm64_const_caps_ready" },
	{ 0x7c32d0f0, "printk" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0x931d802e, "inet_getname" },
	{ 0x57888b28, "skb_copy_bits" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0x110af95f, "tcp_v4_syn_recv_sock" },
	{ 0xbde5ace8, "__per_cpu_offset" },
	{ 0x4ee43b34, "seq_putc" },
	{ 0x29034c86, "__cpu_online_mask" },
	{ 0x63c4d61f, "__bitmap_weight" },
	{ 0x6f9f7709, "__cpu_possible_mask" },
	{ 0x9f8f2b40, "seq_printf" },
	{ 0x29e70905, "single_open" },
	{ 0x1fdc7df2, "_mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "D784FAF246B57A557A2DC19");
