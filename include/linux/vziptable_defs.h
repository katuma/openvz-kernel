#ifndef _LINUX_VZIPTABLE_DEFS_H
#define _LINUX_VZIPTABLE_DEFS_H

#include <linux/types.h>
#include <linux/sched.h>

/*
 * This masks represent modules
 *
 * Strictly speaking we use only a small subset
 * of this bits novadays but we MUST RESERVE all
 * the bits were ever used in a sake of ABI compatibility
 * (ie compatibility with vzctl user-space utility)
 *
 * DON'T EVER DELETE/MODIFY THIS BITS
 */
#define VE_IPT_GENERATE(name, shift)	name = (1U << shift)

enum ve_ipt_mods {
	VE_IPT_GENERATE(VE_IP_IPTABLES_MOD,		0),
	VE_IPT_GENERATE(VE_IP_FILTER_MOD,		1),
	VE_IPT_GENERATE(VE_IP_MANGLE_MOD,		2),
	VE_IPT_GENERATE(VE_IP_MATCH_LIMIT_MOD,		3),
	VE_IPT_GENERATE(VE_IP_MATCH_MULTIPORT_MOD,	4),
	VE_IPT_GENERATE(VE_IP_MATCH_TOS_MOD,		5),
	VE_IPT_GENERATE(VE_IP_TARGET_TOS_MOD,		6),
	VE_IPT_GENERATE(VE_IP_TARGET_REJECT_MOD,	7),
	VE_IPT_GENERATE(VE_IP_TARGET_TCPMSS_MOD,	8),
	VE_IPT_GENERATE(VE_IP_MATCH_TCPMSS_MOD,		9),
	VE_IPT_GENERATE(VE_IP_MATCH_TTL_MOD,		10),
	VE_IPT_GENERATE(VE_IP_TARGET_LOG_MOD,		11),
	VE_IPT_GENERATE(VE_IP_MATCH_LENGTH_MOD,		12),
	VE_IPT_GENERATE(VE_IP_CONNTRACK_MOD,		14),
	VE_IPT_GENERATE(VE_IP_CONNTRACK_FTP_MOD,	15),
	VE_IPT_GENERATE(VE_IP_CONNTRACK_IRC_MOD,	16),
	VE_IPT_GENERATE(VE_IP_MATCH_CONNTRACK_MOD,	17),
	VE_IPT_GENERATE(VE_IP_MATCH_STATE_MOD,		18),
	VE_IPT_GENERATE(VE_IP_MATCH_HELPER_MOD,		19),
	VE_IPT_GENERATE(VE_IP_NAT_MOD,			20),
	VE_IPT_GENERATE(VE_IP_NAT_FTP_MOD,		21),
	VE_IPT_GENERATE(VE_IP_NAT_IRC_MOD,		22),
	VE_IPT_GENERATE(VE_IP_TARGET_REDIRECT_MOD,	23),
	VE_IPT_GENERATE(VE_IP_MATCH_OWNER_MOD,		24),
	VE_IPT_GENERATE(VE_IP_MATCH_MAC_MOD,		25),
	VE_IPT_GENERATE(VE_IP_IPTABLES6_MOD,		26),
	VE_IPT_GENERATE(VE_IP_FILTER6_MOD,		27),
	VE_IPT_GENERATE(VE_IP_MANGLE6_MOD,		28),
	VE_IPT_GENERATE(VE_IP_IPTABLE_NAT_MOD,		29),
	VE_IPT_GENERATE(VE_NF_CONNTRACK_MOD,		30),
};

/* these masks represent modules with their dependences */
#define VE_IP_IPTABLES		(VE_IP_IPTABLES_MOD)
#define VE_IP_FILTER		(VE_IP_FILTER_MOD | VE_IP_IPTABLES)
#define VE_IP_MANGLE		(VE_IP_MANGLE_MOD | VE_IP_IPTABLES)
#define VE_IP_IPTABLES6		(VE_IP_IPTABLES6_MOD)
#define VE_IP_FILTER6		(VE_IP_FILTER6_MOD | VE_IP_IPTABLES6)
#define VE_IP_MANGLE6		(VE_IP_MANGLE6_MOD | VE_IP_IPTABLES6)
#define VE_NF_CONNTRACK		(VE_NF_CONNTRACK_MOD | VE_IP_IPTABLES)
#define VE_IP_CONNTRACK		(VE_IP_CONNTRACK_MOD | VE_IP_IPTABLES)
#define VE_IP_CONNTRACK_FTP	(VE_IP_CONNTRACK_FTP_MOD | VE_IP_CONNTRACK)
#define VE_IP_CONNTRACK_IRC	(VE_IP_CONNTRACK_IRC_MOD | VE_IP_CONNTRACK)
#define VE_IP_NAT		(VE_IP_NAT_MOD | VE_IP_CONNTRACK)
#define VE_IP_NAT_FTP		(VE_IP_NAT_FTP_MOD | VE_IP_NAT | VE_IP_CONNTRACK_FTP)
#define VE_IP_NAT_IRC		(VE_IP_NAT_IRC_MOD | VE_IP_NAT | VE_IP_CONNTRACK_IRC)
#define VE_IP_IPTABLE_NAT	(VE_IP_IPTABLE_NAT_MOD | VE_IP_CONNTRACK)

/* safe iptables mask to be used by default */
#define VE_IP_DEFAULT		(VE_IP_IPTABLES | VE_IP_FILTER | VE_IP_MANGLE)

#define VE_IP_ALL		(~0ULL)
#define VE_IP_NONE		(0ULL)

static inline bool mask_ipt_allow(__u64 permitted, __u64 mask)
{
	return (permitted & mask) == mask;
}

#endif /* _LINUX_VZIPTABLE_DEFS_H */
