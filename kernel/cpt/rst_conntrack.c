/*
 *
 *  kernel/cpt/rst_conntrack.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>
#include <linux/ve.h>
#include <linux/vzcalluser.h>
#include <linux/cpt_image.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#if defined(CONFIG_VE_IPTABLES) && \
    (defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE))

#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>

#define ASSERT_READ_LOCK(x) do { } while (0)
#define ASSERT_WRITE_LOCK(x) do { } while (0)


#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>

struct ct_holder
{
	struct ct_holder *next;
	struct nf_conn *ct;
	int index;
};

static int decode_tuple(struct cpt_ipct_tuple *v,
			 struct nf_conntrack_tuple *tuple, int dir,
			 cpt_context_t *ctx)
{
	tuple->dst.u3.ip = v->cpt_dst;
	tuple->dst.u.all = v->cpt_dstport;
	tuple->src.l3num = v->cpt_l3num;
	tuple->dst.protonum = v->cpt_protonum;

	tuple->dst.dir = v->cpt_dir;
	if (dir != tuple->dst.dir) {
		eprintk_ctx("dir != tuple->dst.dir\n");
		return -EINVAL;
	}

	if (ctx->image_version < CPT_VERSION_32)
		tuple->src.l3num = AF_INET;
	else
		tuple->src.l3num = v->cpt_l3num;

	tuple->src.u3.ip = v->cpt_src;
	tuple->src.u.all = v->cpt_srcport;
	return 0;
}

static int decode_tuple_mask(struct cpt_ipct_tuple *v,
			 struct nf_conntrack_tuple_mask *tuple, int dir,
			 cpt_context_t *ctx)
{
	tuple->src.u3.ip = v->cpt_src;
	tuple->src.u.all = v->cpt_srcport;
	return 0;
}

static void convert_connexpect_image(struct cpt_ip_connexpect_image *ci)
{
	struct cpt_ip_connexpect_image_compat img;
	void *po, *pt;
	unsigned long size;

	memcpy(&img, ci, sizeof(struct cpt_ip_connexpect_image_compat));

	/* skip cpt_ct_tuple */
	po = &img.cpt_ct_tuple;
	size = (long) po - (long) &img;
	memcpy(&img, ci, size);

	/* convert cpt_tuple and cpt_mask */
	pt = &ci->cpt_tuple;
	po = &img.cpt_tuple;
	memcpy(pt, po, sizeof(struct cpt_ipct_tuple_compat));
	ci->cpt_tuple.cpt_l3num = AF_INET;
	pt = &ci->cpt_mask;
	po = &img.cpt_mask;
	memcpy(pt, po, sizeof(struct cpt_ipct_tuple_compat));
	ci->cpt_mask.cpt_l3num = AF_INET;

	pt = &ci->cpt_dir;
	po = &img.cpt_dir;
	size = sizeof(struct cpt_ip_connexpect_image) + (long) ci - (long) pt;
	memcpy(pt, po, size);
}

static int undump_expect_list(struct nf_conn *ct,
			      struct cpt_ip_conntrack_image *ci,
			      loff_t pos, struct ct_holder *ct_list,
			      cpt_context_t *ctx)
{
	loff_t end;
	int err;

	end = pos + ci->cpt_next;
	pos += ci->cpt_hdrlen;
	while (pos < end) {
		struct cpt_ip_connexpect_image v;
		struct nf_conntrack_expect *exp;
		struct nf_conn *sibling;

		err = rst_get_object(CPT_OBJ_NET_CONNTRACK_EXPECT, pos, &v, ctx);
		if (err)
			return err;

		if (ctx->image_version < CPT_VERSION_32)
			convert_connexpect_image(&v);

		sibling = NULL;
		if (v.cpt_sibling_conntrack) {
			struct ct_holder *c;

			for (c = ct_list; c; c = c->next) {
				if (c->index == v.cpt_sibling_conntrack) {
					sibling = c->ct;
					break;
				}
			}
			if (!sibling) {
				eprintk_ctx("lost sibling of expectation\n");
				return -EINVAL;
			}
		}

		spin_lock_bh(&nf_conntrack_lock);

		/* It is possible. Helper module could be just unregistered,
		 * if expectation were on the list, it would be destroyed. */
		if (nfct_help(ct) == NULL) {
			spin_unlock_bh(&nf_conntrack_lock);
			dprintk_ctx("conntrack: no helper and non-trivial expectation\n");
			continue;
		}

		exp = nf_ct_expect_alloc(NULL);
		if (exp == NULL) {
			spin_unlock_bh(&nf_conntrack_lock);
			return -ENOMEM;
		}

		if (decode_tuple(&v.cpt_tuple, &exp->tuple, 0, ctx) ||
		    decode_tuple_mask(&v.cpt_mask, &exp->mask, 0, ctx)) {
			nf_ct_expect_put(exp);
			spin_unlock_bh(&nf_conntrack_lock);
			return -EINVAL;
		}

		exp->master = ct;
		nf_conntrack_get(&ct->ct_general);
		nf_ct_expect_insert(exp);
#if 0
		if (sibling) {
			exp->sibling = sibling;
			sibling->master = exp;
			LIST_DELETE(&ve_ip_conntrack_expect_list, exp);
			ct->expecting--;
			nf_conntrack_get(&master_ct(sibling)->infos[0]);
		} else
#endif
		if (del_timer(&exp->timeout)) {
			exp->timeout.expires = jiffies + v.cpt_timeout * HZ;
			add_timer(&exp->timeout);
		}
		spin_unlock_bh(&nf_conntrack_lock);

		nf_ct_expect_put(exp);

		pos += v.cpt_next;
	}
	return 0;
}

static int undump_one_ct(struct cpt_ip_conntrack_image *ci, loff_t pos,
			 struct ct_holder **ct_list, cpt_context_t *ctx)
{
	int err = 0;
	struct nf_conn *ct;
	struct ct_holder *c;
	struct nf_conntrack_tuple orig, repl;
	struct nf_conn_nat *nat;

	c = kmalloc(sizeof(struct ct_holder), GFP_KERNEL);
	if (c == NULL)
		return -ENOMEM;

	if (decode_tuple(&ci->cpt_tuple[0], &orig, 0, ctx) ||
	    decode_tuple(&ci->cpt_tuple[1], &repl, 1, ctx)) {
		kfree(c);
		return -EINVAL;
	}

	ct = nf_conntrack_alloc(get_exec_env()->ve_netns, &orig, &repl,
						get_exec_ub(), GFP_KERNEL);
	if (!ct || IS_ERR(ct)) {
		kfree(c);
		return -ENOMEM;
	}

	c->ct = ct;
	c->next = *ct_list;
	*ct_list = c;
	c->index = ci->cpt_index;

	rcu_read_lock();
	/* try an implicit helper assignation */
	err = __nf_ct_try_assign_helper(ct, GFP_ATOMIC);
	if (err < 0)
		goto err2;

	ct->status = ci->cpt_status;

	memcpy(&ct->proto, ci->cpt_proto_data, sizeof(ct->proto));
	if (nfct_help(ct))
		memcpy(&nfct_help(ct)->help, ci->cpt_help_data, \
					sizeof(nfct_help(ct)->help));

#if defined(CONFIG_NF_CONNTRACK_MARK)
	ct->mark = ci->cpt_mark;
#endif

	nat = nfct_nat(ct);

	if (ct->status & IPS_NAT_DONE_MASK) {
		nat = nf_ct_ext_add(ct, NF_CT_EXT_NAT, GFP_ATOMIC);
		if (nat == NULL) {
			eprintk_ctx("conntrack: failed to add NAT extension\n");
			err = -ENOMEM;
			goto err2;
		}
#ifdef CONFIG_NF_NAT_NEEDED
#if defined(CONFIG_IP_NF_TARGET_MASQUERADE) || \
	defined(CONFIG_IP_NF_TARGET_MASQUERADE_MODULE)
		nat->masq_index = ci->cpt_masq_index;
#endif
		nat->seq[0].correction_pos = ci->cpt_nat_seq[0].cpt_correction_pos;
		nat->seq[0].offset_before = ci->cpt_nat_seq[0].cpt_offset_before;
		nat->seq[0].offset_after = ci->cpt_nat_seq[0].cpt_offset_after;
		nat->seq[1].correction_pos = ci->cpt_nat_seq[1].cpt_correction_pos;
		nat->seq[1].offset_before = ci->cpt_nat_seq[1].cpt_offset_before;
		nat->seq[1].offset_after = ci->cpt_nat_seq[1].cpt_offset_after;

		nf_nat_hash_conntrack(get_exec_env()->ve_netns, ct);
#endif
	}

	nf_conntrack_hash_insert(ct);
	ct->timeout.expires = jiffies + ci->cpt_timeout;

	if (err == 0 && ci->cpt_next > ci->cpt_hdrlen)
		err = undump_expect_list(ct, ci, pos, *ct_list, ctx);
        rcu_read_unlock();

	return err;
err2:
        rcu_read_unlock();
        nf_conntrack_free(ct);
        return err;
}

struct ip_ct_tcp_state_compat /*2.6.18*/
{
        u_int32_t       td_end;         /* max of seq + len */
        u_int32_t       td_maxend;      /* max of ack + max(win, 1) */               
        u_int32_t       td_maxwin;      /* max(win) */
        u_int8_t        td_scale;       /* window scale factor */
        u_int8_t        loose;          /* used when connection picked up from the middle */
        u_int8_t        flags;          /* per direction options */
};

struct ip_ct_tcp_compat /*2.6.18*/
{
	struct ip_ct_tcp_state_compat seen[2];	/* connection parameters per direction */
	u_int8_t	state;		/* state of the connection (enum tcp_conntrack) */
	/* For detecting stale connections */
	u_int8_t	last_dir;	/* Direction of the last packet (enum ip_conntrack_dir) */
	u_int8_t	retrans;	/* Number of retransmitted packets */
	u_int8_t	last_index;	/* Index of the last packet */
	u_int32_t	last_seq;	/* Last sequence number seen in dir */
	u_int32_t	last_ack;	/* Last sequence number seen in opposite dir */
	u_int32_t	last_end;	/* Last seq + len */
	u_int16_t	last_win;	/* Last window advertisement seen in dir */
};

void convert_proto_data_tcp_state(struct ip_ct_tcp_state *state)
{
	struct ip_ct_tcp_state_compat img;
	memcpy(&img, state, sizeof(struct ip_ct_tcp_state_compat));
	memset(state, 0, sizeof(struct ip_ct_tcp_state));
	state->td_end = img.td_end;
	state->td_maxend = img.td_maxend;
	state->td_maxwin = img.td_maxwin;
	state->td_scale = img.td_scale;
	state->flags = img.flags;
}

void convert_proto_data_tcp(struct ip_ct_tcp *data)
{
	struct ip_ct_tcp_compat img;

	memcpy(&img, data, sizeof(struct ip_ct_tcp_compat));
	memset(data, 0, sizeof(struct ip_ct_tcp));

	memcpy(&data->seen[0], &img.seen[0], sizeof(struct ip_ct_tcp_state_compat));
	convert_proto_data_tcp_state(&data->seen[0]);
	memcpy(&data->seen[1], &img.seen[1], sizeof(struct ip_ct_tcp_state_compat));
	convert_proto_data_tcp_state(&data->seen[1]);
	data->state = img.state;

	data->last_dir = img.last_dir;
	data->retrans = img.retrans;
	data->last_index = img.last_index;
	data->last_seq = img.last_seq;
	data->last_ack = img.last_ack;
	data->last_end = img.last_end;
	data->last_win = img.last_win;
}

static void convert_conntrack_image(struct cpt_ip_conntrack_image *ci)
{
	struct cpt_ip_conntrack_image_compat img;
	void *po, *pt;
	long size, n = sizeof(struct cpt_ip_conntrack_image);

	memcpy(&img, ci, sizeof(struct cpt_ip_conntrack_image_compat));

	/* convert cpt_tuple */
	pt = &ci->cpt_tuple[0].cpt_l3num;
	size = n - ((long)pt - (long)ci);
	memset(pt, 0, size);
	ci->cpt_tuple[0].cpt_l3num = AF_INET;

	pt = &ci->cpt_tuple[1];
	po = &img.cpt_tuple[1];
	memcpy(pt, po, sizeof(struct cpt_ipct_tuple_compat));
	ci->cpt_tuple[1].cpt_l3num = AF_INET;

	/* fix cpt_proto_data */
	pt = &ci->cpt_status;
	po = &img.cpt_status;
	size = (long) &img.cpt_help_data - (long) po;
	memcpy(pt, po, size);

	if (ci->cpt_tuple[0].cpt_protonum == IPPROTO_TCP)
		convert_proto_data_tcp((struct ip_ct_tcp *)ci->cpt_proto_data);

	/* fix cpt_help_data */
	pt = &ci->cpt_help_data;
	po = &img.cpt_help_data;
	size = (long) &img.cpt_initialized - (long) po;
	memcpy(pt, po, size);

	/* skip cpt_initialized, cpt_num_manips, cpt_nat_manips */
	pt = &ci->cpt_nat_seq;
	po = &img.cpt_nat_seq;
	size = n - ((long)pt - (long)ci);
	memcpy(pt, po, size);
}

int rst_restore_ip_conntrack(struct cpt_context * ctx)
{
	int err = 0;
	loff_t sec = ctx->sections[CPT_SECT_NET_CONNTRACK];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct cpt_ip_conntrack_image ci;
	struct ct_holder *c;
	struct ct_holder *ct_list = NULL;

	if (sec == CPT_NULL)
		return 0;

	BUILD_BUG_ON(sizeof(ci.cpt_proto_data) < sizeof(union nf_conntrack_proto));
	BUILD_BUG_ON(sizeof(ci.cpt_help_data) < sizeof(union nf_conntrack_help));

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_NET_CONNTRACK || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		err = rst_get_object(CPT_OBJ_NET_CONNTRACK, sec, &ci, ctx);
		if (err)
			break;

		if (ctx->image_version < CPT_VERSION_32)
			convert_conntrack_image(&ci);

		err = undump_one_ct(&ci, sec, &ct_list, ctx);
		if (err)
			break;
		sec += ci.cpt_next;
	}

	while ((c = ct_list) != NULL) {
		ct_list = c->next;
		if (c->ct)
			add_timer(&c->ct->timeout);
		kfree(c);
	}

	return err;
}

#else

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>

int rst_restore_ip_conntrack(struct cpt_context * ctx)
{
	if (ctx->sections[CPT_SECT_NET_CONNTRACK] != CPT_NULL)
		return -EINVAL;
	return 0;
}

#endif
