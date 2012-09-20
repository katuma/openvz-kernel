/*
 *
 *  kernel/cpt/rst_socket.c
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
#include <linux/namei.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/mount.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/scm.h>
#include <net/af_unix.h>

#include <bc/kmem.h>
#include <bc/sock_orphan.h>
#include <bc/net.h>
#include <bc/tcp.h>


#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_files.h"
#include "cpt_socket.h"
#include "cpt_kernel.h"

#include "cpt_syscalls.h"


static int setup_sock_common(struct sock *sk, struct cpt_sock_image *si,
			     loff_t pos, struct cpt_context *ctx)
{
	struct timeval tmptv;

	if (sk->sk_socket) {
		sk->sk_socket->flags = si->cpt_ssflags;
		sk->sk_socket->state = si->cpt_sstate;
	}
	sk->sk_reuse = si->cpt_reuse;
	sk->sk_shutdown = si->cpt_shutdown;
	sk->sk_userlocks = si->cpt_userlocks;
	sk->sk_no_check = si->cpt_no_check;
	sock_reset_flag(sk, SOCK_DBG);
	if (si->cpt_debug)
		sock_set_flag(sk, SOCK_DBG);
	sock_reset_flag(sk, SOCK_RCVTSTAMP);
	if (si->cpt_rcvtstamp)
		sock_set_flag(sk, SOCK_RCVTSTAMP);
	sock_reset_flag(sk, SOCK_LOCALROUTE);
	if (si->cpt_localroute)
		sock_set_flag(sk, SOCK_LOCALROUTE);
	sk->sk_protocol = si->cpt_protocol;
	sk->sk_err = si->cpt_err;
	sk->sk_err_soft = si->cpt_err_soft;
	sk->sk_priority = si->cpt_priority;
	sk->sk_rcvlowat = si->cpt_rcvlowat;
	sk->sk_rcvtimeo = si->cpt_rcvtimeo;
	if (si->cpt_rcvtimeo == CPT_NULL)
		sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	sk->sk_sndtimeo = si->cpt_sndtimeo;
	if (si->cpt_sndtimeo == CPT_NULL)
		sk->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT;
	sk->sk_rcvbuf = si->cpt_rcvbuf;
	sk->sk_sndbuf = si->cpt_sndbuf;
	sk->sk_bound_dev_if = si->cpt_bound_dev_if;
	sk->sk_flags = si->cpt_flags;
	sk->sk_lingertime = si->cpt_lingertime;
	if (si->cpt_lingertime == CPT_NULL)
		sk->sk_lingertime = MAX_SCHEDULE_TIMEOUT;
	sk->sk_peercred.pid = si->cpt_peer_pid;
	sk->sk_peercred.uid = si->cpt_peer_uid;
	sk->sk_peercred.gid = si->cpt_peer_gid;
	cpt_timeval_import(&tmptv, si->cpt_stamp);
	sk->sk_stamp = timeval_to_ktime(tmptv);
	return 0;
}

static struct file *sock_mapfile(struct socket *sock)
{
	int fd = sock_map_fd(sock, 0);

	if (fd >= 0) {
		struct file *file = sock->file;
		get_file(file);
		sc_close(fd);
		return file;
	}
	return ERR_PTR(fd);
}

/* Assumption is that /tmp exists and writable.
 * In previous versions we assumed that listen() will autobind
 * the socket. It does not do this for AF_UNIX by evident reason:
 * socket in abstract namespace is accessible, unlike socket bound
 * to deleted FS object.
 */

static int
select_deleted_name(char * name, cpt_context_t *ctx)
{
	int i;

	for (i=0; i<100; i++) {
		struct nameidata nd;
		unsigned int rnd = net_random();

		sprintf(name, "/tmp/SOCK.%08x", rnd);

		if (path_lookup(name, 0, &nd) != 0)
			return 0;

		path_put(&nd.path);
	}

	eprintk_ctx("failed to allocate deleted socket inode\n");
	return -ELOOP;
}

/*
 * This function is used for backward compability with old image versions.
 */
static int unix_bind_to_path(struct socket *sock, char *name,
				struct sockaddr* addr, int addrlen,
				struct cpt_sock_image *si, cpt_context_t *ctx)
{
	struct sockaddr_un sun;
	int err;
	struct nameidata nd;

	nd.path.dentry = NULL;

	if (name[0]) {
		if (si->cpt_sockflags & CPT_SOCK_DELETED) {
			addr = (struct sockaddr*)&sun;
			addr->sa_family = AF_UNIX;
			name = ((char*)addr) + 2;
			err = select_deleted_name(name, ctx);
			if (err) {
				eprintk_ctx("%s: can't select name\n", __func__);
				return err;
			}
			addrlen = 2 + strlen(name);
		} else {
			if (path_lookup(name, 0, &nd))
				nd.path.dentry = NULL;
			else {
				if (!S_ISSOCK(nd.path.dentry->d_inode->i_mode)) {
					eprintk_ctx("%s: not a socket dentry %s\n",
							__func__, name);
					return -EINVAL;
				}
				sc_unlink(name);
			}
		}
	}

	err = sock->ops->bind(sock, addr, addrlen);
	if (!err && name[0]) {
		if (si->cpt_sockflags & CPT_SOCK_DELETED)
			sc_unlink(name);
		else if (nd.path.dentry) {
			sc_chown(name, nd.path.dentry->d_inode->i_uid,
				 nd.path.dentry->d_inode->i_gid);
			sc_chmod(name, nd.path.dentry->d_inode->i_mode);
		}
	}

	if (nd.path.dentry)
		path_put(&nd.path);

	return err;
}

static int unix_bind_to_mntref(struct sock *sk, char *name,
				struct sockaddr* addr, int addrlen,
				struct cpt_sock_image *si, cpt_context_t *ctx)
{
	struct unix_bind_info bi;
	int err;
	cpt_object_t *mntobj;

	if (!name[0]) {
		if (addrlen <= sizeof(short)) {
			eprintk_ctx("%s: unsupported hidden name len: %d\n",
					__func__, addrlen);
			return -EINVAL;
		}
		return sk->sk_socket->ops->bind(sk->sk_socket,  addr, addrlen);
	}

	err = unix_attach_addr(sk, (struct sockaddr_un *)addr,
				addrlen);
	if (err) {
		eprintk_ctx("%s: can't attach unix address %d to %s\n",
						__func__, err, name);
		return err;
	}

	mntobj = lookup_cpt_obj_bypos(CPT_OBJ_VFSMOUNT_REF,
			si->cpt_vfsmount_ref, ctx);
	if (mntobj == NULL) {
		eprintk_ctx("%s: can't find vfsmount for unix socket %s\n",
				__func__, name);
		return -EINVAL;
	}

	if (strlen(name) < mntobj->o_lock) {
		eprintk_ctx("%s: unix socket with too short name (%d %s)\n",
				__func__, mntobj->o_lock, name);
		return -EINVAL;
	}

	bi.sk = sk;
	strcpy(bi.path, name);
	bi.path_off = mntobj->o_lock;
	bi.i_mode = 0;
	if (cpt_object_has(si, cpt_i_mode))
		bi.i_mode = si->cpt_i_mode;
	bi.next = NULL;

	return rebind_unix_socket(mntobj->o_obj, &bi, LOOKUP_DIVE);
}

static int can_be_rebound_by_mntref(struct socket *sock,
					struct cpt_sock_image *si,
					cpt_context_t *ctx)
{
	if (ctx->image_version < CPT_VERSION_18_4)
		return 0;

	if (si->cpt_sockflags & CPT_SOCK_DELETED)
		return 0;

	return 1;
}

/*
 * We use this special bind function instead of sock->ops->bind because
 * overmounted sockets can't be binded that generic way. And we want to have
 * only one function for rebinding all kinds of sockets. 
 */
static int bind_unix_socket(struct socket *sock, struct cpt_sock_image *si,
		 cpt_context_t *ctx)
{
	int err;
	char *name;
	struct sockaddr* addr;
	int addrlen;

	if ((addrlen = si->cpt_laddrlen) <= 2)
		return 0;

	if (si->cpt_sockflags & CPT_SOCK_DELAYED)
		return rst_delay_unix_bind(sock->sk, si, ctx);

	name = ((char*)si->cpt_laddr) + 2;
	addr = (struct sockaddr *)si->cpt_laddr;

	if (can_be_rebound_by_mntref(sock, si, ctx))
		err = unix_bind_to_mntref(sock->sk, name, addr, addrlen, si, ctx);
	else
		err = unix_bind_to_path(sock, name, addr, addrlen, si, ctx);

	if (err)
		eprintk_ctx("%s: can't rebind unix socket %d\n", __func__, err);

	return err;
}

static int fixup_unix_address(struct socket *sock, struct cpt_sock_image *si,
			      struct cpt_context *ctx)
{
	struct sock *sk = sock->sk;
	cpt_object_t *obj;
	struct sock *parent;

	if (sk->sk_family != AF_UNIX || sk->sk_state == TCP_LISTEN)
		return 0;

	if (si->cpt_parent == -1)
		return bind_unix_socket(sock, si, ctx);

	obj = lookup_cpt_obj_byindex(CPT_OBJ_SOCKET, si->cpt_parent, ctx);
	if (!obj)
		return 0;

	parent = obj->o_obj;
	if (unix_sk(parent)->addr) {
		if (unix_sk(sk)->addr &&
		    atomic_dec_and_test(&unix_sk(sk)->addr->refcnt))
			kfree(unix_sk(sk)->addr);
		atomic_inc(&unix_sk(parent)->addr->refcnt);
		unix_sk(sk)->addr = unix_sk(parent)->addr;
	}
	return 0;
}

static int generic_restore_queues(struct sock *sk, struct cpt_sock_image *si,
				  loff_t pos, struct cpt_context *ctx)
{
	loff_t endpos;

	endpos = pos + si->cpt_next;
	pos = pos + si->cpt_hdrlen;
	while (pos < endpos) {
		struct sk_buff *skb;
		__u32 type;
		int err;

		err = rst_sock_attr(&pos, sk, ctx);
		if (!err)
			continue;
		if (err < 0)
			return err;

		skb = rst_skb(sk, &pos, NULL, &type, ctx);
		if (IS_ERR(skb))
			return PTR_ERR(skb);

		if (type == CPT_SKB_RQ) {
			skb_set_owner_r(skb, sk);
			skb_queue_tail(&sk->sk_receive_queue, skb);
		} else {
			wprintk_ctx("strange socket queue type %u\n", type);
			kfree_skb(skb);
		}
	}
	return 0;
}

static int open_socket(cpt_object_t *obj, struct cpt_sock_image *si,
		       struct cpt_context *ctx)
{
	int err;
	struct socket *sock;
	struct socket *sock2 = NULL;
	struct file *file;
	cpt_object_t *fobj;
	cpt_object_t *pobj = NULL;

	err = sock_create(si->cpt_family, si->cpt_type, si->cpt_protocol,
			       &sock);
	if (err)
		return err;

	if (si->cpt_socketpair) {
		err = sock_create(si->cpt_family, si->cpt_type,
				       si->cpt_protocol, &sock2);
		if (err)
			goto err_out;

		err = sock->ops->socketpair(sock, sock2);
		if (err < 0)
			goto err_out;

		/* Socketpair with a peer outside our environment.
		 * So, we create real half-open pipe and do not worry
		 * about dead end anymore. */
		if (si->cpt_peer == -1) {
			sock_release(sock2);
			sock2 = NULL;
		}
	}

	cpt_obj_setobj(obj, sock->sk, ctx);

	if (si->cpt_file != CPT_NULL) {
		file = sock_mapfile(sock);
		err = PTR_ERR(file);
		if (IS_ERR(file))
			goto err_out;

		err = -ENOMEM;

		obj->o_parent = file;

		if ((fobj = cpt_object_add(CPT_OBJ_FILE, file, ctx)) == NULL)
			goto err_out;
		cpt_obj_setpos(fobj, si->cpt_file, ctx);
		cpt_obj_setindex(fobj, si->cpt_index, ctx);
	}

	if (sock2) {
		struct file *file2;

		pobj = lookup_cpt_obj_byindex(CPT_OBJ_SOCKET, si->cpt_peer, ctx);
		if (!pobj) BUG();
		if (pobj->o_obj) BUG();
		cpt_obj_setobj(pobj, sock2->sk, ctx);

		if (pobj->o_ppos != CPT_NULL) {
			file2 = sock_mapfile(sock2);
			err = PTR_ERR(file2);
			if (IS_ERR(file2))
				goto err_out;

			err = -ENOMEM;
			if ((fobj = cpt_object_add(CPT_OBJ_FILE, file2, ctx)) == NULL)
				goto err_out;
			cpt_obj_setpos(fobj, pobj->o_ppos, ctx);
			cpt_obj_setindex(fobj, si->cpt_peer, ctx);

			pobj->o_parent = file2;
		}
	}

	setup_sock_common(sock->sk, si, obj->o_pos, ctx);
	if (sock->sk->sk_family == AF_INET || sock->sk->sk_family == AF_INET6) {
		int saved_reuse = sock->sk->sk_reuse;

		inet_sk(sock->sk)->freebind = 1;
		sock->sk->sk_reuse = 2;
		if (si->cpt_laddrlen) {
			err = sock->ops->bind(sock, (struct sockaddr *)&si->cpt_laddr, si->cpt_laddrlen);
			if (err) {
				dprintk_ctx("binding failed: %d, do not worry\n", err);
			}
		}
		sock->sk->sk_reuse = saved_reuse;
		err = rst_socket_in(si, obj->o_pos, sock->sk, ctx);
		if (err) {
			eprintk_ctx("open_socket: Warning! socket restoring "
					"failed: %d\n", err);
			/*
			 * For now we do not want to abort migration
			 * due to a socket restoring failure.
			 */
		}
	} else if (sock->sk->sk_family == AF_NETLINK) {
		struct sockaddr_nl *nl = (struct sockaddr_nl *)&si->cpt_laddr;
		if (nl->nl_pid) {
			err = sock->ops->bind(sock, (struct sockaddr *)&si->cpt_laddr, si->cpt_laddrlen);
			if (err) {
				eprintk_ctx("AF_NETLINK binding failed: %d\n", err);
			}
		}
		if (si->cpt_raddrlen && nl->nl_pid) {
			err = sock->ops->connect(sock, (struct sockaddr *)&si->cpt_raddr, si->cpt_raddrlen, O_NONBLOCK);
			if (err) {
				eprintk_ctx("oops, AF_NETLINK connect failed: %d\n", err);
			}
		}
		generic_restore_queues(sock->sk, si, obj->o_pos, ctx);
	} else if (sock->sk->sk_family == PF_PACKET) {
		struct sockaddr_ll *ll = (struct sockaddr_ll *)&si->cpt_laddr;
		if (ll->sll_protocol || ll->sll_ifindex) {
			int alen = si->cpt_laddrlen;
			if (alen < sizeof(struct sockaddr_ll))
				alen = sizeof(struct sockaddr_ll);
			err = sock->ops->bind(sock, (struct sockaddr *)&si->cpt_laddr, alen);
			if (err) {
				eprintk_ctx("AF_PACKET binding failed: %d\n", err);
			}
		}
		generic_restore_queues(sock->sk, si, obj->o_pos, ctx);
	}

	err = fixup_unix_address(sock, si, ctx);
	if (err)
		goto err_out;

	if (sock2) {
		err = rst_get_object(CPT_OBJ_SOCKET, pobj->o_pos, si, ctx);
		if (err)
			goto err_out;
		setup_sock_common(sock2->sk, si, pobj->o_pos, ctx);
		err = fixup_unix_address(sock2, si, ctx);
		if (err)
			goto err_out;
	}

	if ((sock->sk->sk_family == AF_INET || sock->sk->sk_family == AF_INET6)
	    && (int)si->cpt_parent != -1) {
		cpt_object_t *lobj = lookup_cpt_obj_byindex(CPT_OBJ_SOCKET, si->cpt_parent, ctx);
		if (lobj && cpt_attach_accept(lobj->o_obj, sock->sk, ctx) == 0)
			sock->sk = NULL;
	}


	if (si->cpt_file == CPT_NULL && sock->sk &&
	    sock->sk->sk_family == AF_INET) {
		struct sock *sk = sock->sk;

		if (sk) {
			sock->sk = NULL;

			local_bh_disable();
			bh_lock_sock(sk);
			if (sock_owned_by_user(sk))
				eprintk_ctx("oops, sock is locked by user\n");

			sock_hold(sk);
			sock_orphan(sk);
			ub_inc_orphan_count(sk);
			bh_unlock_sock(sk);
			local_bh_enable();
			sock_put(sk);
			dprintk_ctx("orphaning socket %p\n", sk);
		}
	}

	if (si->cpt_file == CPT_NULL && sock->sk == NULL)
		sock_release(sock);

	return 0;

err_out:
	if (sock2)
		sock_release(sock2);
	sock_release(sock);
	return err;
}

static int open_listening_socket(loff_t pos, struct cpt_sock_image *si,
				 struct cpt_context *ctx)
{
	int err;
	struct socket *sock;
	struct file *file;
	cpt_object_t *obj, *fobj;

	err = sock_create(si->cpt_family, si->cpt_type, si->cpt_protocol,
			       &sock);
	if (err) {
		eprintk_ctx("open_listening_socket: sock_create: %d (family: %d, type: %d, protocol: %d)\n",
				err, (int)si->cpt_family, (int)si->cpt_type, (int)si->cpt_protocol);
		return err;
	}

	sock->sk->sk_reuse = 2;
	sock->sk->sk_bound_dev_if = si->cpt_bound_dev_if;

	if (sock->sk->sk_family == AF_UNIX) {
		err = bind_unix_socket(sock, si, ctx);
		if (err) {
			eprintk_ctx("bind unix: %d\n", err);
			goto err_out;
		}
	} else if (si->cpt_laddrlen) {
		if (sock->sk->sk_family == AF_INET || sock->sk->sk_family == AF_INET6)
			inet_sk(sock->sk)->freebind = 1;

		err = sock->ops->bind(sock, (struct sockaddr *)&si->cpt_laddr, si->cpt_laddrlen);

		if (err) {
			eprintk_ctx("open_listening_socket: bind: %d\n", err);
			goto err_out;
		}
	}

	err = sock->ops->listen(sock, si->cpt_max_ack_backlog);
	if (err) {
		eprintk_ctx("open_listening_socket: listen: %d, %Ld, %x\n", err, pos, si->cpt_sockflags);
		goto err_out;
	}

	/* Now we may access socket body directly and fixup all the things. */

	file = sock_mapfile(sock);
	err = PTR_ERR(file);
	if (IS_ERR(file)) {
		eprintk_ctx("open_listening_socket: map: %d\n", err);
		goto err_out;
	}

	err = -ENOMEM;
	if ((fobj = cpt_object_add(CPT_OBJ_FILE, file, ctx)) == NULL)
		goto err_out;
	if ((obj = cpt_object_add(CPT_OBJ_SOCKET, sock->sk, ctx)) == NULL)
		goto err_out;
	cpt_obj_setpos(obj, pos, ctx);
	cpt_obj_setindex(obj, si->cpt_index, ctx);
	obj->o_parent = file;
	cpt_obj_setpos(fobj, si->cpt_file, ctx);
	cpt_obj_setindex(fobj, si->cpt_index, ctx);

	setup_sock_common(sock->sk, si, pos, ctx);

	if (si->cpt_family == AF_INET || si->cpt_family == AF_INET6) {
		rst_listen_socket_in(sock->sk, si, pos, ctx);
		rst_restore_synwait_queue(sock->sk, si, pos, ctx);
	}

	return 0;

err_out:
	sock_release(sock);
	return err;
}

static int
rst_sock_attr_mcfilter(loff_t *pos_p, struct sock *sk, cpt_context_t *ctx)
{
	int err;
	loff_t pos = *pos_p;
	struct cpt_sockmc_image v;

	err = rst_get_object(CPT_OBJ_SOCK_MCADDR, pos, &v, ctx);
	if (err)
		return err;

	*pos_p += v.cpt_next;

	if (v.cpt_family == AF_INET)
		return rst_sk_mcfilter_in(sk, &v, pos, ctx);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (v.cpt_family == AF_INET6)
		return rst_sk_mcfilter_in6(sk, &v, pos, ctx); 
#endif
	else
		return -EAFNOSUPPORT;
}


static int
rst_sock_attr_skfilter(loff_t *pos_p, struct sock *sk, cpt_context_t *ctx)
{
	int err;
	struct sk_filter *fp, *old_fp; 
	loff_t pos = *pos_p;
	struct cpt_obj_bits v;

	err = rst_get_object(CPT_OBJ_SKFILTER, pos, &v, ctx);
	if (err)
		return err;

	*pos_p += v.cpt_next;

	if (v.cpt_size % sizeof(struct sock_filter))
		return -EINVAL;

	fp = sock_kmalloc(sk, v.cpt_size+sizeof(*fp), GFP_KERNEL_UBC);
	if (fp == NULL)
		return -ENOMEM;
	atomic_set(&fp->refcnt, 1);
	fp->len = v.cpt_size/sizeof(struct sock_filter);

	err = ctx->pread(fp->insns, v.cpt_size, ctx, pos+v.cpt_hdrlen);
	if (err) {
		sk_filter_uncharge(sk, fp);
		return err;
	}

	old_fp = sk->sk_filter;
	sk->sk_filter = fp;
	if (old_fp)
		sk_filter_uncharge(sk, old_fp);
	return 0;
}


/*
 * returns:
 *   0 - success, pos_p updated
 * > 0 - type of next object
 * < 0 - error
 */
int rst_sock_attr(loff_t *pos_p, struct sock *sk, cpt_context_t *ctx)
{
	int err;
	loff_t pos = *pos_p;
	struct cpt_object_hdr hdr;

	err = rst_get_object(0, pos, &hdr, ctx);
	if (err)
		return err;

	if (hdr.cpt_object == CPT_OBJ_SKFILTER)
		err = rst_sock_attr_skfilter(pos_p, sk, ctx);
	else if (hdr.cpt_object == CPT_OBJ_SOCK_MCADDR)
		err = rst_sock_attr_mcfilter(pos_p, sk, ctx);
	else
		err = hdr.cpt_object;

	return err;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static void rst_tcp_cb_from_v4(struct cpt_skb_image *v, struct sk_buff *skb)
{
	/*
	 * sizeof(struct inet_skb_parm) == 16
	 * sizeof(struct tcp_skb_cb) - sizeof(tcp_skb_cb.header) == 20
	 *   => sizeof(struct tcp_skb_cb) == 36
	 * sizeof(struct cpt_skb_image.cb) = 40
	 *   => tcp_skb_cb in IPv4 format fits into cpt_skb_image.cb
	 */
	BUILD_BUG_ON(sizeof(skb->cb) - sizeof(struct inet6_skb_parm) <
		sizeof(struct tcp_skb_cb) - sizeof(struct inet6_skb_parm));
	memcpy(skb->cb, v->cpt_cb, sizeof(struct inet_skb_parm));
	memcpy(skb->cb + sizeof(struct inet6_skb_parm),
		(void *)v->cpt_cb + sizeof(struct inet_skb_parm),
		sizeof(struct tcp_skb_cb) - sizeof(struct inet6_skb_parm));
}
static void rst_tcp_cb_from_v6(struct cpt_skb_image *v, struct sk_buff *skb)
{
	memcpy(skb->cb, v->cpt_cb, sizeof(v->cpt_cb));
}
#else
static void rst_tcp_cb_from_v4(struct cpt_skb_image *v, struct sk_buff *skb)
{
	memcpy(skb->cb, v->cpt_cb, sizeof(v->cpt_cb));
}
static void rst_tcp_cb_from_v6(struct cpt_skb_image *v, struct sk_buff *skb)
{
	/*
	 * sizeof(struct inet6_skb_parm) == 24
	 * sizeof(struct tcp_skb_cb) - sizeof(tcp_skb_cb.header) == 20
	 *   => sizeof(struct tcp_skb_cb) == 44
	 * sizeof(struct cpt_skb_image.cb) = 40
	 *   => tcp_skb_cb in IPv6 format does not fit into cpt_skb_image.cb,
	 *      do not write more than sizeof(v->cpt_cb)
	 */
	BUILD_BUG_ON(sizeof(skb->cb) - sizeof(struct inet_skb_parm) <
		sizeof(struct tcp_skb_cb) - sizeof(struct inet_skb_parm));
	memcpy(skb->cb, v->cpt_cb, sizeof(struct inet_skb_parm));
	memcpy(skb->cb + sizeof(struct inet_skb_parm),
		(void *)v->cpt_cb + sizeof(struct inet6_skb_parm),
		min(sizeof(struct tcp_skb_cb) - sizeof(struct inet_skb_parm),
			sizeof(v->cpt_cb) - sizeof(struct inet6_skb_parm)));
}
#endif

struct tcp_skb_cb_ipv6 {
	union {
		struct inet_skb_parm	h4;
		struct inet6_skb_parm	h6;
	} header;
	__u32		seq;
	__u32		end_seq;
	__u32		when;
	__u8		flags;
	__u8		sacked;
	__u16		urg_ptr;
	__u32		ack_seq;
};

struct sk_buff * rst_skb(struct sock *sk, loff_t *pos_p, __u32 *owner,
			 __u32 *queue, struct cpt_context *ctx)
{
	int err;
	struct sk_buff *skb;
	struct cpt_skb_image v;
	loff_t pos = *pos_p;
	struct scm_fp_list *fpl = NULL;
	struct timeval tmptv;

	err = rst_get_object(CPT_OBJ_SKB, pos, &v, ctx);
	if (err)
		return ERR_PTR(err);
	*pos_p = pos + v.cpt_next;

	if (owner)
		*owner = v.cpt_owner;
	if (queue)
		*queue = v.cpt_queue;

	skb = alloc_skb(v.cpt_len + v.cpt_hspace + v.cpt_tspace, GFP_KERNEL);
	if (skb == NULL)
		return ERR_PTR(-ENOMEM);
	skb_reserve(skb, v.cpt_hspace);
	skb_put(skb, v.cpt_len);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->transport_header = v.cpt_h;
	skb->network_header = v.cpt_nh;
	skb->mac_header = v.cpt_mac;
#else
	skb->transport_header = skb->head + v.cpt_h;
	skb->network_header = skb->head + v.cpt_nh;
	skb->mac_header = skb->head + v.cpt_mac;
#endif
	BUILD_BUG_ON(sizeof(skb->cb) < sizeof(v.cpt_cb));
	if (sk->sk_protocol == IPPROTO_TCP) {
		/*
		 * 1) 2.6.9-x VZ kernels did not have IPv6 support compiled in
		 *    => if image_version < CPT_VERSION_9*
		 *    cpt_skb_image.cpt_cb is in IPv4 format.
		 * 2) 2.6.18-x kernels with image_version >= CPT_VERSION_18_2
		 *    and 2.6.16-x >= 027stab029 create cpt_skb_image.cpt_cb
		 *    in IPv6 format despite the kernel IPv6 support.
		 * 3) 2.6.18-x kernels with image_version < CPT_VERSION_18_2
		 *    and 2.6.16-x < 027stab029 create cpt_cb in IPv4 format
		 *    in case IPv6 support was not compiled in and
		 *    in IPv6 format otherwise.
		 *    All PVC 2.6.1[68]-x kernels have IPv6 support => we assume
		 *    any 2.6.1[68]-x kernel produces cpt_cb in IPv6 format.
		 *    Those, who compile old 2.6.1[68]-x kernels without IPv6
		 *    support - beware!
		 */
		if (ctx->image_version >= CPT_VERSION_16) {
			/*
			 * we assume cpt_skb_image.cpt_cb is in IPv6 format
			 * despite the kernel IPv6 support
			 */
			rst_tcp_cb_from_v6(&v, skb);
		} else {
			/*
			 * this case is for 2.6.9-x kernels which produce
			 * cpt_skb_image.cpt_cb in IPv4 format
			 */
			rst_tcp_cb_from_v4(&v, skb);
		}
	} else
		memcpy(skb->cb, v.cpt_cb, sizeof(v.cpt_cb));
	skb->mac_len = v.cpt_mac_len;

	skb->csum = v.cpt_csum;
	skb->local_df = v.cpt_local_df;
	skb->pkt_type = v.cpt_pkt_type;
	skb->ip_summed = v.cpt_ip_summed;
	skb->priority = v.cpt_priority;
	skb->protocol = v.cpt_protocol;
	cpt_timeval_import(&tmptv, v.cpt_stamp);
	skb->tstamp = timeval_to_ktime(tmptv);

	skb_shinfo(skb)->gso_segs = v.cpt_gso_segs;
	skb_shinfo(skb)->gso_size = v.cpt_gso_size;
	if (ctx->image_version == 0) {
		skb_shinfo(skb)->gso_segs = 1;
		skb_shinfo(skb)->gso_size = 0;
	}

	if (v.cpt_next > v.cpt_hdrlen) {
		pos = pos + v.cpt_hdrlen;
		while (pos < *pos_p) {
			union {
				struct cpt_obj_bits b;
				struct cpt_fd_image f;
			} u;

			err = rst_get_object(-1, pos, &u, ctx);
			if (err) {
				kfree_skb(skb);
				return ERR_PTR(err);
			}
			if (u.b.cpt_object == CPT_OBJ_BITS) {
				if (u.b.cpt_size != v.cpt_hspace + skb->len) {
					eprintk_ctx("invalid skb image %u != %u + %u\n", u.b.cpt_size, v.cpt_hspace, skb->len);
					kfree_skb(skb);
					return ERR_PTR(-EINVAL);
				}

				err = ctx->pread(skb->head, u.b.cpt_size, ctx, pos+u.b.cpt_hdrlen);
				if (err) {
					kfree_skb(skb);
					return ERR_PTR(err);
				}
			} else if (u.f.cpt_object == CPT_OBJ_FILEDESC) {
				if (!fpl) {
					fpl = kmalloc(sizeof(struct scm_fp_list),
							GFP_KERNEL_UBC);
					if (!fpl) {
						kfree_skb(skb);
						return ERR_PTR(-ENOMEM);
					}
					fpl->count = 0;
					UNIXCB(skb).fp = fpl;
				}
				fpl->fp[fpl->count] = rst_file(u.f.cpt_file, -1, ctx);
				if (!IS_ERR(fpl->fp[fpl->count]))
					fpl->count++;
			}
			pos += u.b.cpt_next;
		}
	}

	return skb;
}

static int restore_unix_rqueue(struct sock *sk, struct cpt_sock_image *si,
			       loff_t pos, struct cpt_context *ctx)
{
	loff_t endpos;

	endpos = pos + si->cpt_next;
	pos = pos + si->cpt_hdrlen;
	while (pos < endpos) {
		struct sk_buff *skb;
		struct sock *owner_sk;
		__u32 owner;
		int err;

		err = rst_sock_attr(&pos, sk, ctx);
		if (!err)
			continue;
		if (err < 0)
			return err;

		skb = rst_skb(sk, &pos, &owner, NULL, ctx);
		if (IS_ERR(skb))
			return PTR_ERR(skb);

		owner_sk = unix_peer(sk);
		if (owner != -1) {
			cpt_object_t *pobj;
			pobj = lookup_cpt_obj_byindex(CPT_OBJ_SOCKET, owner, ctx);
			if (pobj == NULL) {
				eprintk_ctx("orphan af_unix skb?\n");
				kfree_skb(skb);
				continue;
			}
			owner_sk = pobj->o_obj;
		}
		if (owner_sk == NULL) {
			dprintk_ctx("orphan af_unix skb 2?\n");
			kfree_skb(skb);
			continue;
		}
		skb_set_owner_w(skb, owner_sk);
		if (UNIXCB(skb).fp)
			skb->destructor = unix_destruct_fds;
		skb_queue_tail(&sk->sk_receive_queue, skb);
		if (sk->sk_state == TCP_LISTEN) {
			struct socket *sock = skb->sk->sk_socket;
			if (sock == NULL) BUG();
			if (sock->file) BUG();
			skb->sk->sk_socket = NULL;
			skb->sk->sk_sleep = NULL;
			sock->sk = NULL;
			sock_release(sock);
		}
	}
	return 0;
}


/* All the sockets are created before we start to open files */

int rst_sockets(struct cpt_context *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_SOCKET];
	loff_t endsec;
	cpt_object_t *obj;
	struct cpt_section_hdr h;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err) {
		eprintk_ctx("rst_sockets: ctx->pread: %d\n", err);
		return err;
	}
	if (h.cpt_section != CPT_SECT_SOCKET || h.cpt_hdrlen < sizeof(h)) {
		eprintk_ctx("rst_sockets: hdr err\n");
		return -EINVAL;
	}

	/* The first pass: we create socket index and open listening sockets. */
	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		struct cpt_sock_image *sbuf = cpt_get_buf(ctx);
		err = rst_get_object(CPT_OBJ_SOCKET, sec, sbuf, ctx);
		if (err) {
			eprintk_ctx("rst_sockets: rst_get_object: %d\n", err);
			cpt_release_buf(ctx);
			return err;
		}
		if (sbuf->cpt_state == TCP_LISTEN) {
			err = open_listening_socket(sec, sbuf, ctx); 
			cpt_release_buf(ctx);
			if (err) {
				eprintk_ctx("rst_sockets: open_listening_socket: %d\n", err);
				return err;
			}
		} else {
			cpt_release_buf(ctx);
			obj = alloc_cpt_object(GFP_KERNEL, ctx);
			if (obj == NULL)
				return -ENOMEM;
			cpt_obj_setindex(obj, sbuf->cpt_index, ctx);
			cpt_obj_setpos(obj, sec, ctx);
			obj->o_ppos  = sbuf->cpt_file;
			intern_cpt_object(CPT_OBJ_SOCKET, obj, ctx);
		}
		sec += sbuf->cpt_next;
	}

	/* Pass 2: really restore sockets */
	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct cpt_sock_image *sbuf;
		if (obj->o_obj != NULL)
			continue;
		sbuf = cpt_get_buf(ctx);
		err = rst_get_object(CPT_OBJ_SOCKET, obj->o_pos, sbuf, ctx);
		if (err) {
			eprintk_ctx("rst_sockets: rst_get_object: %d\n", err);
			cpt_release_buf(ctx);
			return err;
		}
		if (sbuf->cpt_state == TCP_LISTEN) BUG();
		err = open_socket(obj, sbuf, ctx);
		cpt_release_buf(ctx);
		if (err) {
			eprintk_ctx("rst_sockets: open_socket: %d\n", err);
			return err;
		}
	}

	return 0;
}

int rst_orphans(struct cpt_context *ctx)
{
	int err;
	loff_t sec = ctx->sections[CPT_SECT_ORPHANS];
	loff_t endsec;
	cpt_object_t *obj;
	struct cpt_section_hdr h;

	if (sec == CPT_NULL)
		return 0;

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_ORPHANS || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		struct cpt_sock_image *sbuf = cpt_get_buf(ctx);
		err = rst_get_object(CPT_OBJ_SOCKET, sec, sbuf, ctx);
		if (err) {
			cpt_release_buf(ctx);
			return err;
		}
		obj = alloc_cpt_object(GFP_KERNEL, ctx);
		if (obj == NULL) {
			cpt_release_buf(ctx);
			return -ENOMEM;
		}
		obj->o_pos = sec;
		obj->o_ppos  = sbuf->cpt_file;
		err = open_socket(obj, sbuf, ctx);
		dprintk_ctx("Restoring orphan: %d\n", err);
		free_cpt_object(obj, ctx);
		cpt_release_buf(ctx);
		if (err)
			return err;
		sec += sbuf->cpt_next;
	}

	return 0;
}

/* In this function we release sockets without links.
 * If nothing fails this sockets will be linked with skbs in
 * rst_sockets_complete() -> restore_unix_rqueue()
 */
void rst_rollback_sockets(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct sock *sk = obj->o_obj;

		if (sk == NULL) continue;

		if (sk->sk_family != AF_UNIX)
			continue;

		if (sk->sk_socket->file == NULL)
			sock_release(sk->sk_socket);
	}
}

/* Pass 3: I understand, this is not funny already :-),
 * but we have to do another pass to establish links between
 * not-paired AF_UNIX SOCK_DGRAM sockets and to restore AF_UNIX
 * skb queues with proper skb->sk links.
 *
 * This could be made at the end of rst_sockets(), but we defer
 * restoring af_unix queues up to the end of restoring files to
 * make restoring passed FDs cleaner.
 */

int rst_sockets_complete(struct cpt_context *ctx)
{
	int err;
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_SOCKET) {
		struct cpt_sock_image *sbuf;
		struct sock *sk = obj->o_obj;
		struct sock *peer;

		if (!sk) BUG();

		if (sk->sk_family != AF_UNIX)
			continue;

		sbuf = cpt_get_buf(ctx);
		err = rst_get_object(CPT_OBJ_SOCKET, obj->o_pos, sbuf, ctx);
		if (err) {
			cpt_release_buf(ctx);
			return err;
		}

		if (sbuf->cpt_next > sbuf->cpt_hdrlen)
			restore_unix_rqueue(sk, sbuf, obj->o_pos, ctx);

		cpt_release_buf(ctx);

		if (sk->sk_type == SOCK_DGRAM && unix_peer(sk) == NULL) {
			cpt_object_t *pobj;

			sbuf = cpt_get_buf(ctx);
			err = rst_get_object(CPT_OBJ_SOCKET, obj->o_pos, sbuf, ctx);
			if (err) {
				cpt_release_buf(ctx);
				return err;
			}

			if (sbuf->cpt_peer != -1) {
				pobj = lookup_cpt_obj_byindex(CPT_OBJ_SOCKET, sbuf->cpt_peer, ctx);
				if (pobj) {
					peer = pobj->o_obj;
					sock_hold(peer);
					unix_peer(sk) = peer;
				}
			}
			cpt_release_buf(ctx);
		}
	}

	rst_orphans(ctx);

	return 0;
}

