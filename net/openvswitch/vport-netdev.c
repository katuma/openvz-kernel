/*
 * Copyright (c) 2007-2011 Nicira Networks.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/llc.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>

#include <net/llc.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

static inline int netdev_rx_handler_register(struct net_device *dev,
					     void *rx_handler,
					     void *rx_handler_data)
{
	if (dev->br_port)
		return -EBUSY;

	rcu_assign_pointer(dev->br_port, rx_handler_data);
	return 0;
}

static inline void netdev_rx_handler_unregister(struct net_device *dev)
{
	rcu_assign_pointer(dev->br_port, NULL);
}

/* Must be called with rcu_read_lock. */
static void netdev_port_receive(struct vport *vport, struct sk_buff *skb)
{
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return;
	}

	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 * (No one comes after us, since we tell handle_bridge() that we took
	 * the packet.) */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	skb_push(skb, ETH_HLEN);
	ovs_vport_receive(vport, skb);
}

/* Called with rcu_read_lock and bottom-halves disabled. */
static struct sk_buff* netdev_frame_hook(struct net_bridge_port *p, struct sk_buff *skb)
{
	netdev_port_receive((struct vport *)p, skb);
	return NULL;
}

int ovs_install_br_hook(void)
{
	if (br_handle_frame_hook) {
		printk(KERN_ERR "Can't init open vSwitch in case of bridge "
				"hook is already installed\n");
		return -EBUSY;
	}

	br_handle_frame_hook = netdev_frame_hook;
	return 0;
}

void ovs_remove_br_hook(void)
{
	br_handle_frame_hook = NULL;
}

static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct netdev_vport *netdev_vport;
	int err;

	vport = ovs_vport_alloc(sizeof(struct netdev_vport),
				&ovs_netdev_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev = dev_get_by_name(&init_net, parms->name);
	if (!netdev_vport->dev) {
		err = -ENODEV;
		goto error_free_vport;
	}

	if (netdev_vport->dev->flags & IFF_LOOPBACK ||
	    netdev_vport->dev->type != ARPHRD_ETHER ||
	    ovs_is_internal_dev(netdev_vport->dev)) {
		err = -EINVAL;
		goto error_put;
	}

	err = netdev_rx_handler_register(netdev_vport->dev, netdev_frame_hook,
					 vport);
	if (err)
		goto error_put;

	dev_set_promiscuity(netdev_vport->dev, 1);
	netdev_vport->dev->priv_flags |= IFF_OVS_DATAPATH;

	return vport;

error_put:
	dev_put(netdev_vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void netdev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(netdev_vport->dev);
	dev_set_promiscuity(netdev_vport->dev, -1);

	synchronize_rcu();

	dev_put(netdev_vport->dev);
	ovs_vport_free(vport);
}

const char *ovs_netdev_get_name(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->name;
}

int ovs_netdev_get_ifindex(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->ifindex;
}

static unsigned int packet_length(const struct sk_buff *skb)
{
	unsigned int length = skb->len - ETH_HLEN;

	if (skb->protocol == htons(ETH_P_8021Q))
		length -= VLAN_HLEN;

	return length;
}

static int netdev_send(struct vport *vport, struct sk_buff *skb)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	int mtu = netdev_vport->dev->mtu;
	int len;

	if (unlikely(packet_length(skb) > mtu && !skb_is_gso(skb))) {
		if (net_ratelimit())
			pr_warn("%s: dropped over-mtu packet: %d > %d\n",
				ovs_dp_name(vport->dp), packet_length(skb), mtu);
		goto error;
	}

	if (unlikely(skb_warn_if_lro(skb)))
		goto error;

	skb->dev = netdev_vport->dev;
	len = skb->len;
	dev_queue_xmit(skb);

	return len;

error:
	kfree_skb(skb);
	ovs_vport_record_error(vport, VPORT_E_TX_DROPPED);
	return 0;
}

/* Returns null if this device is not attached to a datapath. */
struct vport *ovs_netdev_get_vport(struct net_device *dev)
{
	return (struct vport *)rcu_dereference(dev->br_port);
}

const struct vport_ops ovs_netdev_vport_ops = {
	.type		= OVS_VPORT_TYPE_NETDEV,
	.create		= netdev_create,
	.destroy	= netdev_destroy,
	.get_name	= ovs_netdev_get_name,
	.get_ifindex	= ovs_netdev_get_ifindex,
	.send		= netdev_send,
};
