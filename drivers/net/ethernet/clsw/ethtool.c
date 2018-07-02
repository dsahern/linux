/*
 * drivers/net/ethernet/cumulus/ethtool.c - ethtool ops for switch netdevs
 * Copyright (c) 2017-18 Cumulus Networks
 * Copyright (c) 2017-18 David Ahern <dsa@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <saiport.h>

#include "clsw-private.h"
#include "router.h"
#include "sdhal_be.h"

char clsw_version[] = "1.0";

struct clsw_stats {
	sai_port_stat_t	id;
	char		string[ETH_GSTRING_LEN];
};

static const struct clsw_stats clsw_stats_gstrings[] = {
	{ SAI_PORT_STAT_IF_IN_OCTETS,		"rx_bytes"	},
	{ SAI_PORT_STAT_IF_IN_UCAST_PKTS,	"rx_ucast_pkts"	},
	{ SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS,	"rx_non-ucast_pkts" },
	{ SAI_PORT_STAT_IF_IN_DISCARDS,		"rx_discards"	},
	{ SAI_PORT_STAT_IF_IN_ERRORS,		"rx_errors"	},
	{ SAI_PORT_STAT_IF_IN_BROADCAST_PKTS,	"rx_bcast_pkts"	},
	{ SAI_PORT_STAT_IF_IN_MULTICAST_PKTS,	"rx_mcast_pkts" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS,	   "rx_pkts_1_to_64" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS,    "rx_pkts_65_to_127" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS,   "rx_pkts_128_to_255" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS,   "rx_pkts_256_to_511" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS,  "rx_pkts_512_to_1023" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_1024_TO_1518_OCTETS, "rx_pkts_1024_to_1518" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_1519_TO_2047_OCTETS, "rx_pkts_1519_to_2047" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_2048_TO_4095_OCTETS, "rx_pkts_2048_to_4095" },
	{ SAI_PORT_STAT_ETHER_IN_PKTS_4096_TO_9216_OCTETS, "rx_pkts_4096_to_9216" },
	{ SAI_PORT_STAT_IF_OUT_OCTETS,		"tx_bytes"	},
	{ SAI_PORT_STAT_IF_OUT_UCAST_PKTS,	"tx_ucast_pkts"	},
	{ SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS,	"tx_non-ucast_pkts" },
	{ SAI_PORT_STAT_IF_OUT_DISCARDS,	"tx_discards"	},
	{ SAI_PORT_STAT_IF_OUT_ERRORS,		"tx_errors"	},
	{ SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS,	"tx_bcast_pkts"	},
	{ SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS,	"tx_mcast_pkts"	},
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_64_OCTETS,	    "tx_pkts_1_to_64" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_65_TO_127_OCTETS,    "tx_pkts_65_to_127" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_128_TO_255_OCTETS,   "tx_pkts_128_to_255" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_256_TO_511_OCTETS,   "tx_pkts_256_to_511" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_512_TO_1023_OCTETS,  "tx_pkts_512_to_1023" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS, "tx_pkts_1024_to_1518" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_1519_TO_2047_OCTETS, "tx_pkts_1519_to_2047" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_2048_TO_4095_OCTETS, "tx_pkts_2048_to_4095" },
	{ SAI_PORT_STAT_ETHER_OUT_PKTS_4096_TO_9216_OCTETS, "tx_pkts_4096_to_9216" },
};

#define CLSW_STATS_LEN  ARRAY_SIZE(clsw_stats_gstrings)

static sai_port_stat_t counter_ids[CLSW_STATS_LEN];
static bool init_counter_ids = true;

static void clsw_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *drvinfo)
{
	// TO-DO: can we return something about the switch here
	strlcpy(drvinfo->driver, "clsw", sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, clsw_version, sizeof(drvinfo->version));
}

static void clsw_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct clsw_port *port = clsw_port_find_by_dev(dev);
	int err;

	if (!port)
		goto err_out;

	err = sdhal_be_ops->port_get_stats(port, counter_ids,
					   CLSW_STATS_LEN, data);
	if (err) {
		pr_err("Failed to get stats for device %s: %x\n",
		       dev->name, err);
		goto err_out;
	}

	return;
err_out:
	memset(data, 0, sizeof(u64) * CLSW_STATS_LEN);
}

static void clsw_get_stats_strings(struct net_device *dev, u32 sset, u8 *data)
{
	u8 *p = data;
	int i;

	for (i = 0; i < CLSW_STATS_LEN; i++) {
		memcpy(p, clsw_stats_gstrings[i].string, ETH_GSTRING_LEN);
		p += ETH_GSTRING_LEN;
	}
}

static void clsw_get_strings(struct net_device *dev, u32 sset, u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		return clsw_get_stats_strings(dev, sset, data);
	}
}

static int clsw_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return CLSW_STATS_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

static int clsw_get_link_ksettings(struct net_device *dev,
				   struct ethtool_link_ksettings *ks)
{
	struct clsw_port *port = clsw_port_find_by_dev(dev);

	if (!port) {
		pr_err("No port struct for device %s; can not get speed\n",
		       dev->name);
		return -ENOENT;
	}

	ethtool_link_ksettings_zero_link_mode(ks, supported);
	ethtool_link_ksettings_add_link_mode(ks, supported, 10000baseCR_Full);
	ethtool_link_ksettings_add_link_mode(ks, supported, 10000baseSR_Full);
	ethtool_link_ksettings_add_link_mode(ks, supported, 10000baseLR_Full);
	ethtool_link_ksettings_add_link_mode(ks, supported, 10000baseLRM_Full);
	ethtool_link_ksettings_add_link_mode(ks, supported, 10000baseER_Full);
	ethtool_link_ksettings_add_link_mode(ks, supported, FIBRE);
	ethtool_link_ksettings_add_link_mode(ks, supported, Autoneg);

	ks->base.port = PORT_FIBRE;
	ks->base.eth_tp_mdix = ETH_TP_MDI;

	return sdhal_be_ops->port_get_speed(port, &ks->base.speed,
					    &ks->base.autoneg, &ks->base.duplex);
}

static int clsw_set_link_ksettings(struct net_device *dev,
				   const struct ethtool_link_ksettings *ks)
{
	struct clsw_port *port = clsw_port_find_by_dev(dev);
	u32 speed = SPEED_UNKNOWN;
	u8 autoneg = AUTONEG_DISABLE;
	u8 duplex = DUPLEX_FULL;
	int err;

	if (!port) {
		pr_err("No port struct for device %s; can not set speed\n",
		       dev->name);
		return -ENOENT;
	}

	err = sdhal_be_ops->port_get_speed(port, &speed, &autoneg, &duplex);
	if (err) {
		pr_err("Failed to get current speed settings for dev %s\n",
		       dev->name);
		return err;
	}

	if (ks->base.speed   != speed ||
	    ks->base.autoneg != autoneg ||
	    ks->base.duplex  != duplex) {
		return sdhal_be_ops->port_set_speed(port, ks->base.speed,
						    ks->base.autoneg, ks->base.duplex);
	}

	return 0;
}

static const struct ethtool_ops clsw_ethtool_ops = {
	.get_drvinfo		= clsw_get_drvinfo,
	.get_strings		= clsw_get_strings,
	.get_ethtool_stats	= clsw_get_ethtool_stats,
	.get_sset_count		= clsw_get_sset_count,

	.get_link_ksettings	= clsw_get_link_ksettings,
	.set_link_ksettings	= clsw_set_link_ksettings,
};

void clsw_port_ethtool_fini(struct clsw_port *port)
{
	port->dev->ethtool_ops = NULL;
}

int clsw_port_ethtool_init(struct clsw_port *port)
{
	/* first time through copy sai ids into an array
	 * that can be passed to sai call
	 */
	if (init_counter_ids) {
		int i;

		init_counter_ids = false;
		for (i = 0; i < CLSW_STATS_LEN; i++)
			counter_ids[i] = clsw_stats_gstrings[i].id;
	}

	// TO-DO: if ethtool_ops is already set, save original ops in clsw_port
	port->dev->ethtool_ops = &clsw_ethtool_ops;

	return 0;
}
