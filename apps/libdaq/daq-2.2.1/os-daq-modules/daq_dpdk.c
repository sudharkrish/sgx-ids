/*
** Copyright (C) 2016
**     University of Science and Technology of China.  All rights reserved.
** Author: Tiwei Bie <btw () mail ustc edu cn>
**         Jiaxin Liu <jiaxin10 () mail ustc edu cn>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
** Mar 2017 - Napatech A/S - fc@napatech.com
** Added support for DPDK 16.07 and Snort 3.0 with multiple packet processing
** threads with the option to use DPDK multi-queue splitting (RSS).
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>

#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>

#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#ifndef IN_ENCLAVE
#include <rte_eal.h>
#endif

#define DAQ_DPDK_VERSION 17.08

#define MBUF_CACHE_SIZE 512
#define MAX_ARGS 64

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096
#define NUM_MBUFS 8192
#define BURST_SIZE 32
#define MBUF_PKT_SIZE  RTE_MBUF_DEFAULT_BUF_SIZE

#define MODULUS(a,b) (b)?(a % b):0

#define TAKE_LOCK(lck) \
        {int _rval; do {_rval = rte_atomic16_cmpset(lck, 0, 1);} while (unlikely(_rval == 0));}

#define RELEASE_LOCK(lck) \
        *(lck) = 0;

#define MAX_PORTS 16
static volatile uint16_t port_lock[MAX_PORTS+1];

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .header_split   = 0, /* Header Split disabled */
        .hw_ip_checksum = 0, /* IP checksum offload disabled */
        .hw_vlan_filter = 0, /* VLAN filtering disabled */
        .jumbo_frame    = 0, /* Jumbo Frame Support disabled */
        .hw_strip_crc   = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

#define MAX_DPDK_DEVICES  MAX_PORTS
#define MAX_RX_QUEUES  64
#define MAX_TX_QUEUES  64

#define DPDKINST_STARTED       0x1

/* Device equals a single dpdk device, which may have multiple queues */
typedef struct _dpdk_device {
    struct rte_mempool *mbuf_pool[MAX_RX_QUEUES];
    uint32_t flags;
    uint16_t max_rx_queues;
    uint16_t max_tx_queues;
    uint16_t num_rx_queues;
    uint16_t num_tx_queues;
    uint8_t port;
    int index;
    int ref_cnt;
    pthread_t tid;
} DpdkDevice;

static DpdkDevice *dpdk_devices[MAX_DPDK_DEVICES];
static int num_dpdk_devices;

typedef struct _dpdk_link {
    DpdkDevice *dev;
    uint16_t rx_queue;
    uint16_t tx_queue;
} DpdkLink;

#define DEV_IDX 0
#define PEER_IDX 1
#define LINK_NUM_DEVS 2

#define MODE_DPDK 0
#define MODE_SNORT 1

/*
 *  Interface is either a single port (dpdk0) or dual
 *  ports for bidirectional inline mode (dpdk0:dpdk1)
 */
typedef struct _dpdk_interface {
    char *descr;
    char *filter;
    int snaplen;
    int timeout;
    int debug;
    DpdkLink link[LINK_NUM_DEVS];
    struct sfbpf_program fcode;
    volatile int break_loop;
    int promisc_flag;
    int mode;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
    struct rte_ring *rx_ring;  /* receive ring  DPDK thread -> Snort thread */
    struct rte_ring *tx_ring;  /* transmit ring Snort thread -> DPDK thread */
} Dpdk_Interface_t;

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

#define MAX_RSSHASH_BITS  (6)
#define MAX_RXRINGS_NUM   (1<<MAX_RSSHASH_BITS)
#define RSSHASH_BITS_MASK (MAX_RXRINGS_NUM - 1)
static struct rte_ring* rx_rings[MAX_RXRINGS_NUM] = {NULL};
static unsigned char hash_rings[MAX_RXRINGS_NUM] = {0};

static void dpdk_daq_reset_stats(void *handle);

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

static struct timeval time_from_usec(uint64_t usec) {
    struct timeval t;
    t.tv_usec = usec % 1000000;
    t.tv_sec = usec / 1000000;
    return t;
}

static int parse_args(char *inputstring, char **argv) {
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;) {
        if (**ap != '\0')
            if (++ap >= &argv[MAX_ARGS])
                break;
    }
    return ap - argv;
}

/* Snort thread only: read from rx_ring and callback into Snort */
static int deliver_to_snort(Dpdk_Interface_t* dpdk_intf, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user) {
    struct rte_mbuf *rx_burst[BURST_SIZE];
    struct rte_mbuf *tx_burst[BURST_SIZE];
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    const uint8_t *data;
    uint16_t len;
    int c = 0, burst_size;
    uint16_t i, got_one, ignored_one, sent_one;
    uint16_t nb_rx, nb_tx;

    int peer_exists = dpdk_intf->link[PEER_IDX].dev ? 1 : 0;
    struct rte_ring* rx_ring = dpdk_intf->rx_ring;
    struct rte_ring* tx_ring = dpdk_intf->tx_ring;

    /* init DAQ packet header fields that never change */
    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr.flags = 0;
    daqhdr.opaque = 0;
    daqhdr.priv_ptr = NULL;
    daqhdr.address_space_id = 0;

    /* infinite loop if cnt == 0 (usual mode) */
    while (c < cnt || cnt <= 0) {
        got_one = ignored_one = sent_one = 0;

        /* Has breakloop() been called? */
        if (dpdk_intf->break_loop) {
            dpdk_intf->break_loop = 0;
            return 0;
        }

        burst_size = BURST_SIZE;
        if (cnt > 0 && cnt - c < BURST_SIZE)
            burst_size = cnt - c;

        /* dequeue from DPDK thread for subsequent Snort analysis */
        nb_rx = rte_ring_dequeue_burst(rx_ring, (void **)rx_burst, burst_size, NULL);
        if (unlikely(nb_rx == 0))
            continue;

        nb_tx = 0;

        /* feed retrieved packets to Snort engine via callback() */
        for (i = 0; i < nb_rx; i++) {
            verdict = DAQ_VERDICT_PASS;

            data = rte_pktmbuf_mtod(rx_burst[i], void *);
            len  = rte_pktmbuf_data_len(rx_burst[i]);

            /* check if can ignore this packet using BPF filter */
            if (dpdk_intf->fcode.bf_insns && sfbpf_filter(dpdk_intf->fcode.bf_insns, data, len, len) == 0) {
                ignored_one = 1;
                dpdk_intf->stats.packets_filtered++;
                goto send_packet;
            }
            got_one = 1;

            daqhdr.ingress_index = rx_burst[i]->port;
            daqhdr.egress_index  = peer_exists ? rx_burst[i]->port^1 : DAQ_PKTHDR_UNKNOWN;
            daqhdr.ts            = time_from_usec(rx_burst[i]->timestamp);
            daqhdr.caplen        = len;
            daqhdr.pktlen        = len;

            if (callback) {
                verdict = callback(user, &daqhdr, data);
                if (verdict >= MAX_DAQ_VERDICT)
                    verdict = DAQ_VERDICT_PASS;
                dpdk_intf->stats.verdicts[verdict]++;
                verdict = verdict_translation_table[verdict];
            }

            dpdk_intf->stats.packets_received++;
            c++;

send_packet:
            if (verdict == DAQ_VERDICT_PASS && peer_exists)
                tx_burst[nb_tx++] = rx_burst[i];
            else
                rte_pktmbuf_free(rx_burst[i]);
        }

        /* if in IPS (inline) mode, need to send PASS packets to network */
        if (peer_exists && nb_tx) {
            /* enqueue for DPDK thread (free stuck packets if ring is full) */
            uint16_t nbidx = rte_ring_enqueue_burst(tx_ring, (void **)tx_burst, nb_tx, NULL);
            if (unlikely(nbidx < nb_tx))
                for (i = nbidx; i < nb_tx; i++)
                    rte_pktmbuf_free(tx_burst[i]);
            sent_one = 1;
        }

#if 0
        /* there was no work in this iteration, maybe time out? */
        if ((!got_one && !ignored_one && !sent_one)) {
            struct timeval now;

            if (dpdk_intf->timeout == -1)
                continue;

            /* If time out, return control to the caller */
            gettimeofday(&now, NULL);
            if (now.tv_sec > ts.tv_sec ||
                    (now.tv_usec - ts.tv_usec) > dpdk_intf->timeout * 1000)
                return 0;
        }
#endif
    }

    return 0;
}

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#ifndef IN_ENCLAVE
/* before start, number of queues (rx/tx) must have been calculated */
int dpdk_start_device(void *handle, void *dev) {
    /* need opaque pointers-args because func is OCALLed */
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    DpdkDevice *device = (DpdkDevice *) dev;

    struct rte_eth_conf port_conf = port_conf_default;
    int port, queue, ret, socket;
    uint16_t rx_queues, tx_queues;

    port = device->port;
    socket = rte_eth_dev_socket_id(port);

    TAKE_LOCK(&port_lock[port]);

    /* Same thread as the device creator must start the device */
    if ((device->flags & DPDKINST_STARTED) || device->tid != pthread_self()) {
        int loop = 0;
        RELEASE_LOCK(&port_lock[port]);
        while (!(device->flags & DPDKINST_STARTED) && loop < 20000) {
            usleep(100);
            loop++;
        }
        return (device->flags & DPDKINST_STARTED) ? DAQ_SUCCESS : DAQ_ERROR;
    }

    if (dpdk_intf->debug) {
        printf("[%lx] DPDK Start device %s on port %i - with number of rx queues %i and tx queues %i\n", pthread_self(),
                dpdk_intf->descr, port, device->num_rx_queues, device->num_tx_queues);
    }

    rx_queues = RTE_MIN(device->num_rx_queues, device->max_rx_queues);
    tx_queues = RTE_MIN(device->num_tx_queues, device->max_tx_queues);

    /* step 1: configure Ethernet device `port` */
    ret = rte_eth_dev_configure(port, rx_queues, tx_queues, &port_conf);
    if (ret != 0) {
        DPE(dpdk_intf->errbuf, "%s: Couldn't configure port %d\n", __FUNCTION__, port);
        goto err;
    }

    /* step 2: allocate and set up receive queues for Ethernet device `port` */
    for (queue = 0; queue < rx_queues; queue++) {
        if (dpdk_intf->debug)
            printf("Setup DPDK Rx queue %i on port %i\n", queue, port);
        ret = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE, socket, NULL, device->mbuf_pool[queue]);
        if (ret != 0) {
            DPE(dpdk_intf->errbuf, "%s: Couldn't setup rx queue %d for port %d\n", __FUNCTION__, queue, port);
            goto err;
        }
    }

    /* step 2: allocate and set up transmit queues for Ethernet device `port` */
    for (queue = 0; queue < tx_queues; queue++) {
        if (dpdk_intf->debug)
            printf("Setup DPDK Tx queue %i on port %i\n", queue, port);
        ret = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE, socket, NULL);
        if (ret != 0) {
            DPE(dpdk_intf->errbuf, "%s: Couldn't setup tx queue %d for port %d\n", __FUNCTION__, queue, port);
            goto err;
        }
    }

    /* step 3: start Ethernet device */
    ret = rte_eth_dev_start(port);
    if (ret != 0) {
        DPE(dpdk_intf->errbuf, "%s: Couldn't start device for port %d\n", __FUNCTION__, port);
        goto err;
    }

    /* misc: set promiscuous mode if needed */
    if (dpdk_intf->promisc_flag)
        rte_eth_promiscuous_enable(port);

    /* misc: set hash filter for correct bidirectional analysis */
    struct rte_eth_hash_filter_info info;
    if (rte_eth_dev_filter_supported(port, RTE_ETH_FILTER_HASH) == 0) {
        memset(&info, 0, sizeof(info));
        info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
        info.info.enable = 1;
        if (dpdk_intf->debug)
            printf("Set syn hash filter on port %i\n", port);
        ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
        if (ret < 0)
            printf("Cannot set symmetric hash enable per port on port %u\n", port);
    }

    device->flags |= DPDKINST_STARTED;
    RELEASE_LOCK(&port_lock[port]);
    return DAQ_SUCCESS;

err:
  RELEASE_LOCK(&port_lock[port]);
  return DAQ_ERROR;
}

static void dpdk_print_stats(uint8_t port_id) {
    struct rte_eth_xstat_name *xstats_names;
    uint64_t *values;
    int len, i;

    /* Get number of stats */
    len = rte_eth_xstats_get_names_by_id(port_id, NULL, 0, NULL);
    if (len < 0) {
        printf("Cannot get xstats count\n");
        return;
    }

    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
    /* Retrieve xstats names, passing NULL for IDs to return all statistics */
    if (len != rte_eth_xstats_get_names_by_id(port_id, xstats_names, len, NULL)) {
        printf("Cannot get xstat names\n");
        free(xstats_names);
        return;
    }

    values = malloc(sizeof(values) * len);
    /* Getting xstats values */
    if (len != rte_eth_xstats_get_by_id(port_id, NULL, values, len)) {
        printf("Cannot get xstat values\n");
        free(xstats_names);
        return;
    }

    /* Print all xstats names and values */
    for (i = 0; i < len; i++) {
        if (strstr(xstats_names[i].name, "rx_priority0_dropped") ||
            strstr(xstats_names[i].name, "rx_total_packets") ||
            strstr(xstats_names[i].name, "rx_total_bytes"))
        fprintf(stderr, "[dpdk stats] %s: %"PRIu64"\n", xstats_names[i].name, values[i]);
    }
}

static void dpdk_destroy_device(DpdkDevice **device) {
    if (!device) return;
    if (*device) {
        if (--(*device)->ref_cnt == 0) {
            dpdk_print_stats((*device)->port);
            (*device)->flags &= ~DPDKINST_STARTED;
            rte_eth_dev_stop((*device)->port);
            rte_eth_dev_close((*device)->port);
            free(*device);
            *device = NULL;
        }
    }
}

/* NOTE this function must be mutex protected */
static DpdkDevice *dpdk_create_rx_device(const char *port_name, uint16_t *rx_queue, char *errbuf,
        size_t errlen, int queues, int debug) {
    DpdkDevice *device;
    int i, port;
    char poolname[64];
    static int index = 0;
    struct rte_eth_dev_info inf;

    *rx_queue = 0;

    /* init `port` with port number; interface name must be `dpdkXX` */
    if (strncmp(port_name, "dpdk", 4) != 0 || sscanf(&port_name[4], "%d", &port) != 1) {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, port_name);
        return NULL;
    }

    /* find device `port` in list of DPDK devices, init its Rx mbuf pool, and return */
    for (i = 0; i < num_dpdk_devices; i++) {
        if (port == dpdk_devices[i]->port) {
            if (dpdk_devices[i]->num_rx_queues >= dpdk_devices[i]->max_rx_queues)
                return NULL;

            if (debug)
                printf("DPDK - device found with port = %i, number of queues %i\n",
                        port, dpdk_devices[i]->num_rx_queues + 1);

            if (dpdk_devices[i]->flags & DPDKINST_STARTED) {
                printf("INTERNAL ERROR - device created too late!\n");
                return NULL;
            }
            *rx_queue = MODULUS(dpdk_devices[i]->num_rx_queues, dpdk_devices[i]->max_rx_queues);

            dpdk_devices[i]->num_rx_queues++;
            dpdk_devices[i]->ref_cnt++;

            if (dpdk_devices[i]->mbuf_pool[*rx_queue] == NULL) {
                snprintf(poolname, sizeof(poolname), "MBUF_POOL%d:%d", port, *rx_queue);

                /* create mbuf pool for later reuse by rx queues */
                dpdk_devices[i]->mbuf_pool[*rx_queue] = rte_pktmbuf_pool_create(poolname,
                        NUM_MBUFS / dpdk_devices[i]->max_rx_queues,
                        MBUF_CACHE_SIZE, 0, MBUF_PKT_SIZE, rte_socket_id());

                if (dpdk_devices[i]->mbuf_pool[*rx_queue] == NULL) {
                    snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n", __FUNCTION__);
                    goto err;
                }
            }

            return dpdk_devices[i];
        }
    }

    /* port not found, new DPDK port device needed */
    device = calloc(1, sizeof(DpdkDevice));
    if (!device) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate a new device structure.", __FUNCTION__);
        goto err;
    }

    /* This thread is the only one allowed to setup and start the device */
    device->tid = pthread_self();
    device->index = index++;
    device->port = port;
    device->ref_cnt = 1;

    rte_eth_dev_info_get(port, &inf);
    if (debug) {
        printf("driver name: %s\n",   inf.driver_name);
        printf("max Rx pktlen: %i\n", inf.max_rx_pktlen);
        printf("Max Rx queues: %i\n", inf.max_rx_queues);
        printf("Max Tx queues: %i\n", inf.max_tx_queues);
        printf("Daq Port ID    %i\n", device->index);
    }

    if (queues >= 1) {
        inf.max_rx_queues = RTE_MIN(inf.max_rx_queues, queues);
        inf.max_tx_queues = RTE_MIN(inf.max_tx_queues, queues);
    }

    device->max_rx_queues = RTE_MIN(MAX_RX_QUEUES, inf.max_rx_queues);
    device->max_tx_queues = RTE_MIN(MAX_TX_QUEUES, inf.max_tx_queues);
    device->num_rx_queues = 1;

    snprintf(poolname, sizeof(poolname), "MBUF_POOL%d:0", port);

    /* create mbuf pool for later reuse by rx queues */
    device->mbuf_pool[0] = rte_pktmbuf_pool_create(poolname, NUM_MBUFS / device->max_rx_queues,
                MBUF_CACHE_SIZE, 0, MBUF_PKT_SIZE, rte_socket_id());

    if (device->mbuf_pool[0] == NULL) {
        snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n", __FUNCTION__);
        goto err;
    }

    if (num_dpdk_devices < MAX_DPDK_DEVICES)
        dpdk_devices[num_dpdk_devices++] = device;
    else
        goto err;

    if (debug)
      printf("DPDK - device created on port = %i\n", port);

    *rx_queue = 0; // always first queue
    return device;

err:
    dpdk_destroy_device(&device);
    return NULL;
}

/* for Snort's inline mode (IPS), must bridge two DPDK ports --
 * simply specify that there is a non-zero `num_tx_queues` on both ports
 */
static int dpdk_create_bridge(Dpdk_Interface_t *dpdk_intf) {
    int i;

    /* Add Tx functionality for inline on both devices */
    for (i = 0; i < LINK_NUM_DEVS; i++) {
        if (dpdk_intf->link[i].dev->num_tx_queues >= dpdk_intf->link[i].dev->max_tx_queues)
            return DAQ_ERROR_NODEV;
        dpdk_intf->link[i].tx_queue = MODULUS(dpdk_intf->link[i].dev->num_tx_queues, dpdk_intf->link[i].dev->max_tx_queues);
        dpdk_intf->link[i].dev->num_tx_queues++;
    }

    if (dpdk_intf->debug) {
        printf("Created bridge between port %i and port %i, dev rx queue %i, dev tx queue %i, peer rx queue %i, peer tx queue %i\n",
                dpdk_intf->link[DEV_IDX].dev->port, dpdk_intf->link[PEER_IDX].dev->port, dpdk_intf->link[DEV_IDX].rx_queue,
                dpdk_intf->link[DEV_IDX].tx_queue, dpdk_intf->link[PEER_IDX].rx_queue, dpdk_intf->link[PEER_IDX].tx_queue);
    }

    return DAQ_SUCCESS;
}

static void dpdk_close(Dpdk_Interface_t *dpdk_intf) {
    int i;
    if (!dpdk_intf)
        return;

    for (i = 0; i < LINK_NUM_DEVS; i++) {
        if (dpdk_intf->link[i].dev)
            dpdk_destroy_device(&dpdk_intf->link[i].dev);
    }

    sfbpf_freecode(&dpdk_intf->fcode);
    dpdk_intf->state = DAQ_STATE_STOPPED;
}

#if 0
/* TODO: only for testing */
static int lcore_print_stats(void *arg) {
    unsigned second = 0;
    while (1) {
        printf("----------------------------- START second %u\n", second);
        dpdk_print_stats(0);
        printf("----------------------------- END second %u\n", second++);
        sleep(1);
    }
    return 0; /* unreachable */
}
#endif

/* init DPDK and rte_rings */
int dpdk_initialize(char* config_name, int config_snaplen, unsigned config_timeout, uint32_t config_flags, int config_mode,
        char* dpdk_args, int debug, int dpdk_queues, void** ctxt_ptr, char* errbuf, size_t errlen) {
    Dpdk_Interface_t *dpdk_intf;
    DpdkDevice *device;
    char dpdk_port[IFNAMSIZ];
    int num_ports = 0;
    size_t len;
    int i, ret, rval = DAQ_ERROR;
    char argv0[] = "fake";
    char *argv[MAX_ARGS + 1];
    int argc;
    uint16_t queue;
    char *dev = NULL;
    char ring_name[100];
    static char interface_name[1024] = "";
    static struct rte_ring* tx_ring = NULL;
    static uint16_t dev_idx = 0;
    static int first = 1, ports = 0;
    static volatile uint32_t threads_in = 0;
    static int dpdk_threads_num  = 0;
    static int snort_threads_num = 0;
    static int threads_num       = 0;

    threads_in++;
    TAKE_LOCK(&port_lock[MAX_PORTS]);
    threads_num++;

    dpdk_intf = calloc(1, sizeof(Dpdk_Interface_t));
    if (!dpdk_intf) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    /* Make sure only 1 Interface string is specified */
    if (interface_name[0] == 0) {
        if (strlen(config_name) > sizeof(interface_name)-1) {
            snprintf(errbuf, errlen, "%s: Invalid interface - too long!", __FUNCTION__);
            goto err;
        }
        strcpy(interface_name, config_name);
    }
    else
    {
        if (strcmp(interface_name, config_name) != 0) {
            snprintf(errbuf, errlen, "%s: Only 1 -i command supported on this DAQ!", __FUNCTION__);
            goto err;
        }
    }

    dpdk_intf->descr = strdup(config_name);
    if (!dpdk_intf->descr) {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdk_intf->snaplen = config_snaplen;
    dpdk_intf->timeout = (config_timeout > 0) ? (int) config_timeout : -1;
    dpdk_intf->promisc_flag = (config_flags & DAQ_CFG_PROMISC);

    if (first) {
        /* Import the DPDK arguments and other configuration values. */
        argv[0] = argv0;
        argc = parse_args(dpdk_args, &argv[1]) + 1;
        optind = 1;

        /* step 1: initialize EAL, executed once on MASTER core */
        ret = rte_eal_init(argc, argv);
        if (ret < 0) {
            snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
            rval = DAQ_ERROR_INVAL;
            goto err;
        }

        /* step 2: get total number of found Ethernet devices */
        ports = rte_eth_dev_count();
        if (ports == 0) {
            snprintf(errbuf, errlen, "%s: No Ethernet ports!\n", __FUNCTION__);
            rval = DAQ_ERROR_NODEV;
            goto err;
        }

        /* step 3: create single tx ring to pass packets from Snort -> to DPDK threads */
        /* NOTE: we create one rx ring per Snort thread below for balancing of packets */
        snprintf(ring_name, 100, "tx-ring");
        tx_ring = rte_ring_create(ring_name, 2048, SOCKET_ID_ANY, 0);
    
        /* calculate number N of DPDK threads as "dpdk_queues" for passive mode
         * or as "dpdk_queues*2" for inline mode (due to two Ethernet ports);
         * first N threads are inited as DPDK threads, the rest as Snort threads
         */
        dpdk_threads_num = dpdk_queues;
        if (strchr(dpdk_intf->descr, ':'))
            dpdk_threads_num = dpdk_queues*2;
 
#if 0
        /* -------------------------------------------------------------------- */
        /* TODO: only for testing, create new thread to show stats every second */
        rte_eal_remote_launch(lcore_print_stats, NULL, 1); /* lcore 1 */
        /* -------------------------------------------------------------------- */
#endif

        first = 0;
    }

    dpdk_intf->debug = debug;
    dpdk_intf->rx_ring = NULL;
    dpdk_intf->tx_ring = tx_ring;

    if (threads_num <= dpdk_threads_num) {
        /* ----- DPDK thread initialization ----- */
        dpdk_intf->mode = MODE_DPDK;

        dev = dpdk_intf->descr;
        while (dev[dev_idx] != '\0') {
            len = strcspn(&dev[dev_idx], ": ");
            if (len >= sizeof(dpdk_port)) {
                snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
                goto err;
            }
            if (len != 0) {
                snprintf(dpdk_port, len + 1, "%s", &dev[dev_idx]);

                num_ports++;
                device = dpdk_create_rx_device(dpdk_port, &queue, errbuf, errlen, dpdk_queues, dpdk_intf->debug);
                if (!device)
                    goto err;

                dev_idx += len + 1;

                /* if in IPS (inline) mode, need a link (bridge) between two ports */
                if (config_mode != DAQ_MODE_PASSIVE) {
                    if (num_ports == 2) {
                        /* this is the second port, so initialize peer and create bridge */
                        dpdk_intf->link[PEER_IDX].dev = device;
                        dpdk_intf->link[PEER_IDX].rx_queue = queue;

                        if (dpdk_create_bridge(dpdk_intf) != DAQ_SUCCESS) {
                            snprintf(errbuf, errlen, "%s: Couldn't create the bridge between dpdk%d and dpdk%d!",
                                     __FUNCTION__, dpdk_intf->link[DEV_IDX].dev->port, dpdk_intf->link[PEER_IDX].dev->port);
                            goto err;
                        }
                        break;
                    }
                    else
                    {
                        /* this is the first port, so initialize myself */
                        if (dev[dev_idx-1] != ':') {
                            snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s' - inline, but not \":\" separated!",
                                    __FUNCTION__, dpdk_intf->descr);
                            goto err;
                        }
                        dpdk_intf->link[DEV_IDX].dev = device;
                        dpdk_intf->link[DEV_IDX].rx_queue = queue;
                    }
                }
                else
                {
                    /* in IDS (passive) mode, initialize only myself */
                    if (dev[dev_idx-1] == ':') {
                        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s' - passive, but \":\" separator found!",
                                __FUNCTION__, dpdk_intf->descr);
                        goto err;
                    }
                    dpdk_intf->link[DEV_IDX].dev = device;
                    dpdk_intf->link[DEV_IDX].rx_queue = queue;
                    if (dpdk_intf->link[DEV_IDX].dev->max_tx_queues) {
                        dpdk_intf->link[DEV_IDX].dev->num_tx_queues = 1;
                        dpdk_intf->link[DEV_IDX].tx_queue = 0;
                    }
                    break;
                }
            }
            else
              break;
        }

        if (strlen(dev) <= dev_idx) dev_idx = 0;

        /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
        if (!dpdk_intf->link[DEV_IDX].dev || (config_mode != DAQ_MODE_PASSIVE && !dpdk_intf->link[PEER_IDX].dev)) {
            snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                    __FUNCTION__, dpdk_intf->descr);
            goto err;
        }
    }
    else
    {
        /* ----- Snort thread initialization ----- */
        dpdk_intf->mode = MODE_SNORT;

        /* create rx ring for each Snort thread; DPDK threads must correctly balance incoming packets */
        snprintf(ring_name, 100, "rx-ring%d", snort_threads_num);
        rx_rings[snort_threads_num] = rte_ring_create(ring_name, 2048, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
        dpdk_intf->rx_ring = rx_rings[snort_threads_num];
        snort_threads_num++;

        /* not best design: hash_rings recalculated on each new Snort thread, but good enough */
        for (i = 0; i < MAX_RXRINGS_NUM; i++)
            hash_rings[i] = i % snort_threads_num;

#ifdef MANUAL_PIN_SNORT_THREADS
        /* pin Snort threads to dedicated cores for performance */
        static int core_id = 2;  /* TODO: hardcoded pinning of Snort threads starts with core 2 */
        int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
        if (core_id >= num_cores) {
            snprintf(errbuf, errlen, "%s: Not enough cores for pinning of Snort threads!",
                    __FUNCTION__);
            goto err;
        }

        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_id, &cpuset);

        pthread_t current_thread = pthread_self();
        if ( pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset) ) {
            snprintf(errbuf, errlen, "%s: Could not set affinity for Snort thread on core %d!",
                    __FUNCTION__, core_id);
            goto err;
        }
        core_id++;
#endif
    }

    dpdk_intf->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = dpdk_intf;

    RELEASE_LOCK(&port_lock[MAX_PORTS]);
    threads_in--;

    do  {
        /* Wait for other threads to finish */
        usleep(100);
    } while (threads_in);

    return DAQ_SUCCESS;

err:
    if (dpdk_intf) {
        dpdk_close(dpdk_intf);
        if (dpdk_intf->descr)
            free(dpdk_intf->descr);
        free(dpdk_intf);
    }

    RELEASE_LOCK(&port_lock[MAX_PORTS]);
    threads_in--;
    return rval;
}

/* DPDK thread only: acquire packets from port and put into rx_ring */
int dpdk_acquire(void* handle) {
    /* need opaque pointers-args because func is OCALLed */
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    DpdkLink *link = (DpdkLink *)&dpdk_intf->link;

    struct rte_ring* rx_ring = NULL; /* chosen based on RSS hash */
    struct rte_ring* tx_ring = dpdk_intf->tx_ring;

    DpdkDevice *device, *peer;
    uint16_t dev_queue = 0, peer_queue = 0;
    uint16_t i, alt;
    struct rte_mbuf *rx_burst[BURST_SIZE];
    struct rte_mbuf *tx_burst[BURST_SIZE];
    uint16_t tx_num, nb_rx, nb_tx;
    uint16_t nbidx, cnt;
    int res;

    /* infinite loop */
    while (1) {
        for (alt = 0; alt < LINK_NUM_DEVS; alt++) {
            /* Has breakloop() been called? */
            if (dpdk_intf->break_loop) {
                dpdk_intf->break_loop = 0;
                return 0;
            }

            if (link[alt].dev == NULL)
                continue;

            device = link[alt].dev;
            dev_queue = link[alt].rx_queue;
            peer = link[alt^1].dev;
            peer_queue = link[alt^1].tx_queue;

            /* retrieve burst of input packets from receive queue */
            nb_rx = rte_eth_rx_burst(device->port, dev_queue, rx_burst, BURST_SIZE);
            if (unlikely(nb_rx == 0))
                continue;
            dpdk_intf->stats.hw_packets_received += nb_rx;

            /* enqueue for Snort threads (free stuck packets if ring is full) */
            for (i = 0; i < nb_rx; i++) {
                rx_ring = rx_rings[hash_rings[rx_burst[i]->hash.rss & RSSHASH_BITS_MASK]];
                res = rte_ring_enqueue(rx_ring, (void *)rx_burst[i]);
                if (unlikely(res != 0))
                    rte_pktmbuf_free(rx_burst[i]);
            }

            /* if in IPS (inline) mode, send packets to peer port */
            if (peer) {
                nbidx = cnt = 0;

                /* dequeue from Snort thread for subsequent send */
                tx_num = rte_ring_dequeue_burst(tx_ring, (void **)tx_burst, BURST_SIZE, NULL);
                if (unlikely(tx_num == 0))
                    continue;

                /* try to send all tx_num output packets in bursts on transmit queue */
                do {
                    nb_tx = rte_eth_tx_burst(peer->port, peer_queue, &tx_burst[nbidx], tx_num - nbidx);
                    nbidx += nb_tx;
                } while (nbidx < tx_num && ++cnt < 100);

                /* free stuck packets received on tx_ring but not sent on port */
                if (unlikely(nbidx < tx_num))
                    for (i = nbidx; i < tx_num; i++)
                        rte_pktmbuf_free(tx_burst[i]);
            }
        }
    }
    return 0;
}

int dpdk_stop(void *handle) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    TAKE_LOCK(&port_lock[MAX_PORTS]);
    dpdk_close(dpdk_intf);
    RELEASE_LOCK(&port_lock[MAX_PORTS]);

    return DAQ_SUCCESS;
}

void dpdk_shutdown(void *handle) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    TAKE_LOCK(&port_lock[MAX_PORTS]);
    dpdk_close(dpdk_intf);
    if (dpdk_intf->descr)
        free(dpdk_intf->descr);
    if (dpdk_intf->filter)
        free(dpdk_intf->filter);
    free(dpdk_intf);
    RELEASE_LOCK(&port_lock[MAX_PORTS]);
}
#endif // ifndef IN_ENCLAVE

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#ifdef IN_ENCLAVE
/* inside SGX enclave, must go through ocall interface */
int ocall_dpdk_initialize(char* config_name, int config_snaplen, unsigned int config_timeout, uint32_t config_flags, int config_mode,
               char* dpdk_args, int debug, int dpdk_queues, void** ctxt_ptr, char* errbuf, size_t errlen);
int ocall_dpdk_start_device(void* handle, void* dev);
int ocall_dpdk_acquire(void* handle);
int ocall_dpdk_stop(void* handle);
int ocall_dpdk_shutdown(void* handle);

#define CALL_DPDK_INITIALIZE   ocall_dpdk_initialize
#define CALL_DPDK_START_DEVICE ocall_dpdk_start_device
#define CALL_DPDK_ACQUIRE      ocall_dpdk_acquire
#define CALL_DPDK_STOP         ocall_dpdk_stop
#define CALL_DPDK_SHUTDOWN     ocall_dpdk_shutdown
#else
/* no SGX enclave, can directly call function */
#define CALL_DPDK_INITIALIZE   dpdk_initialize
#define CALL_DPDK_START_DEVICE dpdk_start_device
#define CALL_DPDK_ACQUIRE      dpdk_acquire
#define CALL_DPDK_STOP         dpdk_stop
#define CALL_DPDK_SHUTDOWN     dpdk_shutdown
#endif

/* entry point for DAQ initialization */
static int dpdk_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen) {
    DAQ_Dict *entry;
    char *dpdk_args = NULL;
    int debug = 0;
    int dpdk_queues = 1;

    for (entry = config->values; entry; entry = entry->next) {
        if (!strcmp(entry->key, "dpdk_args"))
            dpdk_args = entry->value;
        else if (!strcmp(entry->key, "debug"))
                debug = 1;
        else if (!strcmp(entry->key, "dpdk_queues")) {
                    dpdk_queues = atoi(entry->value);
                    if (dpdk_queues < 1) dpdk_queues = 1;
        }
    }

    return CALL_DPDK_INITIALIZE(config->name, config->snaplen, config->timeout, config->flags, config->mode, dpdk_args, debug, dpdk_queues, ctxt_ptr, errbuf, errlen);
}

static int dpdk_daq_set_filter(void *handle, const char *filter) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    if (dpdk_intf->mode == MODE_DPDK) {
        /* ----- DPDK thread does not use BPF filter ----- */
        return DAQ_SUCCESS;
    }

    /* ----- Snort thread compiles and uses BPF filter ----- */
    struct sfbpf_program fcode;

    if (dpdk_intf->filter)
        free(dpdk_intf->filter);

    dpdk_intf->filter = strdup(filter);
    if (!dpdk_intf->filter) {
        DPE(dpdk_intf->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(dpdk_intf->snaplen, DLT_EN10MB, &fcode, dpdk_intf->filter, 1, 0) < 0) {
        DPE(dpdk_intf->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&dpdk_intf->fcode);
    dpdk_intf->fcode.bf_len = fcode.bf_len;
    dpdk_intf->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

/* entry point to start packet acquisition */
static int dpdk_daq_start(void *handle) {
    int i;
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    if (dpdk_intf->mode == MODE_DPDK) {
        /* ----- DPDK thread initialization ----- */
        for (i = 0; i < LINK_NUM_DEVS; i++) {
            if (dpdk_intf->link[i].dev) {
                if (CALL_DPDK_START_DEVICE(dpdk_intf, dpdk_intf->link[i].dev) != DAQ_SUCCESS)
                    return DAQ_ERROR;
            }
        }
    }
    else
    {
        /* ----- Snort thread initialization ----- */
        /* nothing to do */
    }

    dpdk_daq_reset_stats(handle);
    dpdk_intf->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

/* entry point for packet acquisition inf loop */
static int dpdk_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    /* TODO: how to support bidirectional flow (need same Snort thread) ??
     *       even worse, how to support stateful flows if we "load-balance" Snort-threads ??
     *       (NOTE: ignoring for now and concentrating on 1:1 threads)
     */

    if (dpdk_intf->mode == MODE_DPDK) {
        /* ----- DPDK thread infinite loop ----- */
        return CALL_DPDK_ACQUIRE(dpdk_intf);
    }
    else
    {
        /* ----- Snort thread infinite loop ----- */
        return deliver_to_snort(dpdk_intf, cnt, callback, metaback, user);
    }
    return 0;
}

/* entry point for injecting packets into output stream */
static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse) {
    /* TODO: update to distinguish between DPDK and Snort threads */
#if 0
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    int tx_index;
    uint16_t tx_queue, rx_queue;
    DpdkDevice *device = NULL;
    struct rte_mbuf *m;

    if (reverse) {
        if (!dpdk_intf->link[DEV_IDX].dev ||
            !dpdk_intf->link[DEV_IDX].dev->max_tx_queues)
            return DAQ_ERROR_NODEV;

        tx_index = hdr->ingress_index;
        tx_queue = dpdk_intf->link[DEV_IDX].tx_queue;
        rx_queue = dpdk_intf->link[PEER_IDX].rx_queue;

        device = dpdk_intf->link[DEV_IDX].dev;
    }
    else
    {
        if (!dpdk_intf->link[PEER_IDX].dev ||
            !dpdk_intf->link[PEER_IDX].dev->max_tx_queues)
            return DAQ_ERROR_NODEV;

        tx_index = hdr->egress_index;
        tx_queue = dpdk_intf->link[PEER_IDX].tx_queue;
        rx_queue = dpdk_intf->link[DEV_IDX].rx_queue;

        device = dpdk_intf->link[PEER_IDX].dev;
    }

    if (!device || device->index != tx_index) {
        DPE(dpdk_intf->errbuf, "%s: Unrecognized interface specified: %u",
                __FUNCTION__, tx_index);
        return DAQ_ERROR_NODEV;
    }

    m = rte_pktmbuf_alloc(device->mbuf_pool[rx_queue]);
    if (!m) {
        DPE(dpdk_intf->errbuf, "%s: Couldn't allocate memory for packet.",
                __FUNCTION__);
        return DAQ_ERROR_NOMEM;
    }

    rte_memcpy(rte_pktmbuf_mtod(m, void *), packet_data, len);
    rte_pktmbuf_data_len(m) = len;

    /* send one packet */
    const uint16_t nb_tx = rte_eth_tx_burst(device->port, tx_queue, &m, 1);

    if (unlikely(nb_tx == 0)) {
        DPE(dpdk_intf->errbuf, "%s: Couldn't send packet. Try again.", __FUNCTION__);
        rte_pktmbuf_free(m);
        return DAQ_ERROR_AGAIN;
    }
#endif
    return DAQ_SUCCESS;
}

/* entry point for breaking loop: set `break_loop` volatile bool;
 * this function is called by master thread, bool is checked by pig in acquire()
 */
static int dpdk_daq_breakloop(void *handle) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    dpdk_intf->break_loop = 1;
    return DAQ_SUCCESS;
}

static int dpdk_daq_stop(void *handle) {
    return CALL_DPDK_STOP(handle);
}

static void dpdk_daq_shutdown(void *handle) {
    CALL_DPDK_SHUTDOWN(handle);
}

static DAQ_State dpdk_daq_check_status(void *handle) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    return dpdk_intf->state;
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    rte_memcpy(stats, &dpdk_intf->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

static void dpdk_daq_reset_stats(void *handle) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    memset(&dpdk_intf->stats, 0, sizeof(DAQ_Stats_t));
}

static int dpdk_daq_get_snaplen(void *handle) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    return dpdk_intf->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
        DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
        DAQ_CAPA_DEVICE_INDEX;
}

static int dpdk_daq_get_datalink_type(void *handle) {
    return DLT_EN10MB; // Ethernet, "10MB" is historical
}

static const char *dpdk_daq_get_errbuf(void *handle) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    return dpdk_intf->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string) {
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    if (!string)  return;
    DPE(dpdk_intf->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *name) {
    int port, i;

    if (strncmp(name, "dpdk", 4) != 0 || sscanf(&name[4], "%d", &port) != 1)
        return DAQ_ERROR_NODEV;

    for (i = 0; i < num_dpdk_devices; i++) {
        if (dpdk_devices[i]->port == port)
            return dpdk_devices[i]->index;
    }

    return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_API_VERSION,
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .initialize = */ dpdk_daq_initialize,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .start = */ dpdk_daq_start,
    /* .acquire = */ dpdk_daq_acquire,
    /* .inject = */ dpdk_daq_inject,
    /* .breakloop = */ dpdk_daq_breakloop,
    /* .stop = */ dpdk_daq_stop,
    /* .shutdown = */ dpdk_daq_shutdown,
    /* .check_status = */ dpdk_daq_check_status,
    /* .get_stats = */ dpdk_daq_get_stats,
    /* .reset_stats = */ dpdk_daq_reset_stats,
    /* .get_snaplen = */ dpdk_daq_get_snaplen,
    /* .get_capabilities = */ dpdk_daq_get_capabilities,
    /* .get_datalink_type = */ dpdk_daq_get_datalink_type,
    /* .get_errbuf = */ dpdk_daq_get_errbuf,
    /* .set_errbuf = */ dpdk_daq_set_errbuf,
    /* .get_device_index = */ dpdk_daq_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL
};
