/*
 * Copyright (c) 2024, STACKIT GmbH & Co. KG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <net/if.h>
#include <linux/rtnetlink.h>

#include "netlink-notifier.h"
#include "openvswitch/vlog.h"

#include "binding.h"
#include "hash.h"
#include "hmapx.h"
#include "route-table.h"
#include "route.h"
#include "route-table-notify.h"
#include "route-exchange-netlink.h"

VLOG_DEFINE_THIS_MODULE(route_table_notify);

struct route_table_watch_request {
    struct hmap_node node;
    uint32_t table_id;
};

struct route_table_watch_entry {
    struct hmap_node node;
    uint32_t table_id;
    struct nln *nln;
    struct nln_notifier *route_notifier;
    struct nln_notifier *route6_notifier;
};

static struct hmap watches = HMAP_INITIALIZER(&watches);
static bool any_route_table_changed;
static struct route_table_msg rtmsg;

static uint32_t
route_table_notify_hash_watch(uint32_t table_id)
{
    return hash_add(0, table_id);
}

void
route_table_add_watch_request(struct hmap *route_table_watches,
                              uint32_t table_id)
{
    struct route_table_watch_request *wr = xzalloc(sizeof *wr);
    wr->table_id = table_id;
    hmap_insert(route_table_watches, &wr->node,
                route_table_notify_hash_watch(wr->table_id));
}

static void
route_table_change(const void *change_, void *aux OVS_UNUSED)
{
    const struct route_table_msg *change = change_;
    if (change && change->rd.rtm_protocol != RTPROT_OVN) {
        any_route_table_changed = true;
    }
}

static void
add_watch_entry(uint32_t table_id)
{
    struct route_table_watch_entry *we;
    uint32_t hash = route_table_notify_hash_watch(table_id);
    we = xzalloc(sizeof *we);
    we->table_id = table_id;
    VLOG_INFO("Registering new route table watcher for table %d.",
             table_id);
    we->nln = nln_create(NETLINK_ROUTE, route_table_parse, &rtmsg);

    we->route_notifier =
        nln_notifier_create(we->nln, RTNLGRP_IPV4_ROUTE,
                            route_table_change, NULL);
    if (!we->route_notifier) {
        VLOG_WARN("Failed to create ipv4 route table watcher for "
                  "table %d. We will miss routing table updates.", table_id);
    }

    we->route6_notifier =
        nln_notifier_create(we->nln, RTNLGRP_IPV6_ROUTE,
                            route_table_change, NULL);
    if (!we->route6_notifier) {
        VLOG_WARN("Failed to create ipv6 route table watcher for "
                  "table %d. We will miss routing table updates.", table_id);
    }

    hmap_insert(&watches, &we->node, hash);
}

static void
remove_watch_entry(struct route_table_watch_entry *we)
{
    hmap_remove(&watches, &we->node);
    VLOG_INFO("Removing route table watcher for table %d.",
             we->table_id);
    nln_notifier_destroy(we->route_notifier);
    nln_notifier_destroy(we->route6_notifier);
    nln_destroy(we->nln);
    free(we);
}

void
route_table_notify_run(bool *changed)
{
    any_route_table_changed = false;

    struct route_table_watch_entry *we;
    HMAP_FOR_EACH (we, node, &watches) {
        nln_run(we->nln);
    }

    *changed = any_route_table_changed;
}

void
route_table_notify_wait(void)
{
    struct route_table_watch_entry *we;
    HMAP_FOR_EACH (we, node, &watches) {
        nln_wait(we->nln);
    }
}

static struct route_table_watch_entry*
find_watch_entry(uint32_t table_id)
{
    struct route_table_watch_entry *we;
    uint32_t hash = route_table_notify_hash_watch(table_id);
    HMAP_FOR_EACH_WITH_HASH (we, node, hash, &watches) {
        if (table_id == we->table_id) {
            return we;
        }
    }
    return NULL;
}

void
route_table_notify_update_watches(struct hmap *route_table_watches)
{
    struct hmapx sync_watches = HMAPX_INITIALIZER(&sync_watches);
    struct route_table_watch_entry *we;
    HMAP_FOR_EACH (we, node, &watches) {
        hmapx_add(&sync_watches, we);
    }

    struct route_table_watch_request *wr;
    HMAP_FOR_EACH_SAFE (wr, node, route_table_watches) {
        we = find_watch_entry(wr->table_id);
        if (we) {
            hmapx_find_and_delete(&sync_watches, we);
        } else {
            add_watch_entry(wr->table_id);
        }
        hmap_remove(route_table_watches, &wr->node);
        free(wr);
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &sync_watches) {
        remove_watch_entry(node->data);
    }
}
