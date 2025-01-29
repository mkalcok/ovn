/*
 * Copyright (c) 2024, Canonical, Ltd.
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

#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "route.h"


VLOG_DEFINE_THIS_MODULE(exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* While the linux kernel can handle 2^32 routing tables, only so many can fit
 * in the corresponding VRF interface name. */
#define MAX_TABLE_ID 1000000000

#define PRIORITY_DEFAULT 1000
#define PRIORITY_LOCAL_BOUND 100

bool
route_exchange_relevant_port(const struct sbrec_port_binding *pb)
{
    return pb && smap_get_bool(&pb->options, "dynamic-routing", false);
}

uint32_t
advertise_route_hash(const struct in6_addr *dst, unsigned int plen)
{
    uint32_t hash = hash_bytes(dst->s6_addr, 16, 0);
    return hash_int(plen, hash);
}

const struct sbrec_port_binding*
route_exchange_find_port(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                         const struct sbrec_chassis *chassis,
                         const struct sset *active_tunnels,
                         const struct sbrec_port_binding *pb)
{
    if (!pb) {
        return NULL;
    }
    if (route_exchange_relevant_port(pb)) {
        return pb;
    }
    const char *crp = smap_get(&pb->options, "chassis-redirect-port");
    if (!crp) {
        return NULL;
    }
    if (!lport_is_chassis_resident(sbrec_port_binding_by_name, chassis,
                                   active_tunnels, crp)) {
        return NULL;
    }
    const struct sbrec_port_binding *crpbp = lport_lookup_by_name(
        sbrec_port_binding_by_name, crp);
    if (route_exchange_relevant_port(crpbp)) {
        return crpbp;
    }
    return NULL;
}

static void
advertise_datapath_cleanup(struct advertise_datapath_entry *ad)
{
    struct advertise_route_entry *ar;
    HMAP_FOR_EACH_SAFE (ar, node, &ad->routes) {
        hmap_remove(&ad->routes, &ar->node);
        free(ar);
    }
    hmap_destroy(&ad->routes);
    smap_destroy(&ad->bound_ports);
    free(ad);
}

static struct advertise_datapath_entry*
advertise_datapath_find(const struct hmap *datapaths,
                        const struct sbrec_datapath_binding *db)
{
    struct advertise_datapath_entry *ade;
    HMAP_FOR_EACH_WITH_HASH (ade, node, db->tunnel_key, datapaths) {
        if (ade->db == db) {
            return ade;
        }
    }
    return NULL;
}

void
route_run(struct route_ctx_in *r_ctx_in,
          struct route_ctx_out *r_ctx_out)
{
    const struct local_datapath *ld;
    struct advertise_datapath_entry *ad;

    HMAP_FOR_EACH (ld, hmap_node, r_ctx_in->local_datapaths) {
        if (!ld->n_peer_ports || ld->is_switch) {
            continue;
        }

        ad = xzalloc(sizeof(*ad));
        ad->db = ld->datapath;
        hmap_init(&ad->routes);
        smap_init(&ad->bound_ports);

        /* This is a LR datapath, find LRPs with route exchange options
         * that are bound locally. */
        for (size_t i = 0; i < ld->n_peer_ports; i++) {
            const struct sbrec_port_binding *local_peer
                = ld->peer_ports[i].local;
            const struct sbrec_port_binding *repb = route_exchange_find_port(
                r_ctx_in->sbrec_port_binding_by_name,
                r_ctx_in->chassis,
                r_ctx_in->active_tunnels,
                local_peer);
            if (!repb) {
                continue;
            }

            ad->maintain_vrf |= smap_get_bool(
                &repb->options, "dynamic-routing-maintain-vrf", false);
            char *ifname = nullable_xstrdup(
                                    smap_get(&repb->options,
                                             "dynamic-routing-ifname"));

            const char *vrf_name = smap_get(&repb->options,
                                      "dynamic-routing-vrf-name");
            if (vrf_name && strlen(vrf_name) >= sizeof ad->vrf_name) {
                VLOG_WARN("Ignoring vrf name %s, since it is too long",
                          vrf_name);
                vrf_name = NULL;
            }
            if (vrf_name) {
                memcpy(ad->vrf_name, vrf_name, strlen(vrf_name) + 1);
            } else {
                snprintf(ad->vrf_name, sizeof ad->vrf_name, "ovnvrf%"PRIi64,
                         ad->db->tunnel_key);
            }

            smap_add_nocopy(&ad->bound_ports,
                            xstrdup(local_peer->logical_port), ifname);
        }

        if (smap_is_empty(&ad->bound_ports)) {
            advertise_datapath_cleanup(ad);
            continue;
        }
        tracked_datapath_add(ld->datapath, TRACKED_RESOURCE_NEW,
                             r_ctx_out->tracked_re_datapaths);

        /* While tunnel_key would most likely never be negative, the compiler
         * has opinions if we don't check before using it in snprintf below. */
        if (ld->datapath->tunnel_key < 0 ||
            ld->datapath->tunnel_key > MAX_TABLE_ID) {
            VLOG_WARN_RL(&rl,
                         "skip route sync for datapath "UUID_FMT", "
                         "tunnel_key %"PRIi64" would make VRF interface name "
                         "overflow.",
                         UUID_ARGS(&ld->datapath->header_.uuid),
                         ld->datapath->tunnel_key);
            goto cleanup;
        }

        hmap_insert(r_ctx_out->announce_routes, &ad->node, ad->db->tunnel_key);
        continue;

cleanup:
        advertise_datapath_cleanup(ad);
    }

    const struct sbrec_advertised_route *route;
    SBREC_ADVERTISED_ROUTE_FOR_EACH (route, r_ctx_in->ovnsb_idl) {
        struct in6_addr prefix;
        unsigned int plen;
        if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
            VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in route "
                         UUID_FMT, route->ip_prefix,
                         UUID_ARGS(&route->header_.uuid));
            continue;
        }

        ad = advertise_datapath_find(r_ctx_out->announce_routes,
                                     route->datapath);
        if (!ad) {
            continue;
        }

        unsigned int priority = PRIORITY_DEFAULT;

        if (route->tracked_port) {
            if (lport_is_local(
                      r_ctx_in->sbrec_port_binding_by_name,
                      r_ctx_in->chassis,
                      r_ctx_in->active_tunnels,
                      route->tracked_port->logical_port)) {
                priority = PRIORITY_LOCAL_BOUND;
                sset_add(r_ctx_out->tracked_ports_local,
                         route->tracked_port->logical_port);
            } else {
                sset_add(r_ctx_out->tracked_ports_remote,
                         route->tracked_port->logical_port);
            }
        }

        struct advertise_route_entry *ar = xzalloc(sizeof(*ar));
        hmap_insert(&ad->routes, &ar->node,
                    advertise_route_hash(&prefix, plen));
        ar->addr = prefix;
        ar->plen = plen;
        ar->priority = priority;
    }
}

void
route_cleanup(struct hmap *announce_routes)
{
    struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH_SAFE (ad, node, announce_routes) {
        hmap_remove(announce_routes, &ad->node);
        advertise_datapath_cleanup(ad);
    }
}
