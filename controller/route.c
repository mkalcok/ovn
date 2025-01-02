/*
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
    return (pb && smap_get_bool(&pb->options, "dynamic-routing", false));
}

uint32_t
advertise_route_hash(const struct in6_addr *dst, unsigned int plen)
{
    uint32_t hash = hash_bytes(dst->s6_addr, 16, 0);
    return hash_int(plen, hash);
}

const struct sbrec_port_binding*
find_route_exchange_pb(struct ovsdb_idl_index *sbrec_port_binding_by_name,
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

static bool
pb_is_local(struct ovsdb_idl_index *sbrec_port_binding_by_name,
            const struct sbrec_chassis *chassis,
            const struct sset *active_tunnels,
            const char *port_name)
{
    if (lport_is_chassis_resident(sbrec_port_binding_by_name, chassis,
                                active_tunnels, port_name)) {
        return true;
    }

    const struct sbrec_port_binding *pb = lport_lookup_by_name(
        sbrec_port_binding_by_name, port_name);

    const char *crp = smap_get(&pb->options, "chassis-redirect-port");
    if (!crp) {
        return NULL;
    }

    return lport_is_chassis_resident(sbrec_port_binding_by_name, chassis,
                                     active_tunnels, crp);
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

void
route_run(struct route_ctx_in *r_ctx_in,
          struct route_ctx_out *r_ctx_out)
{
    tracked_datapaths_destroy(r_ctx_out->tracked_re_datapaths);
    sset_clear(r_ctx_out->tracked_ports_local);
    sset_clear(r_ctx_out->tracked_ports_remote);

    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, r_ctx_in->local_datapaths) {
        if (!ld->n_peer_ports || ld->is_switch) {
            continue;
        }

        bool relevant_datapath = false;
        struct advertise_datapath_entry *ad = xzalloc(sizeof(*ad));
        ad->key = ld->datapath->tunnel_key;
        ad->db = ld->datapath;
        hmap_init(&ad->routes);
        smap_init(&ad->bound_ports);

        /* This is a LR datapath, find LRPs with route exchange options
         * that are bound locally. */
        for (size_t i = 0; i < ld->n_peer_ports; i++) {
            const struct sbrec_port_binding *local_peer
                = ld->peer_ports[i].local;
            const struct sbrec_port_binding *repb = find_route_exchange_pb(
                r_ctx_in->sbrec_port_binding_by_name,
                r_ctx_in->chassis,
                r_ctx_in->active_tunnels,
                local_peer);
            if (!repb) {
                continue;
            }

            ad->maintain_vrf |= smap_get_bool(&repb->options,
                                          "maintain-vrf", false);
            ad->use_netns |= smap_get_bool(&repb->options,
                                       "use-netns", false);
            char *ifname = nullable_xstrdup(
                                    smap_get(&repb->options,
                                             "dynamic-routing-ifname"));
            relevant_datapath = true;
            smap_add_nocopy(&ad->bound_ports,
                            xstrdup(local_peer->logical_port), ifname);
        }

        if (!relevant_datapath) {
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

        if (ad->maintain_vrf && ad->use_netns) {
            VLOG_WARN_RL(&rl,
                         "For Datapath %"PRIu64" both maintain-vrf and "
                         "use-netns are set, this will never work",
                         ld->datapath->tunnel_key);
            goto cleanup;
        }

        struct sbrec_advertised_route *route_filter =
            sbrec_advertised_route_index_init_row(
                r_ctx_in->sbrec_advertised_route_by_datapath);
        sbrec_advertised_route_index_set_datapath(route_filter, ld->datapath);
        struct sbrec_advertised_route *route;
        SBREC_ADVERTISED_ROUTE_FOR_EACH_EQUAL (route, route_filter,
                r_ctx_in->sbrec_advertised_route_by_datapath) {
            struct in6_addr prefix;
            unsigned int plen;
            if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
                VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in route "
                             UUID_FMT, route->ip_prefix,
                             UUID_ARGS(&route->header_.uuid));
                continue;
            }

            unsigned int priority = PRIORITY_DEFAULT;

            if (route->tracked_port) {
                if (pb_is_local(
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
        sbrec_advertised_route_index_destroy_row(route_filter);

        hmap_insert(r_ctx_out->announce_routes, &ad->node, ad->key);
        continue;

cleanup:
        advertise_datapath_cleanup(ad);
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
