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

#include <errno.h>
#include <net/if.h>

#include "openvswitch/vlog.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "route.h"
#include "route-table-notify.h"
#include "route-exchange.h"
#include "route-exchange-netlink.h"


VLOG_DEFINE_THIS_MODULE(route_exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static struct sset _maintained_vrfs = SSET_INITIALIZER(&_maintained_vrfs);

struct route_entry {
    struct hmap_node hmap_node;

    const struct sbrec_learned_route *sb_route;

    const struct sbrec_datapath_binding *sb_db;
    const struct sbrec_port_binding *logical_port;
    char *ip_prefix;
    char *nexthop;
    bool stale;
};

static struct route_entry *
route_alloc_entry(struct hmap *routes,
                  const struct sbrec_datapath_binding *sb_db,
                  const struct sbrec_port_binding *logical_port,
                  const char *ip_prefix, const char *nexthop)
{
    struct route_entry *route_e = xzalloc(sizeof *route_e);

    route_e->sb_db = sb_db;
    route_e->logical_port = logical_port;
    route_e->ip_prefix = xstrdup(ip_prefix);
    route_e->nexthop = xstrdup(nexthop);
    route_e->stale = false;
    uint32_t hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port->logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    hmap_insert(routes, &route_e->hmap_node, hash);

    return route_e;
}

static struct route_entry *
route_lookup_or_add(struct hmap *route_map,
                    const struct sbrec_datapath_binding *sb_db,
                    const struct sbrec_port_binding *logical_port,
                    const char *ip_prefix, const char *nexthop)
{
    struct route_entry *route_e;
    uint32_t hash;

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port->logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (!strcmp(route_e->nexthop, nexthop)) {
            return route_e;
        }
    }

    route_e = route_alloc_entry(route_map, sb_db,
                                logical_port, ip_prefix, nexthop);
    return route_e;
}

static void
route_erase_entry(struct route_entry *route_e)
{
    free(route_e->ip_prefix);
    free(route_e->nexthop);
    free(route_e);
}

static void
sb_sync_learned_routes(const struct sbrec_datapath_binding *datapath,
                       const struct hmap *learned_routes,
                       const struct smap *bound_ports,
                       struct ovsdb_idl_txn *ovnsb_idl_txn,
                       struct ovsdb_idl_index *sbrec_learned_route_by_datapath,
                       struct ovsdb_idl_index *sbrec_port_binding_by_name)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    struct route_entry *route_e;
    const struct sbrec_learned_route *sb_route;

    struct sbrec_learned_route *filter =
        sbrec_learned_route_index_init_row(sbrec_learned_route_by_datapath);
    sbrec_learned_route_index_set_datapath(filter, datapath);
    SBREC_LEARNED_ROUTE_FOR_EACH_EQUAL (sb_route, filter,
                                        sbrec_learned_route_by_datapath) {
        /* If the port is not local we don't care about it.
         * Some other ovn-controller will handle it.
         * We may not use smap_get since the value might be validly NULL. */
        if (!smap_get_node(bound_ports,
                           sb_route->logical_port->logical_port)) {
            continue;
        }
        route_e = route_alloc_entry(&sync_routes,
                                    sb_route->datapath,
                                    sb_route->logical_port,
                                    sb_route->ip_prefix,
                                    sb_route->nexthop);
        route_e->stale = true;
        route_e->sb_route = sb_route;
    }
    sbrec_learned_route_index_destroy_row(filter);

    struct re_nl_received_route_node *learned_route;
    HMAP_FOR_EACH (learned_route, hmap_node, learned_routes) {
        char *ip_prefix = normalize_v46_prefix(&learned_route->addr,
                                               learned_route->plen);
        char *nexthop = normalize_v46(&learned_route->nexthop);

        struct smap_node *port_node;
        SMAP_FOR_EACH (port_node, bound_ports) {
            /* The user specified an ifname, but we learned it on a different
             * port. */
            if (port_node->value && strcmp(port_node->value,
                                           learned_route->ifname)) {
                continue;
            }

            const struct sbrec_port_binding *logical_port =
                lport_lookup_by_name(sbrec_port_binding_by_name,
                                     port_node->key);
            if (!logical_port) {
                continue;
            }

            route_e = route_lookup_or_add(&sync_routes,
                datapath,
                logical_port, ip_prefix, nexthop);
            route_e->stale = false;
            if (!route_e->sb_route) {
                sb_route = sbrec_learned_route_insert(ovnsb_idl_txn);
                sbrec_learned_route_set_datapath(sb_route, datapath);
                sbrec_learned_route_set_logical_port(sb_route, logical_port);
                sbrec_learned_route_set_ip_prefix(sb_route, ip_prefix);
                sbrec_learned_route_set_nexthop(sb_route, nexthop);
                route_e->sb_route = sb_route;
            }
        }
        free(ip_prefix);
        free(nexthop);
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        if (route_e->stale) {
            sbrec_learned_route_delete(route_e->sb_route);
        }
        route_erase_entry(route_e);
    }
    hmap_destroy(&sync_routes);
}

void
route_exchange_run(struct route_exchange_ctx_in *r_ctx_in,
                   struct route_exchange_ctx_out *r_ctx_out)
{
    struct sset old_maintained_vrfs = SSET_INITIALIZER(&old_maintained_vrfs);
    sset_swap(&_maintained_vrfs, &old_maintained_vrfs);

    const struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH (ad, node, r_ctx_in->announce_routes) {
        struct hmap received_routes
                = HMAP_INITIALIZER(&received_routes);
        char vrf_name[IFNAMSIZ + 1];
        snprintf(vrf_name, sizeof vrf_name, "ovnvrf%"PRIi64,
                 ad->key);

        if (ad->maintain_vrf) {
            int error = re_nl_create_vrf(vrf_name, ad->key);
            if (error && error != EEXIST) {
                VLOG_WARN_RL(&rl,
                             "Unable to create VRF %s for datapath "
                             "%"PRId64": %s.",
                             vrf_name, ad->key,
                             ovs_strerror(error));
                goto out;
            }
            sset_add(&_maintained_vrfs, vrf_name);
        } else {
            /* a previous maintain-vrf flag was removed. We should therfor
             * also not delete it even if we created it previously. */
            sset_find_and_delete(&_maintained_vrfs, vrf_name);
            sset_find_and_delete(&old_maintained_vrfs, vrf_name);
        }

        re_nl_sync_routes(ad->key, &ad->routes,
                          &received_routes);

        sb_sync_learned_routes(ad->db, &received_routes,
                               &ad->bound_ports,
                               r_ctx_in->ovnsb_idl_txn,
                               r_ctx_in->sbrec_learned_route_by_datapath,
                               r_ctx_in->sbrec_port_binding_by_name);

        struct route_table_watch_request *wr = xzalloc(sizeof(*wr));
        wr->table_id = ad->key;
        hmap_insert(&r_ctx_out->route_table_watches, &wr->node,
                    route_table_notify_hash_watch(wr->table_id));

out:
        re_nl_received_routes_destroy(&received_routes);
    }

    /* Remove VRFs previously maintained by us not found in the above loop. */
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &old_maintained_vrfs) {
        if (!sset_find(&_maintained_vrfs, vrf_name)) {
            re_nl_delete_vrf(vrf_name);
        }
        sset_delete(&old_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }
    sset_destroy(&old_maintained_vrfs);
}

void
route_exchange_cleanup(void)
{
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &_maintained_vrfs) {
        re_nl_delete_vrf(vrf_name);
    }
}

void
route_exchange_destroy(void)
{
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &_maintained_vrfs) {
        sset_delete(&_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }

    sset_destroy(&_maintained_vrfs);
}
