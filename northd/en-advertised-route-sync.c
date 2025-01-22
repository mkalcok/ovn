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

#include "smap.h"
#include "stopwatch.h"
#include "northd.h"

#include "en-advertised-route-sync.h"
#include "en-lr-stateful.h"
#include "lib/stopwatch-names.h"
#include "openvswitch/hmap.h"
#include "ovn-util.h"

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct lr_stateful_table *lr_stateful_table,
    const struct hmap *parsed_routes,
    struct advertised_route_sync_data *data);

bool
advertised_route_sync_lr_stateful_change_handler(struct engine_node *node,
                                                 void *data_)
{
    /* We only actually use lr_stateful data if we expose individual host
     * routes. In this case we for now just recompute.
     * */
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);
    struct advertised_route_sync_data *data = data_;

    struct hmapx_node *hmapx_node;
    const struct lr_stateful_record *lr_stateful_rec;
    HMAPX_FOR_EACH (hmapx_node, &lr_stateful_data->trk_data.crupdated) {
        lr_stateful_rec = hmapx_node->data;
        if (uuidset_contains(&data->nb_lr_stateful,
                             &lr_stateful_rec->nbr_uuid)) {
            return false;
        }
    }

    return true;
}

bool
advertised_route_sync_northd_change_handler(struct engine_node *node,
                                            void *data_)
{
    struct advertised_route_sync_data *data = data_;
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return false;
    }

    /* We indirectly use northd_data->ls_ports if we announce host routes.
     * For now we just recompute on any change to lsps that are relevant to us.
     */

    struct hmapx_node *hmapx_node;
    const struct ovn_port *op;
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.created) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return false;
        }
    }
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.updated) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return false;
        }
    }
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.deleted) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return false;
        }
    }

    return true;
}

static void
routes_sync_init(struct advertised_route_sync_data *data)
{
    uuidset_init(&data->nb_lr_stateful);
    uuidset_init(&data->nb_ls);
}

static void
routes_sync_destroy(struct advertised_route_sync_data *data)
{
    uuidset_destroy(&data->nb_lr_stateful);
    uuidset_destroy(&data->nb_ls);
}


void
*en_advertised_route_sync_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct advertised_route_sync_data *data = xzalloc(sizeof *data);
    routes_sync_init(data);
    return data;
}

void
en_advertised_route_sync_cleanup(void *data OVS_UNUSED)
{
    routes_sync_destroy(data);
}

void
en_advertised_route_sync_run(struct engine_node *node, void *data OVS_UNUSED)
{
    routes_sync_destroy(data);
    routes_sync_init(data);

    struct advertised_route_sync_data *routes_sync_data = data;
    struct routes_data *routes_data
        = engine_get_input_data("routes", node);
    const struct engine_context *eng_ctx = engine_get_context();
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table =
        EN_OVSDB_GET(engine_get_input("SB_advertised_route", node));
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);

    stopwatch_start(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());

    advertised_route_table_sync(eng_ctx->ovnsb_idl_txn,
                      sbrec_advertised_route_table,
                      &lr_stateful_data->table,
                      &routes_data->parsed_routes,
                      routes_sync_data);

    stopwatch_stop(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

struct ar_entry {
    struct hmap_node hmap_node;

    const struct sbrec_datapath_binding *sb_db;

    const struct sbrec_port_binding *logical_port;
    char *ip_prefix;
    const struct sbrec_port_binding *tracked_port;
};

static struct ar_entry *
ar_alloc_entry(struct hmap *routes,
               const struct sbrec_datapath_binding *sb_db,
               const struct sbrec_port_binding *logical_port,
               char *ip_prefix,
               const struct sbrec_port_binding *tracked_port)
{
    struct ar_entry *route_e = xzalloc(sizeof *route_e);

    route_e->sb_db = sb_db;
    route_e->logical_port = logical_port;
    route_e->ip_prefix = ip_prefix;
    if (tracked_port) {
        route_e->tracked_port = tracked_port;
    }
    uint32_t hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port->logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    hmap_insert(routes, &route_e->hmap_node, hash);

    return route_e;
}

static struct ar_entry *
ar_find(struct hmap *route_map,
                    const struct sbrec_datapath_binding *sb_db,
                    const struct sbrec_port_binding *logical_port,
                    const char *ip_prefix,
                    const struct sbrec_port_binding *tracked_port)
{
    struct ar_entry *route_e;
    uint32_t hash;

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port->logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (!uuid_equals(&sb_db->header_.uuid,
                         &route_e->sb_db->header_.uuid)) {
            continue;
        }

        if (!uuid_equals(&logical_port->header_.uuid,
                         &route_e->logical_port->header_.uuid)) {
            continue;
        }

        if (strcmp(ip_prefix, route_e->ip_prefix)) {
            continue;
        }

        if (tracked_port != route_e->tracked_port) {
            continue;
        }

        return route_e;
    }

    return NULL;
}

static void
ar_entry_free(struct ar_entry *route_e)
{
    free(route_e->ip_prefix);
    free(route_e);
}

static void
publish_lport_addresses(struct hmap *sync_routes,
                        const struct sbrec_datapath_binding *sb_db,
                        const struct ovn_port *logical_port,
                        struct lport_addresses *addresses,
                        const struct ovn_port *tracking_port)
{
    for (size_t i = 0; i < addresses->n_ipv4_addrs; i++) {
        const struct ipv4_netaddr *addr = &addresses->ipv4_addrs[i];
        char *addr_s = xasprintf("%s/32", addr->addr_s);
        ar_alloc_entry(sync_routes, sb_db, logical_port->sb,
                       addr_s, tracking_port->sb);
    }
    for (size_t i = 0; i < addresses->n_ipv6_addrs; i++) {
        if (in6_is_lla(&addresses->ipv6_addrs[i].network)) {
            continue;
        }
        const struct ipv6_netaddr *addr = &addresses->ipv6_addrs[i];
        char *addr_s = xasprintf("%s/128", addr->addr_s);
        ar_alloc_entry(sync_routes, sb_db, logical_port->sb,
                       addr_s, tracking_port->sb);
    }
}

/* Collect all IP addresses connected to the out_port of a route.
 * This traverses all LSPs on the LS connected to the out_port. */
static void
publish_host_routes(struct hmap *sync_routes,
                    const struct lr_stateful_table *lr_stateful_table,
                    const struct parsed_route *route,
                    struct advertised_route_sync_data *data)
{
    struct ovn_port *port;
    struct ovn_datapath *lsp_od = route->out_port->peer->od;

    if (!lsp_od->nbs) {
        return;
    }

    /* We need to track the LS we are publishing routes from, so that we can
     * recompute when any port on there changes. */
    uuidset_insert(&data->nb_ls, &lsp_od->nbs->header_.uuid);
    HMAP_FOR_EACH (port, dp_node, &lsp_od->ports) {
        if (port->peer) {
            /* This is a LSP connected to an LRP */
            struct lport_addresses *addresses = &port->peer->lrp_networks;
            publish_lport_addresses(sync_routes, route->od->sb,
                                    route->out_port,
                                    addresses, port->peer);

            const struct lr_stateful_record *lr_stateful_rec;
            lr_stateful_rec = lr_stateful_table_find_by_index(
                lr_stateful_table, port->peer->od->index);
            /* We also need to track this LR as we need to recompute when
             * any of its IPs change. */
            uuidset_insert(&data->nb_lr_stateful,
                           &lr_stateful_rec->nbr_uuid);
            struct ovn_port_routable_addresses addrs = get_op_addresses(
                port->peer, lr_stateful_rec, false);
            for (size_t i = 0; i < addrs.n_addrs; i++) {
                publish_lport_addresses(sync_routes, route->od->sb,
                                        route->out_port,
                                        &addrs.laddrs[i],
                                        port->peer);
            }
            destroy_routable_addresses(&addrs);
        } else {
            /* This is just a plain LSP */
            for (size_t i = 0; i < port->n_lsp_addrs; i++) {
                publish_lport_addresses(sync_routes, route->od->sb,
                                        route->out_port,
                                        &port->lsp_addrs[i],
                                        port);
            }
        }
    }
}

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct lr_stateful_table *lr_stateful_table,
    const struct hmap *parsed_routes,
    struct advertised_route_sync_data *data)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    struct uuidset host_route_lrps = UUIDSET_INITIALIZER(&host_route_lrps);

    const struct parsed_route *route;

    struct ar_entry *route_e;
    const struct sbrec_advertised_route *sb_route;
    HMAP_FOR_EACH (route, key_node, parsed_routes) {
        if (route->is_discard_route) {
            continue;
        }
        if (prefix_is_link_local(&route->prefix, route->plen)) {
            continue;
        }
        if (!route->od->dynamic_routing) {
            continue;
        }
        if (route->source == ROUTE_SOURCE_CONNECTED) {
            if (!route->out_port->dynamic_routing_connected) {
                continue;
            }
            /* If we advertise host routes, we only need to do so once per
             * LRP. */
            const struct uuid *route_uuid =
                &route->out_port->nbrp->header_.uuid;
            if (smap_get_bool(&route->out_port->nbrp->options,
                              "dynamic-routing-connected-as-host-routes",
                              false) &&
                !uuidset_contains(&host_route_lrps, route_uuid)) {
                uuidset_insert(&host_route_lrps, route_uuid);
                publish_host_routes(&sync_routes, lr_stateful_table,
                                    route, data);
                continue;
            }
        }
        if (route->source == ROUTE_SOURCE_STATIC &&
                !route->out_port->dynamic_routing_static) {
            continue;
        }

        char *ip_prefix = normalize_v46_prefix(&route->prefix,
                                               route->plen);
        route_e = ar_alloc_entry(&sync_routes, route->od->sb,
                                 route->out_port->sb, ip_prefix, NULL);
    }
    uuidset_destroy(&host_route_lrps);

    SBREC_ADVERTISED_ROUTE_TABLE_FOR_EACH_SAFE (sb_route,
                                                sbrec_advertised_route_table) {
        route_e = ar_find(&sync_routes, sb_route->datapath,
                          sb_route->logical_port, sb_route->ip_prefix,
                          sb_route->tracked_port);
        if (route_e) {
          hmap_remove(&sync_routes, &route_e->hmap_node);
          ar_entry_free(route_e);
        } else {
          sbrec_advertised_route_delete(sb_route);
        }
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        const struct sbrec_advertised_route *sr =
            sbrec_advertised_route_insert(ovnsb_txn);
        sbrec_advertised_route_set_datapath(sr, route_e->sb_db);
        sbrec_advertised_route_set_logical_port(sr, route_e->logical_port);
        sbrec_advertised_route_set_ip_prefix(sr, route_e->ip_prefix);
        sbrec_advertised_route_set_tracked_port(sr, route_e->tracked_port);
        ar_entry_free(route_e);
    }

    hmap_destroy(&sync_routes);
}

