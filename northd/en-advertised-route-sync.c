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

#include "openvswitch/vlog.h"
#include "smap.h"
#include "stopwatch.h"
#include "northd.h"

#include "en-advertised-route-sync.h"
#include "lib/stopwatch-names.h"
#include "openvswitch/hmap.h"
#include "ovn-util.h"

VLOG_DEFINE_THIS_MODULE(en_advertised_route_sync);

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct hmap *parsed_routes);

void
*en_advertised_route_sync_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_advertised_route_sync_cleanup(void *data OVS_UNUSED)
{
}

void
en_advertised_route_sync_run(struct engine_node *node, void *data OVS_UNUSED)
{
    struct routes_data *routes_data
        = engine_get_input_data("routes", node);
    const struct engine_context *eng_ctx = engine_get_context();
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table =
        EN_OVSDB_GET(engine_get_input("SB_advertised_route", node));

    stopwatch_start(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());

    advertised_route_table_sync(eng_ctx->ovnsb_idl_txn,
                      sbrec_advertised_route_table,
                      &routes_data->parsed_routes);

    stopwatch_stop(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

struct ar_entry {
    struct hmap_node hmap_node;

    const struct sbrec_advertised_route *sb_route;
    const struct sbrec_datapath_binding *sb_db;

    const struct sbrec_port_binding *logical_port;
    char *ip_prefix;
    bool stale;
};

static struct ar_entry *
ar_alloc_entry(struct hmap *routes,
                  const struct sbrec_datapath_binding *sb_db,
                  const struct sbrec_port_binding *logical_port,
                  const char *ip_prefix)
{
    struct ar_entry *route_e = xzalloc(sizeof *route_e);

    route_e->sb_db = sb_db;
    route_e->logical_port = logical_port;
    route_e->ip_prefix = xstrdup(ip_prefix);
    route_e->stale = false;
    uint32_t hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port->logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    hmap_insert(routes, &route_e->hmap_node, hash);

    return route_e;
}

static struct ar_entry *
ar_lookup_or_add(struct hmap *route_map,
                    const struct sbrec_datapath_binding *sb_db,
                    const struct sbrec_port_binding *logical_port,
                    const char *ip_prefix)
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

        return route_e;
    }

    route_e = ar_alloc_entry(route_map, sb_db,
                             logical_port, ip_prefix);
    return route_e;
}

static void
route_erase_entry(struct ar_entry *route_e)
{
    free(route_e->ip_prefix);
    free(route_e);
}

static bool
get_nbrp_or_nbr_option(const struct ovn_port *op, const char *key)
{
    return smap_get_bool(&op->nbrp->options, key,
        smap_get_bool(&op->od->nbr->options, key, false));
}

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct hmap *parsed_routes)
{
    if (!ovnsb_txn) {
        return;
    }

    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);

    const struct parsed_route *route;

    struct ar_entry *route_e;
    const struct sbrec_advertised_route *sb_route;
    SBREC_ADVERTISED_ROUTE_TABLE_FOR_EACH (sb_route,
                                           sbrec_advertised_route_table) {
        route_e = ar_alloc_entry(&sync_routes,
                                    sb_route->datapath,
                                    sb_route->logical_port,
                                    sb_route->ip_prefix);
        route_e->stale = true;
        route_e->sb_route = sb_route;
    }

    HMAP_FOR_EACH (route, key_node, parsed_routes) {
        if (route->is_discard_route) {
            continue;
        }
        if (prefix_is_link_local(&route->prefix, route->plen)) {
            continue;
        }
        if (!smap_get_bool(&route->od->nbr->options, "dynamic-routing",
                           false)) {
            continue;
        }
        if (route->source == ROUTE_SOURCE_CONNECTED &&
                !get_nbrp_or_nbr_option(route->out_port,
                                        "dynamic-routing-connected")) {
            continue;
        }
        if (route->source == ROUTE_SOURCE_STATIC &&
                !get_nbrp_or_nbr_option(route->out_port,
                                        "dynamic-routing-static")) {
            continue;
        }

        char *ip_prefix = normalize_v46_prefix(&route->prefix,
                                               route->plen);
        route_e = ar_lookup_or_add(&sync_routes, route->od->sb,
                                   route->out_port->sb, ip_prefix);
        route_e->stale = false;

        if (!route_e->sb_route) {
            const struct sbrec_advertised_route *sr =
                sbrec_advertised_route_insert(ovnsb_txn);
            sbrec_advertised_route_set_datapath(sr, route_e->sb_db);
            sbrec_advertised_route_set_logical_port(sr, route_e->logical_port);
            sbrec_advertised_route_set_ip_prefix(sr, route_e->ip_prefix);
            route_e->sb_route = sr;
        }

        free(ip_prefix);
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        if (route_e->stale) {
            sbrec_advertised_route_delete(route_e->sb_route);
        }
        route_erase_entry(route_e);
    }
    hmap_destroy(&sync_routes);
}

