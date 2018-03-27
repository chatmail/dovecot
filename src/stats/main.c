/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "stats-settings.h"
#include "stats-event-category.h"
#include "stats-metrics.h"
#include "client-writer.h"
#include "client-reader.h"

static struct stats_metrics *metrics;

static bool client_is_writer(const char *path)
{
	const char *name, *suffix;

	name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	else
		name++;

	suffix = strrchr(name, '-');
	if (suffix == NULL)
		suffix = name;
	else
		suffix++;

	return strcmp(suffix, "writer") == 0;
}

static void client_connected(struct master_service_connection *conn)
{
	if (client_is_writer(conn->name))
		(void)client_writer_create(conn->fd, metrics);
	else
		(void)client_reader_create(conn->fd, metrics);
	master_service_client_connection_accept(conn);
}

static void main_preinit(void)
{
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	void **sets = master_service_settings_get_others(master_service);
	const struct stats_settings *set = sets[0];

	metrics = stats_metrics_init(set);
	stats_event_categories_init();
	client_readers_init();
	client_writers_init();
}

static void main_deinit(void)
{
	client_readers_deinit();
	client_writers_deinit();
	stats_event_categories_deinit();
	stats_metrics_deinit(&metrics);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&stats_setting_parser_info,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_IDLE_DIE |
		MASTER_SERVICE_FLAG_UPDATE_PROCTITLE;
	const char *error;

	master_service = master_service_init("stats", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service, "stats: ");

	main_preinit();

	master_service_init_finish(master_service);
	main_init();
	master_service_run(master_service, client_connected);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
