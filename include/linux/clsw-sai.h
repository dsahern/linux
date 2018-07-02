#ifndef _LINUX_CLSW_SAI_H
#define _LINUX_CLSW_SAI_H

#include <sai.h>

struct clsw_sai_ops {
	sai_status_t (*sai_api_query)(sai_api_t sai_api_id,
				      void **api_method_table);

	// sai_log_set
	// sai_object_type_query
	// sai_switch_id_query
	// sai_dbg_generate_dump

	/* string pass to create_switch, SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO
	 * attrbibute
	 */
	char hw_info[128];
};

int clsw_sdhal_register(struct clsw_sai_ops *sai_ops);
int clsw_sdhal_unregister(struct clsw_sai_ops *sai_ops);

#endif
