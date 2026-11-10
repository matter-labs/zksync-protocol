use zksync_types::StorageLogQuery;

use crate::glue::{GlueFrom, GlueInto};

impl GlueFrom<crate::vm_latest::utils::logs::StorageLogQuery> for StorageLogQuery {
    fn glue_from(value: crate::vm_latest::utils::logs::StorageLogQuery) -> Self {
        Self {
            log_query: value.log_query.glue_into(),
            log_type: value.log_type,
        }
    }
}
