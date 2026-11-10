use crate::glue::GlueInto;

pub trait HistoryMode: Default + GlueInto<Self::Vm1_5_2> {
    type Vm1_5_2: crate::vm_latest::HistoryMode;
}

impl HistoryMode for crate::vm_latest::HistoryEnabled {
    type Vm1_5_2 = crate::vm_latest::HistoryEnabled;
}

impl HistoryMode for crate::vm_latest::HistoryDisabled {
    type Vm1_5_2 = crate::vm_latest::HistoryDisabled;
}
