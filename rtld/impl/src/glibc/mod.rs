pub(crate) mod v2_39;

pub(crate) use v2_39::{
    RtldGlobal, RtldGlobalRo, RtldGlobalRoAux, deallocate_tcb, dtv_value, init_tcb, set_dtv_value,
};
