use super::context::OpenShared;
use crate::core_impl::{ActiveTlsResolver, ExtraData};
use alloc::string::String;
use elf_loader::linker::{RelocationInputs, RelocationPlanner, RelocationRequest};
use elf_loader::{arch::NativeArch, memory::HostRegion};

pub(super) struct DlopenPlanner<'ctx, 'mgr> {
    shared: &'ctx OpenShared<'mgr>,
}

impl<'ctx, 'mgr> DlopenPlanner<'ctx, 'mgr> {
    pub(super) fn new(shared: &'ctx OpenShared<'mgr>) -> Self {
        Self { shared }
    }
}

impl RelocationPlanner<String, ExtraData, NativeArch, HostRegion, ActiveTlsResolver>
    for DlopenPlanner<'_, '_>
{
    fn plan(
        &self,
        req: &RelocationRequest<'_, String, ExtraData, NativeArch, HostRegion, ActiveTlsResolver>,
    ) -> core::result::Result<RelocationInputs<NativeArch, ActiveTlsResolver>, elf_loader::Error>
    {
        log::debug!("Planning relocation for dylib [{}]", req.key());

        let relocation_scope = self.shared.prepare_relocation(req.scope());
        let inputs = RelocationInputs::scope(relocation_scope);
        if self.shared.flags.is_now() {
            Ok(inputs.eager())
        } else if self.shared.flags.is_lazy() {
            Ok(inputs.lazy())
        } else {
            Ok(inputs)
        }
    }
}
