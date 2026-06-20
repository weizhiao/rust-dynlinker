use super::context::OpenShared;
use crate::core_impl::{ActiveTlsResolver, ExtraData};
use alloc::string::String;
use elf_loader::linker::{RelocationInputs, RelocationPlanner, RelocationRequest};
use elf_loader::{arch::NativeArch, image::ModuleScope, memory::HostRegion};

pub(super) struct DlopenPlanner<'ctx, 'mgr> {
    shared: &'ctx OpenShared<'mgr>,
    relocation_scope: Option<ModuleScope<NativeArch, ActiveTlsResolver>>,
}

impl<'ctx, 'mgr> DlopenPlanner<'ctx, 'mgr> {
    pub(super) fn new(shared: &'ctx OpenShared<'mgr>) -> Self {
        Self {
            shared,
            relocation_scope: None,
        }
    }
}

impl RelocationPlanner<String, ExtraData, NativeArch, HostRegion, ActiveTlsResolver>
    for DlopenPlanner<'_, '_>
{
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, String, ExtraData, NativeArch, HostRegion, ActiveTlsResolver>,
    ) -> core::result::Result<RelocationInputs<NativeArch, ActiveTlsResolver>, elf_loader::Error>
    {
        if self.relocation_scope.is_none() {
            self.relocation_scope = Some(self.shared.prepare_relocation(req.scope()));
        }

        log::debug!("Planning relocation for dylib [{}]", req.key());

        let relocation_scope = self
            .relocation_scope
            .as_ref()
            .expect("Relocation scope must be initialized");
        let inputs = RelocationInputs::scope(relocation_scope.clone());
        if self.shared.flags.is_now() {
            Ok(inputs.eager())
        } else if self.shared.flags.is_lazy() {
            Ok(inputs.lazy())
        } else {
            Ok(inputs)
        }
    }
}
