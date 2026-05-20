use super::context::OpenShared;
use crate::core_impl::ExtraData;
use alloc::string::String;
use elf_loader::image::ModuleScope;
use elf_loader::linker::{RelocationInputs, RelocationPlanner, RelocationRequest};

pub(super) struct DlopenPlanner<'ctx, 'mgr> {
    shared: &'ctx OpenShared<'mgr>,
    relocation_scope: Option<ModuleScope>,
}

impl<'ctx, 'mgr> DlopenPlanner<'ctx, 'mgr> {
    pub(super) fn new(shared: &'ctx OpenShared<'mgr>) -> Self {
        Self {
            shared,
            relocation_scope: None,
        }
    }
}

impl RelocationPlanner<String, ExtraData> for DlopenPlanner<'_, '_> {
    fn plan(
        &mut self,
        req: &RelocationRequest<'_, String, ExtraData>,
    ) -> core::result::Result<RelocationInputs<ExtraData>, elf_loader::Error> {
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
