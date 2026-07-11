use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
use elf_loader::elf::ElfDyn;

use crate::abi::link_map::LinkMap;

#[derive(Default)]
pub struct ExtraData {
    pub(crate) c_name: Option<CString>,
    pub(crate) link_map: Option<Box<LinkMap>>,
    pub(crate) needed_libs: Vec<String>,
    pub(crate) dynamic_table: Option<Box<[ElfDyn]>>,
}

impl core::fmt::Debug for ExtraData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("UserData");
        d.field("c_name", &self.c_name);
        d.field("link_map", &self.link_map);
        d.field("needed_libs", &self.needed_libs);
        d.field("dynamic_table", &self.dynamic_table);
        d.finish()
    }
}
