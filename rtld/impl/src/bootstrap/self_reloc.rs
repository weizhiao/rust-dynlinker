use crate::arch::{
    NATIVE_RELOCATION_ENTRY_SIZE_TAG, NATIVE_RELOCATION_SIZE_TAG, NATIVE_RELOCATION_TAG,
};
use core::ptr::NonNull;
use dlopen_rs::rtld::{
    elf::{ElfDyn, ElfDynamicTag, ElfRelType, ElfRelr, NativeArch, RelocationArch},
    memory::{ElfResult, ImageMemory, VmAddr},
    relocation::{relocate_relative, relocate_relr},
};

#[derive(Copy, Clone)]
struct RelocationTables {
    rela: RelocationTable,
    relr: RelocationTable,
    has_lifecycle: bool,
}

#[derive(Copy, Clone)]
struct RelocationTable {
    offset: usize,
    size: usize,
    entry_size: usize,
}

impl RelocationTable {
    const fn empty(entry_size: usize) -> Self {
        Self {
            offset: 0,
            size: 0,
            entry_size,
        }
    }

    const fn is_empty(self) -> bool {
        self.size == 0
    }

    fn validate<T>(self) -> Option<Self> {
        let entry_size = core::mem::size_of::<T>();
        if self.is_empty() {
            return Some(Self { entry_size, ..self });
        }
        if self.offset == 0
            || self.entry_size != entry_size
            || !self.size.is_multiple_of(self.entry_size)
        {
            return None;
        }
        Some(self)
    }

    const fn len(self) -> usize {
        self.size / self.entry_size
    }
}

impl RelocationTables {
    unsafe fn parse(dynamic: *const usize) -> Option<Self> {
        if dynamic.is_null() {
            return None;
        }

        let dynamic = dynamic.cast::<ElfDyn>();
        let mut rela = RelocationTable::empty(core::mem::size_of::<ElfRelType>());
        let mut relr = RelocationTable::empty(core::mem::size_of::<ElfRelr>());
        let mut has_lifecycle = false;
        let mut index = 0usize;
        while index < 4096 {
            let entry = unsafe { core::ptr::read_unaligned(dynamic.add(index)) };
            let tag = entry.tag();
            let value = entry.value();
            if tag == ElfDynamicTag::NULL {
                return Some(Self {
                    rela: rela.validate::<ElfRelType>()?,
                    relr: relr.validate::<ElfRelr>()?,
                    has_lifecycle,
                });
            } else if tag == ElfDynamicTag::NEEDED {
                return None;
            } else if tag == NATIVE_RELOCATION_TAG {
                rela.offset = value;
            } else if tag == NATIVE_RELOCATION_SIZE_TAG {
                rela.size = value;
            } else if tag == NATIVE_RELOCATION_ENTRY_SIZE_TAG && value != 0 {
                rela.entry_size = value;
            } else if tag == ElfDynamicTag::RELR {
                relr.offset = value;
            } else if tag == ElfDynamicTag::RELRSZ {
                relr.size = value;
            } else if tag == ElfDynamicTag::RELRENT && value != 0 {
                relr.entry_size = value;
            } else if (tag == ElfDynamicTag::JMPREL || tag == ElfDynamicTag::PLTRELSZ) && value != 0
            {
                return None;
            } else if matches!(
                tag,
                ElfDynamicTag::INIT
                    | ElfDynamicTag::FINI
                    | ElfDynamicTag::INIT_ARRAY
                    | ElfDynamicTag::INIT_ARRAYSZ
                    | ElfDynamicTag::FINI_ARRAY
                    | ElfDynamicTag::FINI_ARRAYSZ
                    | ElfDynamicTag::PREINIT_ARRAY
                    | ElfDynamicTag::PREINIT_ARRAYSZ
            ) && value != 0
            {
                has_lifecycle = true;
            }
            index = index.wrapping_add(1);
        }
        None
    }

    const fn can_pass_through(self) -> bool {
        self.rela.is_empty() && self.relr.is_empty() && !self.has_lifecycle
    }

    unsafe fn apply(self, load_bias: usize) -> bool {
        let memory = BootstrapMemory { load_bias };
        if !self.rela.is_empty() {
            let relocations = unsafe {
                core::slice::from_raw_parts(
                    load_bias.wrapping_add(self.rela.offset) as *const ElfRelType,
                    self.rela.len(),
                )
            };
            for relative in relocations.split(|rel| rel.r_type() == NativeArch::NONE) {
                if relative.is_empty() {
                    continue;
                }
                if !relative
                    .iter()
                    .all(|rel| rel.r_type() == NativeArch::RELATIVE)
                    || relocate_relative::<NativeArch, _>(relative, &memory).is_err()
                {
                    return false;
                }
            }
        }

        if self.relr.is_empty() {
            return true;
        }
        let entries = unsafe {
            core::slice::from_raw_parts(
                load_bias.wrapping_add(self.relr.offset) as *const ElfRelr,
                self.relr.len(),
            )
        };
        relocate_relr(entries, &memory).is_ok()
    }
}

pub(super) unsafe fn relocate(dynamic: *const usize, load_bias: usize) -> bool {
    unsafe { RelocationTables::parse(dynamic) }
        .is_some_and(|relocations| unsafe { relocations.apply(load_bias) })
}

pub(super) unsafe fn can_pass_through(dynamic: *const usize) -> bool {
    dynamic.is_null()
        || unsafe { RelocationTables::parse(dynamic) }
            .is_some_and(RelocationTables::can_pass_through)
}

#[derive(Copy, Clone)]
struct BootstrapMemory {
    load_bias: usize,
}

impl ImageMemory for BootstrapMemory {
    fn base(&self) -> VmAddr {
        VmAddr::new(self.load_bias)
    }

    fn range_at(&self, _addr: VmAddr) -> Option<core::ops::Range<VmAddr>> {
        None
    }

    fn host_ptr(&self, addr: VmAddr) -> Option<NonNull<u8>> {
        NonNull::new(addr.get() as *mut u8)
    }

    fn host_ptr_range(&self, addr: VmAddr, len: usize) -> Option<NonNull<u8>> {
        if len != 0 {
            addr.get().checked_add(len - 1)?;
        }
        self.host_ptr(addr)
    }

    fn read_bytes(&self, addr: VmAddr, dst: &mut [u8]) -> ElfResult<()> {
        if !dst.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(addr.get() as *const u8, dst.as_mut_ptr(), dst.len())
            };
        }
        Ok(())
    }

    fn write_bytes(&self, addr: VmAddr, src: &[u8]) -> ElfResult<()> {
        if !src.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr(), addr.get() as *mut u8, src.len())
            };
        }
        Ok(())
    }
}
