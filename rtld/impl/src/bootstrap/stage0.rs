use crate::runtime::{RTLD_FATAL_EXIT_STATUS, exit, read_usize};
use core::ptr::{NonNull, null};
use dlopen_rs::rtld::{
    auxv::{
        AT_BASE, AT_CLKTCK, AT_ENTRY, AT_FPUCW, AT_HWCAP, AT_HWCAP2, AT_HWCAP3, AT_HWCAP4,
        AT_MINSIGSTKSZ, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PLATFORM, AT_SECURE,
        AT_SYSINFO_EHDR,
    },
    elf::{
        ElfDyn, ElfDynamicTag, ElfHeader, ElfPhdr, ElfProgramType, ElfRelType, ElfRelr, NativeArch,
        RelocationArch,
    },
    memory::{ElfResult, ImageMemory, VmAddr},
    relocation::{relocate_relative, relocate_relr},
};

#[derive(Copy, Clone)]
pub(super) struct AuxState {
    pub(super) phdr: usize,
    pub(super) phent: usize,
    pub(super) phnum: usize,
    pub(super) base: usize,
    pub(super) entry: usize,
    pub(super) secure: usize,
    pub(super) pagesize: usize,
    pub(super) platform: usize,
    pub(super) hwcap: usize,
    pub(super) hwcap2: usize,
    pub(super) hwcap3: usize,
    pub(super) hwcap4: usize,
    pub(super) clktck: usize,
    pub(super) fpucw: usize,
    pub(super) minsigstacksize: usize,
    pub(super) sysinfo_ehdr: usize,
}

impl AuxState {
    const fn empty() -> Self {
        Self {
            phdr: 0,
            phent: 0,
            phnum: 0,
            base: 0,
            entry: 0,
            secure: 0,
            pagesize: 0,
            platform: 0,
            hwcap: 0,
            hwcap2: 0,
            hwcap3: 0,
            hwcap4: 0,
            clktck: 0,
            fpucw: 0,
            minsigstacksize: 0,
            sysinfo_ehdr: 0,
        }
    }

    fn phdrs(self) -> PhdrIter {
        PhdrIter {
            aux: self,
            index: 0,
        }
    }

    fn find_phdr(self, program_type: ElfProgramType) -> Option<ElfPhdr> {
        self.phdrs()
            .find(|phdr| phdr.program_type() == program_type)
    }

    fn phdr_at(self, index: usize) -> Option<ElfPhdr> {
        if index >= self.phnum || self.phdr == 0 || self.phent < core::mem::size_of::<ElfPhdr>() {
            return None;
        }

        let offset = index.wrapping_mul(self.phent);
        let ptr = (self.phdr as *const u8).wrapping_add(offset) as *const ElfPhdr;
        Some(unsafe { core::ptr::read_unaligned(ptr) })
    }
}

struct PhdrIter {
    aux: AuxState,
    index: usize,
}

impl Iterator for PhdrIter {
    type Item = ElfPhdr;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        let Some(phdr) = self.aux.phdr_at(index) else {
            self.index = self.aux.phnum;
            return None;
        };
        self.index = self.index.wrapping_add(1);
        Some(phdr)
    }
}

#[derive(Copy, Clone)]
pub(super) struct Stage0 {
    pub(super) stack: *const usize,
    pub(super) argc: usize,
    pub(super) argv: *const *const u8,
    pub(super) envp: *const *const u8,
    pub(super) auxv: *const usize,
    pub(super) aux: AuxState,
    pub(super) main_load_bias: usize,
    pub(super) main_dynamic: *const usize,
    pub(super) rtld_load_bias: usize,
    pub(super) rtld_dynamic: *const usize,
    pub(super) direct_invocation: bool,
}

pub(super) fn stage0(
    stack: *const usize,
    rtld_ehdr: *const ElfHeader,
    rtld_dynamic: *const usize,
) -> Stage0 {
    let argc = unsafe { read_usize(stack) };
    let argv = unsafe { stack.add(1) as *const *const u8 };

    let envp_start = unsafe { stack.add(argc.wrapping_add(2)) };
    let mut envp = envp_start;
    while unsafe { read_usize(envp) } != 0 {
        envp = unsafe { envp.add(1) };
    }

    let auxv = unsafe { envp.add(1) };
    let aux = unsafe { parse_auxv(auxv) };
    let main_load_bias = main_load_bias(aux);
    let main_dynamic = main_dynamic(aux, main_load_bias);
    let direct_invocation = aux.base == 0 || main_dynamic == rtld_dynamic;
    let rtld_load_bias = rtld_ehdr as usize;

    let Some(rtld_relocs) = (unsafe { Relocs::parse(rtld_dynamic) }) else {
        exit(RTLD_FATAL_EXIT_STATUS);
    };
    if !unsafe { rtld_relocs.apply(rtld_load_bias) } {
        exit(RTLD_FATAL_EXIT_STATUS);
    }

    Stage0 {
        stack,
        argc,
        argv,
        envp: envp_start as *const *const u8,
        auxv,
        aux,
        main_load_bias,
        main_dynamic,
        rtld_load_bias,
        rtld_dynamic,
        direct_invocation,
    }
}

unsafe fn parse_auxv(mut auxp: *const usize) -> AuxState {
    let mut aux = AuxState::empty();
    loop {
        let kind = unsafe { read_usize(auxp) };
        let value = unsafe { read_usize(auxp.add(1)) };
        auxp = unsafe { auxp.add(2) };
        match kind {
            AT_NULL => return aux,
            AT_PHDR => aux.phdr = value,
            AT_PHENT => aux.phent = value,
            AT_PHNUM => aux.phnum = value,
            AT_BASE => aux.base = value,
            AT_ENTRY => aux.entry = value,
            AT_SECURE => aux.secure = value,
            AT_PAGESZ => aux.pagesize = value,
            AT_PLATFORM => aux.platform = value,
            AT_HWCAP => aux.hwcap = value,
            AT_HWCAP2 => aux.hwcap2 = value,
            AT_HWCAP3 => aux.hwcap3 = value,
            AT_HWCAP4 => aux.hwcap4 = value,
            AT_CLKTCK => aux.clktck = value,
            AT_FPUCW => aux.fpucw = value,
            AT_MINSIGSTKSZ => aux.minsigstacksize = value,
            AT_SYSINFO_EHDR => aux.sysinfo_ehdr = value,
            _ => {}
        }
    }
}

fn main_load_bias(aux: AuxState) -> usize {
    aux.find_phdr(ElfProgramType::PHDR)
        .map(|phdr| aux.phdr.wrapping_sub(phdr.p_vaddr().get()))
        .unwrap_or(0)
}

fn main_dynamic(aux: AuxState, load_bias: usize) -> *const usize {
    aux.find_phdr(ElfProgramType::DYNAMIC)
        .map(|phdr| load_bias.wrapping_add(phdr.p_vaddr().get()) as *const usize)
        .unwrap_or(null())
}

#[derive(Copy, Clone)]
enum Relocs {
    Rela(RelocTable),
    Relr(RelocTable),
}

#[derive(Copy, Clone)]
struct RelocTable {
    offset: usize,
    size: usize,
    entry_size: usize,
}

impl RelocTable {
    const fn empty(entry_size: usize) -> Self {
        Self {
            offset: 0,
            size: 0,
            entry_size,
        }
    }

    fn is_empty(self) -> bool {
        self.size == 0
    }

    fn validate<T>(self) -> Option<Self> {
        let entry_size = core::mem::size_of::<T>();
        if self.is_empty() {
            return Some(Self { entry_size, ..self });
        }
        if self.offset == 0 || self.entry_size != entry_size || self.size % self.entry_size != 0 {
            return None;
        }
        Some(self)
    }

    fn len(self) -> usize {
        self.size / self.entry_size
    }
}

impl Relocs {
    fn new(rela: RelocTable, relr: RelocTable) -> Option<Self> {
        let rela = rela.validate::<ElfRelType>()?;
        let relr = relr.validate::<ElfRelr>()?;
        match (!rela.is_empty(), !relr.is_empty()) {
            (false, false) => None,
            (true, false) => Some(Self::Rela(rela)),
            (false, true) => Some(Self::Relr(relr)),
            (true, true) => None,
        }
    }

    unsafe fn parse(dynamic: *const usize) -> Option<Self> {
        if dynamic.is_null() {
            return None;
        }
        let dynamic = dynamic.cast::<ElfDyn>();
        let mut rela = RelocTable::empty(core::mem::size_of::<ElfRelType>());
        let mut relr = RelocTable::empty(core::mem::size_of::<ElfRelr>());
        let mut index = 0usize;
        while index < 4096 {
            let entry = unsafe { core::ptr::read_unaligned(dynamic.add(index)) };
            let tag = entry.tag();
            let value = entry.value();
            if tag == ElfDynamicTag::NULL {
                return Self::new(rela, relr);
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
            }
            index = index.wrapping_add(1);
        }

        None
    }

    unsafe fn apply(self, load_bias: usize) -> bool {
        match self {
            Self::Rela(table) => unsafe { apply_relocations(table, load_bias) },
            Self::Relr(table) => unsafe { apply_relr_relocations(table, load_bias) },
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
const NATIVE_RELOCATION_TAG: ElfDynamicTag = ElfDynamicTag::REL;
#[cfg(all(not(target_arch = "x86"), not(target_arch = "arm")))]
const NATIVE_RELOCATION_TAG: ElfDynamicTag = ElfDynamicTag::RELA;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
const NATIVE_RELOCATION_SIZE_TAG: ElfDynamicTag = ElfDynamicTag::RELSZ;
#[cfg(all(not(target_arch = "x86"), not(target_arch = "arm")))]
const NATIVE_RELOCATION_SIZE_TAG: ElfDynamicTag = ElfDynamicTag::RELASZ;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
const NATIVE_RELOCATION_ENTRY_SIZE_TAG: ElfDynamicTag = ElfDynamicTag::RELENT;
#[cfg(all(not(target_arch = "x86"), not(target_arch = "arm")))]
const NATIVE_RELOCATION_ENTRY_SIZE_TAG: ElfDynamicTag = ElfDynamicTag::RELAENT;

pub(super) unsafe fn can_tail_jump_main(dynamic: *const usize) -> bool {
    if dynamic.is_null() {
        return true;
    }

    let dynamic = dynamic.cast::<ElfDyn>();
    let mut rela = RelocTable::empty(core::mem::size_of::<ElfRelType>());
    let mut relr = RelocTable::empty(core::mem::size_of::<ElfRelr>());
    let mut index = 0usize;
    while index < 4096 {
        let entry = unsafe { core::ptr::read_unaligned(dynamic.add(index)) };
        let tag = entry.tag();
        let value = entry.value();
        if tag == ElfDynamicTag::NULL {
            return rela
                .validate::<ElfRelType>()
                .zip(relr.validate::<ElfRelr>())
                .is_some_and(|(rela, relr)| rela.is_empty() && relr.is_empty());
        } else if tag == ElfDynamicTag::NEEDED {
            return false;
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
        } else if (tag == ElfDynamicTag::JMPREL || tag == ElfDynamicTag::PLTRELSZ) && value != 0 {
            return false;
        }
        index = index.wrapping_add(1);
    }

    false
}

#[derive(Copy, Clone)]
struct BootstrapMemory {
    load_bias: usize,
}

impl BootstrapMemory {
    const fn new(load_bias: usize) -> Self {
        Self { load_bias }
    }
}

impl ImageMemory for BootstrapMemory {
    fn base(&self) -> VmAddr {
        VmAddr::new(self.load_bias)
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

unsafe fn apply_relocations(table: RelocTable, load_bias: usize) -> bool {
    if table.is_empty() {
        return true;
    }

    let relocations = unsafe {
        core::slice::from_raw_parts(
            load_bias.wrapping_add(table.offset) as *const ElfRelType,
            table.len(),
        )
    };
    let memory = BootstrapMemory::new(load_bias);
    for relative in relocations.split(|rel| rel.r_type() == NativeArch::NONE) {
        if relative.is_empty() {
            continue;
        }
        if !relative
            .iter()
            .all(|rel| rel.r_type() == NativeArch::RELATIVE)
        {
            return false;
        }
        if relocate_relative::<NativeArch, _>(relative, &memory).is_err() {
            return false;
        }
    }
    true
}

unsafe fn apply_relr_relocations(table: RelocTable, load_bias: usize) -> bool {
    if table.is_empty() {
        return true;
    }

    let entries = unsafe {
        core::slice::from_raw_parts(
            load_bias.wrapping_add(table.offset) as *const ElfRelr,
            table.len(),
        )
    };
    relocate_relr(entries, &BootstrapMemory::new(load_bias)).is_ok()
}
