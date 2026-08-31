use crate::cli::DirectProgram;
use dlopen_rs::rtld::{
    auxv::{
        AT_BASE, AT_CLKTCK, AT_ENTRY, AT_EXECFN, AT_FPUCW, AT_HWCAP, AT_HWCAP2, AT_HWCAP3,
        AT_HWCAP4, AT_MINSIGSTKSZ, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PLATFORM,
        AT_SECURE, AT_SYSINFO_EHDR,
    },
    elf::{ElfPhdr, ElfProgramType},
};

#[derive(Copy, Clone)]
pub(super) struct AuxValues {
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

impl AuxValues {
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

    pub(super) fn load_bias(self) -> usize {
        self.find_phdr(ElfProgramType::PHDR)
            .map(|phdr| self.phdr.wrapping_sub(phdr.p_vaddr().get()))
            .unwrap_or(0)
    }

    pub(super) fn dynamic(self, load_bias: usize) -> *const usize {
        self.find_phdr(ElfProgramType::DYNAMIC)
            .map(|phdr| load_bias.wrapping_add(phdr.p_vaddr().get()) as *const usize)
            .unwrap_or(core::ptr::null())
    }

    pub(super) fn has_tls(self) -> bool {
        self.find_phdr(ElfProgramType::TLS).is_some()
    }

    fn find_phdr(self, program_type: ElfProgramType) -> Option<ElfPhdr> {
        (0..self.phnum)
            .filter_map(|index| self.phdr_at(index))
            .find(|phdr| phdr.program_type() == program_type)
    }

    fn phdr_at(self, index: usize) -> Option<ElfPhdr> {
        if self.phdr == 0 || self.phent < core::mem::size_of::<ElfPhdr>() {
            return None;
        }
        let offset = index.checked_mul(self.phent)?;
        let ptr = (self.phdr as *const u8)
            .wrapping_add(offset)
            .cast::<ElfPhdr>();
        Some(unsafe { core::ptr::read_unaligned(ptr) })
    }
}

#[derive(Copy, Clone)]
pub(super) struct ProcessStack {
    pub(super) argc: usize,
    pub(super) argv: *const *const u8,
    pub(super) envp: *const *const u8,
    pub(super) auxv: *const usize,
    pub(super) exec_path: *const u8,
}

#[derive(Copy, Clone)]
pub(super) struct InitialStack {
    pub(super) raw: *const usize,
    pub(super) process: ProcessStack,
    pub(super) aux: AuxValues,
}

impl InitialStack {
    pub(super) unsafe fn parse(stack: *const usize) -> Self {
        let argc = unsafe { stack.read() };
        let argv = unsafe { stack.add(1).cast::<*const u8>() };
        let envp = unsafe { stack.add(argc.wrapping_add(2)).cast::<*const u8>() };
        let mut auxv = envp.cast::<usize>();
        while unsafe { auxv.read() } != 0 {
            auxv = unsafe { auxv.add(1) };
        }
        auxv = unsafe { auxv.add(1) };

        Self {
            raw: stack,
            process: ProcessStack {
                argc,
                argv,
                envp,
                auxv,
                exec_path: core::ptr::null(),
            },
            aux: unsafe { parse_auxv(auxv) },
        }
    }

    pub(super) unsafe fn rewrite_for_program(self, direct: DirectProgram) -> ProcessStack {
        let argc = self.process.argc.wrapping_sub(direct.argv_index);
        let src = unsafe { self.raw.add(1 + direct.argv_index) };
        let dst = unsafe { self.raw.add(1).cast_mut() };
        let mut end = self.process.auxv;
        while unsafe { end.read() } != AT_NULL {
            end = unsafe { end.add(2) };
        }
        end = unsafe { end.add(2) };

        let count = (end as usize - src as usize) / core::mem::size_of::<usize>();
        for index in 0..count {
            unsafe { dst.add(index).write(src.add(index).read()) };
        }

        unsafe { self.raw.cast_mut().write(argc) };
        let exec_path = unsafe { dst.read() as *const u8 };
        if !direct.argv0.is_null() {
            unsafe { dst.write(direct.argv0 as usize) };
        }

        let argv = unsafe { self.raw.add(1).cast::<*const u8>() };
        let envp = unsafe { self.raw.add(argc.wrapping_add(2)).cast::<*const u8>() };
        let mut auxv = envp.cast::<usize>();
        while unsafe { auxv.read() } != 0 {
            auxv = unsafe { auxv.add(1) };
        }

        ProcessStack {
            argc,
            argv,
            envp,
            auxv: unsafe { auxv.add(1) },
            exec_path,
        }
    }
}

unsafe fn parse_auxv(mut auxv: *const usize) -> AuxValues {
    let mut aux = AuxValues::empty();
    loop {
        let kind = unsafe { auxv.read() };
        let value = unsafe { auxv.add(1).read() };
        auxv = unsafe { auxv.add(2) };
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

pub(super) unsafe fn patch_auxv(
    mut auxv: *mut usize,
    phdr: usize,
    phnum: usize,
    base: usize,
    entry: usize,
    exec_path: *const u8,
) {
    if auxv.is_null() {
        return;
    }

    loop {
        let kind = unsafe { auxv.read() };
        if kind == AT_NULL {
            return;
        }
        let value = unsafe { auxv.add(1) };
        match kind {
            AT_PHDR => unsafe { value.write(phdr) },
            AT_PHENT => unsafe { value.write(core::mem::size_of::<ElfPhdr>()) },
            AT_PHNUM => unsafe { value.write(phnum) },
            AT_BASE => unsafe { value.write(base) },
            AT_ENTRY => unsafe { value.write(entry) },
            AT_EXECFN => unsafe { value.write(exec_path as usize) },
            _ => {}
        }
        auxv = unsafe { auxv.add(2) };
    }
}
