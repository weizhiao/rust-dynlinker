mod publish;
mod self_reloc;
mod stack;
mod startup;

use crate::globals::{publish_rseq_offset, publish_tls_static_info};
use crate::runtime::{RTLD_FATAL_EXIT_STATUS, exit, write_stderr};
use core::fmt::{self, Write};
use dlopen_rs::rtld::elf::ElfHeader;

#[unsafe(no_mangle)]
pub extern "C" fn rtld_bootstrap(
    stack: *const usize,
    rtld_ehdr: *const ElfHeader,
    rtld_dynamic: *const usize,
) -> usize {
    let input = startup::StartupInput::new(stack, rtld_ehdr, rtld_dynamic);
    if let Some(entry) = input.pass_through_entry() {
        return entry;
    }
    match startup::run(&input) {
        Ok(entry) => entry,
        Err(error) => {
            let prefix = if input.is_direct() {
                b"rtld: direct exec failed: ".as_slice()
            } else {
                b"rtld: startup failed: ".as_slice()
            };
            write_stderr(prefix);
            let _ = write!(StderrWriter, "{error}");
            write_stderr(b"\n");
            exit(RTLD_FATAL_EXIT_STATUS);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rtld_fini() {
    dlopen_rs::rtld::finalize_startup();
}

pub(super) fn publish_tls_layout() {
    let (size, align) = crate::tls::static_info();
    unsafe {
        publish_tls_static_info(size, align);
        publish_rseq_offset(crate::tls::rseq_offset());
    }
}

struct StderrWriter;

impl Write for StderrWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        write_stderr(value.as_bytes());
        Ok(())
    }
}
