use super::stage0::{Stage0, can_tail_jump_main};
use crate::runtime::{RTLD_FATAL_EXIT_STATUS, exit, write_stderr};
use core::fmt::{self, Write};

pub(super) enum Stage1Failure {
    DirectExec(dlopen_rs::Error),
    KernelMappedMain(dlopen_rs::Error),
}

pub(super) fn stage2(stage0: &Stage0, failure: Stage1Failure) -> usize {
    match failure {
        Stage1Failure::DirectExec(err) => {
            write_stage1_error(b"rtld: direct exec failed: ", &err);
            exit(RTLD_FATAL_EXIT_STATUS);
        }
        Stage1Failure::KernelMappedMain(err) => {
            if stage0.aux.entry != 0 && unsafe { can_tail_jump_main(stage0.main_dynamic) } {
                return stage0.aux.entry;
            }

            write_stage1_error(b"rtld: stage-1 failed: ", &err);
            exit(RTLD_FATAL_EXIT_STATUS);
        }
    }
}

struct StderrWriter;

impl Write for StderrWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_stderr(s.as_bytes());
        Ok(())
    }
}

fn write_stage1_error(prefix: &[u8], err: &dlopen_rs::Error) {
    write_stderr(prefix);
    let _ = write!(StderrWriter, "{err}");
    write_stderr(b"\n");
}
