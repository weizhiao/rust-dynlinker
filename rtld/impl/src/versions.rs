use core::arch::global_asm;

global_asm!(
    r#"
    .symver __libc_stack_end, __libc_stack_end@@GLIBC_2.2.5, remove
    .symver _dl_debug_state, _dl_debug_state@@GLIBC_2.2.5, remove
    .symver _r_debug, _r_debug@@GLIBC_2.2.5, remove

    .section .text,"ax",@progbits
    .globl __rtld_dlopen_glibc_2_2_5
    .type __rtld_dlopen_glibc_2_2_5,@function
__rtld_dlopen_glibc_2_2_5:
    jmp dlopen
    .size __rtld_dlopen_glibc_2_2_5, . - __rtld_dlopen_glibc_2_2_5

    .globl __rtld_dlsym_glibc_2_2_5
    .type __rtld_dlsym_glibc_2_2_5,@function
__rtld_dlsym_glibc_2_2_5:
    jmp dlsym
    .size __rtld_dlsym_glibc_2_2_5, . - __rtld_dlsym_glibc_2_2_5

    .globl __rtld_dlclose_glibc_2_2_5
    .type __rtld_dlclose_glibc_2_2_5,@function
__rtld_dlclose_glibc_2_2_5:
    jmp dlclose
    .size __rtld_dlclose_glibc_2_2_5, . - __rtld_dlclose_glibc_2_2_5

    .globl __rtld_dlerror_glibc_2_2_5
    .type __rtld_dlerror_glibc_2_2_5,@function
__rtld_dlerror_glibc_2_2_5:
    jmp dlerror
    .size __rtld_dlerror_glibc_2_2_5, . - __rtld_dlerror_glibc_2_2_5

    .symver __rtld_dlopen_glibc_2_2_5, dlopen@GLIBC_2.2.5, remove
    .symver __rtld_dlsym_glibc_2_2_5, dlsym@GLIBC_2.2.5, remove
    .symver __rtld_dlclose_glibc_2_2_5, dlclose@GLIBC_2.2.5, remove
    .symver __rtld_dlerror_glibc_2_2_5, dlerror@GLIBC_2.2.5, remove

    .symver __tls_get_addr, __tls_get_addr@@GLIBC_2.3, remove

    .symver __rtld_version_placeholder, __rtld_version_placeholder@@GLIBC_2.34, remove

    .globl __rtld_dlopen_glibc_2_34
    .type __rtld_dlopen_glibc_2_34,@function
__rtld_dlopen_glibc_2_34:
    jmp dlopen
    .size __rtld_dlopen_glibc_2_34, . - __rtld_dlopen_glibc_2_34

    .globl __rtld_dlsym_glibc_2_34
    .type __rtld_dlsym_glibc_2_34,@function
__rtld_dlsym_glibc_2_34:
    jmp dlsym
    .size __rtld_dlsym_glibc_2_34, . - __rtld_dlsym_glibc_2_34

    .globl __rtld_dlclose_glibc_2_34
    .type __rtld_dlclose_glibc_2_34,@function
__rtld_dlclose_glibc_2_34:
    jmp dlclose
    .size __rtld_dlclose_glibc_2_34, . - __rtld_dlclose_glibc_2_34

    .globl __rtld_dlerror_glibc_2_34
    .type __rtld_dlerror_glibc_2_34,@function
__rtld_dlerror_glibc_2_34:
    jmp dlerror
    .size __rtld_dlerror_glibc_2_34, . - __rtld_dlerror_glibc_2_34

    .symver __rtld_dlopen_glibc_2_34, dlopen@GLIBC_2.34, remove
    .symver __rtld_dlsym_glibc_2_34, dlsym@GLIBC_2.34, remove
    .symver __rtld_dlclose_glibc_2_34, dlclose@GLIBC_2.34, remove
    .symver __rtld_dlerror_glibc_2_34, dlerror@GLIBC_2.34, remove

    .symver _dl_find_object, _dl_find_object@@GLIBC_2.35, remove
    .symver __rseq_flags, __rseq_flags@@GLIBC_2.35, remove
    .symver __rseq_offset, __rseq_offset@@GLIBC_2.35, remove
    .symver __rseq_size, __rseq_size@@GLIBC_2.35, remove

    .symver _dl_argv, _dl_argv@@GLIBC_PRIVATE, remove
    .symver _dl_find_dso_for_object, _dl_find_dso_for_object@@GLIBC_PRIVATE, remove
    .symver __libc_enable_secure, __libc_enable_secure@@GLIBC_PRIVATE, remove
    .symver _dl_deallocate_tls, _dl_deallocate_tls@@GLIBC_PRIVATE, remove
    .symver _rtld_global_ro, _rtld_global_ro@@GLIBC_PRIVATE, remove
    .symver _dl_signal_error, _dl_signal_error@@GLIBC_PRIVATE, remove
    .symver _dl_signal_exception, _dl_signal_exception@@GLIBC_PRIVATE, remove
    .symver _dl_audit_symbind_alt, _dl_audit_symbind_alt@@GLIBC_PRIVATE, remove
    .symver __tunable_is_initialized, __tunable_is_initialized@@GLIBC_PRIVATE, remove
    .symver _dl_rtld_di_serinfo, _dl_rtld_di_serinfo@@GLIBC_PRIVATE, remove
    .symver _dl_allocate_tls, _dl_allocate_tls@@GLIBC_PRIVATE, remove
    .symver __tunable_get_val, __tunable_get_val@@GLIBC_PRIVATE, remove
    .symver _dl_catch_exception, _dl_catch_exception@@GLIBC_PRIVATE, remove
    .symver _dl_allocate_tls_init, _dl_allocate_tls_init@@GLIBC_PRIVATE, remove
    .symver _rtld_global, _rtld_global@@GLIBC_PRIVATE, remove
    .symver __nptl_change_stack_perm, __nptl_change_stack_perm@@GLIBC_PRIVATE, remove
    .symver _dl_audit_preinit, _dl_audit_preinit@@GLIBC_PRIVATE, remove
    .symver _dl_exception_free, _dl_exception_free@@GLIBC_PRIVATE, remove
    .symver _dl_exception_create, _dl_exception_create@@GLIBC_PRIVATE, remove
    .symver _dl_exception_create_format, _dl_exception_create_format@@GLIBC_PRIVATE, remove
    .symver _dl_fatal_printf, _dl_fatal_printf@@GLIBC_PRIVATE, remove
    .symver _dl_get_tls_static_info, _dl_get_tls_static_info@@GLIBC_PRIVATE, remove
    .symver _dl_x86_get_cpu_features, _dl_x86_get_cpu_features@@GLIBC_PRIVATE, remove
"#
);
