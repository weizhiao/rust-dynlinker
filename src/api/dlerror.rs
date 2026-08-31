use alloc::{ffi::CString, string::ToString};
use core::{ffi::c_char, fmt::Display, ptr::null_mut};

struct DlErrorState {
    pending: Option<CString>,
    returned: Option<CString>,
}

impl DlErrorState {
    #[cfg(feature = "std")]
    const fn new() -> Self {
        Self {
            pending: None,
            returned: None,
        }
    }

    fn with_error(error: CString) -> Self {
        Self {
            pending: Some(error),
            returned: None,
        }
    }

    fn take(&mut self) -> *mut c_char {
        self.returned = self.pending.take();
        self.returned
            .as_ref()
            .map_or(null_mut(), |error| error.as_ptr().cast_mut())
    }
}

fn error_message(error: impl Display) -> CString {
    let mut bytes = error.to_string().into_bytes();
    for byte in &mut bytes {
        if *byte == 0 {
            *byte = b'?';
        }
    }
    CString::new(bytes).expect("interior NUL bytes were replaced")
}

#[cfg(feature = "std")]
mod state {
    use super::{DlErrorState, error_message};
    use core::{cell::RefCell, ffi::c_char, fmt::Display};

    std::thread_local! {
        static DLERROR: RefCell<DlErrorState> = const { RefCell::new(DlErrorState::new()) };
    }

    pub(super) fn clear() {
        DLERROR.with(|state| *state.borrow_mut() = DlErrorState::new());
    }

    pub(super) fn set(error: impl Display) {
        let error = error_message(error);
        DLERROR.with(|state| *state.borrow_mut() = DlErrorState::with_error(error));
    }

    pub(super) fn take() -> *mut c_char {
        DLERROR.with(|state| state.borrow_mut().take())
    }
}

#[cfg(not(feature = "std"))]
mod state {
    use super::{DlErrorState, error_message};
    use alloc::collections::BTreeMap;
    use core::{ffi::c_char, fmt::Display, ptr::null_mut};
    use elf_loader::tls::DefaultTlsResolver;
    use spin::Mutex;

    static DLERROR: Mutex<BTreeMap<usize, DlErrorState>> = Mutex::new(BTreeMap::new());

    fn thread_key() -> usize {
        DefaultTlsResolver::get_thread_pointer() as usize
    }

    pub(super) fn clear() {
        DLERROR.lock().remove(&thread_key());
    }

    pub(super) fn set(error: impl Display) {
        DLERROR
            .lock()
            .insert(thread_key(), DlErrorState::with_error(error_message(error)));
    }

    pub(super) fn take() -> *mut c_char {
        let key = thread_key();
        let mut errors = DLERROR.lock();
        let Some(state) = errors.get_mut(&key) else {
            return null_mut();
        };
        let error = state.take();
        if error.is_null() {
            errors.remove(&key);
        }
        error
    }
}

pub(crate) fn clear() {
    state::clear();
}

pub(crate) fn set(error: impl Display) {
    state::set(error);
}

/// Returns the most recent dynamic-linking error for the current thread.
///
/// A second call returns null unless another dynamic-linking error occurred.
#[unsafe(no_mangle)]
pub extern "C" fn dlerror() -> *mut c_char {
    state::take()
}
