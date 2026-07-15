//! Serializes registry access while allowing same-thread reentry.

use super::manager::{FileIdentity, Manager};
use alloc::{collections::BTreeMap, string::String};
use core::cell::{Ref, RefCell, RefMut};

#[derive(Default)]
pub(super) struct IdentityIndex {
    committed: BTreeMap<FileIdentity, String>,
}

impl IdentityIndex {
    #[inline]
    pub(super) fn find(&self, identity: FileIdentity) -> Option<String> {
        self.committed.get(&identity).cloned()
    }

    #[inline]
    pub(super) fn insert(&mut self, identity: FileIdentity, name: String) {
        self.committed.insert(identity, name);
    }

    #[inline]
    pub(super) fn remove(&mut self, identity: FileIdentity) {
        self.committed.remove(&identity);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct IdentityLookup<'a> {
    index: &'a RefCell<IdentityIndex>,
}

impl IdentityLookup<'_> {
    #[inline]
    pub(crate) fn find(self, identity: FileIdentity) -> Option<String> {
        self.index.borrow().find(identity)
    }
}

#[cfg(feature = "std")]
mod imp {
    use std::{
        marker::PhantomData,
        rc::Rc,
        sync::{Condvar, Mutex, MutexGuard},
        thread::{self, ThreadId},
    };

    #[derive(Default)]
    struct LockState {
        owner: Option<ThreadId>,
        depth: usize,
    }

    pub(super) struct LoaderLock {
        state: Mutex<LockState>,
        available: Condvar,
    }

    impl LoaderLock {
        pub(super) fn new() -> Self {
            Self {
                state: Mutex::new(LockState::default()),
                available: Condvar::new(),
            }
        }

        fn lock_state(&self) -> MutexGuard<'_, LockState> {
            self.state.lock().unwrap_or_else(|err| err.into_inner())
        }

        pub(super) fn lock(&self) -> LoaderGuard<'_> {
            let current = thread::current().id();
            let mut state = self.lock_state();
            while state.owner.as_ref().is_some_and(|owner| *owner != current) {
                state = self
                    .available
                    .wait(state)
                    .unwrap_or_else(|err| err.into_inner());
            }
            state.owner = Some(current);
            state.depth = state
                .depth
                .checked_add(1)
                .expect("loader lock recursion overflow");
            LoaderGuard {
                lock: self,
                _not_send: PhantomData,
            }
        }

        fn unlock(&self) {
            let current = thread::current().id();
            let mut state = self.lock_state();
            debug_assert_eq!(state.owner, Some(current));
            state.depth = state
                .depth
                .checked_sub(1)
                .expect("loader lock guard must be balanced");
            if state.depth == 0 {
                state.owner = None;
                self.available.notify_one();
            }
        }
    }

    #[must_use = "the loader lock is released when the guard is dropped"]
    pub(super) struct LoaderGuard<'a> {
        lock: &'a LoaderLock,
        _not_send: PhantomData<Rc<()>>,
    }

    impl Drop for LoaderGuard<'_> {
        fn drop(&mut self) {
            self.lock.unlock();
        }
    }
}

#[cfg(not(feature = "std"))]
mod imp {
    use alloc::rc::Rc;
    use core::{
        marker::PhantomData,
        sync::atomic::{AtomicU32, AtomicUsize, Ordering},
    };

    const FUTEX_WAIT_PRIVATE: usize = 128;
    const FUTEX_WAKE_PRIVATE: usize = 129;

    pub(super) struct LoaderLock {
        owner: AtomicU32,
        depth: AtomicUsize,
    }

    impl LoaderLock {
        pub(super) const fn new() -> Self {
            Self {
                owner: AtomicU32::new(0),
                depth: AtomicUsize::new(0),
            }
        }

        fn current_thread() -> u32 {
            let tid = unsafe { syscalls::raw_syscall!(syscalls::Sysno::gettid) } as u32;
            debug_assert_ne!(tid, 0);
            tid
        }

        fn futex(&self, op: usize, value: usize) {
            let owner = core::ptr::from_ref(&self.owner) as usize;
            let _ = unsafe { syscalls::syscall4(syscalls::Sysno::futex, owner, op, value, 0) };
        }

        pub(super) fn lock(&self) -> LoaderGuard<'_> {
            let current = Self::current_thread();
            loop {
                let owner = self.owner.load(Ordering::Acquire);
                if owner == current {
                    self.depth
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                            depth.checked_add(1)
                        })
                        .expect("loader lock recursion overflow");
                    break;
                }
                if owner == 0
                    && self
                        .owner
                        .compare_exchange(0, current, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                {
                    self.depth.store(1, Ordering::Relaxed);
                    break;
                }
                self.futex(FUTEX_WAIT_PRIVATE, owner as usize);
            }

            LoaderGuard {
                lock: self,
                _not_send: PhantomData,
            }
        }

        fn unlock(&self) {
            let current = Self::current_thread();
            debug_assert_eq!(self.owner.load(Ordering::Relaxed), current);
            let depth = self.depth.fetch_sub(1, Ordering::Release);
            debug_assert_ne!(depth, 0);
            if depth == 1 {
                self.owner.store(0, Ordering::Release);
                self.futex(FUTEX_WAKE_PRIVATE, 1);
            }
        }
    }

    #[must_use = "the loader lock is released when the guard is dropped"]
    pub(super) struct LoaderGuard<'a> {
        lock: &'a LoaderLock,
        _not_send: PhantomData<Rc<()>>,
    }

    impl Drop for LoaderGuard<'_> {
        fn drop(&mut self) {
            self.lock.unlock();
        }
    }
}

use imp::{LoaderGuard, LoaderLock};

/// Process-wide dynamic-loader registry.
pub(crate) struct Registry {
    loader: LoaderLock,
    manager: RefCell<Manager>,
    identities: RefCell<IdentityIndex>,
}

// SAFETY: `loader` serializes access to the registry state across threads on both std and no_std
// builds. Same-thread reentry is allowed, while each `RefCell` checks its own nested borrows.
unsafe impl Sync for Registry {}

#[must_use = "the registry lock is released when the guard is dropped"]
pub(crate) struct RegistryGuard<'a> {
    _loader: LoaderGuard<'a>,
    manager: &'a RefCell<Manager>,
    identities: &'a RefCell<IdentityIndex>,
}

impl Registry {
    pub(super) fn new(manager: Manager) -> Self {
        Self {
            loader: LoaderLock::new(),
            manager: RefCell::new(manager),
            identities: RefCell::new(IdentityIndex::default()),
        }
    }

    #[inline]
    pub(crate) fn lock(&self) -> RegistryGuard<'_> {
        RegistryGuard {
            _loader: self.loader.lock(),
            manager: &self.manager,
            identities: &self.identities,
        }
    }
}

impl RegistryGuard<'_> {
    #[inline]
    #[track_caller]
    pub(crate) fn borrow(&self) -> Ref<'_, Manager> {
        self.manager.borrow()
    }

    #[inline]
    #[track_caller]
    pub(crate) fn borrow_mut(&self) -> RefMut<'_, Manager> {
        self.manager.borrow_mut()
    }

    #[inline]
    pub(crate) fn identity_lookup(&self) -> IdentityLookup<'_> {
        IdentityLookup {
            index: self.identities,
        }
    }

    #[inline]
    #[track_caller]
    pub(super) fn identities_mut(&self) -> RefMut<'_, IdentityIndex> {
        self.identities.borrow_mut()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::super::REGISTRY;
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn loader_lock_is_reentrant_and_serializes_threads() {
        let outer = REGISTRY.lock();
        let inner = REGISTRY.lock();
        drop(inner);

        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _guard = REGISTRY.lock();
            acquired_tx.send(Instant::now()).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(
            acquired_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "another thread acquired the loader lock while it was held"
        );
        let released_at = Instant::now();
        drop(outer);

        let acquired_at = acquired_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(acquired_at >= released_at);
        worker.join().unwrap();
    }
}
