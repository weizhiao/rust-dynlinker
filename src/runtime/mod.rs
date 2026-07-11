pub(crate) mod debug;
mod state;

pub(crate) use state::{ARGC, ARGV, ENVP};

#[cfg(feature = "std")]
mod host;
#[cfg(not(feature = "std"))]
pub mod rtld;
