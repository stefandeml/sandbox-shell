//! # sx - Lightweight sandbox for macOS development
//!
//! `sx` wraps shell sessions and commands in macOS Seatbelt sandboxes,
//! restricting filesystem and network access to protect the user's system.
//!
//! ## Library Usage
//!
//! Add `sx` as a dependency with default features disabled:
//!
//! ```toml
//! [dependencies]
//! sx = { version = "0.2", default-features = false }
//! ```
//!
//! Then use the [`Sandbox`] builder to configure and execute sandboxed commands:
//!
//! ```no_run
//! use sx::{Sandbox, NetworkMode};
//!
//! // Run a command in a restricted sandbox
//! let result = Sandbox::new("/path/to/workdir")
//!     .network(NetworkMode::Offline)
//!     .allow_read("/usr")
//!     .allow_read("/bin")
//!     .deny_read("/home/user/.ssh")
//!     .profile("rust")
//!     .execute(&["cargo", "build"])
//!     .unwrap();
//!
//! assert_eq!(result.exit_code, 0);
//! ```
//!
//! For capturing output programmatically:
//!
//! ```no_run
//! use sx::Sandbox;
//!
//! let (status, stdout, stderr) = Sandbox::new("/tmp/workdir")
//!     .allow_read("/usr")
//!     .execute_captured(&["echo", "hello"])
//!     .unwrap();
//!
//! let output = String::from_utf8_lossy(&stdout);
//! ```
//!
//! ## Generating Profiles Without Executing
//!
//! ```no_run
//! use sx::{Sandbox, NetworkMode};
//!
//! let profile = Sandbox::new("/path/to/workdir")
//!     .network(NetworkMode::Localhost)
//!     .allow_read("/usr")
//!     .generate_profile()
//!     .unwrap();
//!
//! println!("{}", profile); // Seatbelt profile string
//! ```

#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
pub mod detection;
pub mod sandbox;
pub mod shell;
pub mod utils;

// Public re-exports for library consumers
pub use config::schema::NetworkMode;
pub use sandbox::builder::Sandbox;
pub use sandbox::executor::{ExecutionError, ExecutionResult};
pub use sandbox::seatbelt::{SandboxParams, SeatbeltError};

#[cfg(feature = "cli")]
use anyhow::Result;
#[cfg(feature = "cli")]
use cli::args::Args;

#[cfg(feature = "cli")]
pub fn run() -> Result<()> {
    let args = Args::parse_args();

    if args.init {
        return cli::commands::init_config();
    }

    if args.explain {
        return cli::commands::explain(&args);
    }

    if args.dry_run {
        return cli::commands::dry_run(&args);
    }

    cli::commands::execute(&args)
}
