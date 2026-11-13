//! Core domain model for Via.
//!
//! This crate is the shared vocabulary every other Via crate speaks. It holds
//! types and validation only: no I/O, no async runtime, no Docker, no
//! transport. That keeps the dependency graph one-directional.
//!
//! ```text
//! via-core
//!    ├── via-compose    what `docker compose config` says -> core::Deployment
//!    ├── via-bundle     a compose file, its files and images <-> bundle file
//!    └── via-runtime    `docker compose up`, and reading what it started
//! ```
//!
//! A [`Deployment`] describes a release for people and for the health gate.
//! What runs is the compose file, under the official `docker compose`.

mod deployment;
mod digest;
mod error;
mod id;
mod platform;
mod release;
pub mod settings;

pub use deployment::{
    DEPLOYMENT_SCHEMA_VERSION, Dependency, DependencyCondition, Deployment, HealthCheck,
    HealthGate, ImageRef, Mount, Network, OLDEST_DEPLOYMENT_SCHEMA, PortMapping, Protocol,
    Readiness, RestartPolicy, Service, VariableSpec, Volume,
};
pub use digest::Digest;
pub use error::Error;
pub use id::{AppName, DeviceId, ReleaseId, ServiceName};
pub use platform::Platform;
pub use release::{ArtifactRef, ReleaseRef, ReleaseTarget};

/// The labels `docker compose` puts on what it creates.
pub const LABEL_PROJECT: &str = "com.docker.compose.project";
pub const LABEL_SERVICE: &str = "com.docker.compose.service";
pub const LABEL_ONE_OFF: &str = "com.docker.compose.oneoff";

/// The label on containers made before viaos ran Compose. See `via_runtime`.
pub const LABEL_LEGACY_PROJECT: &str = "via.project";

/// The `docker` to run. A build of `via` and of the OS each set `VIA_DOCKER` to
/// the same pinned package, so a file reads the same on both.
pub fn docker_program() -> std::ffi::OsString {
    std::env::var_os("VIA_DOCKER").unwrap_or_else(|| "docker".into())
}
