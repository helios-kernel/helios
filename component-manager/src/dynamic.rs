//! Opt-in dynamic component subtree lifecycle (`--features dynamic-components`).
//!
//! Strictly bounded by a designated parent realm (`dynamic_mount = true`) and
//! its [`crate::model::CapabilityCeiling`] + [`crate::model::OomTier`]. Never
//! compiled into default `component-manager` binaries.

use std::collections::BTreeMap;
use std::path::Path;

use crate::manifest::{
    ManifestError, load_dynamic_subtree_from_dir, load_dynamic_subtree_from_map,
};
use crate::supervisor::{Supervisor, SupervisorError, SupervisorRuntime};

/// Why mounting a dynamic component subtree failed.
#[derive(Debug, thiserror::Error)]
pub enum DynamicMountError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Supervisor(#[from] SupervisorError),
}

impl<R: SupervisorRuntime> Supervisor<R> {
    /// Parses, validates, and mounts a dynamic `component.toml` directory tree under
    /// `parent_moniker`.
    ///
    /// Rejects mounting if `parent_moniker` does not exist, lacks `dynamic_mount = true`,
    /// contains unknown TOML fields, has routing cycles, or requests any capability or
    /// `oom_tier` exceeding `parent_moniker`'s ceiling.
    pub async fn mount_dynamic_dir(
        &mut self,
        parent_moniker: &str,
        subtree_name: &str,
        dir: &Path,
    ) -> Result<String, DynamicMountError> {
        let parent = self
            .node_by_moniker(parent_moniker)
            .ok_or_else(|| SupervisorError::UnknownComponent {
                moniker: parent_moniker.to_owned(),
            })?
            .clone();
        let subtree = load_dynamic_subtree_from_dir(&parent, subtree_name, dir)?;
        Ok(self
            .mount_validated_dynamic_subtree(parent_moniker, subtree)
            .await?)
    }

    /// Parses, validates, and mounts an in-memory `moniker -> component.toml` dynamic
    /// subtree strictly bounded by `parent_moniker`'s capability ceiling.
    pub async fn mount_dynamic_map(
        &mut self,
        parent_moniker: &str,
        entries: BTreeMap<String, String>,
    ) -> Result<String, DynamicMountError> {
        let parent = self
            .node_by_moniker(parent_moniker)
            .ok_or_else(|| SupervisorError::UnknownComponent {
                moniker: parent_moniker.to_owned(),
            })?
            .clone();
        let subtree = load_dynamic_subtree_from_map(&parent, entries)?;
        Ok(self
            .mount_validated_dynamic_subtree(parent_moniker, subtree)
            .await?)
    }

    /// Gracefully stops and unmounts a previously mounted dynamic subtree.
    pub async fn unmount_dynamic(
        &mut self,
        subtree_root_moniker: &str,
    ) -> Result<(), SupervisorError> {
        self.unmount_dynamic_subtree_by_moniker(subtree_root_moniker)
            .await
    }
}
