//! The firmware dashboard (`/d/<key>`, with the bulk view at `/d/<key>/bulk`):
//! a private, read-only view of every donated image and every bulk upload,
//! behind a key of its own (`runtime/dashboard.key`, not the bulk admin key).
//! It never shows addresses, grant tokens or grant notes. The same page runs
//! publicly at `/dashboard` without the operational parts (`public.rs`).

pub mod catalog;
pub mod families;
pub mod http;
pub mod inspect;
pub mod kind;
pub mod public;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;

use crate::bulk::grants;
use crate::config::Config;
use crate::reclassify;
use crate::telegram::backfill;
use crate::telegram::poster::EditQueue;
use catalog::Catalog;

pub struct Dashboard {
    key: String,
    pub catalog: Arc<Catalog>,
    pub backfill: backfill::Status,
    pub reclassify: reclassify::Status,
    pub edits: Arc<EditQueue>,
    pub firmware_dir: PathBuf,
    pub inspector: inspect::Inspector,
    pub public: public::Public,
}

impl Dashboard {
    pub fn open(
        config: &Config,
        catalog: Arc<Catalog>,
        backfill: backfill::Status,
        reclassify: reclassify::Status,
        edits: Arc<EditQueue>,
    ) -> Result<Self> {
        let key = grants::load_or_create_key(&config.dashboard_key_path(), "dashboard", "dashboard-url")?;
        Ok(Self {
            key,
            catalog,
            backfill,
            reclassify,
            edits,
            firmware_dir: config.firmware_dir.clone(),
            inspector: Default::default(),
            public: public::Public::new(config),
        })
    }

    pub fn key_ok(&self, key: &str) -> bool {
        grants::valid_admin_key(key) && grants::ct_eq(key, &self.key)
    }
}
