//! A game's data files, as the player writes them under PeerParty's folder or a game data
//! source serves them: their shapes, bounds and checks, in one place for the hook, which
//! reads them, and the launcher, which checks what it fetches for the hook's cache
//! (launcher/src/sources.rs) before keeping it.
//!
//! - `patterns`: a module's curl patterns file (`patterns\<module>.json`).
//! - `rallyhere`: a game's RallyHere `config.json` and its harvested files
//!   (`rallyhere\<exe stem>\harvested\*.json`).
//!
//! The files are untrusted: read with `json`'s parser (its depth limit) and refused whole
//! on any wrong type or bound.

pub mod patterns;
pub mod rallyhere;
