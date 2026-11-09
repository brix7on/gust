use crate::services;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

fn nn<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    pub selected: String,
    pub game_filter: bool,
    pub auto_retune: bool,
    pub extra_strategies: bool,
    pub auto_start_bypass: bool,
    #[serde(deserialize_with = "nn")]
    pub groups: HashMap<String, bool>,
    pub zapret_version: String,
    pub tg_secret: String,
    pub discord_direct: bool,
    pub tg_enabled: bool,
    pub last_tune: i64,
    pub lang: String,
    pub engine: String,
    pub engine_picked: bool,
    #[serde(deserialize_with = "nn")]
    pub added_hosts: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            selected: String::new(),
            game_filter: false,
            auto_retune: true,
            extra_strategies: true,
            auto_start_bypass: true,
            groups: services::fill_groups(HashMap::new()),
            zapret_version: String::new(),
            tg_secret: String::new(),
            discord_direct: false,
            tg_enabled: false,
            last_tune: 0,
            lang: "auto".into(),
            engine: "gust".into(),
            engine_picked: false,
            added_hosts: Vec::new(),
        }
    }
}
