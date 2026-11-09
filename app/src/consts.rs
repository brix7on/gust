pub const NAME: &str = "Gust";
pub const DEFAULT_PORT: u16 = 18765;
pub const VERSION: &str = match option_env!("GUST_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
pub const SELF_REPO: &str = "brix7on/gust";
pub const ZAP_REPO: &str = "Flowseal/zapret-discord-youtube";
pub const TWIN_PREFIX: &str = "Gust · ";
pub const ENGINE_NAME: &str = "gust-engine.exe";
pub const TG_IMAGE: &str = "gust-tg.exe";
pub const OLD_TG_IMAGE: &str = "TgWsProxy_windows.exe";
