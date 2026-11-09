use serde::Serialize;

#[derive(Serialize, Clone, Default)]
pub struct SetupState {
    pub busy: bool,
    pub msg: String,
    pub err: String,
}

#[derive(Serialize, Clone, Default, Debug)]
pub struct TuneResult {
    pub strategy: String,
    pub passed: usize,
    pub total: usize,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Serialize, Clone, Default)]
pub struct TuneState {
    pub running: bool,
    pub scope: String,
    pub idx: usize,
    pub total: usize,
    pub current: String,
    pub msg: String,
    pub results: Vec<TuneResult>,
}

#[derive(Serialize, Clone, Default)]
pub struct CheckResult {
    pub group: String,
    pub name: String,
    pub ok: bool,
    pub ms: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub err: String,
}

#[derive(Serialize, Clone, Default)]
pub struct CheckState {
    pub running: bool,
    pub at: i64,
    pub internet: bool,
    pub results: Vec<CheckResult>,
}
