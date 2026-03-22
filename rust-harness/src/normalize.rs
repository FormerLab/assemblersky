use serde::Serialize;

#[derive(Serialize)]
pub struct NormalizedRecord {
    #[serde(rename = "$type")]
    pub r#type: String,
    pub text: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_at: String,
}

#[derive(Serialize)]
pub struct NormalizedEvent {
    pub kind: String,
    pub op: String,
    pub collection: String,
    pub seq: u64,
    pub repo: String,
    pub rev: String,
    pub rkey: String,
    pub record: NormalizedRecord,
}
