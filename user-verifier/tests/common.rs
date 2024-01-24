use serde::Serialize;

pub fn to_bytes<T: Serialize>(structure: T) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &structure).map(|_| bytes)
}
