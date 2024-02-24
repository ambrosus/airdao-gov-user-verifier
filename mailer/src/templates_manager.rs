use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct TemplatesManagerConfig {
    #[serde(flatten)]
    pub templates: HashMap<String, String>,
}

pub struct TemplatesManager {
    pub templates: HashMap<String, String>,
}

impl TemplatesManager {
    pub async fn new(config: TemplatesManagerConfig) -> anyhow::Result<Self> {
        let mut templates = HashMap::new();

        for (template, path) in &config.templates {
            let content = tokio::fs::read_to_string(path).await.map_err(|e| {
                anyhow::anyhow!("Failed to read `{template}` (path: `{path}`) content. Error: {e}")
            })?;

            templates.insert(template.clone(), content);
        }

        Ok(Self { templates })
    }
}
