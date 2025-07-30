use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub virustotal_api_key: Option<String>,
    pub hybrid_analysis_api_key: Option<String>,
    pub malware_bazaar_api_key: Option<String>,
    pub timeout_seconds: u64,
    pub max_retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            virustotal_api_key: None,
            hybrid_analysis_api_key: None,
            malware_bazaar_api_key: None,
            timeout_seconds: 30,
            max_retries: 3,
        }
    }
}

impl Config {
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let mut config = Config::default();
        
        // 从环境变量加载API密钥
        if let Ok(vt_key) = std::env::var("VIRUSTOTAL_API_KEY") {
            config.virustotal_api_key = Some(vt_key);
        }
        
        if let Ok(ha_key) = std::env::var("HYBRID_ANALYSIS_API_KEY") {
            config.hybrid_analysis_api_key = Some(ha_key);
        }
        
        if let Ok(mb_key) = std::env::var("MALWARE_BAZAAR_API_KEY") {
            config.malware_bazaar_api_key = Some(mb_key);
        }
        
        // 如果提供了配置文件路径，从文件加载
        if let Some(path) = config_path {
            if path.exists() {
                let config_content = std::fs::read_to_string(path)
                    .with_context(|| format!("无法读取配置文件: {:?}", path))?;
                
                let file_config: Config = serde_json::from_str(&config_content)
                    .with_context(|| "解析配置文件失败")?;
                
                // 文件中的配置会覆盖环境变量
                if file_config.virustotal_api_key.is_some() {
                    config.virustotal_api_key = file_config.virustotal_api_key;
                }
                if file_config.hybrid_analysis_api_key.is_some() {
                    config.hybrid_analysis_api_key = file_config.hybrid_analysis_api_key;
                }
                if file_config.malware_bazaar_api_key.is_some() {
                    config.malware_bazaar_api_key = file_config.malware_bazaar_api_key;
                }
                
                config.timeout_seconds = file_config.timeout_seconds;
                config.max_retries = file_config.max_retries;
            }
        }
        
        Ok(config)
    }
    
    pub fn save_example_config(path: &Path) -> Result<()> {
        let example_config = Config {
            virustotal_api_key: Some("your_virustotal_api_key_here".to_string()),
            hybrid_analysis_api_key: Some("your_hybrid_analysis_api_key_here".to_string()),
            malware_bazaar_api_key: Some("your_malware_bazaar_api_key_here".to_string()),
            timeout_seconds: 30,
            max_retries: 3,
        };
        
        let config_json = serde_json::to_string_pretty(&example_config)
            .context("序列化配置失败")?;
        
        std::fs::write(path, config_json)
            .with_context(|| format!("无法写入配置文件: {:?}", path))?;
        
        Ok(())
    }
}