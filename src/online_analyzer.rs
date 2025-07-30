use anyhow::{Result, Context};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use crate::elf_parser::ElfInfo;
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct OnlineAnalysisResult {
    pub virustotal: Option<VirusTotalResult>,
    pub hybrid_analysis: Option<HybridAnalysisResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VirusTotalResult {
    pub scan_id: Option<String>,
    pub permalink: Option<String>,
    pub positives: u32,
    pub total: u32,
    pub scans: HashMap<String, ScanResult>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub detected: bool,
    pub version: Option<String>,
    pub result: Option<String>,
    pub update: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HybridAnalysisResult {
    pub job_id: Option<String>,
    pub analysis_url: Option<String>,
    pub threat_score: Option<u32>,
    pub verdict: Option<String>,
}

pub struct OnlineAnalyzer {
    client: Client,
    config: Config,
}

impl OnlineAnalyzer {
    pub fn new(config: &Config) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("创建HTTP客户端失败");
        
        Self {
            client,
            config: config.clone(),
        }
    }
    
    pub async fn analyze(&self, elf_info: &ElfInfo) -> Result<OnlineAnalysisResult> {
        let mut result = OnlineAnalysisResult {
            virustotal: None,
            hybrid_analysis: None,
        };
        
        // VirusTotal 分析
        if let Some(ref api_key) = self.config.virustotal_api_key {
            match self.query_virustotal(&elf_info.hashes.sha256, api_key).await {
                Ok(vt_result) => result.virustotal = Some(vt_result),
                Err(e) => eprintln!("VirusTotal查询失败: {}", e),
            }
        }
        
        // Hybrid Analysis 分析
        if let Some(ref api_key) = self.config.hybrid_analysis_api_key {
            match self.query_hybrid_analysis(&elf_info.hashes.sha256, api_key).await {
                Ok(ha_result) => result.hybrid_analysis = Some(ha_result),
                Err(e) => eprintln!("Hybrid Analysis查询失败: {}", e),
            }
        }
        
        Ok(result)
    }
    
    async fn query_virustotal(&self, sha256: &str, api_key: &str) -> Result<VirusTotalResult> {
        let url = format!("https://www.virustotal.com/vtapi/v2/file/report");
        
        let params = [
            ("apikey", api_key),
            ("resource", sha256),
        ];
        
        let response = self.client
            .get(&url)
            .query(&params)
            .send()
            .await
            .context("VirusTotal API请求失败")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("VirusTotal API返回错误: {}", response.status()));
        }
        
        let vt_response: serde_json::Value = response
            .json()
            .await
            .context("解析VirusTotal响应失败")?;
        
        // 检查响应代码
        if vt_response["response_code"].as_i64() == Some(0) {
            return Ok(VirusTotalResult {
                scan_id: None,
                permalink: None,
                positives: 0,
                total: 0,
                scans: HashMap::new(),
                first_seen: None,
                last_seen: None,
            });
        }
        
        let scans = vt_response["scans"]
            .as_object()
            .unwrap_or(&serde_json::Map::new())
            .iter()
            .map(|(k, v)| {
                let scan_result = ScanResult {
                    detected: v["detected"].as_bool().unwrap_or(false),
                    version: v["version"].as_str().map(|s| s.to_string()),
                    result: v["result"].as_str().map(|s| s.to_string()),
                    update: v["update"].as_str().map(|s| s.to_string()),
                };
                (k.clone(), scan_result)
            })
            .collect();
        
        Ok(VirusTotalResult {
            scan_id: vt_response["scan_id"].as_str().map(|s| s.to_string()),
            permalink: vt_response["permalink"].as_str().map(|s| s.to_string()),
            positives: vt_response["positives"].as_u64().unwrap_or(0) as u32,
            total: vt_response["total"].as_u64().unwrap_or(0) as u32,
            scans,
            first_seen: vt_response["first_seen"].as_str().map(|s| s.to_string()),
            last_seen: vt_response["last_seen"].as_str().map(|s| s.to_string()),
        })
    }
    
    async fn query_hybrid_analysis(&self, sha256: &str, api_key: &str) -> Result<HybridAnalysisResult> {
        let url = format!("https://www.hybrid-analysis.com/api/v2/search/hash");
        
        let params = [
            ("hash", sha256),
        ];
        
        let response = self.client
            .post(&url)
            .header("api-key", api_key)
            .header("User-Agent", "Falcon Sandbox")
            .form(&params)
            .send()
            .await
            .context("Hybrid Analysis API请求失败")?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Hybrid Analysis API返回错误: {}", response.status()));
        }
        
        let ha_response: serde_json::Value = response
            .json()
            .await
            .context("解析Hybrid Analysis响应失败")?;
        
        // 如果没有找到结果
        if ha_response.as_array().map_or(true, |arr| arr.is_empty()) {
            return Ok(HybridAnalysisResult {
                job_id: None,
                analysis_url: None,
                threat_score: None,
                verdict: None,
            });
        }
        
        let first_result = &ha_response[0];
        
        Ok(HybridAnalysisResult {
            job_id: first_result["job_id"].as_str().map(|s| s.to_string()),
            analysis_url: first_result["analysis_url"].as_str().map(|s| s.to_string()),
            threat_score: first_result["threat_score"].as_u64().map(|n| n as u32),
            verdict: first_result["verdict"].as_str().map(|s| s.to_string()),
        })
    }
}