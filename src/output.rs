use anyhow::Result;
use crate::elf_parser::ElfInfo;
use crate::online_analyzer::OnlineAnalysisResult;

pub fn print_results(
    elf_info: &ElfInfo,
    online_results: Option<&OnlineAnalysisResult>,
    format: &str,
) -> Result<()> {
    match format.to_lowercase().as_str() {
        "json" => print_json_output(elf_info, online_results),
        "text" | _ => print_text_output(elf_info, online_results),
    }
}

fn print_json_output(
    elf_info: &ElfInfo,
    online_results: Option<&OnlineAnalysisResult>,
) -> Result<()> {
    let output = serde_json::json!({
        "elf_info": elf_info,
        "online_analysis": online_results
    });
    
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_text_output(
    elf_info: &ElfInfo,
    online_results: Option<&OnlineAnalysisResult>,
) -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                         ELF 文件分析报告                                                 ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!();
    
    // 基本信息
    println!("📁 基本信息:");
    println!("   文件路径: {}", elf_info.file_path);
    println!("   文件大小: {} bytes", elf_info.file_size);
    println!("   架构: {}", elf_info.architecture);
    println!("   入口点: 0x{:x}", elf_info.entry_point);
    println!();
    
    // 哈希值
    println!("🔐 文件哈希:");
    println!("   sha512:    {}", elf_info.hashes.sha512);
    println!("   SHA1:   {}", elf_info.hashes.sha1);
    println!("   SHA256: {}", elf_info.hashes.sha256);
    println!();
    
    // 程序头
    if !elf_info.program_headers.is_empty() {
        println!("📋 程序头 ({} 个):", elf_info.program_headers.len());
        for (i, ph) in elf_info.program_headers.iter().enumerate() {
            println!("   [{:2}] 类型: {:20} 虚拟地址: 0x{:08x} 大小: {:8} 权限: {}",
                i, ph.segment_type, ph.virtual_address, ph.file_size, ph.permissions);
        }
        println!();
    }
    
    // 节头
    if !elf_info.section_headers.is_empty() {
        println!("📑 节头 ({} 个):", elf_info.section_headers.len());
        for (i, sh) in elf_info.section_headers.iter().take(10).enumerate() {
            println!("   [{:2}] {:20} 类型: {:15} 虚拟地址: 0x{:08x} 大小: {}",
                i, sh.name, sh.section_type, sh.virtual_address, sh.size);
        }
        if elf_info.section_headers.len() > 10 {
            println!("   ... 还有 {} 个节", elf_info.section_headers.len() - 10);
        }
        println!();
    }
    
    // 导入函数
    if !elf_info.imported_functions.is_empty() {
        println!("📥 导入函数 ({} 个):", elf_info.imported_functions.len());
        for func in elf_info.imported_functions.iter().take(15) {
            if !func.is_empty() {
                println!("   - {}", func);
            }
        }
        if elf_info.imported_functions.len() > 15 {
            println!("   ... 还有 {} 个函数", elf_info.imported_functions.len() - 15);
        }
        println!();
    }
    
    // 导出函数
    if !elf_info.exported_functions.is_empty() {
        println!("📤 导出函数 ({} 个):", elf_info.exported_functions.len());
        for func in elf_info.exported_functions.iter().take(15) {
            if !func.is_empty() {
                println!("   - {}", func);
            }
        }
        if elf_info.exported_functions.len() > 15 {
            println!("   ... 还有 {} 个函数", elf_info.exported_functions.len() - 15);
        }
        println!();
    }
    
    // 字符串
    if !elf_info.strings.is_empty() {
        println!("📝 提取的字符串 ({} 个，显示前20个):", elf_info.strings.len());
        for string in elf_info.strings.iter().take(20) {
            if string.len() > 80 {
                println!("   \"{}...\"", &string[..77]);
            } else {
                println!("   \"{}\"", string);
            }
        }
        if elf_info.strings.len() > 20 {
            println!("   ... 还有 {} 个字符串", elf_info.strings.len() - 20);
        }
        println!();
    }
    
    // 在线分析结果
    if let Some(online) = online_results {
        println!("🌐 在线分析结果:");
        
        // VirusTotal 结果
        if let Some(vt) = &online.virustotal {
            println!("   🔍 VirusTotal:");
            if vt.total > 0 {
                println!("      检测结果: {}/{} 引擎检测到威胁", vt.positives, vt.total);
                if let Some(ref permalink) = vt.permalink {
                    println!("      详细报告: {}", permalink);
                }
                if vt.positives > 0 {
                    println!("      🚨 检测到的威胁:");
                    for (engine, result) in &vt.scans {
                        if result.detected {
                            if let Some(ref malware_name) = result.result {
                                println!("         - {}: {}", engine, malware_name);
                            }
                        }
                    }
                }
            } else {
                println!("      状态: 未找到扫描记录");
            }
        }
        
        // Hybrid Analysis 结果
        if let Some(ha) = &online.hybrid_analysis {
            println!("   🔬 Hybrid Analysis:");
            if let Some(ref verdict) = ha.verdict {
                println!("      判决: {}", verdict);
            }
            if let Some(threat_score) = ha.threat_score {
                println!("      威胁评分: {}/100", threat_score);
            }
            if let Some(ref analysis_url) = ha.analysis_url {
                println!("      分析报告: {}", analysis_url);
            }
            if ha.verdict.is_none() && ha.threat_score.is_none() {
                println!("      状态: 未找到分析记录");
            }
        }
        
        println!();
    }
    
    println!("分析完成! 🎉");
    Ok(())
}