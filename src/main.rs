use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod elf_parser;
mod hash_extractor;
mod online_analyzer;
mod config;
mod output;

use elf_parser::ElfAnalyzer;
use online_analyzer::OnlineAnalyzer;
use config::Config;

#[derive(Parser)]
#[command(name = "elf-analyzer")]
#[command(about = "ELF文件分析工具，支持在线沙箱和特征库查询")]
struct Args {
    #[arg(help = "要分析的ELF文件路径")]
    file: PathBuf,
    
    #[arg(short, long, help = "配置文件路径")]
    config: Option<PathBuf>,
    
    #[arg(short, long, help = "输出格式 (text/json)", default_value = "text")]
    output: String,
    
    #[arg(long, help = "启用在线分析")]
    online: bool,
    
    #[arg(long, help = "仅显示基本ELF信息")]
    basic_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // 加载配置
    let config = Config::load(args.config.as_deref())?;
    
    // 分析ELF文件
    let mut analyzer = ElfAnalyzer::new();
    let elf_info = analyzer.analyze(&args.file)?;
    
    // 在线分析（如果启用）
    let online_results = if args.online && !args.basic_only {
        let online_analyzer = OnlineAnalyzer::new(&config);
        Some(online_analyzer.analyze(&elf_info).await?)
    } else {
        None
    };
    
    // 输出结果
    output::print_results(&elf_info, online_results.as_ref(), &args.output)?;
    
    Ok(())
}