use anyhow::{Result, Context};
use goblin::elf::Elf;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use crate::hash_extractor::HashInfo;

#[derive(Debug, Serialize, Deserialize)]
pub struct ElfInfo {
    pub file_path: String,
    pub file_size: u64,
    pub architecture: String,
    pub entry_point: u64,
    pub program_headers: Vec<ProgramHeaderInfo>,
    pub section_headers: Vec<SectionHeaderInfo>,
    pub dynamic_symbols: Vec<String>,
    pub imported_functions: Vec<String>,
    pub exported_functions: Vec<String>,
    pub strings: Vec<String>,
    pub hashes: HashInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramHeaderInfo {
    pub segment_type: String,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub permissions: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SectionHeaderInfo {
    pub name: String,
    pub section_type: String,
    pub virtual_address: u64,
    pub size: u64,
    pub flags: String,
}

pub struct ElfAnalyzer;

impl ElfAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&mut self, file_path: &Path) -> Result<ElfInfo> {
        let file_data = fs::read(file_path)
            .with_context(|| format!("无法读取文件: {:?}", file_path))?;
        
        let elf = Elf::parse(&file_data)
            .with_context(|| "解析ELF文件失败")?;
        
        let file_size = file_data.len() as u64;
        let hashes = crate::hash_extractor::extract_hashes(&file_data);
        
        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64",
            goblin::elf::header::EM_386 => "i386",
            goblin::elf::header::EM_ARM => "ARM",
            goblin::elf::header::EM_AARCH64 => "AArch64",
            _ => "Unknown",
        }.to_string();
        
        let program_headers = elf.program_headers.iter().map(|ph| {
            let permissions = format!("{}{}{}",
                if ph.p_flags & goblin::elf::program_header::PF_R != 0 { "R" } else { "-" },
                if ph.p_flags & goblin::elf::program_header::PF_W != 0 { "W" } else { "-" },
                if ph.p_flags & goblin::elf::program_header::PF_X != 0 { "X" } else { "-" }
            );
            
            ProgramHeaderInfo {
                segment_type: format!("{:?}", ph.p_type),
                virtual_address: ph.p_vaddr,
                file_size: ph.p_filesz,
                memory_size: ph.p_memsz,
                permissions,
            }
        }).collect();
        
        let section_headers = elf.section_headers.iter().enumerate().map(|(i, sh)| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            SectionHeaderInfo {
                name,
                section_type: format!("{:?}", sh.sh_type),
                virtual_address: sh.sh_addr,
                size: sh.sh_size,
                flags: format!("{:#x}", sh.sh_flags),
            }
        }).collect();
        
        let dynamic_symbols: Vec<String> = elf.dynsyms.iter()
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
            .map(|s| s.to_string())
            .collect();
        
        let imported_functions: Vec<String> = elf.dynsyms.iter()
            .filter(|sym| sym.st_shndx == 0 && sym.st_value == 0)
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
            .map(|s| s.to_string())
            .collect();
        
        let exported_functions: Vec<String> = elf.dynsyms.iter()
            .filter(|sym| sym.st_shndx != 0 && sym.st_value != 0)
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
            .map(|s| s.to_string())
            .collect();
        
        let strings = self.extract_strings(&file_data);
        
        Ok(ElfInfo {
            file_path: file_path.display().to_string(),
            file_size,
            architecture,
            entry_point: elf.entry,
            program_headers,
            section_headers,
            dynamic_symbols,
            imported_functions,
            exported_functions,
            strings,
            hashes,
        })
    }
    
    fn extract_strings(&self, data: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current_string = Vec::new();
        
        for &byte in data {
            if byte.is_ascii_graphic() || byte == b' ' {
                current_string.push(byte);
            } else if !current_string.is_empty() && current_string.len() >= 4 {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push(s);
                }
                current_string.clear();
            } else {
                current_string.clear();
            }
        }
        
        strings.truncate(1000); // 限制字符串数量
        strings
    }
}