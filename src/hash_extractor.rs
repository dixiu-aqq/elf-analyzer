use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use sha1::Sha1;
use ring::digest;
use hex::encode;
use rayon::prelude::*; // 关键：导入并行 trait

#[derive(Debug, Serialize, Deserialize)]
pub struct HashInfo {
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub file_size: usize,
}

pub fn extract_hashes(data: &[u8]) -> HashInfo {
    // 并行计算（用 rayon 标准写法替代 join3）
    let sha1_digest = calculate_sha1(data);
    let sha256_digest = calculate_sha256(data);
    let sha512_digest = calculate_sha512(data);

    // 或追求极致并行（修复类型问题）：
    // let (sha1_digest, sha256_digest, sha512_digest) = rayon::join(
    //     || calculate_sha1(data),
    //     || rayon::join(|| calculate_sha256(data), || calculate_sha512(data)),
    // );

    HashInfo {
        sha1: encode(sha1_digest),
        sha256: encode(sha256_digest),
        sha512: encode(sha512_digest),
        file_size: data.len(),
    }
}

fn calculate_sha1(data: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().to_vec()
}

fn calculate_sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

fn calculate_sha512(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA512, data).as_ref().to_vec()
}