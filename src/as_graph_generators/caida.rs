use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use chrono::{Duration, Utc};
use reqwest;
use bzip2::read::BzDecoder;
use scraper::{Html, Selector};

use crate::as_graph::{AS, ASGraph, ASN};

const SERIAL_2_URL: &str = "http://data.caida.org/datasets/as-relationships/serial-2/";

pub struct CAIDAASGraphCollector {
    days_ago: u32,
    cache_dir: PathBuf,
}

impl CAIDAASGraphCollector {
    pub fn new(days_ago: u32, cache_dir: &str) -> Self {
        CAIDAASGraphCollector {
            days_ago,
            cache_dir: PathBuf::from(cache_dir),
        }
    }

    pub fn run(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Create cache directory if it doesn't exist
        fs::create_dir_all(&self.cache_dir)?;

        let cached_path = self.get_cached_path();
        if cached_path.exists() {
            println!("Using cached CAIDA data from {:?}", cached_path);
            return Ok(cached_path);
        }

        println!("Downloading CAIDA AS relationships data...");
        let url = self.get_download_url()?;
        let bz2_data = self.download_file(&url)?;
        
        // Decompress and save
        let decompressed = self.decompress_bz2(&bz2_data)?;
        fs::write(&cached_path, decompressed)?;
        
        println!("CAIDA data saved to {:?}", cached_path);
        Ok(cached_path)
    }

    fn get_cached_path(&self) -> PathBuf {
        let date = Utc::now() - Duration::days(self.days_ago as i64);
        let filename = format!("caida_{}.txt", date.format("%Y%m%d"));
        self.cache_dir.join(filename)
    }

    fn get_download_url(&self) -> Result<String, Box<dyn std::error::Error>> {
        let date = Utc::now() - Duration::days(self.days_ago as i64);
        let filename = format!("{}.as-rel2.txt.bz2", date.format("%Y%m%d"));
        Ok(format!("{}{}", SERIAL_2_URL, filename))
    }

    fn download_file(&self, url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let response = reqwest::blocking::get(url)?;
        if !response.status().is_success() {
            return Err(format!("Failed to download {}: {}", url, response.status()).into());
        }
        Ok(response.bytes()?.to_vec())
    }

    fn decompress_bz2(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut decoder = BzDecoder::new(data);
        let mut decompressed = Vec::new();
        std::io::copy(&mut decoder, &mut decompressed)?;
        Ok(decompressed)
    }
}

pub struct CAIDAASGraphJSONConverter {
    file_path: PathBuf,
}

impl CAIDAASGraphJSONConverter {
    pub fn new(file_path: &Path) -> Self {
        CAIDAASGraphJSONConverter {
            file_path: file_path.to_path_buf(),
        }
    }

    pub fn convert(&self) -> Result<ASGraph, Box<dyn std::error::Error>> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        
        let mut as_dict: HashMap<ASN, AS> = HashMap::new();
        let mut tier_1_asns = HashSet::new();
        let mut ixp_asns = HashSet::new();

        for line in reader.lines() {
            let line = line?;
            
            if line.starts_with("# input clique:") {
                // Parse Tier-1 ASNs
                let asns_str = line.trim_start_matches("# input clique:").trim();
                for asn_str in asns_str.split_whitespace() {
                    if let Ok(asn) = asn_str.parse::<ASN>() {
                        tier_1_asns.insert(asn);
                    }
                }
            } else if line.starts_with("# IXP ASes:") {
                // Parse IXP ASNs
                let asns_str = line.trim_start_matches("# IXP ASes:").trim();
                for asn_str in asns_str.split_whitespace() {
                    if let Ok(asn) = asn_str.parse::<ASN>() {
                        ixp_asns.insert(asn);
                    }
                }
            } else if !line.starts_with('#') && !line.trim().is_empty() {
                // Parse relationship line
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 3 {
                    let asn1 = parts[0].parse::<ASN>()?;
                    let asn2 = parts[1].parse::<ASN>()?;
                    let rel_type = parts[2].parse::<i32>()?;
                    
                    // Ensure both ASes exist
                    as_dict.entry(asn1).or_insert_with(|| AS::new(asn1));
                    as_dict.entry(asn2).or_insert_with(|| AS::new(asn2));
                    
                    match rel_type {
                        -1 => {
                            // Provider-Customer relationship (asn1 is provider, asn2 is customer)
                            as_dict.get_mut(&asn1).unwrap().customers.push(asn2);
                            as_dict.get_mut(&asn2).unwrap().providers.push(asn1);
                        }
                        0 => {
                            // Peer-to-peer relationship
                            as_dict.get_mut(&asn1).unwrap().peers.push(asn2);
                            as_dict.get_mut(&asn2).unwrap().peers.push(asn1);
                        }
                        _ => {
                            eprintln!("Unknown relationship type: {}", rel_type);
                        }
                    }
                }
            }
        }

        // Set Tier-1 and IXP flags
        for (&asn, as_obj) in as_dict.iter_mut() {
            if tier_1_asns.contains(&asn) {
                as_obj.tier_1 = true;
            }
            if ixp_asns.contains(&asn) {
                as_obj.ixp = true;
            }
        }

        // Convert Vec to HashSet for unique relationships
        for as_obj in as_dict.values_mut() {
            let peer_set: HashSet<ASN> = as_obj.peers.drain(..).collect();
            let provider_set: HashSet<ASN> = as_obj.providers.drain(..).collect();
            let customer_set: HashSet<ASN> = as_obj.customers.drain(..).collect();
            
            as_obj.peers = peer_set.into_iter().collect();
            as_obj.providers = provider_set.into_iter().collect();
            as_obj.customers = customer_set.into_iter().collect();
        }

        // Build ASGraph
        let mut as_graph = ASGraph::new();
        for (_, as_obj) in as_dict {
            as_graph.insert(as_obj);
        }

        // Run graph algorithms
        as_graph.check_for_cycles()?;
        as_graph.assign_as_propagation_rank();
        as_graph.add_provider_cone_asns();
        as_graph.add_asn_groups();

        Ok(as_graph)
    }
}