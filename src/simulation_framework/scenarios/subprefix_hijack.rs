use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;

use crate::as_graphs::as_graph::{ASGraph, ASN};
use crate::simulation_engine::SimulationEngine;
use crate::route_validator::{ROA, RouteValidator};
use crate::shared::{Relationships, Timestamps};
use crate::simulation_engine::{Announcement, Prefix};
use crate::simulation_framework::scenario::ScenarioTrait;

/// Subprefix hijack scenario
/// Attacker announces a more specific prefix than the legitimate origin
pub struct SubprefixHijack {
    pub attacker_asns: HashSet<ASN>,
    pub legitimate_origin_asns: HashSet<ASN>,
    pub legitimate_prefix: Prefix,
    pub hijacked_prefix: Prefix,
}

impl SubprefixHijack {
    pub fn new(attacker_asns: HashSet<ASN>, legitimate_origin_asns: HashSet<ASN>) -> Self {
        // Default prefixes - legitimate announces /24, attacker announces /25
        let legitimate_prefix = IpNetwork::from_str("1.2.3.0/24").unwrap();
        let hijacked_prefix = IpNetwork::from_str("1.2.3.0/25").unwrap();
        
        SubprefixHijack {
            attacker_asns,
            legitimate_origin_asns,
            legitimate_prefix,
            hijacked_prefix,
        }
    }
}

impl ScenarioTrait for SubprefixHijack {
    fn name(&self) -> &str {
        "SubprefixHijack"
    }
    
    fn get_attacker_asns(&self, _as_graph: &ASGraph) -> HashSet<ASN> {
        self.attacker_asns.clone()
    }
    
    fn get_legitimate_origin_asns(&self, _as_graph: &ASGraph) -> HashSet<ASN> {
        self.legitimate_origin_asns.clone()
    }
    
    fn get_seed_asn_ann_dict(&self, _as_graph: &ASGraph) -> HashMap<ASN, Vec<Announcement>> {
        let mut seed_dict = HashMap::new();
        
        // Legitimate announcement
        for &asn in &self.legitimate_origin_asns {
            let ann = Announcement::new_with_path(
                self.legitimate_prefix,
                vec![],  // Empty AS path for origin
                asn,
                Relationships::Origin,
                Timestamps::Victim,
            );
            seed_dict.insert(asn, vec![ann]);
        }
        
        // Attacker announcement (more specific prefix)
        for &asn in &self.attacker_asns {
            let ann = Announcement::new_with_path(
                self.hijacked_prefix,
                vec![],  // Empty AS path for origin
                asn,
                Relationships::Origin,
                Timestamps::Victim,  // Same timestamp to simulate simultaneous announcement
            );
            seed_dict.insert(asn, vec![ann]);
        }
        
        seed_dict
    }
    
    fn get_roas(&self, _as_graph: &ASGraph) -> Vec<ROA> {
        let mut roas = Vec::new();
        
        // Create ROA for legitimate prefix
        for &asn in &self.legitimate_origin_asns {
            let roa = ROA::new(
                self.legitimate_prefix,
                asn,
                Some(24),  // Max length 24
            );
            roas.push(roa);
        }
        
        roas
    }
    
    fn setup_engine(&self, engine: &mut SimulationEngine, route_validator: &mut RouteValidator) {
        // Clear and add ROAs
        *route_validator = RouteValidator::new();
        for roa in self.get_roas(&engine.as_graph) {
            route_validator.add_roa(roa);
        }
        
        // Seed announcements
        let seed_dict = self.get_seed_asn_ann_dict(&engine.as_graph);
        let mut initial_anns = Vec::new();
        for (asn, anns) in seed_dict {
            for ann in anns {
                initial_anns.push((asn, ann));
            }
        }
        
        engine.setup(initial_anns);
    }
    
    fn is_successful(&self, engine: &SimulationEngine) -> bool {
        // Check if attacker's announcement reached significant portion of network
        let mut attacker_reach = 0;
        let total_ases = engine.as_graph.as_dict.len();
        
        // Check each AS's routing table
        for (_asn, policy) in engine.policy_store.iter() {
            // Check if AS has route to the hijacked prefix from attacker
            if let Some(ann) = policy.local_rib.get(&self.hijacked_prefix) {
                if self.attacker_asns.contains(&ann.origin()) {
                    attacker_reach += 1;
                }
            }
        }
        
        // Success if attacker reached more than 50% of ASes
        let success_ratio = attacker_reach as f64 / total_ases as f64;
        success_ratio > 0.5
    }
}