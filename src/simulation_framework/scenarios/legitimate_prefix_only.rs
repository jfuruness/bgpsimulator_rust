use std::collections::{HashMap, HashSet};
use ipnetwork::IpNetwork;
use std::str::FromStr;

use crate::as_graph::{ASGraph, ASN};
use crate::engine::SimulationEngine;
use crate::route_validator::{ROA, RouteValidator};
use crate::shared::{CommonASNs, Relationships, Timestamps};
use crate::simulation_engine::Announcement;
use crate::simulation_framework::scenario::ScenarioTrait;

/// Scenario where only legitimate prefix is announced (no attack)
pub struct LegitimatePrefixOnly {
    legitimate_origin_asns: HashSet<ASN>,
}

impl LegitimatePrefixOnly {
    pub fn new(legitimate_origin_asns: HashSet<ASN>) -> Self {
        LegitimatePrefixOnly {
            legitimate_origin_asns,
        }
    }
}

impl ScenarioTrait for LegitimatePrefixOnly {
    fn name(&self) -> &str {
        "LegitimatePrefixOnly"
    }
    
    fn get_attacker_asns(&self, _as_graph: &ASGraph) -> HashSet<ASN> {
        // No attackers in this scenario
        HashSet::new()
    }
    
    fn get_legitimate_origin_asns(&self, _as_graph: &ASGraph) -> HashSet<ASN> {
        self.legitimate_origin_asns.clone()
    }
    
    fn get_seed_asn_ann_dict(&self, _as_graph: &ASGraph) -> HashMap<ASN, Vec<Announcement>> {
        let mut seed_dict = HashMap::new();
        
        // Only legitimate announcement
        for &asn in &self.legitimate_origin_asns {
            let prefix = IpNetwork::from_str("10.0.0.0/24").unwrap();
            let ann = Announcement::new(
                prefix,
                vec![],
                asn,
                Relationships::Origin,
                Timestamps::Victim,
            );
            seed_dict.insert(asn, vec![ann]);
        }
        
        seed_dict
    }
    
    fn get_roas(&self, _as_graph: &ASGraph) -> Vec<ROA> {
        let mut roas = Vec::new();
        
        // Create ROA for legitimate prefix
        for &asn in &self.legitimate_origin_asns {
            roas.push(ROA::new(
                IpNetwork::from_str("10.0.0.0/24").unwrap(),
                asn,
                Some(24),
            ));
        }
        
        roas
    }
    
    fn setup_engine(&self, engine: &mut SimulationEngine, route_validator: &mut RouteValidator) {
        // Add ROAs
        for roa in self.get_roas(&engine.as_graph) {
            route_validator.add_roa(roa);
        }
        
        // Seed announcements
        let seed_dict = self.get_seed_asn_ann_dict(&engine.as_graph);
        let seeds: Vec<(ASN, Announcement)> = seed_dict.into_iter()
            .flat_map(|(asn, anns)| anns.into_iter().map(move |ann| (asn, ann)))
            .collect();
        
        engine.setup(seeds);
    }
    
    fn is_successful(&self, engine: &SimulationEngine) -> bool {
        // Success means all ASes have routes to the legitimate prefix
        let legitimate_prefix = IpNetwork::from_str("10.0.0.0/24").unwrap();
        
        let mut has_routes = 0;
        let total_ases = engine.as_graph.as_dict.len();
        
        for (_, policy) in engine.policy_store.iter() {
            if policy.local_rib.contains_key(&legitimate_prefix) {
                has_routes += 1;
            }
        }
        
        // Consider successful if most ASes have routes
        has_routes as f64 / total_ases as f64 > 0.8
    }
}