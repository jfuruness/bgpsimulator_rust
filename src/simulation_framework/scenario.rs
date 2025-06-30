use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::as_graph::{ASGraph, ASN};
use crate::engine::SimulationEngine;
use crate::route_validator::{ROA, RouteValidator};
use crate::shared::Settings;
use crate::simulation_engine::{Announcement, Prefix};

use super::scenario_config::ScenarioConfig;

/// Base trait for all scenarios
pub trait ScenarioTrait: Send + Sync {
    /// Minimum number of propagation rounds for this scenario
    fn min_propagation_rounds(&self) -> u32 {
        1
    }
    
    /// Get the name of this scenario type
    fn name(&self) -> &str;
    
    /// Get attacker ASNs for this scenario
    fn get_attacker_asns(&self, as_graph: &ASGraph) -> HashSet<ASN>;
    
    /// Get legitimate origin ASNs
    fn get_legitimate_origin_asns(&self, as_graph: &ASGraph) -> HashSet<ASN>;
    
    /// Get announcements to seed the simulation with
    fn get_seed_asn_ann_dict(&self, as_graph: &ASGraph) -> HashMap<ASN, Vec<Announcement>>;
    
    /// Get ROAs for the simulation
    fn get_roas(&self, as_graph: &ASGraph) -> Vec<ROA>;
    
    /// Get destination IP address for testing
    fn get_dest_ip_addr(&self) -> IpAddr {
        // Default implementation returns a test IP
        "1.2.3.4".parse().unwrap()
    }
    
    /// Setup the scenario in the engine
    fn setup_engine(&self, engine: &mut SimulationEngine, route_validator: &mut RouteValidator);
    
    /// Check if the scenario outcome is successful
    fn is_successful(&self, engine: &SimulationEngine) -> bool;
}

/// Base scenario struct that holds common data
pub struct Scenario {
    pub config: ScenarioConfig,
    pub percent_ases_randomly_adopting: f64,
    pub attacker_asns: HashSet<ASN>,
    pub legitimate_origin_asns: HashSet<ASN>,
    pub adopting_asns: HashSet<ASN>,
    pub seed_asn_ann_dict: HashMap<ASN, Vec<Announcement>>,
    pub roas: Vec<ROA>,
    pub dest_ip_addr: IpAddr,
}

impl Scenario {
    pub fn new(
        config: ScenarioConfig,
        as_graph: &ASGraph,
        percent_ases_randomly_adopting: f64,
    ) -> Self {
        // Get attacker ASNs
        let attacker_asns = if let Some(override_asns) = &config.override_attacker_asns {
            override_asns.clone()
        } else {
            Self::default_attacker_asns(as_graph)
        };
        
        // Get legitimate origin ASNs
        let legitimate_origin_asns = if let Some(override_asns) = &config.override_legitimate_origin_asns {
            override_asns.clone()
        } else {
            Self::default_legitimate_origin_asns(as_graph)
        };
        
        // Get adopting ASNs based on percentage
        let adopting_asns = if let Some(override_asns) = &config.override_adopting_asns {
            override_asns.clone()
        } else {
            Self::get_random_adopting_asns(as_graph, percent_ases_randomly_adopting)
        };
        
        // Initialize with empty seed dict and ROAs - these will be populated by specific scenarios
        let seed_asn_ann_dict = HashMap::new();
        let roas = Vec::new();
        
        Scenario {
            config,
            percent_ases_randomly_adopting,
            attacker_asns,
            legitimate_origin_asns,
            adopting_asns,
            seed_asn_ann_dict,
            roas,
            dest_ip_addr: "1.2.3.4".parse().unwrap(),
        }
    }
    
    fn default_attacker_asns(as_graph: &ASGraph) -> HashSet<ASN> {
        // Default: pick a random stub AS as attacker
        let stubs: Vec<ASN> = as_graph.as_dict.values()
            .filter(|as_obj| as_obj.customers.is_empty() && !as_obj.ixp)
            .map(|as_obj| as_obj.asn)
            .collect();
            
        if !stubs.is_empty() {
            let idx = rand::random::<usize>() % stubs.len();
            HashSet::from([stubs[idx]])
        } else {
            HashSet::new()
        }
    }
    
    fn default_legitimate_origin_asns(as_graph: &ASGraph) -> HashSet<ASN> {
        // Default: pick a different random stub AS as legitimate origin
        let stubs: Vec<ASN> = as_graph.as_dict.values()
            .filter(|as_obj| as_obj.customers.is_empty() && !as_obj.ixp)
            .map(|as_obj| as_obj.asn)
            .collect();
            
        if stubs.len() > 1 {
            let idx = rand::random::<usize>() % stubs.len();
            HashSet::from([stubs[idx]])
        } else {
            HashSet::new()
        }
    }
    
    fn get_random_adopting_asns(as_graph: &ASGraph, percent: f64) -> HashSet<ASN> {
        let all_asns: Vec<ASN> = as_graph.as_dict.keys().copied().collect();
        let num_to_adopt = ((all_asns.len() as f64) * (percent / 100.0)) as usize;
        
        let mut adopting = HashSet::new();
        let mut remaining = all_asns;
        
        for _ in 0..num_to_adopt.min(remaining.len()) {
            if remaining.is_empty() {
                break;
            }
            let idx = rand::random::<usize>() % remaining.len();
            let asn = remaining.swap_remove(idx);
            adopting.insert(asn);
        }
        
        adopting
    }
}

// External crate for random number generation
extern crate rand;