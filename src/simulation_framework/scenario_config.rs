use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::as_graph::ASN;
use crate::route_validator::ROA;
use crate::shared::Settings;
use crate::simulation_engine::Announcement;

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    /// Label for this scenario configuration
    pub label: String,
    
    /// Name of the scenario class to use
    pub scenario_name: String,
    
    /// Default adoption settings for ASes
    pub default_adoption_settings: HashMap<Settings, bool>,
    
    /// Override attacker ASNs (if None, will be randomly selected)
    pub override_attacker_asns: Option<HashSet<ASN>>,
    
    /// Override legitimate origin ASNs (if None, will be randomly selected)
    pub override_legitimate_origin_asns: Option<HashSet<ASN>>,
    
    /// Override adopting ASNs (if None, will be randomly selected based on percentage)
    pub override_adopting_asns: Option<HashSet<ASN>>,
    
    /// Override seed announcements (if None, scenario will generate them)
    pub override_seed_asn_ann_dict: Option<HashMap<ASN, Vec<Announcement>>>,
    
    /// Override ROAs (if None, scenario will generate them)
    pub override_roas: Option<Vec<ROA>>,
    
    /// Override destination IP address for testing
    pub override_dest_ip_addr: Option<IpAddr>,
}

impl ScenarioConfig {
    pub fn new(label: String, scenario_name: String) -> Self {
        ScenarioConfig {
            label,
            scenario_name,
            default_adoption_settings: HashMap::new(),
            override_attacker_asns: None,
            override_legitimate_origin_asns: None,
            override_adopting_asns: None,
            override_seed_asn_ann_dict: None,
            override_roas: None,
            override_dest_ip_addr: None,
        }
    }
    
    pub fn with_adoption_setting(mut self, setting: Settings, enabled: bool) -> Self {
        self.default_adoption_settings.insert(setting, enabled);
        self
    }
    
    pub fn with_attacker_asns(mut self, asns: HashSet<ASN>) -> Self {
        self.override_attacker_asns = Some(asns);
        self
    }
    
    pub fn with_legitimate_origin_asns(mut self, asns: HashSet<ASN>) -> Self {
        self.override_legitimate_origin_asns = Some(asns);
        self
    }
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        ScenarioConfig::new(
            "Default Scenario".to_string(),
            "SubprefixHijack".to_string(),
        )
    }
}