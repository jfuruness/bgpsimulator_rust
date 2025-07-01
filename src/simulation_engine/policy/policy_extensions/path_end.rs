use std::collections::HashSet;
use crate::as_graphs::as_graph::{AS, ASN};
use crate::shared::{Relationships};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension};
use crate::route_validator::RouteValidator;

/// Path-End policy
pub struct PathEndPolicy {
    pub legitimate_asns: HashSet<ASN>,
}

impl PathEndPolicy {
    pub fn new() -> Self {
        PathEndPolicy {
            legitimate_asns: HashSet::new(),
        }
    }
    
    pub fn add_legitimate_asn(&mut self, asn: ASN) {
        self.legitimate_asns.insert(asn);
    }
}

impl PolicyExtension for PathEndPolicy {
    fn validate_announcement(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
        _route_validator: Option<&RouteValidator>,
    ) -> bool {
        // First do standard validation
        if ann.as_path.is_empty() && recv_relationship != Relationships::Origin {
            return false;
        }

        if ann.as_path.contains(&as_obj.asn) {
            return false;
        }
        
        // Check path-end
        if let Some(&origin) = ann.as_path.last() {
            if !self.legitimate_asns.contains(&origin) {
                return false;
            }
        }
        
        true
    }
    
    fn name(&self) -> &str {
        "PathEnd"
    }
}