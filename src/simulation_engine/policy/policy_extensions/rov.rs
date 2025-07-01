use crate::as_graphs::as_graph::{AS};
use crate::route_validator::RouteValidator;
use crate::shared::{Relationships, ROAValidity};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension};

/// Route Origin Validation (ROV) policy
pub struct ROVPolicy {
    pub route_validator: RouteValidator,
}

impl ROVPolicy {
    pub fn new() -> Self {
        ROVPolicy {
            route_validator: RouteValidator::new(),
        }
    }
    
    fn default_validate(&self, ann: &Announcement, recv_relationship: Relationships, as_obj: &AS) -> bool {
        if ann.as_path.is_empty() && recv_relationship != Relationships::Origin {
            return false;
        }

        if ann.as_path.contains(&as_obj.asn) {
            return false;
        }
        
        if !ann.as_path.is_empty() {
            if let Some(first_asn) = ann.as_path.first() {
                if *first_asn != ann.next_hop_asn {
                    return false;
                }
            }
        }
        
        true
    }
}

impl PolicyExtension for ROVPolicy {
    fn validate_announcement(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
        _route_validator: Option<&RouteValidator>,
    ) -> bool {
        // First do standard validation
        if !self.default_validate(ann, recv_relationship, as_obj) {
            return false;
        }
        
        // Then check ROA validity
        let origin = ann.as_path.last().copied().unwrap_or(ann.next_hop_asn);
        let (validity, _) = self.route_validator.get_roa_outcome(&ann.prefix, origin);
        
        match validity {
            ROAValidity::Valid => true,
            ROAValidity::Unknown => true,  // Accept unknown in basic ROV
            _ => false,  // Reject all invalid types
        }
    }
    
    fn name(&self) -> &str {
        "ROV"
    }
}