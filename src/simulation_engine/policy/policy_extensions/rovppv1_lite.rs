use crate::as_graphs::as_graph::{AS};
use crate::route_validator::RouteValidator;
use crate::shared::{Relationships, ROAValidity};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension, ProcessingResult};

/// ROV++ V1 Lite policy - extends ROV with blackholing
pub struct ROVPPV1LitePolicy {
    pub route_validator: RouteValidator,
}

impl ROVPPV1LitePolicy {
    pub fn new() -> Self {
        ROVPPV1LitePolicy {
            route_validator: RouteValidator::new(),
        }
    }
}

impl PolicyExtension for ROVPPV1LitePolicy {
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
        
        if !ann.as_path.is_empty() {
            if let Some(first_asn) = ann.as_path.first() {
                if *first_asn != ann.next_hop_asn {
                    return false;
                }
            }
        }
        
        // Then check ROA validity
        let origin = ann.as_path.last().copied().unwrap_or(ann.next_hop_asn);
        let (validity, _) = self.route_validator.get_roa_outcome(&ann.prefix, origin);
        
        match validity {
            ROAValidity::Valid => true,
            ROAValidity::Unknown => true,
            _ => false, // Reject invalid announcements
        }
    }
    
    fn process_announcement(
        &mut self,
        ann: &mut Announcement,
        _recv_relationship: Relationships,
        _as_obj: &AS,
    ) -> ProcessingResult {
        // Check if announcement should be blackholed
        if ann.rovpp_blackhole.unwrap_or(false) {
            ProcessingResult::Modified
        } else {
            ProcessingResult::Accept
        }
    }
    
    fn should_propagate(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        send_relationship: Relationships,
    ) -> bool {
        // Don't propagate blackholed announcements
        if ann.rovpp_blackhole.unwrap_or(false) {
            return false;
        }
        
        // Use default Gao-Rexford rules
        match (recv_relationship, send_relationship) {
            (Relationships::Origin, _) => true,
            (Relationships::Customers, _) => true,
            (Relationships::Peers, Relationships::Customers) => true,
            (Relationships::Providers, Relationships::Customers) => true,
            _ => false,
        }
    }
    
    fn name(&self) -> &str {
        "ROVPPV1Lite"
    }
}