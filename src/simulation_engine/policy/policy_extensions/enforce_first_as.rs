use crate::as_graphs::as_graph::{AS};
use crate::shared::{Relationships};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension};
use crate::route_validator::RouteValidator;

/// Enforce First AS policy
pub struct EnforceFirstASPolicy;

impl PolicyExtension for EnforceFirstASPolicy {
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
        
        // Check that first AS in path is the next hop and is a neighbor
        if let Some(&first_as) = ann.as_path.first() {
            if first_as != ann.next_hop_asn {
                return false;
            }
            
            // Check if next hop is actually a neighbor
            let is_neighbor = as_obj.peers.iter().any(|p| p.asn == first_as) ||
                             as_obj.providers.iter().any(|p| p.asn == first_as) ||
                             as_obj.customers.iter().any(|c| c.asn == first_as);
            
            if !is_neighbor {
                return false;
            }
        }
        
        true
    }
    
    fn name(&self) -> &str {
        "EnforceFirstAS"
    }
}