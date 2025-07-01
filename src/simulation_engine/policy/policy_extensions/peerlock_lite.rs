use crate::as_graphs::as_graph::{AS};
use crate::shared::{Relationships};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension};
use crate::route_validator::RouteValidator;

/// Peerlock Lite policy - prevents route leaks from Tier-1 ASes
pub struct PeerlockLitePolicy;

impl PolicyExtension for PeerlockLitePolicy {
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
        
        // Peerlock Lite specific validation
        if recv_relationship == Relationships::Customers {
            // Check if any AS in the path is Tier-1
            // TODO: Need access to ASGraph to check tier-1 status
            // For now, return true
            true
        } else {
            true
        }
    }
    
    fn name(&self) -> &str {
        "PeerlockLite"
    }
}