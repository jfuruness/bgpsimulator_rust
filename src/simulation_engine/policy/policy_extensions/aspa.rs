use crate::as_graphs::as_graph::{AS, ASN, ASGraph};
use crate::shared::{Relationships};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension};
use crate::route_validator::RouteValidator;

/// ASPA (AS Provider Authorization) policy
pub struct ASPAPolicy;

impl ASPAPolicy {
    fn next_hop_valid(&self, ann: &Announcement, as_obj: &AS) -> bool {
        // Next hop should be first ASN in path (unless we're an IXP/route server)
        ann.as_path.first() == Some(&ann.next_hop_asn) || as_obj.ixp
    }
    
    fn provider_check(&self, asn1: ASN, asn2: ASN, as_graph: &ASGraph) -> bool {
        // Check if asn2 is in asn1's providers
        // Returns true if no attestation or if asn2 is a provider of asn1
        // TODO: Need access to ASGraph to check provider relationships and ASPA settings
        true
    }
    
    fn get_max_up_ramp_length(&self, ann: &Announcement, as_graph: &ASGraph) -> usize {
        let reversed_path: Vec<ASN> = ann.as_path.iter().copied().rev().collect();
        
        for i in 0..reversed_path.len() - 1 {
            if !self.provider_check(reversed_path[i], reversed_path[i + 1], as_graph) {
                return i + 1;
            }
        }
        ann.as_path.len()
    }
    
    fn get_max_down_ramp_length(&self, ann: &Announcement, as_graph: &ASGraph) -> usize {
        let reversed_path: Vec<ASN> = ann.as_path.iter().copied().rev().collect();
        
        for i in (1..reversed_path.len()).rev() {
            if !self.provider_check(reversed_path[i], reversed_path[i - 1], as_graph) {
                let j = i + 1; // Adjust for 1-indexing in RFC
                return reversed_path.len() - j + 1;
            }
        }
        ann.as_path.len()
    }
}

impl PolicyExtension for ASPAPolicy {
    fn validate_announcement(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
        _route_validator: Option<&RouteValidator>,
    ) -> bool {
        // Basic validation
        if ann.as_path.is_empty() && recv_relationship != Relationships::Origin {
            return false;
        }

        if ann.as_path.contains(&as_obj.asn) {
            return false;
        }
        
        // ASPA specific validation
        if !self.next_hop_valid(ann, as_obj) {
            return false;
        }
        
        // TODO: Implement full ASPA validation when we have ASGraph access
        true
    }
    
    fn name(&self) -> &str {
        "ASPA"
    }
}