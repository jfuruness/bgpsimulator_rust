pub mod policy_extensions;

use std::cmp::Ordering;
use crate::shared::{Relationships, Settings};
use crate::as_graphs::as_graph::{AS, ASN, ASGraph};
use crate::simulation_engine::announcement::{Announcement, Prefix};
use crate::route_validator::RouteValidator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingResult {
    Accept,
    Reject,
    Modified,
}

/// Core trait for BGP policy extensions
pub trait PolicyExtension: Send + Sync {
    /// Validate an incoming announcement
    fn validate_announcement(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
        route_validator: Option<&RouteValidator>,
    ) -> bool {
        // Default validation - no loops, correct next hop
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
    
    /// Process and potentially modify an announcement
    fn process_announcement(
        &mut self,
        ann: &mut Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
    ) -> ProcessingResult {
        // Default processing - accept without modification
        ProcessingResult::Accept
    }
    
    /// Determine if announcement should be propagated to a specific relationship
    fn should_propagate(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        send_relationship: Relationships,
    ) -> bool {
        // Default Gao-Rexford propagation rules
        match (recv_relationship, send_relationship) {
            (Relationships::Origin, _) => true,
            (Relationships::Customers, _) => true,
            (Relationships::Peers, Relationships::Customers) => true,
            (Relationships::Providers, Relationships::Customers) => true,
            _ => false,
        }
    }
    
    /// Compare two announcements for route selection
    fn compare_announcements(
        &self,
        ann1: &Announcement,
        ann2: &Announcement,
        rel1: Relationships,
        rel2: Relationships,
        as_obj: &AS,
    ) -> Ordering {
        // Default Gao-Rexford preferences
        let pref1 = self.get_gao_rexford_preference(rel1);
        let pref2 = self.get_gao_rexford_preference(rel2);
        
        match pref2.cmp(&pref1) {
            Ordering::Equal => {
                // Prefer shorter AS path
                match ann1.as_path.len().cmp(&ann2.as_path.len()) {
                    Ordering::Equal => {
                        // Tie-break by next hop ASN
                        ann1.next_hop_asn.cmp(&ann2.next_hop_asn)
                    }
                    other => other,
                }
            }
            other => other,
        }
    }
    
    /// Get Gao-Rexford preference value for a relationship
    fn get_gao_rexford_preference(&self, rel: Relationships) -> u8 {
        match rel {
            Relationships::Customers => 3,
            Relationships::Peers => 2,
            Relationships::Providers => 1,
            _ => 0,
        }
    }
    
    /// Setup policy-specific state
    fn setup(&mut self, as_obj: &AS, as_graph: &ASGraph) {}
    
    /// Get the policy name/type
    fn name(&self) -> &str;
}

/// Create a policy extension based on settings
pub fn create_policy_extension(settings: Settings) -> Box<dyn PolicyExtension> {
    use policy_extensions::*;
    
    match settings {
        Settings::BaseDefense => Box::new(bgp::BGPPolicy),
        Settings::Rov => Box::new(rov::ROVPolicy::new()),
        Settings::PeerRov => Box::new(peer_rov::PeerROVPolicy::new()),
        Settings::OnlyToCustomers => Box::new(only_to_customers::OnlyToCustomersPolicy),
        Settings::PathEnd => Box::new(path_end::PathEndPolicy::new()),
        Settings::EnforceFirstAs => Box::new(enforce_first_as::EnforceFirstASPolicy),
        Settings::Aspa => Box::new(aspa::ASPAPolicy),
        Settings::Bgpsec => Box::new(bgpsec::BGPSecPolicy),
        Settings::RovppV1Lite => Box::new(rovppv1_lite::ROVPPV1LitePolicy::new()),
        Settings::PeerLockLite => Box::new(peerlock_lite::PeerlockLitePolicy),
        Settings::EdgeFilter => Box::new(as_path_edge_filter::ASPathEdgeFilterPolicy),
        _ => Box::new(bgp::BGPPolicy), // Default to BGP for unimplemented policies
    }
}