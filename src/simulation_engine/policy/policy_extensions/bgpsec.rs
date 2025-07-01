use std::cmp::Ordering;
use crate::as_graphs::as_graph::{AS};
use crate::shared::{Relationships};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension, ProcessingResult};
use crate::route_validator::RouteValidator;

/// BGPSec policy - cryptographic path validation
pub struct BGPSecPolicy;

impl PolicyExtension for BGPSecPolicy {
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
        
        // BGPSec validation - check if secure path matches AS path
        if let Some(bgpsec_path) = &ann.bgpsec_as_path {
            ann.bgpsec_next_asn == Some(as_obj.asn) && bgpsec_path == &ann.as_path
        } else {
            true // No BGPSec path means regular BGP validation
        }
    }
    
    fn process_announcement(
        &mut self,
        ann: &mut Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
    ) -> ProcessingResult {
        // If BGPSec is valid, maintain the secure path
        if let Some(bgpsec_path) = &ann.bgpsec_as_path {
            if ann.bgpsec_next_asn == Some(as_obj.asn) && 
               bgpsec_path.get(1..) == Some(&ann.as_path[1..]) {
                // Valid BGPSec, update with our ASN
                ann.bgpsec_as_path = Some(ann.as_path.clone());
                ProcessingResult::Modified
            } else {
                // Invalid BGPSec, clear the path
                ann.bgpsec_as_path = None;
                ProcessingResult::Modified
            }
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
        // Use default Gao-Rexford rules
        match (recv_relationship, send_relationship) {
            (Relationships::Origin, _) => true,
            (Relationships::Customers, _) => true,
            (Relationships::Peers, Relationships::Customers) => true,
            (Relationships::Providers, Relationships::Customers) => true,
            _ => false,
        }
    }
    
    fn compare_announcements(
        &self,
        ann1: &Announcement,
        ann2: &Announcement,
        rel1: Relationships,
        rel2: Relationships,
        as_obj: &AS,
    ) -> Ordering {
        // Prefer BGPSec valid announcements
        let ann1_valid = ann1.bgpsec_as_path.is_some() && 
                        ann1.bgpsec_as_path.as_ref() == Some(&ann1.as_path);
        let ann2_valid = ann2.bgpsec_as_path.is_some() && 
                        ann2.bgpsec_as_path.as_ref() == Some(&ann2.as_path);
        
        match (ann1_valid, ann2_valid) {
            (true, false) => Ordering::Less, // ann1 is better
            (false, true) => Ordering::Greater, // ann2 is better
            _ => {
                // Both valid or both invalid, use standard comparison
                let pref1 = self.get_gao_rexford_preference(rel1);
                let pref2 = self.get_gao_rexford_preference(rel2);
                
                match pref2.cmp(&pref1) {
                    Ordering::Equal => {
                        match ann1.as_path.len().cmp(&ann2.as_path.len()) {
                            Ordering::Equal => ann1.next_hop_asn.cmp(&ann2.next_hop_asn),
                            other => other,
                        }
                    }
                    other => other,
                }
            }
        }
    }
    
    fn name(&self) -> &str {
        "BGPSec"
    }
}