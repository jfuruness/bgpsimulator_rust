use std::cmp::Ordering;
use std::collections::HashMap;

use crate::shared::{Relationships, Settings};
use crate::as_graph::{AS, ASN, ASGraph};
use crate::simulation_engine::{Announcement, Prefix};
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

/// Basic BGP policy implementation
pub struct BGPPolicy;

impl PolicyExtension for BGPPolicy {
    fn name(&self) -> &str {
        "BGP"
    }
}

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
        
        use crate::shared::ROAValidity;
        match validity {
            ROAValidity::Valid => true,
            ROAValidity::Unknown => true, // Unknown is allowed in basic ROV
            _ => false, // Reject invalid announcements
        }
    }
    
    fn name(&self) -> &str {
        "ROV"
    }
}

impl ROVPolicy {
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

/// Peer ROV policy - only accepts ROV-valid routes from peers
pub struct PeerROVPolicy {
    pub route_validator: RouteValidator,
}

impl PeerROVPolicy {
    pub fn new() -> Self {
        PeerROVPolicy {
            route_validator: RouteValidator::new(),
        }
    }
}

impl PolicyExtension for PeerROVPolicy {
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
        
        // Check ROA validity - stricter for peers
        let origin = ann.as_path.last().copied().unwrap_or(ann.next_hop_asn);
        let (validity, _) = self.route_validator.get_roa_outcome(&ann.prefix, origin);
        
        use crate::shared::ROAValidity;
        match validity {
            ROAValidity::Valid => true,
            ROAValidity::Unknown => {
                // Only accept unknown from non-peers
                recv_relationship != Relationships::Peers
            }
            _ => false, // Reject invalid announcements
        }
    }
    
    fn name(&self) -> &str {
        "PeerROV"
    }
}

impl PeerROVPolicy {
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

/// Only to Customers policy - marks announcements to only go to customers
pub struct OnlyToCustomersPolicy;

impl PolicyExtension for OnlyToCustomersPolicy {
    fn process_announcement(
        &mut self,
        ann: &mut Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
    ) -> ProcessingResult {
        // Mark announcement as only for customers if received from peer/provider
        if recv_relationship == Relationships::Peers || recv_relationship == Relationships::Providers {
            ann.only_to_customers = Some(true);
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
        // Check if announcement is marked as only to customers
        if ann.only_to_customers.unwrap_or(false) {
            // Only propagate to customers
            send_relationship == Relationships::Customers
        } else {
            // Use default Gao-Rexford rules
            match (recv_relationship, send_relationship) {
                (Relationships::Origin, _) => true,
                (Relationships::Customers, _) => true,
                (Relationships::Peers, Relationships::Customers) => true,
                (Relationships::Providers, Relationships::Customers) => true,
                _ => false,
            }
        }
    }
    
    fn name(&self) -> &str {
        "OnlyToCustomers"
    }
}

/// Path-End policy - extends ROV by checking next-hop of origin
pub struct PathEndPolicy {
    pub route_validator: RouteValidator,
}

impl PathEndPolicy {
    pub fn new() -> Self {
        PathEndPolicy {
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

impl PolicyExtension for PathEndPolicy {
    fn validate_announcement(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
        route_validator: Option<&RouteValidator>,
    ) -> bool {
        // First do standard validation
        if !self.default_validate(ann, recv_relationship, as_obj) {
            return false;
        }
        
        // Then check ROA validity
        let origin = ann.as_path.last().copied().unwrap_or(ann.next_hop_asn);
        let (validity, _) = self.route_validator.get_roa_outcome(&ann.prefix, origin);
        
        use crate::shared::ROAValidity;
        if !matches!(validity, ROAValidity::Valid | ROAValidity::Unknown) {
            return false;
        }
        
        // Path-End specific validation
        if ann.as_path.len() > 1 {
            // Check if origin AS has Path-End enabled
            // Note: We need access to ASGraph to check origin's settings
            // For now, we'll just do the neighbor check
            true  // TODO: Implement proper Path-End check when we have ASGraph access
        } else {
            true
        }
    }
    
    fn name(&self) -> &str {
        "PathEnd"
    }
}

/// Enforce First AS policy - ensures first AS in path is a neighbor
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
        
        // Ensure first ASN in path is the next hop
        if !ann.as_path.is_empty() {
            if let Some(first_asn) = ann.as_path.first() {
                if *first_asn != ann.next_hop_asn {
                    return false;
                }
            }
        }
        
        // Check if next hop is a neighbor
        as_obj.customers.contains(&ann.next_hop_asn) ||
        as_obj.providers.contains(&ann.next_hop_asn) ||
        as_obj.peers.contains(&ann.next_hop_asn)
    }
    
    fn name(&self) -> &str {
        "EnforceFirstAS"
    }
}

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
        
        use crate::shared::ROAValidity;
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

/// AS Path Edge Filter policy - filters based on AS path edges
pub struct ASPathEdgeFilterPolicy;

impl PolicyExtension for ASPathEdgeFilterPolicy {
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
        
        // TODO: Implement AS path edge filtering logic
        // This requires checking if consecutive AS pairs in the path are valid
        true
    }
    
    fn name(&self) -> &str {
        "ASPathEdgeFilter"
    }
}

/// Factory function to create policy based on Settings
pub fn create_policy_extension(settings: Settings) -> Box<dyn PolicyExtension> {
    match settings {
        Settings::BaseDefense => Box::new(BGPPolicy),
        Settings::Rov => Box::new(ROVPolicy::new()),
        Settings::PeerRov => Box::new(PeerROVPolicy::new()),
        Settings::OnlyToCustomers => Box::new(OnlyToCustomersPolicy),
        Settings::PathEnd => Box::new(PathEndPolicy::new()),
        Settings::EnforceFirstAs => Box::new(EnforceFirstASPolicy),
        Settings::Aspa => Box::new(ASPAPolicy),
        Settings::Bgpsec => Box::new(BGPSecPolicy),
        Settings::RovppV1Lite => Box::new(ROVPPV1LitePolicy::new()),
        Settings::PeerLockLite => Box::new(PeerlockLitePolicy),
        Settings::EdgeFilter => Box::new(ASPathEdgeFilterPolicy),
        // Add more policies as implemented
        _ => Box::new(BGPPolicy), // Default to BGP for unimplemented policies
    }
}