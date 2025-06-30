use std::collections::HashSet;
use ipnetwork::IpNetwork;
use std::str::FromStr;

use bgpsimulator::as_graph::AS;
use bgpsimulator::policies::*;
use bgpsimulator::shared::{Relationships, Settings, Timestamps, ROAValidity};
use bgpsimulator::simulation_engine::Announcement;
use bgpsimulator::route_validator::RouteValidator;

fn create_test_as() -> AS {
    AS::from_asn_sets(
        65001,
        HashSet::from([65002, 65003]),  // peers
        HashSet::from([65004]),          // providers
        HashSet::from([65005, 65006]),   // customers
    )
}

fn create_test_announcement() -> Announcement {
    Announcement::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        vec![65002, 65007],  // AS path - doesn't contain 65001
        65002,               // Next hop
        Relationships::Peers,
        Timestamps::Victim,
    )
}

#[test]
fn test_bgp_policy_validation() {
    let policy = BGPPolicy;
    let as_obj = create_test_as();
    let mut ann = create_test_announcement();
    
    // Valid announcement
    assert!(policy.validate_announcement(&ann, Relationships::Peers, &as_obj, None));
    
    // Invalid: loop detection (AS already in path)
    ann.as_path.push(65001);
    assert!(!policy.validate_announcement(&ann, Relationships::Peers, &as_obj, None));
    
    // Invalid: empty AS path from non-origin
    let mut empty_path_ann = ann.clone();
    empty_path_ann.as_path.clear();
    assert!(!policy.validate_announcement(&empty_path_ann, Relationships::Peers, &as_obj, None));
    
    // Valid: empty AS path from origin
    assert!(policy.validate_announcement(&empty_path_ann, Relationships::Origin, &as_obj, None));
}

#[test]
fn test_bgp_policy_propagation() {
    let policy = BGPPolicy;
    let ann = create_test_announcement();
    
    // Test Gao-Rexford propagation rules
    
    // From Origin: propagate to all
    assert!(policy.should_propagate(&ann, Relationships::Origin, Relationships::Customers));
    assert!(policy.should_propagate(&ann, Relationships::Origin, Relationships::Peers));
    assert!(policy.should_propagate(&ann, Relationships::Origin, Relationships::Providers));
    
    // From Customers: propagate to all
    assert!(policy.should_propagate(&ann, Relationships::Customers, Relationships::Customers));
    assert!(policy.should_propagate(&ann, Relationships::Customers, Relationships::Peers));
    assert!(policy.should_propagate(&ann, Relationships::Customers, Relationships::Providers));
    
    // From Peers: only to customers
    assert!(policy.should_propagate(&ann, Relationships::Peers, Relationships::Customers));
    assert!(!policy.should_propagate(&ann, Relationships::Peers, Relationships::Peers));
    assert!(!policy.should_propagate(&ann, Relationships::Peers, Relationships::Providers));
    
    // From Providers: only to customers
    assert!(policy.should_propagate(&ann, Relationships::Providers, Relationships::Customers));
    assert!(!policy.should_propagate(&ann, Relationships::Providers, Relationships::Peers));
    assert!(!policy.should_propagate(&ann, Relationships::Providers, Relationships::Providers));
}

#[test]
fn test_rov_policy_validation() {
    let mut policy = ROVPolicy::new();
    let as_obj = create_test_as();
    
    // Add ROA to validator
    policy.route_validator.add_roa(bgpsimulator::route_validator::ROA::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        65001,  // Authorized origin
        Some(24),
    ));
    
    // Valid announcement (correct origin)
    let valid_ann = Announcement::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        vec![65002, 65008],  // AS path with 65008 as origin (authorized by modifying ROA)
        65002,
        Relationships::Peers,
        Timestamps::Victim,
    );
    // Add ROA for 65008 instead
    policy.route_validator.add_roa(bgpsimulator::route_validator::ROA::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        65008,  // Authorized origin
        Some(24),
    ));
    assert!(policy.validate_announcement(&valid_ann, Relationships::Peers, &as_obj, None));
    
    // Invalid announcement (wrong origin)
    let invalid_ann = Announcement::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        vec![65002, 65003],  // AS path with 65003 as origin (not authorized)
        65002,
        Relationships::Peers,
        Timestamps::Victim,
    );
    assert!(!policy.validate_announcement(&invalid_ann, Relationships::Peers, &as_obj, None));
}

#[test]
fn test_only_to_customers_policy() {
    let mut policy = OnlyToCustomersPolicy;
    let as_obj = create_test_as();
    let mut ann = create_test_announcement();
    
    // Process announcement from peer - should mark as only to customers
    let result = policy.process_announcement(&mut ann, Relationships::Peers, &as_obj);
    assert!(matches!(result, ProcessingResult::Modified));
    assert_eq!(ann.only_to_customers, Some(true));
    
    // Check propagation - should only go to customers
    assert!(policy.should_propagate(&ann, Relationships::Peers, Relationships::Customers));
    assert!(!policy.should_propagate(&ann, Relationships::Peers, Relationships::Peers));
    assert!(!policy.should_propagate(&ann, Relationships::Peers, Relationships::Providers));
    
    // Process announcement from customer - should not modify
    let mut ann2 = create_test_announcement();
    let result2 = policy.process_announcement(&mut ann2, Relationships::Customers, &as_obj);
    assert!(matches!(result2, ProcessingResult::Accept));
}

#[test]
fn test_enforce_first_as_policy() {
    let policy = EnforceFirstASPolicy;
    let as_obj = create_test_as();
    
    // Valid: next hop is first AS and is a neighbor
    let valid_ann = Announcement::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        vec![65002, 65007],  // First AS is 65002 (peer)
        65002,               // Next hop matches first AS
        Relationships::Peers,
        Timestamps::Victim,
    );
    assert!(policy.validate_announcement(&valid_ann, Relationships::Peers, &as_obj, None));
    
    // Invalid: next hop doesn't match first AS
    let invalid_ann1 = Announcement::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        vec![65002, 65007],  // First AS is 65002
        65003,               // Next hop doesn't match
        Relationships::Peers,
        Timestamps::Victim,
    );
    assert!(!policy.validate_announcement(&invalid_ann1, Relationships::Peers, &as_obj, None));
    
    // Invalid: next hop is not a neighbor
    let invalid_ann2 = Announcement::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        vec![65999, 65007],  // First AS is 65999 (not a neighbor)
        65999,               // Next hop matches but not a neighbor
        Relationships::Peers,
        Timestamps::Victim,
    );
    assert!(!policy.validate_announcement(&invalid_ann2, Relationships::Peers, &as_obj, None));
}

#[test]
fn test_bgpsec_policy() {
    let mut policy = BGPSecPolicy;
    let as_obj = create_test_as();
    
    // Valid BGPSec announcement
    let mut valid_ann = create_test_announcement();
    valid_ann.bgpsec_next_asn = Some(65001);  // Receiving AS
    valid_ann.bgpsec_as_path = Some(vec![65002, 65007]);  // Must match AS path
    assert!(policy.validate_announcement(&valid_ann, Relationships::Peers, &as_obj, None));
    
    // Invalid BGPSec: wrong next ASN
    let mut invalid_ann1 = create_test_announcement();
    invalid_ann1.bgpsec_next_asn = Some(65999);  // Wrong next ASN
    invalid_ann1.bgpsec_as_path = Some(vec![65002, 65007]);  // Correct path but wrong next ASN
    assert!(!policy.validate_announcement(&invalid_ann1, Relationships::Peers, &as_obj, None));
    
    // Invalid BGPSec: path mismatch
    let mut invalid_ann2 = create_test_announcement();
    invalid_ann2.bgpsec_next_asn = Some(65001);
    invalid_ann2.bgpsec_as_path = Some(vec![65003, 65004]); // Different path
    assert!(!policy.validate_announcement(&invalid_ann2, Relationships::Peers, &as_obj, None));
    
    // No BGPSec info - should be valid (falls back to regular BGP)
    let regular_ann = create_test_announcement();
    assert!(policy.validate_announcement(&regular_ann, Relationships::Peers, &as_obj, None));
}

#[test]
fn test_policy_factory() {
    // Test that factory creates correct policy types
    let bgp_policy = create_policy_extension(Settings::BaseDefense);
    assert_eq!(bgp_policy.name(), "BGP");
    
    let rov_policy = create_policy_extension(Settings::Rov);
    assert_eq!(rov_policy.name(), "ROV");
    
    let peer_rov_policy = create_policy_extension(Settings::PeerRov);
    assert_eq!(peer_rov_policy.name(), "PeerROV");
    
    let otc_policy = create_policy_extension(Settings::OnlyToCustomers);
    assert_eq!(otc_policy.name(), "OnlyToCustomers");
    
    let bgpsec_policy = create_policy_extension(Settings::Bgpsec);
    assert_eq!(bgpsec_policy.name(), "BGPSec");
}