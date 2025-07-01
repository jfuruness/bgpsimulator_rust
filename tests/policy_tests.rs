use std::collections::HashSet;
use ipnetwork::IpNetwork;
use std::str::FromStr;

use bgpsimulator::as_graphs::as_graph::{ASBuilder, ASGraph};
use bgpsimulator::simulation_engine::policy::policy_extensions::*;
use bgpsimulator::simulation_engine::policy::{PolicyExtension, ProcessingResult};
use bgpsimulator::shared::{Relationships, Settings, Timestamps, ROAValidity};
use bgpsimulator::simulation_engine::{Announcement, Prefix};
use bgpsimulator::route_validator::RouteValidator;

fn create_test_as_graph() -> ASGraph {
    let as1_builder = ASBuilder::new(65001)
        .with_peers(vec![65002, 65003])
        .with_providers(vec![65004])
        .with_customers(vec![65005, 65006]);
    
    let as2_builder = ASBuilder::new(65002)
        .with_peers(vec![65001]);
    
    let as3_builder = ASBuilder::new(65003)
        .with_peers(vec![65001]);
    
    let as4_builder = ASBuilder::new(65004)
        .with_customers(vec![65001]);
    
    let as5_builder = ASBuilder::new(65005)
        .with_providers(vec![65001]);
    
    let as6_builder = ASBuilder::new(65006)
        .with_providers(vec![65001]);
    
    ASGraph::build(vec![
        as1_builder,
        as2_builder,
        as3_builder,
        as4_builder,
        as5_builder,
        as6_builder,
    ])
}

fn create_test_announcement() -> Announcement {
    Announcement::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        65002,               // Next hop
        Relationships::Peers,
    )
}

#[test]
fn test_bgp_policy_validation() {
    let policy = BGPPolicy;
    let as_graph = create_test_as_graph();
    let as_obj = as_graph.get(&65001).unwrap();
    let mut ann = create_test_announcement();
    ann.as_path = vec![65002, 65007]; // Doesn't contain 65001
    
    // Valid announcement
    assert!(policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
    
    // Invalid: loop detection (AS already in path)
    ann.as_path.push(65001);
    assert!(!policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
    
    // Invalid: empty AS path from non-origin
    let mut empty_path_ann = ann.clone();
    empty_path_ann.as_path.clear();
    assert!(!policy.validate_announcement(&empty_path_ann, Relationships::Peers, as_obj, None));
    
    // Valid: empty AS path from origin
    assert!(policy.validate_announcement(&empty_path_ann, Relationships::Origin, as_obj, None));
}

#[test]
fn test_gao_rexford_preferences() {
    let policy = BGPPolicy;
    
    assert_eq!(policy.get_gao_rexford_preference(Relationships::Customers), 3);
    assert_eq!(policy.get_gao_rexford_preference(Relationships::Peers), 2);
    assert_eq!(policy.get_gao_rexford_preference(Relationships::Providers), 1);
    assert_eq!(policy.get_gao_rexford_preference(Relationships::Origin), 0);
}

#[test]
fn test_propagation_rules() {
    let policy = BGPPolicy;
    
    // Origin can propagate to anyone
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Origin, Relationships::Customers));
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Origin, Relationships::Peers));
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Origin, Relationships::Providers));
    
    // Customers can propagate to anyone
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Customers, Relationships::Customers));
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Customers, Relationships::Peers));
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Customers, Relationships::Providers));
    
    // Peers can only propagate to customers
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Peers, Relationships::Customers));
    assert!(!policy.should_propagate(&create_test_announcement(), Relationships::Peers, Relationships::Peers));
    assert!(!policy.should_propagate(&create_test_announcement(), Relationships::Peers, Relationships::Providers));
    
    // Providers can only propagate to customers
    assert!(policy.should_propagate(&create_test_announcement(), Relationships::Providers, Relationships::Customers));
    assert!(!policy.should_propagate(&create_test_announcement(), Relationships::Providers, Relationships::Peers));
    assert!(!policy.should_propagate(&create_test_announcement(), Relationships::Providers, Relationships::Providers));
}

#[test]
fn test_only_to_customers_policy() {
    let mut policy = OnlyToCustomersPolicy;
    let as_graph = create_test_as_graph();
    let as_obj = as_graph.get(&65001).unwrap();
    let mut ann = create_test_announcement();
    
    // Process announcement from peer - should mark as only_to_customers
    let result = policy.process_announcement(&mut ann, Relationships::Peers, as_obj);
    assert_eq!(result, ProcessingResult::Modified);
    assert_eq!(ann.only_to_customers, Some(true));
    
    // Should only propagate to customers
    assert!(policy.should_propagate(&ann, Relationships::Peers, Relationships::Customers));
    assert!(!policy.should_propagate(&ann, Relationships::Peers, Relationships::Peers));
    assert!(!policy.should_propagate(&ann, Relationships::Peers, Relationships::Providers));
    
    // Process announcement from customer - should not mark
    let mut ann2 = create_test_announcement();
    let result2 = policy.process_announcement(&mut ann2, Relationships::Customers, as_obj);
    assert_eq!(result2, ProcessingResult::Accept);
    assert_eq!(ann2.only_to_customers, None);
}

#[test]
fn test_rov_policy() {
    let mut rov_policy = ROVPolicy::new();
    let as_graph = create_test_as_graph();
    let as_obj = as_graph.get(&65001).unwrap();
    
    // Add a valid ROA
    let prefix: Prefix = "10.0.0.0/24".parse().unwrap();
    let roa = bgpsimulator::route_validator::ROA::new(prefix, 65007, Some(24));
    rov_policy.route_validator.add_roa(roa);
    
    // Valid: origin matches ROA
    let mut ann = create_test_announcement();
    ann.as_path = vec![65002, 65007]; // Origin is 65007
    assert!(rov_policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
    
    // Invalid: origin doesn't match ROA
    ann.as_path = vec![65002, 65008]; // Origin is 65008
    assert!(!rov_policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
    
    // Valid: unknown prefix (no ROA)
    let unknown_prefix: Prefix = "20.0.0.0/24".parse().unwrap();
    ann.prefix = unknown_prefix;
    assert!(rov_policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
}

#[test]
fn test_enforce_first_as_policy() {
    let policy = EnforceFirstASPolicy;
    let as_graph = create_test_as_graph();
    let as_obj = as_graph.get(&65001).unwrap();
    let mut ann = create_test_announcement();
    ann.as_path = vec![65002, 65007];
    
    // Valid: first AS in path matches next hop and is a neighbor (peer)
    assert!(policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
    
    // Invalid: first AS doesn't match next hop
    ann.next_hop_asn = 65003;
    assert!(!policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
    
    // Invalid: next hop is not a neighbor
    ann.next_hop_asn = 65009;
    ann.as_path = vec![65009, 65007];
    assert!(!policy.validate_announcement(&ann, Relationships::Peers, as_obj, None));
}