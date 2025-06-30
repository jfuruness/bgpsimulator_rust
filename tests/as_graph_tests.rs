use std::collections::HashSet;
use bgpsimulator::as_graph::{AS, ASGraph};

#[test]
fn test_as_creation() {
    let as1 = AS::from_asn_sets(
        100,
        HashSet::from([200, 300]),  // peers
        HashSet::from([400]),       // providers
        HashSet::from([500, 600]),  // customers
    );
    
    assert_eq!(as1.asn, 100);
    assert_eq!(as1.peers.len(), 2);
    assert_eq!(as1.providers.len(), 1);
    assert_eq!(as1.customers.len(), 2);
    assert!(as1.peers.contains(&200));
    assert!(as1.peers.contains(&300));
    assert!(as1.providers.contains(&400));
    assert!(as1.customers.contains(&500));
    assert!(as1.customers.contains(&600));
}

#[test]
fn test_as_graph_insertion() {
    let mut as_graph = ASGraph::new();
    
    let as1 = AS::from_asn_sets(
        1,
        HashSet::new(),
        HashSet::new(),
        HashSet::from([2]),
    );
    
    let as2 = AS::from_asn_sets(
        2,
        HashSet::new(),
        HashSet::from([1]),
        HashSet::new(),
    );
    
    as_graph.insert(as1);
    as_graph.insert(as2);
    
    assert_eq!(as_graph.as_dict.len(), 2);
    assert!(as_graph.get(&1).is_some());
    assert!(as_graph.get(&2).is_some());
}

#[test]
fn test_cycle_detection() {
    let mut as_graph = ASGraph::new();
    
    // Create a cycle: 1 -> 2 -> 3 -> 1
    let as1 = AS::from_asn_sets(
        1,
        HashSet::new(),
        HashSet::from([3]),  // Provider is 3
        HashSet::from([2]),  // Customer is 2
    );
    
    let as2 = AS::from_asn_sets(
        2,
        HashSet::new(),
        HashSet::from([1]),  // Provider is 1
        HashSet::from([3]),  // Customer is 3
    );
    
    let as3 = AS::from_asn_sets(
        3,
        HashSet::new(),
        HashSet::from([2]),  // Provider is 2
        HashSet::from([1]),  // Customer is 1
    );
    
    as_graph.insert(as1);
    as_graph.insert(as2);
    as_graph.insert(as3);
    
    // Should detect the cycle
    assert!(as_graph.check_for_cycles().is_err());
}

#[test]
fn test_no_cycle() {
    let mut as_graph = ASGraph::new();
    
    // Create a valid hierarchy: 1 -> 2 -> 3
    let as1 = AS::from_asn_sets(
        1,
        HashSet::new(),
        HashSet::new(),      // No providers (Tier 1)
        HashSet::from([2]),  // Customer is 2
    );
    
    let as2 = AS::from_asn_sets(
        2,
        HashSet::new(),
        HashSet::from([1]),  // Provider is 1
        HashSet::from([3]),  // Customer is 3
    );
    
    let as3 = AS::from_asn_sets(
        3,
        HashSet::new(),
        HashSet::from([2]),  // Provider is 2
        HashSet::new(),      // No customers
    );
    
    as_graph.insert(as1);
    as_graph.insert(as2);
    as_graph.insert(as3);
    
    // Should not detect any cycle
    assert!(as_graph.check_for_cycles().is_ok());
}

#[test]
fn test_propagation_rank_assignment() {
    let mut as_graph = ASGraph::new();
    
    // Create a hierarchy
    let mut as1 = AS::from_asn_sets(
        1,
        HashSet::new(),
        HashSet::new(),      // No providers (Tier 1)
        HashSet::from([2]),
    );
    as1.tier_1 = true;
    
    let as2 = AS::from_asn_sets(
        2,
        HashSet::new(),
        HashSet::from([1]),
        HashSet::from([3, 4]),
    );
    
    let as3 = AS::from_asn_sets(
        3,
        HashSet::new(),
        HashSet::from([2]),
        HashSet::new(),
    );
    
    let as4 = AS::from_asn_sets(
        4,
        HashSet::new(),
        HashSet::from([2]),
        HashSet::new(),
    );
    
    as_graph.insert(as1);
    as_graph.insert(as2);
    as_graph.insert(as3);
    as_graph.insert(as4);
    
    // Check for cycles first
    as_graph.check_for_cycles().expect("No cycles should exist");
    
    // Assign propagation ranks
    as_graph.assign_as_propagation_rank();
    
    // Check that ranks are assigned correctly
    let as1_obj = as_graph.get(&1).unwrap();
    let as2_obj = as_graph.get(&2).unwrap();
    let as3_obj = as_graph.get(&3).unwrap();
    let as4_obj = as_graph.get(&4).unwrap();
    
    assert_eq!(as1_obj.propagation_rank, Some(0), "Tier 1 AS should have rank 0");
    assert_eq!(as2_obj.propagation_rank, Some(1), "AS2 should have rank 1");
    assert_eq!(as3_obj.propagation_rank, Some(2), "AS3 should have rank 2");
    assert_eq!(as4_obj.propagation_rank, Some(2), "AS4 should have rank 2");
}

#[test]
fn test_as_neighbors() {
    let as1 = AS::from_asn_sets(
        1,
        HashSet::from([2, 3]),     // peers
        HashSet::from([4]),        // providers
        HashSet::from([5, 6]),     // customers
    );
    
    let provider_neighbors = as1.get_neighbors(bgpsimulator::shared::Relationships::Providers);
    assert_eq!(provider_neighbors.len(), 1);
    assert!(provider_neighbors.contains(&4));
    
    let peer_neighbors = as1.get_neighbors(bgpsimulator::shared::Relationships::Peers);
    assert_eq!(peer_neighbors.len(), 2);
    assert!(peer_neighbors.contains(&2));
    assert!(peer_neighbors.contains(&3));
    
    let customer_neighbors = as1.get_neighbors(bgpsimulator::shared::Relationships::Customers);
    assert_eq!(customer_neighbors.len(), 2);
    assert!(customer_neighbors.contains(&5));
    assert!(customer_neighbors.contains(&6));
}