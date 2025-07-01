use std::collections::HashSet;
use bgpsimulator::as_graphs::as_graph::{ASBuilder, ASGraph};

#[test]
fn test_as_graph_creation() {
    // Create AS builders
    let as1_builder = ASBuilder::new(1)
        .with_customers(vec![2, 3])
        .with_providers(vec![4]);
    
    let as2_builder = ASBuilder::new(2)
        .with_providers(vec![1]);
    
    let as3_builder = ASBuilder::new(3)
        .with_providers(vec![1]);
    
    let as4_builder = ASBuilder::new(4)
        .with_customers(vec![1]);
    
    // Build graph with all ASes at once
    let as_graph = ASGraph::build(vec![as1_builder, as2_builder, as3_builder, as4_builder]);
    
    // Test the graph
    assert_eq!(as_graph.len(), 4);
    
    let as1 = as_graph.get(&1).unwrap();
    assert_eq!(as1.asn, 1);
    assert_eq!(as1.customers.len(), 2);
    assert_eq!(as1.providers.len(), 1);
    
    // Check relationships are bidirectional
    let as2 = as_graph.get(&2).unwrap();
    assert_eq!(as2.providers.len(), 1);
    assert_eq!(as2.providers[0].asn, 1);
    
    let as4 = as_graph.get(&4).unwrap();
    assert_eq!(as4.customers.len(), 1);
    assert_eq!(as4.customers[0].asn, 1);
}

#[test]
fn test_as_graph_neighbors() {
    // Create a simple graph: 1 - 2 - 3 (1 is provider of 2, 2 is provider of 3)
    let as1_builder = ASBuilder::new(1)
        .with_customers(vec![2]);
    
    let as2_builder = ASBuilder::new(2)
        .with_providers(vec![1])
        .with_customers(vec![3]);
    
    let as3_builder = ASBuilder::new(3)
        .with_providers(vec![2]);
    
    let as_graph = ASGraph::build(vec![as1_builder, as2_builder, as3_builder]);
    
    // Test neighbor relationships
    let as2 = as_graph.get(&2).unwrap();
    assert_eq!(as2.neighbors().count(), 2); // has 1 provider and 1 customer
    
    let neighbor_asns: HashSet<_> = as2.neighbors().map(|as_obj| as_obj.asn).collect();
    assert!(neighbor_asns.contains(&1));
    assert!(neighbor_asns.contains(&3));
}

#[test]
fn test_as_graph_peering() {
    // Create two ASes that peer with each other
    let as1_builder = ASBuilder::new(100)
        .with_peers(vec![200]);
    
    let as2_builder = ASBuilder::new(200)
        .with_peers(vec![100]);
    
    let as_graph = ASGraph::build(vec![as1_builder, as2_builder]);
    
    let as1 = as_graph.get(&100).unwrap();
    let as2 = as_graph.get(&200).unwrap();
    
    assert_eq!(as1.peers.len(), 1);
    assert_eq!(as1.peers[0].asn, 200);
    assert_eq!(as2.peers.len(), 1);
    assert_eq!(as2.peers[0].asn, 100);
}

#[test]
fn test_as_graph_tier1() {
    // Create a tier-1 AS with no providers
    let tier1_builder = ASBuilder::new(1000)
        .as_tier_1()
        .with_customers(vec![2000, 3000]);
    
    let as2_builder = ASBuilder::new(2000)
        .with_providers(vec![1000]);
    
    let as3_builder = ASBuilder::new(3000)
        .with_providers(vec![1000]);
    
    let as_graph = ASGraph::build(vec![tier1_builder, as2_builder, as3_builder]);
    
    let tier1 = as_graph.get(&1000).unwrap();
    assert!(tier1.tier_1);
    assert!(tier1.providers.is_empty());
    assert_eq!(tier1.customers.len(), 2);
}

#[test]
fn test_as_graph_propagation_ranks() {
    // Create a hierarchy: 1 -> 2 -> 3, 1 -> 4
    let as1_builder = ASBuilder::new(1)
        .as_tier_1()
        .with_customers(vec![2, 4]);
    
    let as2_builder = ASBuilder::new(2)
        .with_providers(vec![1])
        .with_customers(vec![3]);
    
    let as3_builder = ASBuilder::new(3)
        .with_providers(vec![2]);
    
    let as4_builder = ASBuilder::new(4)
        .with_providers(vec![1]);
    
    let mut as_graph = ASGraph::build(vec![as1_builder, as2_builder, as3_builder, as4_builder]);
    as_graph.assign_as_propagation_rank();
    
    // Check ranks
    let as1 = as_graph.get(&1).unwrap();
    let as2 = as_graph.get(&2).unwrap();
    let as3 = as_graph.get(&3).unwrap();
    let as4 = as_graph.get(&4).unwrap();
    
    assert_eq!(as1.propagation_rank, Some(0)); // Tier-1
    assert_eq!(as2.propagation_rank, Some(1)); // Direct customer of tier-1
    assert_eq!(as4.propagation_rank, Some(1)); // Direct customer of tier-1
    assert_eq!(as3.propagation_rank, Some(2)); // Customer of AS2
}