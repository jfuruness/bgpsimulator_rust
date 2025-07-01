use std::collections::HashMap;
use std::path::Path;

use bgpsimulator::as_graphs::as_graph::{ASBuilder, ASGraph};
use bgpsimulator::simulation_engine::{SimulationEngine, Announcement, Prefix};
use bgpsimulator::engine_runner::{EngineRunConfig, EngineRunner};
use bgpsimulator::shared::{CommonASNs, Outcomes, Settings, Relationships};
use bgpsimulator::simulation_framework::scenario_config::ScenarioConfig;

/// Create a simple test AS graph
fn create_test_as_graph_simple() -> ASGraph {
    // Create AS 1 (Provider)
    let as1_builder = ASBuilder::new(1)
        .as_tier_1()
        .with_customers(vec![2, 3]);
    
    // Create AS 2 (Customer of AS 1, Provider of AS 4)
    let as2_builder = ASBuilder::new(2)
        .with_providers(vec![1])
        .with_customers(vec![4]);
    
    // Create AS 3 (Customer of AS 1)
    let as3_builder = ASBuilder::new(3)
        .with_providers(vec![1]);
    
    // Create AS 4 (Customer of AS 2)
    let as4_builder = ASBuilder::new(4)
        .with_providers(vec![2]);
    
    // Build the graph
    let mut as_graph = ASGraph::build(vec![as1_builder, as2_builder, as3_builder, as4_builder]);
    as_graph.assign_as_propagation_rank();
    
    as_graph
}

#[test]
fn test_basic_propagation() {
    let as_graph = create_test_as_graph_simple();
    let mut engine = SimulationEngine::new(&as_graph);
    
    // Create announcement from AS 4
    let prefix: Prefix = "10.0.0.0/24".parse().unwrap();
    let ann = Announcement::new(
        prefix,
        4,  // next_hop_asn (originating from AS 4)
        Relationships::Origin,
    );
    
    // Setup with initial announcement
    engine.setup(vec![(4, ann)]);
    
    // Run simulation
    engine.run(5);
    
    // Check results
    let snapshot = engine.get_local_rib_snapshot();
    
    // AS 4 should have the announcement (originated it)
    assert!(snapshot.get(&4).unwrap().contains_key("10.0.0.0/24"));
    
    // AS 2 should receive from AS 4 (its customer)
    assert!(snapshot.get(&2).unwrap().contains_key("10.0.0.0/24"));
    let as2_path = &snapshot.get(&2).unwrap()["10.0.0.0/24"];
    assert_eq!(as2_path, &vec![2, 4]);
    
    // AS 1 should receive from AS 2 (its customer)
    assert!(snapshot.get(&1).unwrap().contains_key("10.0.0.0/24"));
    let as1_path = &snapshot.get(&1).unwrap()["10.0.0.0/24"];
    assert_eq!(as1_path, &vec![1, 2, 4]);
    
    // AS 3 should receive from AS 1 (its provider)
    assert!(snapshot.get(&3).unwrap().contains_key("10.0.0.0/24"));
    let as3_path = &snapshot.get(&3).unwrap()["10.0.0.0/24"];
    assert_eq!(as3_path, &vec![3, 1, 2, 4]);
}

#[test]
fn test_loop_prevention() {
    let as_graph = create_test_as_graph_simple();
    let mut engine = SimulationEngine::new(&as_graph);
    
    // Create announcement from AS 1 with a path that already contains AS 3
    let prefix: Prefix = "10.0.0.0/24".parse().unwrap();
    let mut ann = Announcement::new(
        prefix,
        1,
        Relationships::Origin,
    );
    ann.as_path = vec![1, 3, 4]; // Path already contains AS 3, but not AS 2
    
    // Setup with initial announcement
    engine.setup(vec![(1, ann)]);
    
    // Run simulation
    engine.run(5);
    
    // Check results
    let snapshot = engine.get_local_rib_snapshot();
    
    // AS 1 should have the announcement
    assert!(snapshot.get(&1).unwrap().contains_key("10.0.0.0/24"));
    
    // AS 2 should receive it
    assert!(snapshot.get(&2).unwrap().contains_key("10.0.0.0/24"));
    
    // AS 3 should NOT receive it (loop prevention)
    assert!(!snapshot.get(&3).unwrap().contains_key("10.0.0.0/24"));
}

#[test]
fn test_gao_rexford_export_rules() {
    let mut as_graph = ASGraph::new();
    
    // Create a diamond topology:
    //      AS 1 (Tier-1)
    //     /    \
    //   AS 2   AS 3  (peers with each other)
    //     \    /
    //      AS 4
    
    let as1_builder = ASBuilder::new(1)
        .as_tier_1()
        .with_customers(vec![2, 3]);
    
    let as2_builder = ASBuilder::new(2)
        .with_providers(vec![1])
        .with_peers(vec![3])
        .with_customers(vec![4]);
    
    let as3_builder = ASBuilder::new(3)
        .with_providers(vec![1])
        .with_peers(vec![2])
        .with_customers(vec![4]);
    
    let as4_builder = ASBuilder::new(4)
        .with_providers(vec![2, 3]);
    
    let mut as_graph = ASGraph::build(vec![as1_builder, as2_builder, as3_builder, as4_builder]);
    as_graph.assign_as_propagation_rank();
    
    let mut engine = SimulationEngine::new(&as_graph);
    
    // Announcement from AS 4
    let prefix: Prefix = "10.0.0.0/24".parse().unwrap();
    let ann = Announcement::new(prefix, 4, Relationships::Origin);
    
    engine.setup(vec![(4, ann)]);
    engine.run(5);
    
    let snapshot = engine.get_local_rib_snapshot();
    
    // All ASes should receive the announcement
    assert!(snapshot.get(&1).unwrap().contains_key("10.0.0.0/24"));
    assert!(snapshot.get(&2).unwrap().contains_key("10.0.0.0/24"));
    assert!(snapshot.get(&3).unwrap().contains_key("10.0.0.0/24"));
    assert!(snapshot.get(&4).unwrap().contains_key("10.0.0.0/24"));
    
    // Now test announcement from AS 3 (received from peer AS 2)
    let prefix2: Prefix = "20.0.0.0/24".parse().unwrap();
    let ann2 = Announcement::new(prefix2, 2, Relationships::Origin);
    
    engine.setup(vec![(2, ann2)]);
    engine.run(5);
    
    let snapshot2 = engine.get_local_rib_snapshot();
    
    // AS 2 originates
    assert!(snapshot2.get(&2).unwrap().contains_key("20.0.0.0/24"));
    
    // AS 1 receives from customer AS 2
    assert!(snapshot2.get(&1).unwrap().contains_key("20.0.0.0/24"));
    
    // AS 3 receives from peer AS 2
    assert!(snapshot2.get(&3).unwrap().contains_key("20.0.0.0/24"));
    
    // AS 4 receives from provider AS 2
    assert!(snapshot2.get(&4).unwrap().contains_key("20.0.0.0/24"));
}

#[test]
fn test_withdrawal() {
    let as_graph = create_test_as_graph_simple();
    let mut engine = SimulationEngine::new(&as_graph);
    
    // First announce a prefix
    let prefix: Prefix = "10.0.0.0/24".parse().unwrap();
    let ann = Announcement::new(prefix, 4, Relationships::Origin);
    
    engine.setup(vec![(4, ann)]);
    engine.run(5);
    
    // Verify all ASes have the route
    let snapshot = engine.get_local_rib_snapshot();
    assert!(snapshot.get(&1).unwrap().contains_key("10.0.0.0/24"));
    assert!(snapshot.get(&2).unwrap().contains_key("10.0.0.0/24"));
    assert!(snapshot.get(&3).unwrap().contains_key("10.0.0.0/24"));
    assert!(snapshot.get(&4).unwrap().contains_key("10.0.0.0/24"));
    
    // Now send a withdrawal
    let mut withdrawal = Announcement::new(prefix, 4, Relationships::Origin);
    withdrawal.withdraw = true;
    
    engine.setup(vec![(4, withdrawal)]);
    engine.run(5);
    
    // Verify all ASes have removed the route
    let snapshot2 = engine.get_local_rib_snapshot();
    assert!(!snapshot2.get(&1).unwrap().contains_key("10.0.0.0/24"));
    assert!(!snapshot2.get(&2).unwrap().contains_key("10.0.0.0/24"));
    assert!(!snapshot2.get(&3).unwrap().contains_key("10.0.0.0/24"));
    assert!(!snapshot2.get(&4).unwrap().contains_key("10.0.0.0/24"));
}