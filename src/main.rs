// Use the library crate modules
use bgpsimulator::*;

use std::collections::HashSet;
use ipnetwork::IpNetwork;
use std::str::FromStr;

use bgpsimulator::as_graphs::as_graph::{ASBuilder, ASGraph};
use bgpsimulator::simulation_engine::{SimulationEngine, Announcement};
use bgpsimulator::engine_runner::{EngineRunConfig, EngineRunner};
use bgpsimulator::simulation_framework::scenario_config::ScenarioConfig;
use bgpsimulator::shared::{CommonASNs, Relationships, Settings, Timestamps};

fn main() {
    println!("BGP Simulator - Rust\n");
    
    // Run different examples
    run_simple_propagation_example();
    println!("\n{}\n", "=".repeat(80));
    run_hijack_scenario_example();
    println!("\n{}\n", "=".repeat(80));
    run_defense_scenario_example();
}

/// Example 1: Simple BGP propagation
fn run_simple_propagation_example() {
    println!("Example 1: Simple BGP Propagation");
    println!("---------------------------------");
    
    // Create a simple AS topology
    let mut as_graph = create_simple_topology();
    
    // Initialize the AS graph
    as_graph.check_for_cycles().expect("No cycles should exist");
    as_graph.assign_as_propagation_rank();
    as_graph.add_asn_groups();
    
    // Create simulation engine
    let mut engine = SimulationEngine::new(&as_graph);
    
    // Create an initial announcement from AS 65003
    let prefix = IpNetwork::from_str("10.0.0.0/24").unwrap();
    let announcement = Announcement::new_with_path(
        prefix,
        vec![],       // Empty AS path for originated announcements
        65003,        // Next hop
        Relationships::Origin,
        Timestamps::Victim,
    );
    
    // Seed the announcement
    engine.setup(vec![(65003, announcement)]);
    
    // Run simulation for 5 rounds
    println!("\nRunning simulation for 5 rounds...");
    engine.run(5);
    
    // Print results
    println!("\nFinal routing state:");
    let snapshot = engine.get_local_rib_snapshot();
    
    for (asn, ribs) in snapshot {
        if !ribs.is_empty() {
            println!("\nAS {}: ", asn);
            for (prefix, path) in ribs {
                println!("  {} -> {:?}", prefix, path);
            }
        }
    }
}

/// Example 2: Subprefix hijack scenario
fn run_hijack_scenario_example() {
    println!("Example 2: Subprefix Hijack Attack");
    println!("----------------------------------");
    
    let as_graph = create_attack_topology();
    let mut engine = SimulationEngine::new(&as_graph);
    
    // Create legitimate and hijack announcements
    let legitimate_prefix = IpNetwork::from_str("10.0.0.0/24").unwrap();
    let hijacked_prefix = IpNetwork::from_str("10.0.0.0/25").unwrap();
    
    let legitimate_ann = Announcement::new_with_path(
        legitimate_prefix,
        vec![],
        CommonASNs::VICTIM,
        Relationships::Origin,
        Timestamps::Victim,
    );
    
    let hijack_ann = Announcement::new_with_path(
        hijacked_prefix,
        vec![],
        CommonASNs::ATTACKER,
        Relationships::Origin,
        Timestamps::Victim,
    );
    
    // Seed both announcements
    engine.setup(vec![
        (CommonASNs::VICTIM, legitimate_ann),
        (CommonASNs::ATTACKER, hijack_ann),
    ]);
    
    println!("\nVictim AS {} announces: {}", CommonASNs::VICTIM, legitimate_prefix);
    println!("Attacker AS {} announces: {} (more specific)", CommonASNs::ATTACKER, hijacked_prefix);
    
    // Run simulation
    engine.run(10);
    
    // Check who prefers which route
    println!("\nAttack results:");
    let mut victim_count = 0;
    let mut attacker_count = 0;
    
    for (asn, policy) in engine.policy_store.iter() {
        if let Some(ann) = policy.local_rib.get(&hijacked_prefix) {
            if ann.origin() == CommonASNs::ATTACKER {
                attacker_count += 1;
            }
        } else if let Some(ann) = policy.local_rib.get(&legitimate_prefix) {
            if ann.origin() == CommonASNs::VICTIM {
                victim_count += 1;
            }
        }
    }
    
    println!("ASes routing to attacker: {}", attacker_count);
    println!("ASes routing to victim: {}", victim_count);
    println!("Attack success rate: {:.1}%", 
             (attacker_count as f64 / (attacker_count + victim_count) as f64) * 100.0);
}

/// Example 3: Defense with ROV
fn run_defense_scenario_example() {
    println!("Example 3: Defense with ROV (Route Origin Validation)");
    println!("----------------------------------------------------");
    
    let as_graph = create_attack_topology();
    let mut engine = SimulationEngine::new(&as_graph);
    
    // Enable ROV for 50% of ASes
    let all_asns: Vec<u32> = engine.as_graph.as_dict.keys().copied().collect();
    let adopting_count = all_asns.len() / 2;
    
    println!("\nEnabling ROV for {} out of {} ASes", adopting_count, all_asns.len());
    
    for i in 0..adopting_count {
        if let Some(policy) = engine.policy_store.get_mut(&all_asns[i]) {
            policy.settings = Settings::Rov;
            policy.extension = bgpsimulator::simulation_engine::policy::create_policy_extension(Settings::Rov);
        }
    }
    
    // Create ROA for legitimate prefix
    let mut route_validator = bgpsimulator::route_validator::RouteValidator::new();
    route_validator.add_roa(bgpsimulator::route_validator::ROA::new(
        IpNetwork::from_str("10.0.0.0/24").unwrap(),
        CommonASNs::VICTIM,
        Some(24),  // Max length 24 - subprefixes will be invalid
    ));
    
    // Re-run the same attack
    let legitimate_prefix = IpNetwork::from_str("10.0.0.0/24").unwrap();
    let hijacked_prefix = IpNetwork::from_str("10.0.0.0/25").unwrap();
    
    let legitimate_ann = Announcement::new_with_path(
        legitimate_prefix,
        vec![],
        CommonASNs::VICTIM,
        Relationships::Origin,
        Timestamps::Victim,
    );
    
    let hijack_ann = Announcement::new_with_path(
        hijacked_prefix,
        vec![],
        CommonASNs::ATTACKER,
        Relationships::Origin,
        Timestamps::Victim,
    );
    
    engine.setup(vec![
        (CommonASNs::VICTIM, legitimate_ann),
        (CommonASNs::ATTACKER, hijack_ann),
    ]);
    
    engine.run(10);
    
    // Check results with defense
    println!("\nDefense results:");
    let mut protected_count = 0;
    let mut vulnerable_count = 0;
    
    for i in 0..all_asns.len() {
        let asn = all_asns[i];
        if let Some(policy) = engine.policy_store.get(&asn) {
            let has_rov = i < adopting_count;
            
            if let Some(ann) = policy.local_rib.get(&hijacked_prefix) {
                if ann.origin() == CommonASNs::ATTACKER {
                    if has_rov {
                        println!("WARNING: ROV AS {} still vulnerable!", asn);
                    }
                    vulnerable_count += 1;
                }
            } else if let Some(ann) = policy.local_rib.get(&legitimate_prefix) {
                if ann.origin() == CommonASNs::VICTIM {
                    protected_count += 1;
                }
            }
        }
    }
    
    println!("ASes protected (routing to victim): {}", protected_count);
    println!("ASes vulnerable (routing to attacker): {}", vulnerable_count);
    println!("Protection rate: {:.1}%", 
             (protected_count as f64 / (protected_count + vulnerable_count) as f64) * 100.0);
}

fn create_simple_topology() -> ASGraph {
    // Create AS 65001 (Tier 1)
    let as1_builder = ASBuilder::new(65001)
        .as_tier_1()
        .with_customers(vec![65002]);
    
    // Create AS 65002 (Transit)
    let as2_builder = ASBuilder::new(65002)
        .with_providers(vec![65001])
        .with_customers(vec![65003]);
    
    // Create AS 65003 (Stub)
    let as3_builder = ASBuilder::new(65003)
        .with_providers(vec![65002]);
    
    // Build graph
    ASGraph::build(vec![as1_builder, as2_builder, as3_builder])
}

fn create_attack_topology() -> ASGraph {
    let mut builders = Vec::new();
    
    // Create victim and attacker
    builders.push(
        ASBuilder::new(CommonASNs::VICTIM)
            .with_providers(vec![1, 2])
    );
    
    builders.push(
        ASBuilder::new(CommonASNs::ATTACKER)
            .with_providers(vec![3, 4])
    );
    
    // Create intermediate ASes
    for i in 1..=10 {
        let mut builder = ASBuilder::new(i);
        
        if i <= 4 {
            // ASes 1-4 have providers 5-8
            builder = builder.with_providers(vec![i + 4]);
        } else {
            // ASes 5-10 are Tier-1
            builder = builder.as_tier_1();
        }
        
        match i {
            1 | 2 => builder = builder.with_customers(vec![CommonASNs::VICTIM]),
            3 | 4 => builder = builder.with_customers(vec![CommonASNs::ATTACKER]),
            5 => builder = builder.with_customers(vec![1, 3]),
            6 => builder = builder.with_customers(vec![2, 4]),
            7 => builder = builder.with_customers(vec![1, 2]),
            8 => builder = builder.with_customers(vec![3, 4]),
            _ => {},
        };
        
        builders.push(builder);
    }
    
    let mut as_graph = ASGraph::build(builders);
    
    // Initialize graph
    as_graph.check_for_cycles().expect("No cycles should exist");
    as_graph.assign_as_propagation_rank();
    as_graph.add_asn_groups();
    
    as_graph
}
