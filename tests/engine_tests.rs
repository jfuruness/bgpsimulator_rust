use std::collections::{HashMap, HashSet};
use std::path::Path;

use bgpsimulator::as_graph::{AS, ASGraph};
use bgpsimulator::engine::SimulationEngine;
use bgpsimulator::engine_runner::{EngineRunConfig, EngineRunner};
use bgpsimulator::shared::{CommonASNs, Outcomes, Settings};
use bgpsimulator::simulation_framework::scenario_config::ScenarioConfig;

/// Create a simple test AS graph
fn create_test_as_graph_simple() -> ASGraph {
    let mut as_graph = ASGraph::new();
    
    // Create AS 1 (Provider)
    let mut as1 = AS::from_asn_sets(
        1,
        HashSet::new(),           // No peers
        HashSet::new(),           // No providers (Tier 1)
        HashSet::from([2, 3]),    // Customers: AS 2 and AS 3
    );
    as1.tier_1 = true;
    
    // Create AS 2 (Customer of AS 1, Provider of AS 4)
    let as2 = AS::from_asn_sets(
        2,
        HashSet::new(),           // No peers
        HashSet::from([1]),       // Provider: AS 1
        HashSet::from([4]),       // Customer: AS 4
    );
    
    // Create AS 3 (Customer of AS 1)
    let as3 = AS::from_asn_sets(
        3,
        HashSet::new(),           // No peers
        HashSet::from([1]),       // Provider: AS 1
        HashSet::new(),           // No customers
    );
    
    // Create AS 4 (Customer of AS 2)
    let as4 = AS::from_asn_sets(
        4,
        HashSet::new(),           // No peers
        HashSet::from([2]),       // Provider: AS 2
        HashSet::new(),           // No customers
    );
    
    // Add to graph
    as_graph.insert(as1);
    as_graph.insert(as2);
    as_graph.insert(as3);
    as_graph.insert(as4);
    
    // Initialize the graph
    as_graph.check_for_cycles().expect("No cycles should exist");
    as_graph.assign_as_propagation_rank();
    
    as_graph
}

/// Create a test AS graph with attacker and victim
fn create_test_as_graph_with_attacker() -> ASGraph {
    let mut as_graph = ASGraph::new();
    
    let victim_asn = CommonASNs::VICTIM;
    let attacker_asn = CommonASNs::ATTACKER;
    
    // Create victim AS
    let victim_as = AS::from_asn_sets(
        victim_asn,
        HashSet::new(),
        HashSet::from([2, 4, 10]),  // Providers
        HashSet::new(),
    );
    
    // Create attacker AS
    let attacker_as = AS::from_asn_sets(
        attacker_asn,
        HashSet::new(),
        HashSet::from([1, 2]),      // Providers
        HashSet::new(),
    );
    
    // Create provider ASes
    let as1 = AS::from_asn_sets(
        1,
        HashSet::new(),
        HashSet::from([5, 8]),      // Providers
        HashSet::from([attacker_asn]),
    );
    
    let as2 = AS::from_asn_sets(
        2,
        HashSet::new(),
        HashSet::from([8]),         // Providers
        HashSet::from([attacker_asn, victim_asn]),
    );
    
    let as4 = AS::from_asn_sets(
        4,
        HashSet::new(),
        HashSet::from([9]),         // Providers
        HashSet::from([victim_asn]),
    );
    
    // Create Tier-1 ASes
    let mut as5 = AS::from_asn_sets(
        5,
        HashSet::new(),
        HashSet::new(),             // No providers (Tier 1)
        HashSet::from([1]),
    );
    as5.tier_1 = true;
    
    let mut as8 = AS::from_asn_sets(
        8,
        HashSet::new(),
        HashSet::new(),             // No providers (Tier 1)
        HashSet::from([1, 2]),
    );
    as8.tier_1 = true;
    
    let mut as9 = AS::from_asn_sets(
        9,
        HashSet::new(),
        HashSet::new(),             // No providers (Tier 1)
        HashSet::from([4]),
    );
    as9.tier_1 = true;
    
    let as10 = AS::from_asn_sets(
        10,
        HashSet::new(),
        HashSet::new(),             // No providers (Tier 1)
        HashSet::from([victim_asn]),
    );
    
    // Add all ASes to graph
    as_graph.insert(victim_as);
    as_graph.insert(attacker_as);
    as_graph.insert(as1);
    as_graph.insert(as2);
    as_graph.insert(as4);
    as_graph.insert(as5);
    as_graph.insert(as8);
    as_graph.insert(as9);
    as_graph.insert(as10);
    
    // Initialize the graph
    as_graph.check_for_cycles().expect("No cycles should exist");
    as_graph.assign_as_propagation_rank();
    
    as_graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnetwork::IpNetwork;
    use std::str::FromStr;
    
    #[test]
    fn test_basic_propagation() {
        let as_graph = create_test_as_graph_simple();
        let mut engine = SimulationEngine::new(as_graph);
        
        // Create announcement from AS 4
        let prefix = IpNetwork::from_str("10.0.0.0/24").unwrap();
        let announcement = bgpsimulator::simulation_engine::Announcement::new(
            prefix,
            vec![],
            4,
            bgpsimulator::shared::Relationships::Origin,
            bgpsimulator::shared::Timestamps::Victim,
        );
        
        // Seed and run
        engine.setup(vec![(4, announcement)]);
        engine.run(10);
        
        // Check that all ASes received the announcement
        for asn in [1, 2, 3, 4] {
            let policy = engine.policy_store.get(&asn).unwrap();
            assert!(policy.local_rib.contains_key(&prefix),
                    "AS {} should have route to prefix", asn);
        }
    }
    
    #[test]
    fn test_subprefix_hijack_scenario() {
        let as_graph = create_test_as_graph_with_attacker();
        
        // Create scenario config
        let config = ScenarioConfig::new(
            "Test Subprefix Hijack".to_string(),
            "SubprefixHijack".to_string(),
        );
        
        // Create engine run config
        let engine_config = EngineRunConfig::new(
            "test_subprefix_hijack".to_string(),
            config,
            as_graph,
        ).expect("Config creation should succeed");
        
        // Create and run engine runner
        let runner = EngineRunner::new(engine_config)
            .with_base_dir(Path::new("target/test_outputs").to_path_buf())
            .with_overwrite(true);
        
        let outcomes = runner.run().expect("Engine run should succeed");
        
        // Verify some basic properties
        assert!(outcomes.contains_key(&CommonASNs::VICTIM));
        assert!(outcomes.contains_key(&CommonASNs::ATTACKER));
    }
    
    #[test]
    fn test_rov_defense() {
        let as_graph = create_test_as_graph_with_attacker();
        let mut engine = SimulationEngine::new(as_graph);
        
        // Enable ROV for some ASes
        let adopting_asns = vec![1, 2, 5, 8];
        for &asn in &adopting_asns {
            if let Some(policy) = engine.policy_store.get_mut(&asn) {
                policy.settings = Settings::Rov;
                policy.extension = bgpsimulator::policies::create_policy_extension(Settings::Rov);
            }
        }
        
        // Create legitimate and attack announcements
        let legitimate_prefix = IpNetwork::from_str("10.0.0.0/24").unwrap();
        let hijacked_prefix = IpNetwork::from_str("10.0.0.0/25").unwrap();
        
        let legitimate_ann = bgpsimulator::simulation_engine::Announcement::new(
            legitimate_prefix,
            vec![],
            CommonASNs::VICTIM,
            bgpsimulator::shared::Relationships::Origin,
            bgpsimulator::shared::Timestamps::Victim,
        );
        
        let attack_ann = bgpsimulator::simulation_engine::Announcement::new(
            hijacked_prefix,
            vec![],
            CommonASNs::ATTACKER,
            bgpsimulator::shared::Relationships::Origin,
            bgpsimulator::shared::Timestamps::Victim,
        );
        
        // Seed and run
        engine.setup(vec![
            (CommonASNs::VICTIM, legitimate_ann),
            (CommonASNs::ATTACKER, attack_ann),
        ]);
        engine.run(10);
        
        // Check results - with ROV, the attack should be less successful
        let mut rov_protected_count = 0;
        for asn in adopting_asns {
            if let Some(policy) = engine.policy_store.get(&asn) {
                // Check if AS is preferring legitimate route
                if let Some(ann) = policy.local_rib.get(&legitimate_prefix) {
                    if ann.origin() == CommonASNs::VICTIM {
                        rov_protected_count += 1;
                    }
                }
            }
        }
        
        assert!(rov_protected_count > 0, "At least some ROV ASes should be protected");
    }
}

/// Integration test that runs multiple scenarios
#[test]
fn test_multiple_scenarios() {
    let test_configs = vec![
        ("Valid Prefix BGP Simple", "LegitimatePrefixOnly"),
        ("Prefix Hijack BGP Simple", "PrefixHijack"),
        ("Subprefix Hijack BGP Simple", "SubprefixHijack"),
    ];
    
    for (label, scenario_name) in test_configs {
        let as_graph = create_test_as_graph_with_attacker();
        let config = ScenarioConfig::new(label.to_string(), scenario_name.to_string());
        
        let engine_config = EngineRunConfig::new(
            format!("test_{}", scenario_name.to_lowercase()),
            config,
            as_graph,
        ).expect("Config creation should succeed");
        
        let runner = EngineRunner::new(engine_config)
            .with_base_dir(Path::new("target/test_outputs").to_path_buf())
            .with_overwrite(true);
        
        runner.run().expect(&format!("Engine run for {} should succeed", label));
    }
}