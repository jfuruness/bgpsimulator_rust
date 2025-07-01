use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

use crate::simulation_engine::SimulationEngine;
use crate::route_validator::RouteValidator;
use crate::shared::Outcomes;
use crate::simulation_framework::scenario::{Scenario, ScenarioTrait};
use crate::simulation_framework::scenarios::{SubprefixHijack, PrefixHijack, LegitimatePrefixOnly};

use super::engine_run_config::EngineRunConfig;

/// Runs a single engine run with specific configuration
pub struct EngineRunner {
    /// Configuration for this engine run
    pub config: EngineRunConfig,
    
    /// Base directory for storing results
    pub base_dir: PathBuf,
    
    /// Whether to overwrite existing results
    pub overwrite: bool,
    
    /// Whether to compare against ground truth (for testing)
    pub compare_against_ground_truth: bool,
    
    /// Whether to write diagram files
    pub write_diagrams: bool,
    
    /// Storage directory for this specific run
    pub storage_dir: PathBuf,
}

impl EngineRunner {
    pub fn new(config: EngineRunConfig) -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Desktop")
            .join("bgpsimulator_engine_runs");
            
        let storage_dir = base_dir.join(&config.name);
        
        EngineRunner {
            config,
            base_dir,
            overwrite: false,
            compare_against_ground_truth: false,
            write_diagrams: true,
            storage_dir,
        }
    }
    
    pub fn with_base_dir(mut self, dir: PathBuf) -> Self {
        self.base_dir = dir;
        self.storage_dir = self.base_dir.join(&self.config.name);
        self
    }
    
    pub fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }
    
    pub fn with_compare_against_ground_truth(mut self, compare: bool) -> Self {
        self.compare_against_ground_truth = compare;
        self
    }
    
    pub fn with_write_diagrams(mut self, write: bool) -> Self {
        self.write_diagrams = write;
        self
    }
    
    /// Run the engine with the configured scenario
    pub fn run(&self) -> Result<HashMap<u32, Outcomes>, Box<dyn std::error::Error>> {
        // Create storage directory
        fs::create_dir_all(&self.storage_dir)?;
        
        // Create engine and scenario
        let (mut engine, scenario) = self.get_engine_and_scenario()?;
        
        // Get propagation rounds from config or use default
        let propagation_rounds = 100; // Default value, could be from config
        
        // Run engine for specified rounds
        engine.run(propagation_rounds);
        
        // Calculate data plane outcomes
        let outcomes = self.calculate_data_plane_outcomes(&engine, &scenario);
        
        // Store results
        self.store_data(&engine, &outcomes)?;
        
        // Generate diagrams if requested
        if self.write_diagrams {
            self.generate_diagrams(&engine, scenario.as_ref())?;
        }
        
        // Compare against ground truth if requested
        if self.compare_against_ground_truth {
            self.compare_against_ground_truth(&engine, &outcomes)?;
        }
        
        Ok(outcomes)
    }
    
    fn get_engine_and_scenario(&self) -> Result<(SimulationEngine, Box<dyn ScenarioTrait>), Box<dyn std::error::Error>> {
        // Create engine
        let mut engine = SimulationEngine::new(&self.config.as_graph);
        
        // Create scenario based on scenario name
        let scenario: Box<dyn ScenarioTrait> = match self.config.scenario_config.scenario_name.as_str() {
            "SubprefixHijack" => {
                // Create scenario with default attacker/victim ASNs
                // In a real implementation, these would come from the config
                let attacker_asns = self.get_attacker_asns();
                let legitimate_origin_asns = self.get_legitimate_origin_asns();
                Box::new(SubprefixHijack::new(attacker_asns, legitimate_origin_asns))
            },
            "PrefixHijack" => {
                let attacker_asns = self.get_attacker_asns();
                let legitimate_origin_asns = self.get_legitimate_origin_asns();
                Box::new(PrefixHijack::new(attacker_asns, legitimate_origin_asns))
            },
            "LegitimatePrefixOnly" => {
                let legitimate_origin_asns = self.get_legitimate_origin_asns();
                Box::new(LegitimatePrefixOnly::new(legitimate_origin_asns))
            },
            _ => return Err(format!("Unknown scenario: {}", self.config.scenario_config.scenario_name).into()),
        };
        
        // Setup scenario in engine
        let mut route_validator = RouteValidator::new();
        scenario.setup_engine(&mut engine, &mut route_validator);
        
        Ok((engine, scenario))
    }
    
    fn get_attacker_asns(&self) -> std::collections::HashSet<u32> {
        // In a real implementation, these would come from config
        // For now, return a default set
        let mut asns = std::collections::HashSet::new();
        asns.insert(666);  // Default attacker ASN
        asns
    }
    
    fn get_legitimate_origin_asns(&self) -> std::collections::HashSet<u32> {
        // In a real implementation, these would come from config
        // For now, return a default set
        let mut asns = std::collections::HashSet::new();
        asns.insert(777);  // Default victim ASN
        asns
    }
    
    fn calculate_data_plane_outcomes(
        &self,
        engine: &SimulationEngine,
        scenario: &Box<dyn ScenarioTrait>,
    ) -> HashMap<u32, Outcomes> {
        let mut outcomes = HashMap::new();
        
        // Determine outcome based on whether attack was successful
        let attack_successful = scenario.is_successful(engine);
        
        // For each AS, determine its outcome
        for &asn in engine.as_graph.as_dict.keys() {
            if self.get_attacker_asns().contains(&asn) {
                outcomes.insert(asn, if attack_successful {
                    Outcomes::AttackerSuccess
                } else {
                    Outcomes::VictimSuccess
                });
            } else if self.get_legitimate_origin_asns().contains(&asn) {
                outcomes.insert(asn, if attack_successful {
                    Outcomes::VictimSuccess  // Victim loses when attack succeeds
                } else {
                    Outcomes::AttackerSuccess  // Victim wins when attack fails
                });
            } else {
                // For other ASes, check if they have a route
                if let Some(policy) = engine.policy_store.get(&asn) {
                    if !policy.local_rib.is_empty() {
                        outcomes.insert(asn, Outcomes::VictimSuccess);
                    } else {
                        outcomes.insert(asn, Outcomes::DisconnectedOrigin);
                    }
                }
            }
        }
        
        outcomes
    }
    
    fn store_data(
        &self,
        engine: &SimulationEngine,
        outcomes: &HashMap<u32, Outcomes>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Store engine state
        let engine_path = self.storage_dir.join("engine_guess.json");
        let engine_json = serde_json::json!({
            "as_graph_size": engine.as_graph.as_dict.len(),
            "policy_count": engine.policy_store.iter().count(),
            // Add more engine state as needed
        });
        fs::write(engine_path, serde_json::to_string_pretty(&engine_json)?)?;
        
        // Store outcomes
        let outcomes_path = self.storage_dir.join("outcomes_guess.json");
        fs::write(outcomes_path, serde_json::to_string_pretty(&outcomes)?)?;
        
        // Store config
        let config_path = self.storage_dir.join("config.json");
        fs::write(config_path, serde_json::to_string_pretty(&self.config.to_json())?)?;
        
        Ok(())
    }
    
    fn generate_diagrams(
        &self,
        _engine: &SimulationEngine,
        _scenario: &dyn ScenarioTrait,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Diagram generation would be implemented here
        // For now, just create a placeholder file
        let diagram_path = self.storage_dir.join("diagram.txt");
        fs::write(diagram_path, "Diagram generation not yet implemented")?;
        Ok(())
    }
    
    fn compare_against_ground_truth(
        &self,
        _engine: &SimulationEngine,
        _outcomes: &HashMap<u32, Outcomes>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Ground truth comparison would be implemented here
        // This is mainly used for testing
        Ok(())
    }
}