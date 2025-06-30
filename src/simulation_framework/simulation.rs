use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};

use crate::as_graph::ASGraph;
use crate::engine::SimulationEngine;
use crate::route_validator::RouteValidator;
use crate::shared::{Outcomes, Settings};

use super::data_tracker::{DataTracker, SimulationSummary};
use super::scenario::{Scenario, ScenarioTrait};
use super::scenario_config::ScenarioConfig;

pub struct Simulation {
    /// Output directory for results
    pub output_dir: PathBuf,
    
    /// Percentages of ASes randomly adopting for each run
    pub percent_ases_randomly_adopting: Vec<f64>,
    
    /// Scenario configurations to run
    pub scenario_configs: Vec<ScenarioConfig>,
    
    /// Number of trials per configuration
    pub num_trials: usize,
    
    /// Number of CPU cores to use for parallel processing
    pub parse_cpus: usize,
    
    /// AS graph to use for simulations
    pub as_graph: ASGraph,
}

impl Simulation {
    pub fn new(as_graph: ASGraph) -> Self {
        let output_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Desktop")
            .join("sims")
            .join("bgpsimulator_rust");
            
        Simulation {
            output_dir,
            percent_ases_randomly_adopting: vec![10.0, 20.0, 50.0, 80.0, 99.0],
            scenario_configs: vec![
                ScenarioConfig::new(
                    "Subprefix Hijack; ROV Adopting".to_string(),
                    "SubprefixHijack".to_string(),
                ).with_adoption_setting(Settings::Rov, true)
            ],
            num_trials: 10,
            parse_cpus: num_cpus::get().max(1) - 1,
            as_graph,
        }
    }
    
    pub fn with_output_dir(mut self, dir: PathBuf) -> Self {
        self.output_dir = dir;
        self
    }
    
    pub fn with_adoption_percentages(mut self, percentages: Vec<f64>) -> Self {
        self.percent_ases_randomly_adopting = percentages;
        self
    }
    
    pub fn with_scenario_configs(mut self, configs: Vec<ScenarioConfig>) -> Self {
        self.scenario_configs = configs;
        self
    }
    
    pub fn with_num_trials(mut self, trials: usize) -> Self {
        self.num_trials = trials;
        self
    }
    
    /// Run the complete simulation
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running BGP simulations...");
        println!("Output directory: {:?}", self.output_dir);
        std::fs::create_dir_all(&self.output_dir)?;
        
        let start_time = Instant::now();
        
        // Run each scenario configuration
        for scenario_config in &self.scenario_configs {
            println!("\nRunning scenario: {}", scenario_config.label);
            self.run_scenario(scenario_config)?;
        }
        
        let duration = start_time.elapsed();
        println!("\nSimulation complete in {:.2}s", duration.as_secs_f64());
        
        Ok(())
    }
    
    /// Run a single scenario with all adoption percentages
    fn run_scenario(&self, scenario_config: &ScenarioConfig) -> Result<(), Box<dyn std::error::Error>> {
        let mut summary = SimulationSummary::new(scenario_config.label.clone());
        
        // Run for each adoption percentage
        for &percent in &self.percent_ases_randomly_adopting {
            println!("\n  Running with {}% adoption", percent);
            
            let tracker = self.run_trials_for_percentage(scenario_config, percent)?;
            let success_rate = tracker.success_rate();
            
            println!("    Success rate: {:.2}%", success_rate);
            summary.add_data_point(percent, success_rate);
            
            // Save individual results
            tracker.save_to_file(&self.output_dir)?;
        }
        
        // Save summary
        summary.save_to_file(&self.output_dir)?;
        
        Ok(())
    }
    
    /// Run multiple trials for a specific adoption percentage
    fn run_trials_for_percentage(
        &self,
        scenario_config: &ScenarioConfig,
        percent: f64,
    ) -> Result<DataTracker, Box<dyn std::error::Error>> {
        let mut tracker = DataTracker::new(scenario_config.label.clone(), percent);
        
        // Create progress bar
        let pb = ProgressBar::new(self.num_trials as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40} {pos}/{len} trials")?
                .progress_chars("##-"),
        );
        
        // Run trials
        for trial_num in 0..self.num_trials {
            pb.inc(1);
            
            // Create scenario for this trial
            let scenario = Scenario::new(
                scenario_config.clone(),
                &self.as_graph,
                percent,
            );
            
            // Run the trial
            let outcome = self.run_single_trial(&scenario)?;
            tracker.add_outcome(outcome);
        }
        
        pb.finish();
        
        Ok(tracker)
    }
    
    /// Run a single trial of a scenario
    fn run_single_trial(&self, scenario: &Scenario) -> Result<Outcomes, Box<dyn std::error::Error>> {
        // Create a fresh engine for this trial
        let mut engine = SimulationEngine::new(self.as_graph.clone());
        
        // Apply adoption settings to policies
        for (asn, policy) in engine.policy_store.iter_mut() {
            if scenario.adopting_asns.contains(asn) {
                // Apply the adoption settings from the scenario config
                for (setting, &enabled) in &scenario.config.default_adoption_settings {
                    if enabled {
                        policy.settings = *setting;
                        // Update the policy extension based on new settings
                        policy.extension = crate::policies::create_policy_extension(*setting);
                    }
                }
            }
        }
        
        // TODO: Setup the scenario in the engine
        // This requires implementing specific scenario types
        
        // Run the simulation
        engine.run(100); // Run for up to 100 rounds
        
        // TODO: Determine the outcome
        // This requires implementing outcome detection logic
        
        // For now, return a placeholder outcome
        Ok(Outcomes::VictimSuccess)
    }
}

// External crates
extern crate dirs;
extern crate num_cpus;
extern crate indicatif;
extern crate serde_json;