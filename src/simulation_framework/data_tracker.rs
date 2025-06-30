use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::shared::{Outcomes, Settings};

#[derive(Debug, Default)]
pub struct DataTracker {
    /// Track outcomes for each trial
    pub outcomes: Vec<Outcomes>,
    
    /// Track which ASes adopted which settings
    pub adoption_data: HashMap<Settings, Vec<f64>>,
    
    /// Track metrics over time
    pub time_series_data: HashMap<String, Vec<f64>>,
    
    /// Scenario label
    pub scenario_label: String,
    
    /// Percentage of ASes adopting
    pub percent_adopting: f64,
}

impl DataTracker {
    pub fn new(scenario_label: String, percent_adopting: f64) -> Self {
        DataTracker {
            outcomes: Vec::new(),
            adoption_data: HashMap::new(),
            time_series_data: HashMap::new(),
            scenario_label,
            percent_adopting,
        }
    }
    
    pub fn add_outcome(&mut self, outcome: Outcomes) {
        self.outcomes.push(outcome);
    }
    
    pub fn add_adoption_metric(&mut self, setting: Settings, value: f64) {
        self.adoption_data.entry(setting).or_insert_with(Vec::new).push(value);
    }
    
    pub fn add_time_series_metric(&mut self, metric_name: String, value: f64) {
        self.time_series_data.entry(metric_name).or_insert_with(Vec::new).push(value);
    }
    
    pub fn success_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.0;
        }
        
        let successes = self.outcomes.iter()
            .filter(|&outcome| matches!(outcome, Outcomes::AttackerSuccess))
            .count();
            
        (successes as f64) / (self.outcomes.len() as f64) * 100.0
    }
    
    pub fn save_to_file(&self, output_dir: &Path) -> std::io::Result<()> {
        let file_name = format!("{}_{}_percent.json", self.scenario_label, self.percent_adopting);
        let file_path = output_dir.join(file_name);
        
        let data = serde_json::json!({
            "scenario_label": self.scenario_label,
            "percent_adopting": self.percent_adopting,
            "success_rate": self.success_rate(),
            "num_trials": self.outcomes.len(),
            "outcomes": self.outcomes,
            "adoption_data": self.adoption_data,
            "time_series_data": self.time_series_data,
        });
        
        let json = serde_json::to_string_pretty(&data)?;
        fs::write(file_path, json)?;
        
        Ok(())
    }
}

/// Summary data for a complete simulation run
#[derive(Debug)]
pub struct SimulationSummary {
    pub scenario_label: String,
    pub adoption_percentages: Vec<f64>,
    pub success_rates: Vec<f64>,
}

impl SimulationSummary {
    pub fn new(scenario_label: String) -> Self {
        SimulationSummary {
            scenario_label,
            adoption_percentages: Vec::new(),
            success_rates: Vec::new(),
        }
    }
    
    pub fn add_data_point(&mut self, percent: f64, success_rate: f64) {
        self.adoption_percentages.push(percent);
        self.success_rates.push(success_rate);
    }
    
    pub fn save_to_file(&self, output_dir: &Path) -> std::io::Result<()> {
        let file_name = format!("{}_summary.json", self.scenario_label);
        let file_path = output_dir.join(file_name);
        
        let data = serde_json::json!({
            "scenario_label": self.scenario_label,
            "adoption_percentages": self.adoption_percentages,
            "success_rates": self.success_rates,
        });
        
        let json = serde_json::to_string_pretty(&data)?;
        fs::write(file_path, json)?;
        
        Ok(())
    }
}