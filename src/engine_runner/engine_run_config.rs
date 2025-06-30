use std::collections::HashSet;
use std::sync::Mutex;

use crate::as_graph::ASGraph;
use crate::simulation_framework::scenario_config::ScenarioConfig;

/// Configuration for a single engine run
#[derive(Debug, Clone)]
pub struct EngineRunConfig {
    /// Unique name for this engine run
    pub name: String,
    
    /// Scenario configuration
    pub scenario_config: ScenarioConfig,
    
    /// AS graph to use
    pub as_graph: ASGraph,
    
    /// Description for diagram generation
    pub diagram_desc: String,
    
    /// Additional text description
    pub text: String,
    
    /// Ranks for diagram layout
    pub diagram_ranks: Vec<Vec<u32>>,
}

// Track used names to ensure uniqueness
lazy_static::lazy_static! {
    static ref USED_NAMES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

impl EngineRunConfig {
    pub fn new(
        name: String,
        scenario_config: ScenarioConfig,
        as_graph: ASGraph,
    ) -> Result<Self, String> {
        // Check if name is already used
        let mut used_names = USED_NAMES.lock().unwrap();
        if used_names.contains(&name) {
            return Err(format!("Name '{}' already used", name));
        }
        used_names.insert(name.clone());
        
        Ok(EngineRunConfig {
            name,
            scenario_config,
            as_graph,
            diagram_desc: String::new(),
            text: String::new(),
            diagram_ranks: Vec::new(),
        })
    }
    
    pub fn with_diagram_desc(mut self, desc: String) -> Self {
        self.diagram_desc = desc;
        self
    }
    
    pub fn with_text(mut self, text: String) -> Self {
        self.text = text;
        self
    }
    
    pub fn with_diagram_ranks(mut self, ranks: Vec<Vec<u32>>) -> Self {
        self.diagram_ranks = ranks;
        self
    }
    
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "diagram_desc": self.diagram_desc,
            "text": self.text,
            "scenario_config": {
                "label": self.scenario_config.label,
                "scenario_name": self.scenario_config.scenario_name,
                "default_adoption_settings": self.scenario_config.default_adoption_settings,
            },
            "diagram_ranks": self.diagram_ranks,
            // AS graph serialization would be complex, omitting for now
            "as_graph": "AS graph serialization not implemented",
        })
    }
}

// External crate for lazy static initialization
extern crate lazy_static;