pub mod caida;

use crate::as_graphs::as_graph::ASGraph;

pub trait ASGraphGenerator {
    fn generate(&self) -> Result<ASGraph, Box<dyn std::error::Error>>;
}

pub struct CAIDAASGraphGenerator {
    pub days_ago: u32,
    pub cache_dir: String,
}

impl CAIDAASGraphGenerator {
    pub fn new() -> Self {
        CAIDAASGraphGenerator {
            days_ago: 10,
            cache_dir: ".bgp_simulator_cache".to_string(),
        }
    }

    pub fn with_days_ago(mut self, days: u32) -> Self {
        self.days_ago = days;
        self
    }

    pub fn with_cache_dir(mut self, dir: String) -> Self {
        self.cache_dir = dir;
        self
    }
}

impl ASGraphGenerator for CAIDAASGraphGenerator {
    fn generate(&self) -> Result<ASGraph, Box<dyn std::error::Error>> {
        // TODO: Implement CAIDA graph generation with new AS graph API
        unimplemented!("CAIDA graph generation not yet implemented")
    }
}