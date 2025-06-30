// Re-export all public modules
pub mod shared;
pub mod as_graph;
pub mod simulation_engine;
pub mod route_validator;
pub mod engine;
pub mod as_graph_generators;
pub mod policies;
pub mod simulation_framework;
pub mod engine_runner;

// Re-export commonly used types at the crate root
pub use as_graph::{AS, ASGraph, ASN};
pub use engine::SimulationEngine;
pub use shared::{CommonASNs, Outcomes, Relationships, Settings, Timestamps};
pub use simulation_engine::{Announcement, Prefix};
pub use route_validator::{ROA, RouteValidator};