use crate::as_graphs::as_graph::{AS};
use crate::shared::{Relationships};
use crate::simulation_engine::announcement::Announcement;
use crate::simulation_engine::policy::{PolicyExtension, ProcessingResult};

/// Only to Customers (OTC) policy
pub struct OnlyToCustomersPolicy;

impl PolicyExtension for OnlyToCustomersPolicy {
    fn process_announcement(
        &mut self,
        ann: &mut Announcement,
        recv_relationship: Relationships,
        _as_obj: &AS,
    ) -> ProcessingResult {
        // Mark announcements from peers/providers as only to customers
        match recv_relationship {
            Relationships::Peers | Relationships::Providers => {
                ann.only_to_customers = Some(true);
                ProcessingResult::Modified
            }
            _ => ProcessingResult::Accept,
        }
    }
    
    fn should_propagate(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        send_relationship: Relationships,
    ) -> bool {
        // Check OTC marking
        if let Some(true) = ann.only_to_customers {
            // Only propagate to customers
            matches!(send_relationship, Relationships::Customers)
        } else {
            // Use default Gao-Rexford rules
            match (recv_relationship, send_relationship) {
                (Relationships::Origin, _) => true,
                (Relationships::Customers, _) => true,
                (Relationships::Peers, Relationships::Customers) => true,
                (Relationships::Providers, Relationships::Customers) => true,
                _ => false,
            }
        }
    }
    
    fn name(&self) -> &str {
        "OnlyToCustomers"
    }
}