use crate::simulation_engine::policy::PolicyExtension;
use crate::simulation_engine::announcement::Announcement;
use crate::as_graphs::as_graph::AS;
use crate::shared::Relationships;
use crate::route_validator::RouteValidator;

#[derive(Debug, Clone)]
pub struct BGPPolicy;

impl PolicyExtension for BGPPolicy {
    fn name(&self) -> &'static str {
        "BGP"
    }
    
    fn validate_announcement(
        &self,
        ann: &Announcement,
        recv_relationship: Relationships,
        as_obj: &AS,
        _route_validator: Option<&RouteValidator>,
    ) -> bool {
        // Basic BGP validation:
        // 1. Check if AS is not already in the AS path (loop prevention)
        if ann.as_path.contains(&as_obj.asn) {
            return false;
        }
        
        // 2. Withdrawn announcements are always valid
        if ann.withdraw {
            return true;
        }
        
        // 3. Empty AS path is only valid from origin
        if ann.as_path.is_empty() && recv_relationship != Relationships::Origin {
            return false;
        }
        
        // All other announcements are valid
        true
    }
    
    fn should_propagate(
        &self,
        _ann: &Announcement,
        recv_relationship: Relationships,
        send_relationship: Relationships,
    ) -> bool {
        // Gao-Rexford export rules:
        match recv_relationship {
            Relationships::Providers => {
                // Routes from providers are only sent to customers
                matches!(send_relationship, Relationships::Customers)
            }
            Relationships::Peers => {
                // Routes from peers are only sent to customers
                matches!(send_relationship, Relationships::Customers)
            }
            Relationships::Customers => {
                // Routes from customers are sent to all neighbors
                true
            }
            Relationships::Origin => {
                // Originated routes are sent to all neighbors
                true
            }
            _ => false,
        }
    }
}