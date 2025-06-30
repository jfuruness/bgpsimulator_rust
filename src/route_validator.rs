use std::collections::HashSet;
use std::sync::Mutex;
use lru::LruCache;
use ipnetwork::IpNetwork;

use crate::shared::{ROAValidity, ROARouted};
use crate::as_graph::ASN;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ROA {
    pub prefix: IpNetwork,
    pub origin: ASN,
    pub max_length: u8,
    pub ta: Option<String>,
}

impl ROA {
    pub fn new(prefix: IpNetwork, origin: ASN, max_length: Option<u8>) -> Self {
        let max_length = max_length.unwrap_or_else(|| prefix.prefix());
        ROA {
            prefix,
            origin,
            max_length,
            ta: None,
        }
    }

    pub fn with_ta(mut self, ta: String) -> Self {
        self.ta = Some(ta);
        self
    }

    pub fn is_routed(&self) -> bool {
        self.origin != 0
    }

    pub fn is_non_routed(&self) -> bool {
        self.origin == 0
    }

    pub fn covers_prefix(&self, prefix: &IpNetwork) -> bool {
        match (self.prefix, prefix) {
            (IpNetwork::V4(roa_net), IpNetwork::V4(prefix_net)) => {
                roa_net.contains(prefix_net.ip()) && prefix_net.prefix() >= roa_net.prefix()
            }
            (IpNetwork::V6(roa_net), IpNetwork::V6(prefix_net)) => {
                roa_net.contains(prefix_net.ip()) && prefix_net.prefix() >= roa_net.prefix()
            }
            _ => false, // IPv4 ROA doesn't cover IPv6 prefix and vice versa
        }
    }

    pub fn get_validity(&self, prefix: &IpNetwork, origin: ASN) -> ROAValidity {
        if !self.covers_prefix(prefix) {
            return ROAValidity::Unknown;
        }

        let prefix_len = prefix.prefix();
        let valid_length = prefix_len <= self.max_length;
        let valid_origin = self.origin == origin;

        match (valid_length, valid_origin) {
            (true, true) => ROAValidity::Valid,
            (false, true) => ROAValidity::InvalidLength,
            (true, false) => ROAValidity::InvalidOrigin,
            (false, false) => ROAValidity::InvalidLengthAndOrigin,
        }
    }

    pub fn get_outcome(&self, prefix: &IpNetwork, origin: ASN) -> (ROAValidity, ROARouted) {
        let validity = self.get_validity(prefix, origin);
        let routed = if self.is_routed() {
            ROARouted::Routed
        } else {
            ROARouted::NonRouted
        };
        (validity, routed)
    }
}

#[derive(Debug)]
pub struct ROASNode {
    pub prefix: Option<IpNetwork>,
    pub roas: HashSet<ROA>,
    pub left: Option<Box<ROASNode>>,
    pub right: Option<Box<ROASNode>>,
}

impl ROASNode {
    pub fn new() -> Self {
        ROASNode {
            prefix: None,
            roas: HashSet::new(),
            left: None,
            right: None,
        }
    }
}

pub struct RouteValidator {
    root: ROASNode,
    cache: Mutex<LruCache<(IpNetwork, ASN), (ROAValidity, ROARouted)>>,
}

impl RouteValidator {
    pub fn new() -> Self {
        RouteValidator {
            root: ROASNode::new(),
            cache: Mutex::new(LruCache::new(10_000.try_into().unwrap())),
        }
    }

    pub fn add_roa(&mut self, roa: ROA) {
        let binary_prefix = Self::prefix_to_binary(&roa.prefix);
        Self::insert_roa_at_node(&mut self.root, &binary_prefix, 0, roa);
        self.cache.lock().unwrap().clear();
    }

    fn insert_roa_at_node(
        node: &mut ROASNode,
        binary_prefix: &str,
        index: usize,
        roa: ROA,
    ) {
        if index == binary_prefix.len() {
            node.prefix = Some(roa.prefix);
            node.roas.insert(roa);
            return;
        }

        let bit = &binary_prefix[index..index + 1];
        let child = if bit == "0" {
            &mut node.left
        } else {
            &mut node.right
        };

        if child.is_none() {
            *child = Some(Box::new(ROASNode::new()));
        }

        Self::insert_roa_at_node(
            child.as_mut().unwrap(),
            binary_prefix,
            index + 1,
            roa,
        );
    }

    pub fn get_roa_outcome(&self, prefix: &IpNetwork, origin: ASN) -> (ROAValidity, ROARouted) {
        // Check cache first
        if let Some(result) = self.cache.lock().unwrap().get(&(*prefix, origin)) {
            return *result;
        }

        let relevant_roas = self.get_relevant_roas(prefix);
        if relevant_roas.is_empty() {
            let result = (ROAValidity::Unknown, ROARouted::Unknown);
            self.cache.lock().unwrap().put((*prefix, origin), result);
            return result;
        }

        // Get all outcomes and find the best validity
        let mut outcomes: Vec<(ROAValidity, ROARouted)> = relevant_roas
            .iter()
            .map(|roa| roa.get_outcome(prefix, origin))
            .collect();

        // Sort by validity (lower enum value is better)
        outcomes.sort_by_key(|(validity, _)| *validity as u8);

        let result = outcomes[0];
        self.cache.lock().unwrap().put((*prefix, origin), result);
        result
    }

    fn get_relevant_roas(&self, prefix: &IpNetwork) -> Vec<ROA> {
        let mut relevant_roas = Vec::new();
        let binary_prefix = Self::prefix_to_binary(prefix);
        
        self.collect_relevant_roas_from_node(
            &self.root,
            &binary_prefix,
            0,
            prefix,
            &mut relevant_roas,
        );

        relevant_roas
    }

    fn collect_relevant_roas_from_node(
        &self,
        node: &ROASNode,
        binary_prefix: &str,
        index: usize,
        target_prefix: &IpNetwork,
        relevant_roas: &mut Vec<ROA>,
    ) {
        // Check if this node has ROAs that cover the target prefix
        for roa in &node.roas {
            if roa.covers_prefix(target_prefix) {
                relevant_roas.push(roa.clone());
            }
        }

        // Continue traversing if we haven't consumed the entire binary prefix
        if index < binary_prefix.len() {
            let bit = &binary_prefix[index..index + 1];
            let child = if bit == "0" { &node.left } else { &node.right };

            if let Some(child_node) = child {
                self.collect_relevant_roas_from_node(
                    child_node,
                    binary_prefix,
                    index + 1,
                    target_prefix,
                    relevant_roas,
                );
            }
        }
    }

    fn prefix_to_binary(prefix: &IpNetwork) -> String {
        match prefix {
            IpNetwork::V4(net) => {
                let addr_bits = u32::from(net.ip());
                let prefix_len = net.prefix() as usize;
                format!("{:032b}", addr_bits)[..prefix_len].to_string()
            }
            IpNetwork::V6(net) => {
                let addr_bits = u128::from(net.ip());
                let prefix_len = net.prefix() as usize;
                format!("{:0128b}", addr_bits)[..prefix_len].to_string()
            }
        }
    }
}

impl Default for RouteValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_roa_covers_prefix() {
        let roa = ROA::new(
            IpNetwork::from_str("10.0.0.0/8").unwrap(),
            65001,
            Some(24),
        );

        assert!(roa.covers_prefix(&IpNetwork::from_str("10.1.1.0/24").unwrap()));
        assert!(!roa.covers_prefix(&IpNetwork::from_str("192.168.1.0/24").unwrap()));
    }

    #[test]
    fn test_roa_validity() {
        let roa = ROA::new(
            IpNetwork::from_str("10.0.0.0/8").unwrap(),
            65001,
            Some(24),
        );

        // Valid
        assert_eq!(
            roa.get_validity(&IpNetwork::from_str("10.1.0.0/16").unwrap(), 65001),
            ROAValidity::Valid
        );

        // Invalid length
        assert_eq!(
            roa.get_validity(&IpNetwork::from_str("10.1.1.1/32").unwrap(), 65001),
            ROAValidity::InvalidLength
        );

        // Invalid origin
        assert_eq!(
            roa.get_validity(&IpNetwork::from_str("10.1.0.0/16").unwrap(), 65002),
            ROAValidity::InvalidOrigin
        );
    }
}