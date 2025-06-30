use std::collections::{HashMap, HashSet, VecDeque};

use crate::shared::{ASNGroups, Relationships, CycleError};

pub type ASN = u32;

#[derive(Debug, Clone)]
pub struct AS {
    pub asn: ASN,
    pub peers: Vec<ASN>,
    pub providers: Vec<ASN>,
    pub customers: Vec<ASN>,
    pub tier_1: bool,
    pub ixp: bool,
    pub provider_cone_asns: HashSet<ASN>,
    pub propagation_rank: Option<u32>,
}

impl AS {
    pub fn new(asn: ASN) -> Self {
        AS {
            asn,
            peers: Vec::new(),
            providers: Vec::new(),
            customers: Vec::new(),
            tier_1: false,
            ixp: false,
            provider_cone_asns: HashSet::new(),
            propagation_rank: None,
        }
    }

    pub fn from_asn_sets(
        asn: ASN,
        peer_asns: HashSet<ASN>,
        provider_asns: HashSet<ASN>,
        customer_asns: HashSet<ASN>,
    ) -> Self {
        AS {
            asn,
            peers: peer_asns.into_iter().collect(),
            providers: provider_asns.into_iter().collect(),
            customers: customer_asns.into_iter().collect(),
            tier_1: false,
            ixp: false,
            provider_cone_asns: HashSet::new(),
            propagation_rank: None,
        }
    }

    pub fn get_neighbors(&self, rel: Relationships) -> &[ASN] {
        match rel {
            Relationships::Providers => &self.providers,
            Relationships::Peers => &self.peers,
            Relationships::Customers => &self.customers,
            _ => &[],
        }
    }

    pub fn is_stub(&self) -> bool {
        self.customers.is_empty()
    }

    pub fn is_multihomed(&self) -> bool {
        self.customers.is_empty() && (self.providers.len() + self.peers.len()) > 1
    }

    pub fn is_transit(&self) -> bool {
        !self.customers.is_empty()
    }

    pub fn neighbor_asns(&self) -> HashSet<ASN> {
        let mut result = HashSet::new();
        result.extend(&self.peers);
        result.extend(&self.providers);
        result.extend(&self.customers);
        result
    }

    pub fn peer_asns(&self) -> HashSet<ASN> {
        self.peers.iter().copied().collect()
    }

    pub fn provider_asns(&self) -> HashSet<ASN> {
        self.providers.iter().copied().collect()
    }

    pub fn customer_asns(&self) -> HashSet<ASN> {
        self.customers.iter().copied().collect()
    }
}

#[derive(Debug, Clone)]
pub struct ASGraph {
    pub as_dict: HashMap<ASN, AS>,
    pub asn_groups: HashMap<ASNGroups, HashSet<ASN>>,
    pub propagation_ranks: Vec<Vec<ASN>>,
}

impl ASGraph {
    pub fn new() -> Self {
        ASGraph {
            as_dict: HashMap::new(),
            asn_groups: HashMap::new(),
            propagation_ranks: Vec::new(),
        }
    }

    pub fn get(&self, asn: &ASN) -> Option<&AS> {
        self.as_dict.get(asn)
    }

    pub fn get_mut(&mut self, asn: &ASN) -> Option<&mut AS> {
        self.as_dict.get_mut(asn)
    }

    pub fn insert(&mut self, as_obj: AS) {
        self.as_dict.insert(as_obj.asn, as_obj);
    }

    pub fn iter(&self) -> impl Iterator<Item = &AS> {
        self.as_dict.values()
    }

    pub fn check_for_cycles(&self) -> Result<(), CycleError> {
        for as_obj in self.as_dict.values() {
            let mut visited = HashSet::new();
            let mut stack = VecDeque::new();
            
            stack.push_back((as_obj.asn, HashSet::new()));
            
            while let Some((current_asn, mut path)) = stack.pop_back() {
                if path.contains(&current_asn) {
                    return Err(CycleError);
                }
                
                if visited.contains(&current_asn) {
                    continue;
                }
                
                visited.insert(current_asn);
                path.insert(current_asn);
                
                if let Some(current_as) = self.as_dict.get(&current_asn) {
                    for &provider_asn in &current_as.providers {
                        stack.push_back((provider_asn, path.clone()));
                    }
                }
            }
        }
        
        Ok(())
    }

    pub fn add_provider_cone_asns(&mut self) {
        let mut provider_cones: HashMap<ASN, HashSet<ASN>> = HashMap::new();
        
        // Collect all ASNs that need cone calculation
        let all_asns: Vec<ASN> = self.as_dict.keys().copied().collect();
        
        for asn in all_asns {
            if let Some(as_obj) = self.as_dict.get(&asn) {
                if as_obj.tier_1 {
                    let cone = self.calculate_provider_cone(asn, &mut HashMap::new());
                    provider_cones.insert(asn, cone);
                }
            }
        }
        
        // Update the AS objects with their provider cones
        for (asn, cone) in provider_cones {
            if let Some(as_obj) = self.as_dict.get_mut(&asn) {
                as_obj.provider_cone_asns = cone;
            }
        }
    }

    fn calculate_provider_cone(&self, asn: ASN, visited: &mut HashMap<ASN, HashSet<ASN>>) -> HashSet<ASN> {
        if let Some(cone) = visited.get(&asn) {
            return cone.clone();
        }
        
        let mut cone = HashSet::new();
        cone.insert(asn);
        
        if let Some(as_obj) = self.as_dict.get(&asn) {
            for &customer_asn in &as_obj.customers {
                let customer_cone = self.calculate_provider_cone(customer_asn, visited);
                cone.extend(customer_cone);
            }
        }
        
        visited.insert(asn, cone.clone());
        cone
    }

    pub fn assign_as_propagation_rank(&mut self) {
        let mut unassigned: HashSet<ASN> = self.as_dict.keys().copied().collect();
        let mut current_rank = 0u32;
        let mut propagation_ranks = Vec::new();
        
        while !unassigned.is_empty() {
            let mut current_rank_asns = Vec::new();
            
            for &asn in &unassigned {
                if let Some(as_obj) = self.as_dict.get(&asn) {
                    let all_providers_ranked = as_obj.providers.iter().all(|&p| {
                        self.as_dict.get(&p)
                            .map(|provider| provider.propagation_rank.is_some())
                            .unwrap_or(false)
                    });
                    
                    if as_obj.providers.is_empty() || all_providers_ranked {
                        current_rank_asns.push(asn);
                    }
                }
            }
            
            for &asn in &current_rank_asns {
                unassigned.remove(&asn);
                if let Some(as_obj) = self.as_dict.get_mut(&asn) {
                    as_obj.propagation_rank = Some(current_rank);
                }
            }
            
            if !current_rank_asns.is_empty() {
                propagation_ranks.push(current_rank_asns);
                current_rank += 1;
            }
        }
        
        self.propagation_ranks = propagation_ranks;
    }

    pub fn add_asn_groups(&mut self) {
        let mut groups: HashMap<ASNGroups, HashSet<ASN>> = HashMap::new();
        
        let tier_1_asns: HashSet<ASN> = self.as_dict.values()
            .filter(|as_obj| as_obj.tier_1)
            .map(|as_obj| as_obj.asn)
            .collect();
        groups.insert(ASNGroups::Tier1, tier_1_asns);
        
        let stubs: HashSet<ASN> = self.as_dict.values()
            .filter(|as_obj| as_obj.is_stub())
            .map(|as_obj| as_obj.asn)
            .collect();
        groups.insert(ASNGroups::Stubs, stubs.clone());
        
        let multihomed: HashSet<ASN> = self.as_dict.values()
            .filter(|as_obj| as_obj.is_multihomed())
            .map(|as_obj| as_obj.asn)
            .collect();
        groups.insert(ASNGroups::Multihomed, multihomed.clone());
        
        let mut stubs_or_mh = stubs;
        stubs_or_mh.extend(&multihomed);
        groups.insert(ASNGroups::StubsOrMh, stubs_or_mh);
        
        let transit: HashSet<ASN> = self.as_dict.values()
            .filter(|as_obj| as_obj.is_transit())
            .map(|as_obj| as_obj.asn)
            .collect();
        groups.insert(ASNGroups::Transit, transit);
        
        let ixp: HashSet<ASN> = self.as_dict.values()
            .filter(|as_obj| as_obj.ixp)
            .map(|as_obj| as_obj.asn)
            .collect();
        groups.insert(ASNGroups::Ixp, ixp);
        
        groups.insert(ASNGroups::Etc, HashSet::new());
        groups.insert(ASNGroups::Input, HashSet::new());
        
        self.asn_groups = groups;
    }
}

impl Default for ASGraph {
    fn default() -> Self {
        Self::new()
    }
}