use std::collections::{HashMap, VecDeque};

use crate::shared::{Relationships, Settings, Timestamps};
use crate::as_graphs::as_graph::{AS, ASN, ASGraph};
use crate::simulation_engine::policy::{PolicyExtension, ProcessingResult, create_policy_extension};

pub type Prefix = ipnetwork::IpNetwork;

#[derive(Debug, Clone)]
pub struct Announcement {
    pub prefix: Prefix,
    pub as_path: Vec<ASN>,
    pub next_hop_asn: ASN,
    pub recv_relationship: Relationships,
    pub timestamp: Timestamps,
    pub withdraw: bool,
    pub bgpsec_next_asn: Option<ASN>,
    pub bgpsec_as_path: Option<Vec<ASN>>,
    pub only_to_customers: Option<bool>,
    pub rovpp_blackhole: Option<bool>,
    pub rost_ids: Option<Vec<u32>>,
}

impl Announcement {
    pub fn new(
        prefix: Prefix,
        next_hop_asn: ASN,
        recv_relationship: Relationships,
    ) -> Self {
        Announcement {
            prefix,
            as_path: Vec::new(),
            next_hop_asn,
            recv_relationship,
            timestamp: Timestamps::Victim,
            withdraw: false,
            bgpsec_next_asn: None,
            bgpsec_as_path: None,
            only_to_customers: None,
            rovpp_blackhole: None,
            rost_ids: None,
        }
    }
    
    pub fn new_with_path(
        prefix: Prefix,
        as_path: Vec<ASN>,
        next_hop_asn: ASN,
        recv_relationship: Relationships,
        timestamp: Timestamps,
    ) -> Self {
        Announcement {
            prefix,
            as_path,
            next_hop_asn,
            recv_relationship,
            timestamp,
            withdraw: false,
            bgpsec_next_asn: None,
            bgpsec_as_path: None,
            only_to_customers: None,
            rovpp_blackhole: None,
            rost_ids: None,
        }
    }

    pub fn origin(&self) -> ASN {
        self.as_path.last().copied().unwrap_or(self.next_hop_asn)
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    pub fn copy_and_process(&self, next_hop_asn: ASN, recv_relationship: Relationships) -> Self {
        let mut new_ann = self.clone();
        
        if !new_ann.withdraw {
            new_ann.as_path.insert(0, next_hop_asn);
            if let Some(ref mut bgpsec_path) = new_ann.bgpsec_as_path {
                bgpsec_path.insert(0, next_hop_asn);
            }
        }
        
        new_ann.next_hop_asn = next_hop_asn;
        new_ann.recv_relationship = recv_relationship;
        new_ann.bgpsec_next_asn = Some(next_hop_asn);
        
        new_ann
    }
}

#[derive(Debug)]
pub struct AnnInfo {
    pub ann: Announcement,
    pub recv_relationship: Relationships,
}

impl AnnInfo {
    pub fn new(ann: Announcement, recv_relationship: Relationships) -> Self {
        AnnInfo { ann, recv_relationship }
    }
}

pub type RIBsIn = HashMap<ASN, HashMap<Prefix, Announcement>>;
pub type RIBsOut = HashMap<ASN, HashMap<Prefix, Announcement>>;
pub type LocalRIB = HashMap<Prefix, Announcement>;

pub struct Policy {
    pub local_rib: LocalRIB,
    pub recv_q: VecDeque<AnnInfo>,
    pub ribs_in: RIBsIn,
    pub ribs_out: RIBsOut,
    pub settings: Settings,
    pub asn: ASN,
    pub extension: Box<dyn PolicyExtension>,
}

impl Policy {
    pub fn new(asn: ASN) -> Self {
        let settings = Settings::BaseDefense;
        Policy {
            local_rib: HashMap::new(),
            recv_q: VecDeque::new(),
            ribs_in: HashMap::new(),
            ribs_out: HashMap::new(),
            settings,
            asn,
            extension: create_policy_extension(settings),
        }
    }
    
    pub fn with_settings(asn: ASN, settings: Settings) -> Self {
        Policy {
            local_rib: HashMap::new(),
            recv_q: VecDeque::new(),
            ribs_in: HashMap::new(),
            ribs_out: HashMap::new(),
            settings,
            asn,
            extension: create_policy_extension(settings),
        }
    }

    pub fn receive_ann(&mut self, ann: Announcement, recv_relationship: Relationships) {
        self.recv_q.push_back(AnnInfo::new(ann, recv_relationship));
    }

    pub fn process_incoming_anns(&mut self, as_obj: &AS, as_graph: &ASGraph, policy_store: &mut PolicyStore) {
        let anns_to_process: Vec<AnnInfo> = self.recv_q.drain(..).collect();
        
        for ann_info in anns_to_process {
            if self.valid_ann(&ann_info.ann, ann_info.recv_relationship, as_obj) {
                self.process_ann(ann_info.ann, ann_info.recv_relationship, as_obj, as_graph, policy_store);
            }
        }
    }

    pub fn valid_ann(&self, ann: &Announcement, recv_relationship: Relationships, as_obj: &AS) -> bool {
        self.extension.validate_announcement(ann, recv_relationship, as_obj, None)
    }

    pub fn process_ann(&mut self, ann: Announcement, recv_relationship: Relationships, 
                       as_obj: &AS, as_graph: &ASGraph, policy_store: &mut PolicyStore) {
        self.ribs_in.entry(ann.next_hop_asn)
            .or_insert_with(HashMap::new)
            .insert(ann.prefix, ann.clone());
        
        let best_ann = self.get_best_ann_for_prefix(&ann.prefix, as_obj);
        
        if let Some(best) = best_ann {
            self.local_rib.insert(ann.prefix, best.clone());
            
            if self.should_propagate(&best, recv_relationship) {
                self.propagate_ann(&best, as_obj, as_graph, policy_store);
            }
        } else if ann.withdraw {
            self.local_rib.remove(&ann.prefix);
            let withdraw_ann = Announcement {
                prefix: ann.prefix,
                as_path: vec![as_obj.asn],
                next_hop_asn: as_obj.asn,
                recv_relationship: Relationships::Origin,
                timestamp: ann.timestamp,
                withdraw: true,
                bgpsec_next_asn: None,
                bgpsec_as_path: None,
                only_to_customers: None,
                rovpp_blackhole: None,
                rost_ids: None,
            };
            self.propagate_ann(&withdraw_ann, as_obj, as_graph, policy_store);
        }
    }

    pub fn get_best_ann_for_prefix(&self, prefix: &Prefix, as_obj: &AS) -> Option<Announcement> {
        let mut candidates = Vec::new();
        
        for neighbor_ribs in self.ribs_in.values() {
            if let Some(ann) = neighbor_ribs.get(prefix) {
                if !ann.withdraw {
                    candidates.push(ann.clone());
                }
            }
        }
        
        if candidates.is_empty() {
            return None;
        }
        
        candidates.sort_by(|a, b| {
            let rel_a = self.get_relationship(&a.next_hop_asn, as_obj);
            let rel_b = self.get_relationship(&b.next_hop_asn, as_obj);
            self.extension.compare_announcements(a, b, rel_a, rel_b, as_obj)
        });
        
        candidates.into_iter().next()
    }

    fn get_relationship(&self, neighbor_asn: &ASN, as_obj: &AS) -> Relationships {
        if as_obj.customers.iter().any(|as_ref| as_ref.asn == *neighbor_asn) {
            Relationships::Customers
        } else if as_obj.peers.iter().any(|as_ref| as_ref.asn == *neighbor_asn) {
            Relationships::Peers
        } else if as_obj.providers.iter().any(|as_ref| as_ref.asn == *neighbor_asn) {
            Relationships::Providers
        } else {
            Relationships::Unknown
        }
    }


    pub fn should_propagate(&self, ann: &Announcement, recv_relationship: Relationships) -> bool {
        !ann.only_to_customers.unwrap_or(false) || 
        recv_relationship == Relationships::Customers ||
        recv_relationship == Relationships::Origin
    }

    fn propagate_ann(&mut self, ann: &Announcement, as_obj: &AS, as_graph: &ASGraph, policy_store: &mut PolicyStore) {
        for rel in [Relationships::Customers, Relationships::Peers, Relationships::Providers] {
            if self.should_propagate_to_rel(ann, rel) {
                self.propagate_to_neighbors(ann, rel, as_obj, as_graph, policy_store);
            }
        }
    }

    pub fn should_propagate_to_rel(&self, ann: &Announcement, rel: Relationships) -> bool {
        self.extension.should_propagate(ann, ann.recv_relationship, rel)
    }

    fn propagate_to_neighbors(&mut self, ann: &Announcement, rel: Relationships, 
                              as_obj: &AS, as_graph: &ASGraph, policy_store: &mut PolicyStore) {
        let neighbors = as_obj.get_neighbors(rel);
        let mut anns_to_send = Vec::new();
        
        for neighbor_as in neighbors {
            let neighbor_asn = neighbor_as.asn;
            let new_ann = ann.copy_and_process(as_obj.asn, rel);
            
            self.ribs_out.entry(neighbor_asn)
                .or_insert_with(HashMap::new)
                .insert(new_ann.prefix, new_ann.clone());
            
            anns_to_send.push((neighbor_asn, new_ann, rel));
        }
        
        // Send announcements after we're done modifying self
        for (neighbor_asn, new_ann, rel) in anns_to_send {
            if let Some(neighbor_policy) = policy_store.get_mut(&neighbor_asn) {
                neighbor_policy.receive_ann(new_ann, rel);
            }
        }
    }

    pub fn seed_ann(&mut self, mut ann: Announcement) {
        // If the AS path is empty, set it to just our ASN (origination)
        // Otherwise, preserve the existing path (for testing scenarios)
        if ann.as_path.is_empty() && !ann.withdraw {
            ann.as_path = vec![self.asn];
        }
        ann.next_hop_asn = self.asn;
        ann.recv_relationship = Relationships::Origin;
        
        if ann.withdraw {
            // For withdrawals, remove from local RIB
            self.local_rib.remove(&ann.prefix);
        } else {
            // For announcements, put in local RIB
            self.local_rib.insert(ann.prefix, ann);
        }
    }
}

pub struct PolicyStore {
    policies: HashMap<ASN, Policy>,
}

impl PolicyStore {
    pub fn new() -> Self {
        PolicyStore {
            policies: HashMap::new(),
        }
    }

    pub fn create_policy(&mut self, asn: ASN) -> &mut Policy {
        self.policies.entry(asn).or_insert_with(|| Policy::new(asn))
    }

    pub fn get(&self, asn: &ASN) -> Option<&Policy> {
        self.policies.get(asn)
    }

    pub fn get_mut(&mut self, asn: &ASN) -> Option<&mut Policy> {
        self.policies.get_mut(asn)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ASN, &Policy)> {
        self.policies.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&ASN, &mut Policy)> {
        self.policies.iter_mut()
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

pub use ipnetwork;