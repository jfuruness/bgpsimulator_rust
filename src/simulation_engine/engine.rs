use std::collections::HashMap;

use crate::as_graphs::as_graph::{ASGraph, ASN};
use crate::simulation_engine::{Announcement};
use crate::simulation_engine::announcement::{PolicyStore, AnnInfo};
use crate::shared::Relationships;

pub struct SimulationEngine<'a> {
    pub as_graph: &'a ASGraph,
    pub policy_store: PolicyStore,
}

impl<'a> SimulationEngine<'a> {
    pub fn new(as_graph: &'a ASGraph) -> Self {
        let mut policy_store = PolicyStore::new();
        
        // Create policies for all ASes
        for (asn, _) in as_graph.as_dict.iter() {
            policy_store.create_policy(*asn);
        }
        
        SimulationEngine {
            as_graph,
            policy_store,
        }
    }

    pub fn setup(&mut self, initial_announcements: Vec<(ASN, Announcement)>) {
        // Clear all policies
        for (_, policy) in self.policy_store.iter_mut() {
            policy.local_rib.clear();
            policy.recv_q.clear();
            policy.ribs_in.clear();
            policy.ribs_out.clear();
        }

        // Seed initial announcements
        for (asn, ann) in initial_announcements {
            if let Some(policy) = self.policy_store.get_mut(&asn) {
                policy.seed_ann(ann);
            }
        }
        
        // Do initial propagation of seeded announcements
        self.propagate_seeded_announcements();
    }
    
    fn propagate_seeded_announcements(&mut self) {
        // Collect ASes that have announcements to propagate
        let mut asns_with_anns = Vec::new();
        for (asn, policy) in self.policy_store.iter() {
            if !policy.local_rib.is_empty() {
                asns_with_anns.push(*asn);
            }
        }
        
        // Propagate from each AS
        for asn in asns_with_anns {
            let as_obj = match self.as_graph.get(&asn) {
                Some(obj) => obj,
                None => continue,
            };
            
            let mut anns_to_propagate = Vec::new();
            
            if let Some(policy) = self.policy_store.get(&asn) {
                // For each announcement in local RIB, propagate to neighbors
                for (prefix, ann) in &policy.local_rib {
                    // Check propagation to each relationship type
                    for rel in [Relationships::Customers, Relationships::Peers, Relationships::Providers] {
                        let neighbors = as_obj.get_neighbors(rel);
                        
                        for neighbor_as in neighbors {
                            let neighbor_asn = neighbor_as.asn;
                            let recv_rel_for_neighbor = rel.invert();
                            
                            // For initial propagation, remove our ASN from the front if present
                            let mut ann_to_send = ann.clone();
                            if ann_to_send.as_path.first() == Some(&asn) {
                                ann_to_send.as_path.remove(0);
                            }
                            
                            let new_ann = ann_to_send.copy_and_process(as_obj.asn, recv_rel_for_neighbor);
                            anns_to_propagate.push((neighbor_asn, new_ann, recv_rel_for_neighbor));
                        }
                    }
                }
            }
            
            // Send collected announcements
            for (neighbor_asn, new_ann, rel) in anns_to_propagate {
                if let Some(neighbor_policy) = self.policy_store.get_mut(&neighbor_asn) {
                    neighbor_policy.receive_ann(new_ann, rel);
                }
            }
        }
    }

    pub fn run(&mut self, rounds: u32) {
        for _round in 0..rounds {
            self.propagate_round();
        }
    }

    fn propagate_round(&mut self) {
        // Three-phase propagation following Gao-Rexford model
        self.propagate_to_providers();
        self.propagate_to_peers();
        self.propagate_to_customers();
    }

    fn propagate_to_providers(&mut self) {
        // Process in reverse propagation rank order (leaves to roots)
        let ranks = self.as_graph.propagation_ranks.clone();
        
        for rank_asns in ranks.iter().rev() {
            self.process_asns_for_relationship(rank_asns, Relationships::Providers);
        }
    }

    fn propagate_to_peers(&mut self) {
        // Process all ASes for peer relationships
        let all_asns: Vec<ASN> = self.as_graph.as_dict.keys().copied().collect();
        self.process_asns_for_relationship(&all_asns, Relationships::Peers);
    }

    fn propagate_to_customers(&mut self) {
        // Process in propagation rank order (roots to leaves)
        let ranks = self.as_graph.propagation_ranks.clone();
        
        for rank_asns in ranks.iter() {
            self.process_asns_for_relationship(rank_asns, Relationships::Customers);
        }
    }

    fn process_asns_for_relationship(&mut self, asns: &[ASN], _relationship: Relationships) {
        // Process each AS's incoming announcements
        for &asn in asns {
            // Get AS object reference - no cloning needed
            let as_obj = match self.as_graph.get(&asn) {
                Some(obj) => obj,
                None => continue,
            };
            
            // Create a temporary buffer for processing
            let mut anns_to_process = Vec::new();
            
            // Collect announcements from recv_q
            if let Some(policy) = self.policy_store.get_mut(&asn) {
                anns_to_process = policy.recv_q.drain(..).collect();
            }
            
            // Process the announcements
            for ann_info in anns_to_process {
                if let Some(policy) = self.policy_store.get_mut(&asn) {
                    let is_valid = policy.valid_ann(&ann_info.ann, ann_info.recv_relationship, as_obj);
                    
                    if is_valid {
                        // We need a different approach here to avoid borrowing conflicts
                        // Let's collect the announcements to propagate first
                        let mut anns_to_propagate = Vec::new();
                        
                        // Process the announcement and collect propagations
                        policy.ribs_in.entry(ann_info.ann.next_hop_asn)
                            .or_insert_with(HashMap::new)
                            .insert(ann_info.ann.prefix, ann_info.ann.clone());
                        
                        let best_ann = policy.get_best_ann_for_prefix(&ann_info.ann.prefix, as_obj);
                        
                        if let Some(mut best) = best_ann {
                            // When storing in local RIB, prepend our ASN to the path
                            if best.as_path.first() != Some(&asn) {
                                best.as_path.insert(0, asn);
                            }
                            policy.local_rib.insert(ann_info.ann.prefix, best.clone());
                            
                            let should_prop = policy.should_propagate(&best, ann_info.recv_relationship);
                            
                            if should_prop {
                                // Collect announcements to propagate
                                for rel in [Relationships::Customers, Relationships::Peers, Relationships::Providers] {
                                    let should_prop = policy.should_propagate_to_rel(&best, rel);
                                    
                                    if should_prop {
                                        let neighbors = match rel {
                                            Relationships::Customers => &as_obj.customers,
                                            Relationships::Peers => &as_obj.peers,
                                            Relationships::Providers => &as_obj.providers,
                                            _ => continue,
                                        };
                                        
                                        for neighbor_as in neighbors.iter() {
                                            let neighbor_asn = neighbor_as.asn;
                                            let recv_rel_for_neighbor = rel.invert();
                                            
                                            // For propagation, we need the announcement without our ASN prepended
                                            // So we'll use the version from ribs_in if available, or remove our ASN from the path
                                            let mut ann_to_send = best.clone();
                                            if ann_to_send.as_path.first() == Some(&asn) {
                                                ann_to_send.as_path.remove(0);
                                            }
                                            
                                            let new_ann = ann_to_send.copy_and_process(as_obj.asn, recv_rel_for_neighbor);
                                            anns_to_propagate.push((neighbor_asn, new_ann.clone(), recv_rel_for_neighbor));
                                            
                                            // Update ribs_out
                                            policy.ribs_out.entry(neighbor_asn)
                                                .or_insert_with(HashMap::new)
                                                .insert(new_ann.prefix, new_ann);
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Now propagate the collected announcements
                        for (neighbor_asn, new_ann, rel) in anns_to_propagate {
                            if let Some(neighbor_policy) = self.policy_store.get_mut(&neighbor_asn) {
                                neighbor_policy.receive_ann(new_ann, rel);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn get_local_rib_snapshot(&self) -> HashMap<ASN, HashMap<String, Vec<ASN>>> {
        let mut snapshot = HashMap::new();
        
        for (asn, policy) in self.policy_store.iter() {
            let mut as_ribs = HashMap::new();
            
            for (prefix, ann) in &policy.local_rib {
                as_ribs.insert(prefix.to_string(), ann.as_path.clone());
            }
            
            snapshot.insert(*asn, as_ribs);
        }
        
        snapshot
    }
}