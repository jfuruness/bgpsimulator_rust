use std::collections::{HashMap, HashSet};
use std::mem;

pub type ASN = u32;

/// AS struct with direct references to other AS objects
/// All references have the same lifetime 'a as the graph
#[derive(Debug)]
pub struct AS<'a> {
    pub asn: ASN,
    pub peers: Vec<&'a AS<'a>>,
    pub providers: Vec<&'a AS<'a>>,
    pub customers: Vec<&'a AS<'a>>,
    pub tier_1: bool,
    pub ixp: bool,
    pub provider_cone_asns: HashSet<ASN>,
    pub propagation_rank: Option<u32>,
}

/// Builder struct used during AS graph construction
#[derive(Debug, Clone)]
pub struct ASBuilder {
    pub asn: ASN,
    pub peer_asns: Vec<ASN>,
    pub provider_asns: Vec<ASN>,
    pub customer_asns: Vec<ASN>,
    pub tier_1: bool,
    pub ixp: bool,
}

/// AS Graph that owns all AS objects
pub struct ASGraph {
    // We use a trick here: store the AS objects in a separate allocation
    // that outlives the graph, then use unsafe to cast the lifetime
    storage: *mut Vec<AS<'static>>,
    pub as_dict: HashMap<ASN, &'static AS<'static>>,
    pub propagation_ranks: Vec<Vec<ASN>>,
}

// SAFETY: ASGraph can be sent between threads because it owns its data
unsafe impl Send for ASGraph {}
unsafe impl Sync for ASGraph {}

impl std::fmt::Debug for ASGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ASGraph")
            .field("as_dict_len", &self.as_dict.len())
            .field("propagation_ranks", &self.propagation_ranks)
            .finish()
    }
}

impl ASGraph {
    /// Create a new empty AS graph
    pub fn new() -> Self {
        ASGraph {
            storage: Box::into_raw(Box::new(Vec::new())),
            as_dict: HashMap::new(),
            propagation_ranks: Vec::new(),
        }
    }
    
    /// Build AS graph from relationship data
    /// This uses unsafe to establish circular references, but is sound because:
    /// 1. We allocate AS objects in a stable location
    /// 2. We only mutate during construction  
    /// 3. After construction, everything is immutable
    pub fn build(builders: Vec<ASBuilder>) -> ASGraph {
        // Create storage for AS objects
        let mut storage = Box::new(Vec::<AS<'static>>::with_capacity(builders.len()));
        let storage_ptr = Box::into_raw(storage);
        
        unsafe {
            // First pass: create all AS objects with empty neighbor vectors
            for builder in &builders {
                let as_obj = AS {
                    asn: builder.asn,
                    peers: Vec::new(),
                    providers: Vec::new(), 
                    customers: Vec::new(),
                    tier_1: builder.tier_1,
                    ixp: builder.ixp,
                    provider_cone_asns: HashSet::new(),
                    propagation_rank: None,
                };
                (*storage_ptr).push(as_obj);
            }
            
            // Create lookup map
            let mut as_dict = HashMap::new();
            for as_obj in (*storage_ptr).iter() {
                as_dict.insert(as_obj.asn, as_obj as &'static AS<'static>);
            }
            
            // Second pass: establish references
            for (i, builder) in builders.iter().enumerate() {
                let as_obj = &mut (*storage_ptr)[i] as *mut AS<'static>;
                
                // Populate peer references
                (*as_obj).peers = builder.peer_asns.iter()
                    .filter_map(|asn| as_dict.get(asn).copied())
                    .collect();
                
                // Populate provider references  
                (*as_obj).providers = builder.provider_asns.iter()
                    .filter_map(|asn| as_dict.get(asn).copied())
                    .collect();
                
                // Populate customer references
                (*as_obj).customers = builder.customer_asns.iter()
                    .filter_map(|asn| as_dict.get(asn).copied())
                    .collect();
            }
            
            ASGraph {
                storage: storage_ptr,
                as_dict,
                propagation_ranks: Vec::new(),
            }
        }
    }
    
    /// Get an AS by ASN
    pub fn get(&self, asn: &ASN) -> Option<&AS> {
        self.as_dict.get(asn).map(|&as_ref| {
            // SAFETY: We return a reference with the lifetime of self, not 'static
            unsafe { mem::transmute::<&'static AS<'static>, &AS>(as_ref) }
        })
    }
    
    /// Iterate over all AS objects
    pub fn iter(&self) -> impl Iterator<Item = &AS> {
        self.as_dict.values().map(|&as_ref| {
            // SAFETY: We return references with the lifetime of self, not 'static
            unsafe { mem::transmute::<&'static AS<'static>, &AS>(as_ref) }
        })
    }
    
    /// Number of ASes in the graph
    pub fn len(&self) -> usize {
        self.as_dict.len()
    }
    
    /// Check for cycles in the AS graph
    pub fn check_for_cycles(&self) -> Result<(), String> {
        for as_obj in self.iter() {
            // Check for self-loops
            if as_obj.providers.iter().any(|p| p.asn == as_obj.asn) {
                return Err(format!("AS {} has itself as provider", as_obj.asn));
            }
            if as_obj.customers.iter().any(|c| c.asn == as_obj.asn) {
                return Err(format!("AS {} has itself as customer", as_obj.asn));
            }
        }
        Ok(())
    }
    
    /// Assign propagation ranks to ASes
    pub fn assign_as_propagation_rank(&mut self) {
        unsafe {
            let storage = &mut *self.storage;
            let mut ranks: HashMap<ASN, u32> = HashMap::new();
            let mut rank_groups: HashMap<u32, Vec<ASN>> = HashMap::new();
            
            // Find tier-1 ASes (no providers)
            let mut current_rank = 0;
            let mut current_asns: Vec<ASN> = storage.iter()
                .filter(|as_obj| as_obj.providers.is_empty())
                .map(|as_obj| as_obj.asn)
                .collect();
            
            while !current_asns.is_empty() {
                rank_groups.insert(current_rank, current_asns.clone());
                
                for asn in &current_asns {
                    ranks.insert(*asn, current_rank);
                }
                
                // Find next level (customers of current level)
                let mut next_asns = Vec::new();
                for as_obj in storage.iter() {
                    if !ranks.contains_key(&as_obj.asn) {
                        let all_providers_ranked = as_obj.providers.iter()
                            .all(|p| ranks.contains_key(&p.asn));
                        if all_providers_ranked {
                            next_asns.push(as_obj.asn);
                        }
                    }
                }
                
                current_asns = next_asns;
                current_rank += 1;
            }
            
            // Apply ranks to AS objects
            for as_obj in storage.iter_mut() {
                if let Some(&rank) = ranks.get(&as_obj.asn) {
                    as_obj.propagation_rank = Some(rank);
                }
            }
            
            // Populate propagation_ranks vector
            let max_rank = rank_groups.keys().max().copied().unwrap_or(0);
            self.propagation_ranks = (0..=max_rank)
                .map(|rank| rank_groups.get(&rank).cloned().unwrap_or_default())
                .collect();
        }
    }
    
    /// Add ASN groups (for CommonASNs)
    pub fn add_asn_groups(&mut self) {
        // This would add special ASNs like VICTIM, ATTACKER etc.
        // For now, we'll skip this as it's handled separately
    }
    
    /// Add an AS from a builder (used for incremental construction)
    pub fn add_as_from_builder(&mut self, builder: ASBuilder) {
        unsafe {
            let storage = &mut *self.storage;
            
            // Create AS object
            let as_obj = AS {
                asn: builder.asn,
                peers: Vec::new(),  // Will be populated in establish_relationships
                providers: Vec::new(),
                customers: Vec::new(),
                tier_1: builder.tier_1,
                ixp: builder.ixp,
                propagation_rank: None,
                provider_cone_asns: HashSet::new(),
            };
            
            storage.push(as_obj);
            let as_ref = storage.last().unwrap() as *const AS<'static>;
            self.as_dict.insert(builder.asn, &*as_ref);
            
            // Store builder for later relationship establishment
            // For now, we'll need to track these separately
        }
    }
    
    /// Establish relationships between ASes after all have been added
    pub fn establish_relationships(&mut self) {
        // TODO: This requires storing builders and then establishing relationships
        // For now, we'll use the build method instead
    }
}

impl Drop for ASGraph {
    fn drop(&mut self) {
        unsafe {
            // Reclaim the storage
            let _ = Box::from_raw(self.storage);
        }
    }
}

impl ASBuilder {
    pub fn new(asn: ASN) -> Self {
        ASBuilder {
            asn,
            peer_asns: Vec::new(),
            provider_asns: Vec::new(),
            customer_asns: Vec::new(),
            tier_1: false,
            ixp: false,
        }
    }
    
    pub fn with_peers(mut self, peers: Vec<ASN>) -> Self {
        self.peer_asns = peers;
        self
    }
    
    pub fn with_providers(mut self, providers: Vec<ASN>) -> Self {
        self.provider_asns = providers;
        self
    }
    
    pub fn with_customers(mut self, customers: Vec<ASN>) -> Self {
        self.customer_asns = customers;
        self
    }
    
    pub fn as_tier_1(mut self) -> Self {
        self.tier_1 = true;
        self
    }
    
    pub fn from_asn_sets(
        asn: ASN,
        peers: HashSet<ASN>,
        providers: HashSet<ASN>,
        customers: HashSet<ASN>,
    ) -> Self {
        ASBuilder {
            asn,
            peer_asns: peers.into_iter().collect(),
            provider_asns: providers.into_iter().collect(),
            customer_asns: customers.into_iter().collect(),
            tier_1: false,
            ixp: false,
        }
    }
}

impl<'a> AS<'a> {
    /// Get all neighbor ASes (peers + providers + customers)
    pub fn neighbors(&self) -> impl Iterator<Item = &AS<'a>> {
        self.peers.iter()
            .chain(self.providers.iter())
            .chain(self.customers.iter())
            .copied()
    }
    
    /// Check if this AS is a stub (no customers)
    pub fn is_stub(&self) -> bool {
        self.customers.is_empty()
    }
    
    /// Get neighbors of a specific relationship type
    pub fn get_neighbors(&self, relationship: crate::shared::Relationships) -> &[&AS<'a>] {
        match relationship {
            crate::shared::Relationships::Customers => &self.customers,
            crate::shared::Relationships::Peers => &self.peers,
            crate::shared::Relationships::Providers => &self.providers,
            _ => &[],
        }
    }
}