use bgpsimulator::as_graphs::as_graph::{ASGraph, ASBuilder};

fn main() {
    // Create AS relationship data
    let builders = vec![
        ASBuilder::new(1)
            .with_customers(vec![2, 3])
            .as_tier_1(),
        ASBuilder::new(2)
            .with_providers(vec![1])
            .with_customers(vec![4]),
        ASBuilder::new(3)
            .with_providers(vec![1])
            .with_peers(vec![2]),
        ASBuilder::new(4)
            .with_providers(vec![2]),
    ];
    
    // Build the AS graph - note the lifetime is managed by Box
    let as_graph = ASGraph::build(builders);
    
    // Now we can use direct references with zero lookup overhead!
    if let Some(as1) = as_graph.get(&1) {
        println!("AS1 has {} customers", as1.customers.len());
        
        for customer in &as1.customers {
            println!("  AS1 -> AS{} (customer)", customer.asn);
            
            // We can traverse the graph with direct references
            for provider in &customer.providers {
                println!("    AS{} -> AS{} (provider)", customer.asn, provider.asn);
            }
        }
    }
    
    // Verify circular references work
    if let Some(as2) = as_graph.get(&2) {
        println!("\nAS2's relationships:");
        println!("  Providers: {:?}", as2.providers.iter().map(|p| p.asn).collect::<Vec<_>>());
        println!("  Customers: {:?}", as2.customers.iter().map(|c| c.asn).collect::<Vec<_>>());
        
        // Check that AS2's provider (AS1) has AS2 as customer
        for provider in &as2.providers {
            let has_as_customer = provider.customers.iter().any(|c| c.asn == 2);
            println!("  AS{} has AS2 as customer: {}", provider.asn, has_as_customer);
        }
    }
}