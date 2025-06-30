use bgpsimulator::route_validator::{ROA, RouteValidator};
use bgpsimulator::shared::ROAValidity;
use ipnetwork::IpNetwork;
use std::str::FromStr;

#[test]
fn test_roa_creation() {
    let prefix = IpNetwork::from_str("10.0.0.0/8").unwrap();
    let roa = ROA::new(prefix, 65001, Some(24));
    
    assert_eq!(roa.prefix, prefix);
    assert_eq!(roa.origin, 65001);
    assert_eq!(roa.max_length, 24);
    assert!(roa.is_routed());
    assert!(!roa.is_non_routed());
}

#[test]
fn test_roa_covers_prefix() {
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    );
    
    // Should cover more specific prefixes
    assert!(roa.covers_prefix(&IpNetwork::from_str("10.1.1.0/24").unwrap()));
    assert!(roa.covers_prefix(&IpNetwork::from_str("10.0.0.0/16").unwrap()));
    assert!(roa.covers_prefix(&IpNetwork::from_str("10.255.255.0/24").unwrap()));
    
    // Should not cover unrelated prefixes
    assert!(!roa.covers_prefix(&IpNetwork::from_str("192.168.1.0/24").unwrap()));
    assert!(!roa.covers_prefix(&IpNetwork::from_str("172.16.0.0/12").unwrap()));
}

#[test]
fn test_roa_validity_valid() {
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    );
    
    // Valid: correct origin and length within max
    assert_eq!(
        roa.get_validity(&IpNetwork::from_str("10.1.0.0/16").unwrap(), 65001),
        ROAValidity::Valid
    );
    assert_eq!(
        roa.get_validity(&IpNetwork::from_str("10.1.1.0/24").unwrap(), 65001),
        ROAValidity::Valid
    );
}

#[test]
fn test_roa_validity_invalid_length() {
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    );
    
    // Invalid length: /25 exceeds max length of /24
    assert_eq!(
        roa.get_validity(&IpNetwork::from_str("10.1.1.0/25").unwrap(), 65001),
        ROAValidity::InvalidLength
    );
    
    // Invalid length: /32 exceeds max length of /24
    assert_eq!(
        roa.get_validity(&IpNetwork::from_str("10.1.1.1/32").unwrap(), 65001),
        ROAValidity::InvalidLength
    );
}

#[test]
fn test_roa_validity_invalid_origin() {
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    );
    
    // Invalid origin: wrong ASN
    assert_eq!(
        roa.get_validity(&IpNetwork::from_str("10.1.0.0/16").unwrap(), 65002),
        ROAValidity::InvalidOrigin
    );
}

#[test]
fn test_roa_validity_invalid_both() {
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    );
    
    // Invalid both: wrong ASN and length exceeds max
    assert_eq!(
        roa.get_validity(&IpNetwork::from_str("10.1.1.0/25").unwrap(), 65002),
        ROAValidity::InvalidLengthAndOrigin
    );
}

#[test]
fn test_roa_validity_unknown() {
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    );
    
    // Unknown: prefix not covered by ROA
    assert_eq!(
        roa.get_validity(&IpNetwork::from_str("192.168.1.0/24").unwrap(), 65001),
        ROAValidity::Unknown
    );
}

#[test]
fn test_route_validator_basic() {
    let mut validator = RouteValidator::new();
    
    // Add a ROA
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    );
    validator.add_roa(roa);
    
    // Test validation
    let (validity, _) = validator.get_roa_outcome(
        &IpNetwork::from_str("10.1.0.0/16").unwrap(),
        65001,
    );
    assert_eq!(validity, ROAValidity::Valid);
    
    let (validity, _) = validator.get_roa_outcome(
        &IpNetwork::from_str("10.1.0.0/16").unwrap(),
        65002,
    );
    assert_eq!(validity, ROAValidity::InvalidOrigin);
}

#[test]
fn test_route_validator_multiple_roas() {
    let mut validator = RouteValidator::new();
    
    // Add multiple ROAs for the same prefix space
    validator.add_roa(ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    ));
    
    validator.add_roa(ROA::new(
        IpNetwork::from_str("10.1.0.0/16").unwrap(),
        65002,
        Some(24),
    ));
    
    // Test that more specific ROA takes precedence
    let (validity, _) = validator.get_roa_outcome(
        &IpNetwork::from_str("10.1.1.0/24").unwrap(),
        65002,
    );
    assert_eq!(validity, ROAValidity::Valid);
    
    // Test that the broader ROA still applies to other prefixes
    let (validity, _) = validator.get_roa_outcome(
        &IpNetwork::from_str("10.2.0.0/16").unwrap(),
        65001,
    );
    assert_eq!(validity, ROAValidity::Valid);
}

#[test]
fn test_route_validator_cache() {
    let mut validator = RouteValidator::new();
    
    validator.add_roa(ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        65001,
        Some(24),
    ));
    
    // First lookup - will compute and cache
    let (validity1, _) = validator.get_roa_outcome(
        &IpNetwork::from_str("10.1.0.0/16").unwrap(),
        65001,
    );
    
    // Second lookup - should use cache
    let (validity2, _) = validator.get_roa_outcome(
        &IpNetwork::from_str("10.1.0.0/16").unwrap(),
        65001,
    );
    
    assert_eq!(validity1, validity2);
    assert_eq!(validity1, ROAValidity::Valid);
}

#[test]
fn test_non_routed_roa() {
    let roa = ROA::new(
        IpNetwork::from_str("10.0.0.0/8").unwrap(),
        0,  // ASN 0 indicates non-routed
        Some(24),
    );
    
    assert!(!roa.is_routed());
    assert!(roa.is_non_routed());
}