use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Relationships {
    Providers = 1,
    Peers = 2,
    Customers = 3,
    Origin = 4,
    Unknown = 5,
}

impl Relationships {
    pub fn invert(&self) -> Self {
        match self {
            Relationships::Providers => Relationships::Customers,
            Relationships::Customers => Relationships::Providers,
            Relationships::Peers => Relationships::Peers,
            Relationships::Origin => Relationships::Origin,
            Relationships::Unknown => Relationships::Unknown,
        }
    }
}

impl fmt::Display for Relationships {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Relationships::Providers => "PROVIDERS",
            Relationships::Peers => "PEERS",
            Relationships::Customers => "CUSTOMERS",
            Relationships::Origin => "ORIGIN",
            Relationships::Unknown => "UNKNOWN",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ASNGroups {
    Tier1,
    Etc,
    StubsOrMh,
    Stubs,
    Multihomed,
    Transit,
    Input,
    Ixp,
}

impl fmt::Display for ASNGroups {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ASNGroups::Tier1 => "TIER_1",
            ASNGroups::Etc => "ETC",
            ASNGroups::StubsOrMh => "STUBS_OR_MH",
            ASNGroups::Stubs => "STUBS",
            ASNGroups::Multihomed => "MULTIHOMED",
            ASNGroups::Transit => "TRANSIT",
            ASNGroups::Input => "INPUT",
            ASNGroups::Ixp => "IXP",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum Settings {
    BaseDefense = 0,
    Rov = 1,
    PeerRov = 2,
    Bgpisec = 3,
    OnlyToCustomers = 4,
    EdgeFilter = 5,
    Bgpsec = 6,
    PathEnd = 7,
    RovppV1Lite = 8,
    RovppV2Lite = 9,
    RovppV2iLite = 10,
    EnforceFirstAs = 11,
    RovEnforceFirstAs = 12,
    Aspa = 13,
    Aspawn = 14,
    Asra = 15,
    PeerLockLite = 16,
    Rost = 17,
    RovEdgeFilter = 18,
    BgpisecTransitive = 19,
    BgpisecTransitiveProConId = 20,
    ProviderConeId = 21,
    BgpisecTransitiveOnlyToCustomers = 22,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ROAValidity {
    Valid = 0,
    Unknown = 1,
    InvalidLength = 2,
    InvalidOrigin = 3,
    InvalidLengthAndOrigin = 4,
}

impl fmt::Display for ROAValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ROAValidity::Valid => "VALID",
            ROAValidity::Unknown => "UNKNOWN",
            ROAValidity::InvalidLength => "INVALID_LENGTH",
            ROAValidity::InvalidOrigin => "INVALID_ORIGIN",
            ROAValidity::InvalidLengthAndOrigin => "INVALID_LENGTH_AND_ORIGIN",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ROARouted {
    Routed = 0,
    Unknown = 1,
    NonRouted = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Timestamps {
    Victim = 0,
    Attacker = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Outcomes {
    AttackerSuccess = 0,
    VictimSuccess = 1,
    DisconnectedOrigin = 2,
    DisconnectedAttacker = 3,
    DisconnectedVictim = 4,
    DisconnectedNotAsSomehow = 5,
    HijackedSamePath = 6,
    HijackedButBlackholed = 7,
    HijackedButNotDetected = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InAdoptingASNs {
    True,
    False,
    Notapplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonASNs;

impl CommonASNs {
    pub const ATTACKER: u32 = 666;
    pub const VICTIM: u32 = 777;
}

#[derive(Debug, Clone)]
pub struct PolicyPropagateInfo {
    pub settings: Settings,
    pub ribs_out: Option<bool>,
}

impl PolicyPropagateInfo {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            ribs_out: None,
        }
    }
}

#[derive(Debug)]
pub struct CycleError;

impl fmt::Display for CycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cycle detected in AS graph")
    }
}

impl std::error::Error for CycleError {}

#[derive(Debug)]
pub struct GaoRexfordError;

impl fmt::Display for GaoRexfordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gao-Rexford error")
    }
}

impl std::error::Error for GaoRexfordError {}

#[derive(Debug)]
pub struct AnnouncementNotFoundError;

impl fmt::Display for AnnouncementNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Announcement not found")
    }
}

impl std::error::Error for AnnouncementNotFoundError {}