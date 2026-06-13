//! MITRE ATT&CK taxonomy — the canonical nomenclature for everything the engine
//! reports (ADR-0005).
//!
//! Deliberately dependency-free (no graph types) so both the graph vocabulary
//! (`Relation::technique`) and the objective recognizers can name attack steps and
//! goals in ATT&CK terms. We adopt ATT&CK's IDs and names, not any tool's bespoke
//! edge codes; where a tool's catalog is finer-grained than ATT&CK (e.g. specific
//! container-escape mechanisms, all of which are Escape to Host / T1611), that
//! detail lives as procedure-level context on the edge, subordinate to the
//! technique.

/// A MITRE ATT&CK tactic — the adversary's goal. Only the tactics protector
/// targets are enumerated; the Containers matrix has more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Impact,
}

impl Tactic {
    /// The ATT&CK tactic ID (e.g. `TA0006`).
    pub fn id(self) -> &'static str {
        match self {
            Tactic::InitialAccess => "TA0001",
            Tactic::Execution => "TA0002",
            Tactic::Persistence => "TA0003",
            Tactic::PrivilegeEscalation => "TA0004",
            Tactic::CredentialAccess => "TA0006",
            Tactic::Discovery => "TA0007",
            Tactic::LateralMovement => "TA0008",
            Tactic::Impact => "TA0040",
        }
    }
}

/// A reference to a specific ATT&CK technique under a tactic. `'static` strings so
/// it can be a `const`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackRef {
    pub tactic: Tactic,
    pub technique_id: &'static str,
    pub technique: &'static str,
}

/// Initial Access — Exploit Public-Facing Application (T1190): an internet-exposed
/// workload running an image with an exploited-in-wild vulnerability. The proven
/// foothold that completes the entry side of the action bar.
pub const EXPLOIT_PUBLIC_FACING: AttackRef = AttackRef {
    tactic: Tactic::InitialAccess,
    technique_id: "T1190",
    technique: "Exploit Public-Facing Application",
};

/// Credential Access via unsecured credentials — reaching/reading a Secret (T1552).
pub const CREDENTIAL_ACCESS: AttackRef = AttackRef {
    tactic: Tactic::CredentialAccess,
    technique_id: "T1552",
    technique: "Unsecured Credentials",
};

/// Privilege Escalation via container escape — reaching a Host (T1611).
pub const ESCAPE_TO_HOST: AttackRef = AttackRef {
    tactic: Tactic::PrivilegeEscalation,
    technique_id: "T1611",
    technique: "Escape to Host",
};

/// Execution — Deploy Container (T1610): create pods.
pub const DEPLOY_CONTAINER: AttackRef = AttackRef {
    tactic: Tactic::Execution,
    technique_id: "T1610",
    technique: "Deploy Container",
};

/// Execution — Container Administration Command (T1609): exec/attach into pods.
pub const CONTAINER_ADMIN_COMMAND: AttackRef = AttackRef {
    tactic: Tactic::Execution,
    technique_id: "T1609",
    technique: "Container Administration Command",
};

/// Privilege Escalation — Additional Container Cluster Roles (T1098.006): RBAC
/// self-escalation via binding/escalating roles.
pub const RBAC_ESCALATION: AttackRef = AttackRef {
    tactic: Tactic::PrivilegeEscalation,
    technique_id: "T1098.006",
    technique: "Account Manipulation: Additional Container Cluster Roles",
};

/// Impact — Data Destruction (T1485): delete persistent data. A tactic KubeHound
/// does not model — protector's objective layer extends past the path-building set.
pub const DATA_DESTRUCTION: AttackRef = AttackRef {
    tactic: Tactic::Impact,
    technique_id: "T1485",
    technique: "Data Destruction",
};

/// Persistence — Container Orchestration Job (T1053.007): create cronjobs/jobs for
/// durable footholds. Also a tactic outside KubeHound's coverage.
pub const PERSISTENCE_SCHEDULED: AttackRef = AttackRef {
    tactic: Tactic::Persistence,
    technique_id: "T1053.007",
    technique: "Scheduled Task/Job: Container Orchestration Job",
};

/// A verb-on-resource RBAC grant that is itself an attacker objective, with the
/// ATT&CK technique holding it realizes. `group` is the API group (`""` = core);
/// `resource` may be `"*"` to mean "any resource in this group".
#[derive(Debug, Clone, Copy)]
pub struct DangerousCapability {
    pub group: &'static str,
    pub resource: &'static str,
    pub verb: &'static str,
    pub attack: AttackRef,
}

/// The curated set of security-relevant capabilities. The Privilege port mints a
/// Capability node only for grants matching one of these — bounding graph growth
/// to this list rather than the full verb×resource cartesian product (ADR-0005).
pub const CAPABILITY_CATALOG: &[DangerousCapability] = &[
    DangerousCapability {
        group: "",
        resource: "pods",
        verb: "create",
        attack: DEPLOY_CONTAINER,
    },
    DangerousCapability {
        group: "",
        resource: "pods/exec",
        verb: "create",
        attack: CONTAINER_ADMIN_COMMAND,
    },
    DangerousCapability {
        group: "",
        resource: "pods/attach",
        verb: "create",
        attack: CONTAINER_ADMIN_COMMAND,
    },
    DangerousCapability {
        group: "rbac.authorization.k8s.io",
        resource: "rolebindings",
        verb: "create",
        attack: RBAC_ESCALATION,
    },
    DangerousCapability {
        group: "rbac.authorization.k8s.io",
        resource: "clusterrolebindings",
        verb: "create",
        attack: RBAC_ESCALATION,
    },
    DangerousCapability {
        group: "rbac.authorization.k8s.io",
        resource: "*",
        verb: "bind",
        attack: RBAC_ESCALATION,
    },
    DangerousCapability {
        group: "rbac.authorization.k8s.io",
        resource: "*",
        verb: "escalate",
        attack: RBAC_ESCALATION,
    },
    DangerousCapability {
        group: "",
        resource: "persistentvolumeclaims",
        verb: "delete",
        attack: DATA_DESTRUCTION,
    },
    DangerousCapability {
        group: "batch",
        resource: "cronjobs",
        verb: "create",
        attack: PERSISTENCE_SCHEDULED,
    },
];

/// The ATT&CK technique a minted capability `(verb, resource)` realizes, if any.
/// Both the Privilege port (minting) and the objective recognizer (tagging) use
/// this, so the catalogue is the single source of truth.
pub fn capability_technique(verb: &str, resource: &str) -> Option<AttackRef> {
    CAPABILITY_CATALOG
        .iter()
        .find(|c| c.verb == verb && c.resource == resource)
        .map(|c| c.attack)
}
