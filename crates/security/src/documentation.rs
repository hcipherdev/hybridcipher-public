use crate::AuditError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

/// Security documentation generator and manager
#[derive(Debug)]
#[allow(dead_code)]
pub struct SecurityDocumentationManager {
    /// Documentation configuration
    config: DocumentationConfig,

    /// Output directory
    output_dir: PathBuf,

    /// Template manager
    template_manager: TemplateManager,
}

/// Documentation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentationConfig {
    /// Generate threat model documentation
    pub generate_threat_model: bool,

    /// Generate security architecture documentation
    pub generate_security_architecture: bool,

    /// Generate cryptographic implementation details
    pub generate_crypto_details: bool,

    /// Generate security testing procedures
    pub generate_testing_procedures: bool,

    /// Generate compliance documentation
    pub generate_compliance_docs: bool,

    /// Output formats
    pub output_formats: Vec<OutputFormat>,

    /// Include diagrams
    pub include_diagrams: bool,

    /// Include code examples
    pub include_code_examples: bool,
}

/// Output format for documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Markdown,
    Html,
    Pdf,
    Json,
}

/// Template manager for document generation
#[derive(Debug)]
#[allow(dead_code)]
pub struct TemplateManager {
    /// Template directory
    template_dir: PathBuf,

    /// Loaded templates
    templates: HashMap<String, DocumentTemplate>,
}

/// Document template
#[derive(Debug, Clone)]
pub struct DocumentTemplate {
    /// Template name
    pub name: String,

    /// Template content
    pub content: String,

    /// Template variables
    pub variables: Vec<String>,

    /// Template type
    pub template_type: TemplateType,
}

/// Type of document template
#[derive(Debug, Clone)]
pub enum TemplateType {
    ThreatModel,
    SecurityArchitecture,
    CryptographicDetails,
    TestingProcedures,
    ComplianceReport,
    SecurityPolicy,
}

/// Security documentation package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDocumentationPackage {
    /// Package ID
    pub package_id: Uuid,

    /// Generation timestamp
    pub generated_at: DateTime<Utc>,

    /// Configuration used
    pub config: DocumentationConfig,

    /// Generated documents
    pub documents: Vec<SecurityDocument>,

    /// Package metadata
    pub metadata: DocumentationMetadata,
}

/// Individual security document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDocument {
    /// Document ID
    pub document_id: Uuid,

    /// Document type
    pub document_type: DocumentType,

    /// Document title
    pub title: String,

    /// Document content
    pub content: String,

    /// Output format
    pub format: OutputFormat,

    /// File path
    pub file_path: String,

    /// Last updated
    pub last_updated: DateTime<Utc>,

    /// Document metadata
    pub metadata: HashMap<String, String>,
}

/// Type of security document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DocumentType {
    ThreatModel,
    SecurityArchitecture,
    CryptographicImplementation,
    SecurityTestingProcedures,
    ComplianceReport,
    SecurityPolicy,
    IncidentResponsePlan,
    VulnerabilityAssessment,
    AuditReport,
}

/// Documentation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentationMetadata {
    /// Project name
    pub project_name: String,

    /// Project version
    pub project_version: String,

    /// Author information
    pub authors: Vec<String>,

    /// Security classification
    pub security_classification: String,

    /// Review status
    pub review_status: ReviewStatus,

    /// Approval information
    pub approvals: Vec<ApprovalRecord>,

    /// Compliance frameworks
    pub compliance_frameworks: Vec<String>,

    /// Last review date
    pub last_review_date: Option<DateTime<Utc>>,

    /// Next review date
    pub next_review_date: Option<DateTime<Utc>>,
}

/// Review status for documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewStatus {
    Draft,
    UnderReview,
    Approved,
    Expired,
    Deprecated,
}

/// Approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Approver name
    pub approver: String,

    /// Approval date
    pub approval_date: DateTime<Utc>,

    /// Approval level
    pub approval_level: String,

    /// Comments
    pub comments: Option<String>,
}

/// Threat model documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelDocument {
    /// System overview
    pub system_overview: SystemOverview,

    /// Asset identification
    pub assets: Vec<Asset>,

    /// Threat identification
    pub threats: Vec<Threat>,

    /// Vulnerability analysis
    pub vulnerabilities: Vec<Vulnerability>,

    /// Risk assessment
    pub risk_assessment: RiskAssessmentMatrix,

    /// Mitigation strategies
    pub mitigations: Vec<MitigationStrategy>,

    /// Attack trees
    pub attack_trees: Vec<AttackTree>,
}

/// System overview for threat modeling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemOverview {
    /// System description
    pub description: String,

    /// System boundaries
    pub boundaries: Vec<String>,

    /// Data flows
    pub data_flows: Vec<DataFlow>,

    /// Trust boundaries
    pub trust_boundaries: Vec<TrustBoundary>,

    /// External dependencies
    pub external_dependencies: Vec<String>,
}

/// Asset in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// Asset ID
    pub id: String,

    /// Asset name
    pub name: String,

    /// Asset description
    pub description: String,

    /// Asset type
    pub asset_type: AssetType,

    /// Confidentiality requirement
    pub confidentiality: ConfidentialityLevel,

    /// Integrity requirement
    pub integrity: IntegrityLevel,

    /// Availability requirement
    pub availability: AvailabilityLevel,

    /// Asset value
    pub value: AssetValue,
}

/// Type of asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetType {
    Data,
    System,
    Process,
    People,
    Reputation,
}

/// Confidentiality level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfidentialityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

/// Integrity level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Availability level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AvailabilityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Asset value classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetValue {
    Low,
    Medium,
    High,
    Critical,
}

/// Security threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Threat ID
    pub id: String,

    /// Threat name
    pub name: String,

    /// Threat description
    pub description: String,

    /// Threat category
    pub category: ThreatCategory,

    /// Threat source
    pub source: ThreatSource,

    /// Affected assets
    pub affected_assets: Vec<String>,

    /// Likelihood
    pub likelihood: Likelihood,

    /// Impact
    pub impact: Impact,

    /// STRIDE classification
    pub stride: Vec<StrideCategory>,
}

/// Category of threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatCategory {
    Intentional,
    Accidental,
    Environmental,
    Technical,
}

/// Source of threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSource {
    Insider,
    ExternalAttacker,
    NationState,
    Competitor,
    Criminal,
    Terrorist,
    Natural,
    Technical,
}

/// Likelihood of threat occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Likelihood {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Impact of threat realization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Impact {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// STRIDE threat categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StrideCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

/// System vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Vulnerability ID
    pub id: String,

    /// Vulnerability name
    pub name: String,

    /// Description
    pub description: String,

    /// Affected components
    pub affected_components: Vec<String>,

    /// Severity
    pub severity: VulnerabilitySeverity,

    /// Exploitability
    pub exploitability: Exploitability,

    /// Related threats
    pub related_threats: Vec<String>,

    /// Detection methods
    pub detection_methods: Vec<String>,
}

/// Vulnerability severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Exploitability level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Exploitability {
    Easy,
    Medium,
    Hard,
    VeryHard,
}

/// Risk assessment matrix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentMatrix {
    /// Risk entries
    pub risks: Vec<RiskEntry>,

    /// Risk tolerance levels
    pub tolerance_levels: HashMap<String, String>,

    /// Risk categories
    pub categories: Vec<String>,
}

/// Individual risk entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEntry {
    /// Risk ID
    pub id: String,

    /// Associated threat
    pub threat_id: String,

    /// Associated vulnerability
    pub vulnerability_id: String,

    /// Risk level
    pub risk_level: RiskLevel,

    /// Risk score
    pub risk_score: f64,

    /// Risk description
    pub description: String,
}

/// Risk level classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Mitigation strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationStrategy {
    /// Mitigation ID
    pub id: String,

    /// Mitigation name
    pub name: String,

    /// Description
    pub description: String,

    /// Mitigation type
    pub mitigation_type: MitigationType,

    /// Associated risks
    pub associated_risks: Vec<String>,

    /// Implementation status
    pub implementation_status: ImplementationStatus,

    /// Effectiveness
    pub effectiveness: Effectiveness,

    /// Cost
    pub cost: Cost,
}

/// Type of mitigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationType {
    Prevention,
    Detection,
    Response,
    Recovery,
}

/// Implementation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplementationStatus {
    NotStarted,
    InProgress,
    Implemented,
    Verified,
    Maintained,
}

/// Effectiveness level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effectiveness {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Cost level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Cost {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Attack tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTree {
    /// Tree ID
    pub id: String,

    /// Root goal
    pub root_goal: String,

    /// Tree nodes
    pub nodes: Vec<AttackTreeNode>,

    /// Tree metadata
    pub metadata: HashMap<String, String>,
}

/// Attack tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTreeNode {
    /// Node ID
    pub id: String,

    /// Node description
    pub description: String,

    /// Node type
    pub node_type: AttackNodeType,

    /// Parent node
    pub parent: Option<String>,

    /// Child nodes
    pub children: Vec<String>,

    /// Success probability
    pub probability: f64,

    /// Cost to attacker
    pub cost: f64,

    /// Time required
    pub time_required: String,
}

/// Type of attack tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackNodeType {
    Goal,
    AndGate,
    OrGate,
    LeafAction,
}

/// Data flow in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    /// Flow ID
    pub id: String,

    /// Source component
    pub source: String,

    /// Destination component
    pub destination: String,

    /// Data description
    pub data_description: String,

    /// Protocol used
    pub protocol: String,

    /// Security requirements
    pub security_requirements: Vec<String>,
}

/// Trust boundary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundary {
    /// Boundary ID
    pub id: String,

    /// Boundary name
    pub name: String,

    /// Description
    pub description: String,

    /// Components inside boundary
    pub inside_components: Vec<String>,

    /// Components outside boundary
    pub outside_components: Vec<String>,

    /// Security controls at boundary
    pub security_controls: Vec<String>,
}

impl SecurityDocumentationManager {
    /// Create a new documentation manager
    pub fn new(config: DocumentationConfig, output_dir: PathBuf) -> Result<Self, AuditError> {
        let template_manager = TemplateManager::new(output_dir.join("templates"))?;

        Ok(Self {
            config,
            output_dir,
            template_manager,
        })
    }

    /// Generate complete security documentation package
    pub async fn generate_documentation_package(
        &self,
    ) -> Result<SecurityDocumentationPackage, AuditError> {
        let package_id = Uuid::new_v4();
        let generated_at = Utc::now();

        tracing::info!("Generating security documentation package {}", package_id);

        let mut documents = Vec::new();

        // Generate threat model documentation
        if self.config.generate_threat_model {
            let threat_model_doc = self.generate_threat_model_document().await?;
            documents.push(threat_model_doc);
        }

        // Generate security architecture documentation
        if self.config.generate_security_architecture {
            let architecture_doc = self.generate_security_architecture_document().await?;
            documents.push(architecture_doc);
        }

        // Generate cryptographic implementation details
        if self.config.generate_crypto_details {
            let crypto_doc = self.generate_cryptographic_details_document().await?;
            documents.push(crypto_doc);
        }

        // Generate testing procedures
        if self.config.generate_testing_procedures {
            let testing_doc = self.generate_testing_procedures_document().await?;
            documents.push(testing_doc);
        }

        // Generate compliance documentation
        if self.config.generate_compliance_docs {
            let compliance_doc = self.generate_compliance_documentation().await?;
            documents.push(compliance_doc);
        }

        let metadata = self.generate_package_metadata();

        let package = SecurityDocumentationPackage {
            package_id,
            generated_at,
            config: self.config.clone(),
            documents,
            metadata,
        };

        // Save package to disk
        self.save_documentation_package(&package).await?;

        tracing::info!(
            "Security documentation package {} generated with {} documents",
            package_id,
            package.documents.len()
        );

        Ok(package)
    }

    /// Generate threat model document
    async fn generate_threat_model_document(&self) -> Result<SecurityDocument, AuditError> {
        let document_id = Uuid::new_v4();
        let title = "HybridCipher Threat Model".to_string();

        // This would generate a comprehensive threat model
        // For now, generate a basic structure
        let content = self.generate_threat_model_content().await?;

        Ok(SecurityDocument {
            document_id,
            document_type: DocumentType::ThreatModel,
            title,
            content,
            format: OutputFormat::Markdown,
            file_path: "threat_model.md".to_string(),
            last_updated: Utc::now(),
            metadata: HashMap::from([
                ("version".to_string(), "1.0".to_string()),
                ("classification".to_string(), "Internal".to_string()),
            ]),
        })
    }

    /// Generate threat model content
    async fn generate_threat_model_content(&self) -> Result<String, AuditError> {
        let content = r#"# HybridCipher Threat Model

## 1. System Overview

HybridCipher is a post-quantum secure file sharing platform that enables collaborative document management with advanced cryptographic protection.

### 1.1 System Boundaries
- Client applications
- Cryptographic core
- Network communication layer
- Storage subsystem

### 1.2 Key Assets
- User files and documents
- Cryptographic keys
- User authentication data
- Group membership information
- System configuration

## 2. Threat Identification

### 2.1 STRIDE Analysis

#### Spoofing
- T001: Unauthorized user impersonation
- T002: Malicious client application spoofing

#### Tampering
- T003: File content modification during transit
- T004: Cryptographic key tampering
- T005: Configuration tampering

#### Repudiation
- T006: Users denying file access or modification

#### Information Disclosure
- T007: Unauthorized file access
- T008: Cryptographic key exposure
- T009: Metadata leakage

#### Denial of Service
- T010: Service availability attacks
- T011: Resource exhaustion attacks

#### Elevation of Privilege
- T012: Privilege escalation attacks
- T013: Administrative access compromise

## 3. Risk Assessment

### High-Risk Threats
- T008: Cryptographic key exposure (Critical)
- T007: Unauthorized file access (High)
- T004: Cryptographic key tampering (High)

### Medium-Risk Threats
- T003: File content modification (Medium)
- T010: Service availability attacks (Medium)

### Low-Risk Threats
- T006: Users denying file access (Low)

## 4. Mitigation Strategies

### M001: Post-Quantum Cryptography
- **Addresses**: T007, T008, T004
- **Implementation**: MLKEM and MLDSA algorithms
- **Status**: Implemented

### M002: End-to-End Encryption
- **Addresses**: T003, T007
- **Implementation**: AES-GCM with hybrid key exchange
- **Status**: Implemented

### M003: Secure Memory Management
- **Addresses**: T008
- **Implementation**: Memory zeroization and protection
- **Status**: Implemented

### M004: Access Control
- **Addresses**: T007, T012, T013
- **Implementation**: Group-based access control with OPAQUE authentication
- **Status**: Implemented

## 5. Attack Trees

### AT001: Unauthorized File Access
```
Goal: Access protected files without authorization
├── OR: Compromise cryptographic keys
│   ├── AND: Extract keys from memory
│   │   ├── Memory dump attack
│   │   └── Process memory access
│   └── AND: Cryptanalytic attack
│       ├── Algorithm weakness exploitation
│       └── Implementation flaw exploitation
└── OR: Bypass access controls
    ├── Authentication bypass
    └── Authorization bypass
```

## 6. Assumptions and Dependencies

### Security Assumptions
- Underlying OS provides basic security guarantees
- Hardware random number generator is available and secure
- Network communication can be protected with TLS

### Dependencies
- Rust memory safety guarantees
- Third-party cryptographic library security
- Operating system security features

## 7. Residual Risks

### R001: Quantum Computer Threat
- **Risk**: Future quantum computers may break current cryptography
- **Mitigation**: Post-quantum algorithms already implemented
- **Likelihood**: Low (5-10 year timeframe)

### R002: Implementation Vulnerabilities
- **Risk**: Bugs in cryptographic implementation
- **Mitigation**: Extensive testing and code review
- **Likelihood**: Medium

## 8. Recommendations

1. Regular security assessments
2. Continuous monitoring for new threats
3. Update threat model as system evolves
4. Implement additional defense-in-depth measures
5. Consider formal verification for critical components

## 9. Review and Approval

- **Last Review**: [Current Date]
- **Next Review**: [Current Date + 6 months]
- **Approved By**: Security Team
- **Review Cycle**: Semi-annual or when significant changes occur
"#;

        Ok(content.to_string())
    }

    /// Generate security architecture document
    async fn generate_security_architecture_document(
        &self,
    ) -> Result<SecurityDocument, AuditError> {
        let document_id = Uuid::new_v4();
        let content =
            "# Security Architecture\n\n[Architecture documentation would go here]".to_string();

        Ok(SecurityDocument {
            document_id,
            document_type: DocumentType::SecurityArchitecture,
            title: "HybridCipher Security Architecture".to_string(),
            content,
            format: OutputFormat::Markdown,
            file_path: "security_architecture.md".to_string(),
            last_updated: Utc::now(),
            metadata: HashMap::new(),
        })
    }

    /// Generate cryptographic details document
    async fn generate_cryptographic_details_document(
        &self,
    ) -> Result<SecurityDocument, AuditError> {
        let document_id = Uuid::new_v4();
        let content =
            "# Cryptographic Implementation Details\n\n[Crypto details would go here]".to_string();

        Ok(SecurityDocument {
            document_id,
            document_type: DocumentType::CryptographicImplementation,
            title: "HybridCipher Cryptographic Implementation".to_string(),
            content,
            format: OutputFormat::Markdown,
            file_path: "cryptographic_implementation.md".to_string(),
            last_updated: Utc::now(),
            metadata: HashMap::new(),
        })
    }

    /// Generate testing procedures document
    async fn generate_testing_procedures_document(&self) -> Result<SecurityDocument, AuditError> {
        let document_id = Uuid::new_v4();
        let content =
            "# Security Testing Procedures\n\n[Testing procedures would go here]".to_string();

        Ok(SecurityDocument {
            document_id,
            document_type: DocumentType::SecurityTestingProcedures,
            title: "HybridCipher Security Testing Procedures".to_string(),
            content,
            format: OutputFormat::Markdown,
            file_path: "security_testing_procedures.md".to_string(),
            last_updated: Utc::now(),
            metadata: HashMap::new(),
        })
    }

    /// Generate compliance documentation
    async fn generate_compliance_documentation(&self) -> Result<SecurityDocument, AuditError> {
        let document_id = Uuid::new_v4();
        let content = "# Compliance Report\n\n[Compliance documentation would go here]".to_string();

        Ok(SecurityDocument {
            document_id,
            document_type: DocumentType::ComplianceReport,
            title: "HybridCipher Compliance Report".to_string(),
            content,
            format: OutputFormat::Markdown,
            file_path: "compliance_report.md".to_string(),
            last_updated: Utc::now(),
            metadata: HashMap::new(),
        })
    }

    /// Generate package metadata
    fn generate_package_metadata(&self) -> DocumentationMetadata {
        DocumentationMetadata {
            project_name: "HybridCipher".to_string(),
            project_version: "0.1.0".to_string(),
            authors: vec!["Security Team".to_string()],
            security_classification: "Internal".to_string(),
            review_status: ReviewStatus::Draft,
            approvals: Vec::new(),
            compliance_frameworks: vec![
                "NIST Cybersecurity Framework".to_string(),
                "ISO 27001".to_string(),
            ],
            last_review_date: None,
            next_review_date: Some(Utc::now() + chrono::Duration::days(180)),
        }
    }

    /// Save documentation package to disk
    async fn save_documentation_package(
        &self,
        package: &SecurityDocumentationPackage,
    ) -> Result<(), AuditError> {
        // Create output directory
        fs::create_dir_all(&self.output_dir).await?;

        // Save each document
        for document in &package.documents {
            let file_path = self.output_dir.join(&document.file_path);
            fs::write(file_path, &document.content).await?;
        }

        // Save package metadata
        let package_file = self.output_dir.join("package.json");
        let package_json = serde_json::to_string_pretty(package)?;
        fs::write(package_file, package_json).await?;

        Ok(())
    }
}

impl TemplateManager {
    /// Create a new template manager
    fn new(template_dir: PathBuf) -> Result<Self, AuditError> {
        Ok(Self {
            template_dir,
            templates: HashMap::new(),
        })
    }

    /// Load templates from directory
    pub async fn load_templates(&mut self) -> Result<(), AuditError> {
        // Implementation would load templates from files
        Ok(())
    }

    /// Get template by name
    pub fn get_template(&self, name: &str) -> Option<&DocumentTemplate> {
        self.templates.get(name)
    }

    /// Render template with variables
    pub fn render_template(
        &self,
        template_name: &str,
        variables: &HashMap<String, String>,
    ) -> Result<String, AuditError> {
        if let Some(template) = self.get_template(template_name) {
            let mut content = template.content.clone();

            // Simple variable substitution
            for (key, value) in variables {
                let placeholder = format!("{{{}}}", key);
                content = content.replace(&placeholder, value);
            }

            Ok(content)
        } else {
            Err(AuditError::DocumentationFailed {
                message: format!("Template '{}' not found", template_name),
            })
        }
    }
}

impl Default for DocumentationConfig {
    fn default() -> Self {
        Self {
            generate_threat_model: true,
            generate_security_architecture: true,
            generate_crypto_details: true,
            generate_testing_procedures: true,
            generate_compliance_docs: true,
            output_formats: vec![OutputFormat::Markdown, OutputFormat::Html],
            include_diagrams: true,
            include_code_examples: true,
        }
    }
}
