use crate::audit::SecuritySeverity;
use crate::audit::ThreatDetectionConfig;
use crate::errors::ThreatError;
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Advanced threat detection and behavioral analysis system
#[derive(Debug)]
pub struct ThreatDetector {
    /// Configuration
    config: ThreatDetectionConfig,

    /// Behavioral pattern storage
    patterns: Arc<RwLock<HashMap<String, BehavioralPattern>>>,

    /// Anomaly detection models
    anomaly_models: HashMap<String, AnomalyModel>,

    /// Event history for analysis
    event_history: Arc<RwLock<VecDeque<SecurityEvent>>>,

    /// Statistical analyzers
    statistical_analyzers: HashMap<String, StatisticalAnalyzer>,
}

/// Security event for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event ID
    pub id: Uuid,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: String,

    /// Source identifier (user, device, etc.)
    pub source: String,

    /// Target identifier (file, group, etc.)
    pub target: Option<String>,

    /// Event metadata
    pub metadata: HashMap<String, String>,

    /// Success/failure status
    pub success: bool,

    /// Error code if applicable
    pub error_code: Option<String>,

    /// Duration of operation
    pub duration: Option<Duration>,

    /// Resource usage
    pub resource_usage: Option<ResourceUsage>,
}

/// Resource usage during an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU time used (microseconds)
    pub cpu_time_us: u64,

    /// Memory used (bytes)
    pub memory_bytes: u64,

    /// Network bytes sent
    pub network_sent: u64,

    /// Network bytes received
    pub network_received: u64,

    /// Disk bytes read
    pub disk_read: u64,

    /// Disk bytes written
    pub disk_written: u64,
}

/// Behavioral pattern for threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    /// Pattern name
    pub name: String,

    /// Pattern description
    pub description: String,

    /// Event types this pattern applies to
    pub event_types: Vec<String>,

    /// Statistical thresholds
    pub thresholds: HashMap<String, Threshold>,

    /// Baseline metrics
    pub baseline: BaselineMetrics,

    /// Last update timestamp
    pub last_updated: DateTime<Utc>,

    /// Sample count for statistics
    pub sample_count: usize,
}

/// Statistical threshold for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threshold {
    /// Lower bound (for minimum values)
    pub lower_bound: Option<f64>,

    /// Upper bound (for maximum values)
    pub upper_bound: Option<f64>,

    /// Standard deviations from mean
    pub standard_deviations: f64,

    /// Confidence level
    pub confidence_level: f64,

    /// Threshold type
    pub threshold_type: ThresholdType,
}

/// Type of threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdType {
    /// Absolute value threshold
    Absolute,

    /// Standard deviation based
    StandardDeviation,

    /// Percentile based
    Percentile { percentile: f64 },

    /// Rate of change
    RateOfChange,
}

/// Baseline metrics for normal behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetrics {
    /// Mean values for various metrics
    pub means: HashMap<String, f64>,

    /// Standard deviations
    pub standard_deviations: HashMap<String, f64>,

    /// Percentiles (5th, 25th, 50th, 75th, 95th)
    pub percentiles: HashMap<String, Vec<f64>>,

    /// Minimum values observed
    pub minimums: HashMap<String, f64>,

    /// Maximum values observed
    pub maximums: HashMap<String, f64>,

    /// Sample count
    pub sample_count: usize,

    /// Last baseline update
    pub last_updated: DateTime<Utc>,
}

/// Anomaly detection model
#[derive(Debug, Clone)]
pub struct AnomalyModel {
    /// Model name
    pub name: String,

    /// Model type
    pub model_type: AnomalyModelType,

    /// Model parameters
    pub parameters: HashMap<String, f64>,

    /// Training data window size
    pub window_size: usize,

    /// Detection sensitivity
    pub sensitivity: f64,
}

/// Type of anomaly detection model
#[derive(Debug, Clone)]
pub enum AnomalyModelType {
    /// Statistical outlier detection
    StatisticalOutlier,

    /// Time series anomaly detection
    TimeSeries,

    /// Clustering based
    Clustering,

    /// Machine learning based
    MachineLearning,
}

/// Statistical analyzer for events
#[derive(Debug, Clone)]
pub struct StatisticalAnalyzer {
    /// Analyzer name
    pub name: String,

    /// Metrics being tracked
    pub metrics: Vec<String>,

    /// Rolling window for calculations
    pub window_size: usize,

    /// Historical data
    pub data: VecDeque<f64>,
}

/// Threat alert generated by analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    /// Alert ID
    pub id: Uuid,

    /// Alert timestamp
    pub timestamp: DateTime<Utc>,

    /// Alert type
    pub alert_type: ThreatType,

    /// Severity level
    pub severity: SecuritySeverity,

    /// Source of the threat
    pub source: String,

    /// Description of the threat
    pub description: String,

    /// Confidence score (0-1)
    pub confidence: f64,

    /// Supporting evidence
    pub evidence: Vec<Evidence>,

    /// Recommended actions
    pub recommended_actions: Vec<String>,

    /// Related events
    pub related_events: Vec<Uuid>,
}

/// Type of threat detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    /// Unusual access pattern
    AnomalousAccess,

    /// Potential brute force attack
    BruteForce,

    /// Data exfiltration attempt
    DataExfiltration,

    /// Privilege escalation
    PrivilegeEscalation,

    /// Resource abuse
    ResourceAbuse,

    /// Timing attack
    TimingAttack,

    /// Side channel attack
    SideChannel,

    /// Suspicious behavior pattern
    SuspiciousBehavior,

    /// Performance anomaly
    PerformanceAnomaly,
}

/// Evidence supporting a threat alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence type
    pub evidence_type: String,

    /// Evidence description
    pub description: String,

    /// Supporting data
    pub data: HashMap<String, String>,

    /// Confidence in this evidence
    pub confidence: f64,
}

/// Access pattern analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAnalysis {
    /// Analysis timestamp
    pub timestamp: DateTime<Utc>,

    /// User access patterns
    pub user_patterns: HashMap<String, UserAccessPattern>,

    /// Resource access patterns
    pub resource_patterns: HashMap<String, ResourceAccessPattern>,

    /// Anomalies detected
    pub anomalies: Vec<AccessAnomaly>,

    /// Risk score
    pub risk_score: f64,
}

/// User access pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccessPattern {
    /// User identifier
    pub user_id: String,

    /// Access frequency by hour
    pub hourly_frequency: Vec<f64>,

    /// Common access times
    pub common_times: Vec<chrono::NaiveTime>,

    /// Resources frequently accessed
    pub frequent_resources: Vec<String>,

    /// Unusual recent activities
    pub unusual_activities: Vec<String>,
}

/// Resource access pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccessPattern {
    /// Resource identifier
    pub resource_id: String,

    /// Access frequency over time
    pub access_frequency: Vec<f64>,

    /// Users who commonly access this resource
    pub common_users: Vec<String>,

    /// Access methods used
    pub access_methods: HashMap<String, usize>,

    /// Peak usage times
    pub peak_times: Vec<chrono::NaiveTime>,
}

/// Access anomaly detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAnomaly {
    /// Anomaly type
    pub anomaly_type: String,

    /// Description
    pub description: String,

    /// Affected user/resource
    pub affected_entity: String,

    /// Severity level
    pub severity: SecuritySeverity,

    /// Supporting evidence
    pub evidence: Vec<String>,
}

/// Timing analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalysis {
    /// Analysis timestamp
    pub timestamp: DateTime<Utc>,

    /// Operation timing statistics
    pub operation_timings: HashMap<String, TimingStatistics>,

    /// Timing anomalies detected
    pub timing_anomalies: Vec<TimingAnomaly>,

    /// Side-channel risk assessment
    pub side_channel_risk: f64,
}

/// Timing statistics for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingStatistics {
    /// Operation name
    pub operation: String,

    /// Mean execution time
    pub mean_time: Duration,

    /// Standard deviation
    pub std_deviation: Duration,

    /// Minimum time observed
    pub min_time: Duration,

    /// Maximum time observed
    pub max_time: Duration,

    /// Percentiles
    pub percentiles: HashMap<String, Duration>,

    /// Sample count
    pub sample_count: usize,
}

/// Timing anomaly detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnomaly {
    /// Anomaly type
    pub anomaly_type: String,

    /// Operation affected
    pub operation: String,

    /// Observed timing
    pub observed_timing: Duration,

    /// Expected timing range
    pub expected_range: (Duration, Duration),

    /// Deviation from normal
    pub deviation_score: f64,

    /// Potential attack type
    pub potential_attack: Option<String>,
}

/// Threat analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysisReport {
    /// Report timestamp
    pub timestamp: DateTime<Utc>,

    /// Analysis period
    pub analysis_period: (DateTime<Utc>, DateTime<Utc>),

    /// Events analyzed
    pub events_analyzed: usize,

    /// Threat alerts generated
    pub threat_alerts: Vec<ThreatAlert>,

    /// Access pattern analysis
    pub access_analysis: AccessAnalysis,

    /// Timing analysis
    pub timing_analysis: TimingAnalysis,

    /// Overall threat score
    pub threat_score: f64,

    /// Risk assessment
    pub risk_assessment: String,
}

/// Access log for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLog {
    /// Log entries
    pub entries: Vec<AccessLogEntry>,

    /// Log period
    pub period: (DateTime<Utc>, DateTime<Utc>),
}

/// Individual access log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEntry {
    /// Entry timestamp
    pub timestamp: DateTime<Utc>,

    /// User identifier
    pub user_id: String,

    /// Resource accessed
    pub resource: String,

    /// Access method
    pub method: String,

    /// Success/failure
    pub success: bool,

    /// Duration of access
    pub duration: Option<Duration>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Timed operation for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedOperation {
    /// Operation timestamp
    pub timestamp: DateTime<Utc>,

    /// Operation type
    pub operation_type: String,

    /// Operation duration
    pub duration: Duration,

    /// Operation context
    pub context: HashMap<String, String>,

    /// Success/failure
    pub success: bool,
}

impl ThreatDetector {
    /// Create a new threat detector
    pub fn new(config: ThreatDetectionConfig) -> Result<Self, ThreatError> {
        let patterns = Arc::new(RwLock::new(HashMap::new()));
        let event_history = Arc::new(RwLock::new(VecDeque::new()));

        // Initialize anomaly models
        let mut anomaly_models = HashMap::new();
        anomaly_models.insert(
            "access_pattern".to_string(),
            AnomalyModel {
                name: "Access Pattern Anomaly Detection".to_string(),
                model_type: AnomalyModelType::StatisticalOutlier,
                parameters: HashMap::from([
                    ("sensitivity".to_string(), 0.95),
                    ("window_size".to_string(), 1000.0),
                ]),
                window_size: 1000,
                sensitivity: 0.95,
            },
        );

        // Initialize statistical analyzers
        let mut statistical_analyzers = HashMap::new();
        statistical_analyzers.insert(
            "timing".to_string(),
            StatisticalAnalyzer {
                name: "Timing Analysis".to_string(),
                metrics: vec!["duration".to_string(), "cpu_time".to_string()],
                window_size: 1000,
                data: VecDeque::new(),
            },
        );

        Ok(Self {
            config,
            patterns,
            anomaly_models,
            event_history,
            statistical_analyzers,
        })
    }

    /// Record a security event for analysis
    pub async fn record_event(&self, event: SecurityEvent) -> Result<(), ThreatError> {
        let mut history = self.event_history.write().await;

        // Maintain rolling window of events
        if history.len() >= 10000 {
            history.pop_front();
        }

        history.push_back(event);
        Ok(())
    }

    /// Detect suspicious activity in events
    pub async fn detect_suspicious_activity(&self, events: &[SecurityEvent]) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        // Analyze behavioral patterns
        if let Ok(behavioral_alerts) = self.analyze_behavioral_patterns(events).await {
            alerts.extend(behavioral_alerts);
        }

        alerts
    }

    /// Analyze access patterns for anomalies
    pub async fn analyze_access_patterns(
        &self,
        access_log: &AccessLog,
    ) -> Result<AccessAnalysis, ThreatError> {
        let mut user_patterns = HashMap::new();
        let mut anomalies = Vec::new();

        // Analyze user access patterns
        for entry in &access_log.entries {
            let pattern = user_patterns
                .entry(entry.user_id.clone())
                .or_insert_with(|| UserAccessPattern {
                    user_id: entry.user_id.clone(),
                    hourly_frequency: vec![0.0; 24],
                    common_times: Vec::new(),
                    frequent_resources: Vec::new(),
                    unusual_activities: Vec::new(),
                });

            // Update hourly frequency
            let hour = entry.timestamp.hour() as usize;
            pattern.hourly_frequency[hour] += 1.0;
        }

        // Detect access anomalies
        for (user_id, pattern) in &user_patterns {
            if let Some(anomaly) = self.detect_user_access_anomaly(user_id, pattern).await? {
                anomalies.push(anomaly);
            }
        }

        let risk_score = self.calculate_access_risk_score(&anomalies);

        let resource_patterns = HashMap::new();

        Ok(AccessAnalysis {
            timestamp: Utc::now(),
            user_patterns,
            resource_patterns,
            anomalies,
            risk_score,
        })
    }

    /// Validate operation timing for side-channel resistance
    pub async fn validate_operation_timing(
        &self,
        operations: &[TimedOperation],
    ) -> Result<TimingAnalysis, ThreatError> {
        let mut operation_timings = HashMap::new();
        let mut timing_anomalies = Vec::new();

        // Group operations by type
        let mut ops_by_type: HashMap<String, Vec<&TimedOperation>> = HashMap::new();
        for op in operations {
            ops_by_type
                .entry(op.operation_type.clone())
                .or_insert_with(Vec::new)
                .push(op);
        }

        // Analyze timing for each operation type
        for (op_type, ops) in ops_by_type {
            let timings = self.calculate_timing_statistics(&ops)?;

            // Check for timing anomalies
            for op in &ops {
                if let Some(anomaly) = self.detect_timing_anomaly(&op_type, op, &timings)? {
                    timing_anomalies.push(anomaly);
                }
            }

            operation_timings.insert(op_type, timings);
        }

        let side_channel_risk =
            self.assess_side_channel_risk(&operation_timings, &timing_anomalies);

        Ok(TimingAnalysis {
            timestamp: Utc::now(),
            operation_timings,
            timing_anomalies,
            side_channel_risk,
        })
    }

    /// Run comprehensive threat analysis
    pub async fn analyze(&self) -> Result<ThreatAnalysisReport, ThreatError> {
        let history = self.event_history.read().await;
        let events: Vec<SecurityEvent> = history.iter().cloned().collect();
        drop(history);

        // Convert events to access log
        let access_log = self.events_to_access_log(&events);

        // Convert events to timed operations
        let timed_operations = self.events_to_timed_operations(&events);

        // Run analyses
        let threat_alerts = self.detect_suspicious_activity(&events).await;
        let access_analysis = self.analyze_access_patterns(&access_log).await?;
        let timing_analysis = self.validate_operation_timing(&timed_operations).await?;

        let threat_score =
            self.calculate_threat_score(&threat_alerts, &access_analysis, &timing_analysis);
        let risk_assessment = self.generate_risk_assessment(threat_score);

        Ok(ThreatAnalysisReport {
            timestamp: Utc::now(),
            analysis_period: self.get_analysis_period(&events),
            events_analyzed: events.len(),
            threat_alerts,
            access_analysis,
            timing_analysis,
            threat_score,
            risk_assessment,
        })
    }

    // Helper methods

    async fn analyze_behavioral_patterns(
        &self,
        events: &[SecurityEvent],
    ) -> Result<Vec<ThreatAlert>, ThreatError> {
        if !self.config.behavioral_analysis || events.is_empty() {
            return Ok(Vec::new());
        }

        let patterns = self.patterns.read().await;
        if patterns.is_empty() {
            return Ok(Vec::new());
        }

        let reference_pattern = match patterns.values().next() {
            Some(pattern) => pattern,
            None => return Ok(Vec::new()),
        };

        let model_sensitivity = self
            .anomaly_models
            .values()
            .next()
            .map(|model| model.sensitivity)
            .unwrap_or(0.5);

        let analyzer_window = self
            .statistical_analyzers
            .values()
            .next()
            .map(|analyzer| analyzer.window_size)
            .unwrap_or(0);

        let mut alerts = Vec::new();
        for event in events {
            if reference_pattern.event_types.contains(&event.event_type) {
                alerts.push(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: event.timestamp,
                    alert_type: ThreatType::AnomalousAccess,
                    severity: SecuritySeverity::Medium,
                    source: event.source.clone(),
                    description: format!(
                        "Event matched pattern '{}' within window {}",
                        reference_pattern.name, analyzer_window
                    ),
                    confidence: model_sensitivity,
                    evidence: Vec::new(),
                    recommended_actions: vec![
                        "Review user access history".to_string(),
                        "Validate session integrity".to_string(),
                    ],
                    related_events: vec![event.id],
                });
            }
        }

        Ok(alerts)
    }

    async fn detect_user_access_anomaly(
        &self,
        user_id: &str,
        pattern: &UserAccessPattern,
    ) -> Result<Option<AccessAnomaly>, ThreatError> {
        // Check for anomalous access patterns

        // Example: Check for access outside normal hours
        let total_accesses: f64 = pattern.hourly_frequency.iter().sum();
        let night_accesses: f64 = pattern.hourly_frequency[0..6].iter().sum();
        let night_ratio = if total_accesses > 0.0 {
            night_accesses / total_accesses
        } else {
            0.0
        };

        if night_ratio > 0.3 {
            // More than 30% of accesses during night hours
            return Ok(Some(AccessAnomaly {
                anomaly_type: "unusual_hours".to_string(),
                description: format!(
                    "User {} has unusually high night-time access pattern",
                    user_id
                ),
                affected_entity: user_id.to_string(),
                severity: SecuritySeverity::Medium,
                evidence: vec![format!(
                    "Night-time access ratio: {:.2}%",
                    night_ratio * 100.0
                )],
            }));
        }

        Ok(None)
    }

    fn calculate_timing_statistics(
        &self,
        operations: &[&TimedOperation],
    ) -> Result<TimingStatistics, ThreatError> {
        if operations.is_empty() {
            return Err(ThreatError::InsufficientData {
                required_samples: 1,
            });
        }

        let durations: Vec<Duration> = operations.iter().map(|op| op.duration).collect();
        let mean_time = Duration::nanoseconds(
            durations
                .iter()
                .map(|d| d.num_nanoseconds().unwrap_or(0))
                .sum::<i64>()
                / durations.len() as i64,
        );

        let min_time = durations.iter().min().copied().unwrap_or(Duration::zero());
        let max_time = durations.iter().max().copied().unwrap_or(Duration::zero());

        // Calculate standard deviation
        let variance = durations
            .iter()
            .map(|d| {
                let diff =
                    d.num_nanoseconds().unwrap_or(0) - mean_time.num_nanoseconds().unwrap_or(0);
                (diff as f64).powi(2)
            })
            .sum::<f64>()
            / durations.len() as f64;

        let std_deviation = Duration::nanoseconds(variance.sqrt() as i64);

        Ok(TimingStatistics {
            operation: operations[0].operation_type.clone(),
            mean_time,
            std_deviation,
            min_time,
            max_time,
            percentiles: HashMap::new(), // Would calculate actual percentiles
            sample_count: operations.len(),
        })
    }

    fn detect_timing_anomaly(
        &self,
        op_type: &str,
        operation: &TimedOperation,
        stats: &TimingStatistics,
    ) -> Result<Option<TimingAnomaly>, ThreatError> {
        let deviation_threshold = 3.0; // 3 standard deviations

        let mean_ns = stats.mean_time.num_nanoseconds().unwrap_or(0) as f64;
        let std_ns = stats.std_deviation.num_nanoseconds().unwrap_or(0) as f64;
        let observed_ns = operation.duration.num_nanoseconds().unwrap_or(0) as f64;

        let deviation_score = if std_ns > 0.0 {
            (observed_ns - mean_ns).abs() / std_ns
        } else {
            0.0
        };

        if deviation_score > deviation_threshold {
            let lower_bound =
                Duration::nanoseconds((mean_ns - deviation_threshold * std_ns) as i64);
            let upper_bound =
                Duration::nanoseconds((mean_ns + deviation_threshold * std_ns) as i64);

            return Ok(Some(TimingAnomaly {
                anomaly_type: "statistical_outlier".to_string(),
                operation: op_type.to_string(),
                observed_timing: operation.duration,
                expected_range: (lower_bound, upper_bound),
                deviation_score,
                potential_attack: if deviation_score > 5.0 {
                    Some("timing_side_channel".to_string())
                } else {
                    None
                },
            }));
        }

        Ok(None)
    }

    fn assess_side_channel_risk(
        &self,
        timings: &HashMap<String, TimingStatistics>,
        anomalies: &[TimingAnomaly],
    ) -> f64 {
        let mut risk_score = 0.0;

        // Base risk from timing variance
        for stats in timings.values() {
            let coefficient_of_variation = if stats.mean_time.num_nanoseconds().unwrap_or(0) > 0 {
                stats.std_deviation.num_nanoseconds().unwrap_or(0) as f64
                    / stats.mean_time.num_nanoseconds().unwrap_or(1) as f64
            } else {
                0.0
            };

            // Higher variance indicates potential side-channel vulnerability
            risk_score += coefficient_of_variation * 10.0;
        }

        // Additional risk from detected anomalies
        for anomaly in anomalies {
            risk_score += match anomaly.deviation_score {
                score if score > 5.0 => 20.0,
                score if score > 3.0 => 10.0,
                _ => 5.0,
            };
        }

        risk_score.min(100.0)
    }

    fn calculate_access_risk_score(&self, anomalies: &[AccessAnomaly]) -> f64 {
        let mut score: f64 = 0.0;

        for anomaly in anomalies {
            score += match anomaly.severity {
                SecuritySeverity::Critical => 25.0,
                SecuritySeverity::High => 15.0,
                SecuritySeverity::Medium => 10.0,
                SecuritySeverity::Low => 5.0,
                SecuritySeverity::Info => 1.0,
            };
        }

        score.min(100.0)
    }

    fn calculate_threat_score(
        &self,
        alerts: &[ThreatAlert],
        access: &AccessAnalysis,
        timing: &TimingAnalysis,
    ) -> f64 {
        let mut score = 0.0;

        // Score from threat alerts
        for alert in alerts {
            score += match alert.severity {
                SecuritySeverity::Critical => 30.0,
                SecuritySeverity::High => 20.0,
                SecuritySeverity::Medium => 10.0,
                SecuritySeverity::Low => 5.0,
                SecuritySeverity::Info => 1.0,
            } * alert.confidence;
        }

        // Score from access analysis
        score += access.risk_score * 0.3;

        // Score from timing analysis
        score += timing.side_channel_risk * 0.2;

        score.min(100.0)
    }

    fn generate_risk_assessment(&self, threat_score: f64) -> String {
        match threat_score {
            score if score >= 80.0 => "CRITICAL: Immediate security response required".to_string(),
            score if score >= 60.0 => "HIGH: Security review and remediation needed".to_string(),
            score if score >= 40.0 => {
                "MEDIUM: Monitor closely and investigate anomalies".to_string()
            }
            score if score >= 20.0 => "LOW: Normal monitoring sufficient".to_string(),
            _ => "MINIMAL: No immediate security concerns".to_string(),
        }
    }

    fn events_to_access_log(&self, events: &[SecurityEvent]) -> AccessLog {
        let entries = events
            .iter()
            .filter(|e| {
                e.event_type.contains("access")
                    || e.event_type.contains("read")
                    || e.event_type.contains("write")
            })
            .map(|e| AccessLogEntry {
                timestamp: e.timestamp,
                user_id: e.source.clone(),
                resource: e.target.clone().unwrap_or_default(),
                method: e.event_type.clone(),
                success: e.success,
                duration: e.duration,
                metadata: e.metadata.clone(),
            })
            .collect();

        let period = if let (Some(first), Some(last)) = (events.first(), events.last()) {
            (first.timestamp, last.timestamp)
        } else {
            (Utc::now(), Utc::now())
        };

        AccessLog { entries, period }
    }

    fn events_to_timed_operations(&self, events: &[SecurityEvent]) -> Vec<TimedOperation> {
        events
            .iter()
            .filter_map(|e| {
                e.duration.map(|duration| TimedOperation {
                    timestamp: e.timestamp,
                    operation_type: e.event_type.clone(),
                    duration,
                    context: e.metadata.clone(),
                    success: e.success,
                })
            })
            .collect()
    }

    fn get_analysis_period(&self, events: &[SecurityEvent]) -> (DateTime<Utc>, DateTime<Utc>) {
        if let (Some(first), Some(last)) = (events.first(), events.last()) {
            (first.timestamp, last.timestamp)
        } else {
            (Utc::now(), Utc::now())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_threat_config() -> ThreatDetectionConfig {
        ThreatDetectionConfig {
            behavioral_analysis: true,
            anomaly_thresholds: HashMap::from([
                ("login_failure_rate".to_string(), 0.2),
                ("suspicious_timing".to_string(), 0.8),
            ]),
            access_pattern_analysis: true,
            timing_analysis: true,
            confidence_level: 0.95,
        }
    }

    fn sample_event(event_type: &str) -> SecurityEvent {
        SecurityEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            source: "user-123".to_string(),
            target: Some("resource-456".to_string()),
            metadata: HashMap::from([
                ("auth_method".to_string(), "password".to_string()),
                ("ip".to_string(), "127.0.0.1".to_string()),
            ]),
            success: true,
            error_code: None,
            duration: Some(Duration::milliseconds(120)),
            resource_usage: Some(ResourceUsage {
                cpu_time_us: 1200,
                memory_bytes: 1024 * 1024,
                network_sent: 2048,
                network_received: 4096,
                disk_read: 0,
                disk_written: 0,
            }),
        }
    }

    #[tokio::test]
    async fn threat_detector_tracks_events_and_runs_analysis() {
        let config = sample_threat_config();
        let detector = ThreatDetector::new(config.clone()).expect("detector init");

        // Ensure the configuration-backed structures are accessible and populated.
        assert!(detector.config.behavioral_analysis);
        assert!(detector.anomaly_models.contains_key("access_pattern"));
        assert!(detector.statistical_analyzers.contains_key("timing"));

        {
            let mut patterns = detector.patterns.write().await;
            patterns.insert(
                "login-pattern".to_string(),
                BehavioralPattern {
                    name: "login-pattern".to_string(),
                    description: "baseline login behaviour".to_string(),
                    event_types: vec!["login_attempt".to_string()],
                    thresholds: HashMap::new(),
                    baseline: BaselineMetrics {
                        means: HashMap::new(),
                        standard_deviations: HashMap::new(),
                        percentiles: HashMap::new(),
                        minimums: HashMap::new(),
                        maximums: HashMap::new(),
                        sample_count: 0,
                        last_updated: Utc::now(),
                    },
                    last_updated: Utc::now(),
                    sample_count: 0,
                },
            );
        }

        let event = sample_event("login_attempt");
        detector
            .record_event(event.clone())
            .await
            .expect("record event");

        let alerts = detector.detect_suspicious_activity(&[event.clone()]).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].source, event.source);

        let analysis = detector.analyze().await.expect("analysis");
        assert!(analysis.events_analyzed >= 1);
        assert!(analysis.threat_score >= 0.0);
        assert!(analysis
            .timing_analysis
            .operation_timings
            .contains_key("login_attempt"));

        let history = detector.event_history.read().await;
        assert_eq!(history.len(), 1);
    }
}
