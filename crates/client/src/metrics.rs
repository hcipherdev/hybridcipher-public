use serde::{Deserialize, Serialize};
/// Metrics Collection System for HybridCipher Client
///
/// Provides comprehensive metrics collection, aggregation, and export
/// capabilities for operational monitoring and performance analysis.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::errors::ErrorCode;

/// Counter metric for tracking cumulative values
#[derive(Debug, Clone, Default)]
pub struct Counter {
    value: u64,
    labels: HashMap<String, String>,
}

impl Counter {
    /// Create a new counter
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a counter with labels
    pub fn with_labels(labels: HashMap<String, String>) -> Self {
        Self { value: 0, labels }
    }

    /// Increment the counter by 1
    pub fn inc(&mut self) {
        self.value += 1;
    }

    /// Increment the counter by a specific amount
    pub fn add(&mut self, value: u64) {
        self.value += value;
    }

    /// Get the current value
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Get the labels
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }
}

/// Gauge metric for tracking values that can go up and down
#[derive(Debug, Clone, Default)]
pub struct Gauge {
    value: f64,
    labels: HashMap<String, String>,
}

impl Gauge {
    /// Create a new gauge
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a gauge with labels
    pub fn with_labels(labels: HashMap<String, String>) -> Self {
        Self { value: 0.0, labels }
    }

    /// Set the gauge value
    pub fn set(&mut self, value: f64) {
        self.value = value;
    }

    /// Increment the gauge
    pub fn inc(&mut self) {
        self.value += 1.0;
    }

    /// Decrement the gauge
    pub fn dec(&mut self) {
        self.value -= 1.0;
    }

    /// Add to the gauge
    pub fn add(&mut self, value: f64) {
        self.value += value;
    }

    /// Subtract from the gauge
    pub fn sub(&mut self, value: f64) {
        self.value -= value;
    }

    /// Get the current value
    pub fn value(&self) -> f64 {
        self.value
    }

    /// Get the labels
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }
}

/// Histogram for tracking distribution of values
#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: Vec<f64>,
    counts: Vec<u64>,
    sum: f64,
    count: u64,
    labels: HashMap<String, String>,
}

impl Histogram {
    /// Create a new histogram with default buckets
    pub fn new() -> Self {
        Self::with_buckets(vec![
            0.001,
            0.005,
            0.01,
            0.025,
            0.05,
            0.1,
            0.25,
            0.5,
            1.0,
            2.5,
            5.0,
            10.0,
            f64::INFINITY,
        ])
    }

    /// Create a histogram with custom buckets
    pub fn with_buckets(buckets: Vec<f64>) -> Self {
        let count = buckets.len();
        Self {
            buckets,
            counts: vec![0; count],
            sum: 0.0,
            count: 0,
            labels: HashMap::new(),
        }
    }

    /// Create a histogram with labels
    pub fn with_labels(buckets: Vec<f64>, labels: HashMap<String, String>) -> Self {
        let count = buckets.len();
        Self {
            buckets,
            counts: vec![0; count],
            sum: 0.0,
            count: 0,
            labels,
        }
    }

    /// Observe a value
    pub fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;

        for (i, &bucket) in self.buckets.iter().enumerate() {
            if value <= bucket {
                self.counts[i] += 1;
            }
        }
    }

    /// Get the count of observations
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Get the sum of all observations
    pub fn sum(&self) -> f64 {
        self.sum
    }

    /// Get the average value
    pub fn average(&self) -> f64 {
        if self.count > 0 {
            self.sum / self.count as f64
        } else {
            0.0
        }
    }

    /// Get bucket counts
    pub fn bucket_counts(&self) -> &Vec<u64> {
        &self.counts
    }

    /// Get bucket boundaries
    pub fn buckets(&self) -> &Vec<f64> {
        &self.buckets
    }

    /// Get the labels
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }
}

/// Latency histogram specifically for operation timing
pub type LatencyHistogram = Histogram;

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    /// CPU usage percentage (0-100)
    pub cpu_usage_percent: f64,

    /// Memory usage in bytes
    pub memory_usage_bytes: u64,

    /// Available memory in bytes
    pub memory_available_bytes: u64,

    /// Disk usage in bytes
    pub disk_usage_bytes: u64,

    /// Available disk space in bytes
    pub disk_available_bytes: u64,

    /// Network bytes sent
    pub network_sent_bytes: u64,

    /// Network bytes received
    pub network_received_bytes: u64,
}

/// HybridCipher-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMetrics {
    /// Current group size
    pub group_size: u32,

    /// Number of active epochs
    pub active_epochs: u32,

    /// Total files managed
    pub total_files: u64,

    /// Total encrypted data size
    pub total_encrypted_bytes: u64,

    /// Average file size
    pub average_file_size: f64,

    /// Rekey frequency (per day)
    pub rekey_frequency: f64,

    /// Member activity scores
    pub member_activity: HashMap<String, f64>,
}

/// Main metrics collector
pub struct MetricsCollector {
    /// Operation latency histograms
    operation_latencies: Arc<RwLock<HashMap<String, LatencyHistogram>>>,

    /// Error counters by error code
    error_counters: Arc<RwLock<HashMap<ErrorCode, Counter>>>,

    /// Resource usage gauges
    resource_gauges: Arc<RwLock<HashMap<String, Gauge>>>,

    /// Custom counters
    counters: Arc<RwLock<HashMap<String, Counter>>>,

    /// Custom gauges
    gauges: Arc<RwLock<HashMap<String, Gauge>>>,

    /// HybridCipher-specific metrics
    group_metrics: Arc<Mutex<GroupMetrics>>,

    /// Resource metrics
    resource_metrics: Arc<Mutex<ResourceMetrics>>,

    /// Metrics collection start time
    start_time: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            operation_latencies: Arc::new(RwLock::new(HashMap::new())),
            error_counters: Arc::new(RwLock::new(HashMap::new())),
            resource_gauges: Arc::new(RwLock::new(HashMap::new())),
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            group_metrics: Arc::new(Mutex::new(GroupMetrics {
                group_size: 0,
                active_epochs: 0,
                total_files: 0,
                total_encrypted_bytes: 0,
                average_file_size: 0.0,
                rekey_frequency: 0.0,
                member_activity: HashMap::new(),
            })),
            resource_metrics: Arc::new(Mutex::new(ResourceMetrics {
                cpu_usage_percent: 0.0,
                memory_usage_bytes: 0,
                memory_available_bytes: 0,
                disk_usage_bytes: 0,
                disk_available_bytes: 0,
                network_sent_bytes: 0,
                network_received_bytes: 0,
            })),
            start_time: Instant::now(),
        }
    }

    /// Record operation latency
    pub fn record_operation_latency(&self, operation: &str, duration: Duration) {
        let mut latencies = self.operation_latencies.write().unwrap();
        let histogram = latencies
            .entry(operation.to_string())
            .or_insert_with(LatencyHistogram::new);
        histogram.observe(duration.as_secs_f64());
    }

    /// Increment error counter
    pub fn increment_error_counter(&self, error_code: ErrorCode) {
        let mut counters = self.error_counters.write().unwrap();
        let counter = counters.entry(error_code).or_insert_with(Counter::new);
        counter.inc();
    }

    /// Update resource gauge
    pub fn update_resource_gauge(&self, resource: &str, value: f64) {
        let mut gauges = self.resource_gauges.write().unwrap();
        let gauge = gauges
            .entry(resource.to_string())
            .or_insert_with(Gauge::new);
        gauge.set(value);
    }

    /// Increment a custom counter
    pub fn increment_counter(&self, name: &str) {
        let mut counters = self.counters.write().unwrap();
        let counter = counters
            .entry(name.to_string())
            .or_insert_with(Counter::new);
        counter.inc();
    }

    /// Add to a custom counter
    pub fn add_to_counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.write().unwrap();
        let counter = counters
            .entry(name.to_string())
            .or_insert_with(Counter::new);
        counter.add(value);
    }

    /// Set a custom gauge
    pub fn set_gauge(&self, name: &str, value: f64) {
        let mut gauges = self.gauges.write().unwrap();
        let gauge = gauges.entry(name.to_string()).or_insert_with(Gauge::new);
        gauge.set(value);
    }

    /// Update group metrics
    pub fn update_group_metrics(&self, metrics: GroupMetrics) {
        let mut group_metrics = self.group_metrics.lock().unwrap();
        *group_metrics = metrics;
    }

    /// Update resource metrics
    pub fn update_resource_metrics(&self, metrics: ResourceMetrics) {
        let mut resource_metrics = self.resource_metrics.lock().unwrap();
        *resource_metrics = metrics;
    }

    /// Get operation latency statistics
    pub fn get_operation_latency_stats(&self, operation: &str) -> Option<LatencyStats> {
        let latencies = self.operation_latencies.read().unwrap();
        latencies.get(operation).map(|histogram| LatencyStats {
            count: histogram.count(),
            sum: histogram.sum(),
            average: histogram.average(),
            buckets: histogram.bucket_counts().clone(),
        })
    }

    /// Get error count for a specific error code
    pub fn get_error_count(&self, error_code: ErrorCode) -> u64 {
        let counters = self.error_counters.read().unwrap();
        counters.get(&error_code).map(|c| c.value()).unwrap_or(0)
    }

    /// Get total error count
    pub fn get_total_error_count(&self) -> u64 {
        let counters = self.error_counters.read().unwrap();
        counters.values().map(|c| c.value()).sum()
    }

    /// Get resource gauge value
    pub fn get_resource_gauge(&self, resource: &str) -> Option<f64> {
        let gauges = self.resource_gauges.read().unwrap();
        gauges.get(resource).map(|g| g.value())
    }

    /// Get current group metrics
    pub fn get_group_metrics(&self) -> GroupMetrics {
        self.group_metrics.lock().unwrap().clone()
    }

    /// Get current resource metrics
    pub fn get_resource_metrics(&self) -> ResourceMetrics {
        self.resource_metrics.lock().unwrap().clone()
    }

    /// Get uptime in seconds
    pub fn get_uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus_metrics(&self) -> String {
        let mut output = String::new();

        // Export operation latencies
        let latencies = self.operation_latencies.read().unwrap();
        for (operation, histogram) in latencies.iter() {
            output.push_str(&format!(
                "# HELP operation_duration_seconds Time spent on operations\n# TYPE operation_duration_seconds histogram\n"
            ));

            for (i, &bucket) in histogram.buckets().iter().enumerate() {
                let count = histogram.bucket_counts()[i];
                if bucket == f64::INFINITY {
                    output.push_str(&format!(
                        "operation_duration_seconds_bucket{{operation=\"{}\",le=\"+Inf\"}} {}\n",
                        operation, count
                    ));
                } else {
                    output.push_str(&format!(
                        "operation_duration_seconds_bucket{{operation=\"{}\",le=\"{}\"}} {}\n",
                        operation, bucket, count
                    ));
                }
            }

            output.push_str(&format!(
                "operation_duration_seconds_sum{{operation=\"{}\"}} {}\n",
                operation,
                histogram.sum()
            ));
            output.push_str(&format!(
                "operation_duration_seconds_count{{operation=\"{}\"}} {}\n",
                operation,
                histogram.count()
            ));
        }

        // Export error counters
        let error_counters = self.error_counters.read().unwrap();
        output
            .push_str("# HELP errors_total Total number of errors\n# TYPE errors_total counter\n");
        for (error_code, counter) in error_counters.iter() {
            output.push_str(&format!(
                "errors_total{{error_code=\"{:?}\"}} {}\n",
                error_code,
                counter.value()
            ));
        }

        // Export resource gauges
        let resource_gauges = self.resource_gauges.read().unwrap();
        for (resource, gauge) in resource_gauges.iter() {
            output.push_str(&format!(
                "# HELP {} Current {}\n# TYPE {} gauge\n",
                resource, resource, resource
            ));
            output.push_str(&format!("{} {}\n", resource, gauge.value()));
        }

        // Export custom counters
        let counters = self.counters.read().unwrap();
        for (name, counter) in counters.iter() {
            output.push_str(&format!(
                "# HELP {} Custom counter\n# TYPE {} counter\n",
                name, name
            ));
            output.push_str(&format!("{} {}\n", name, counter.value()));
        }

        // Export custom gauges
        let gauges = self.gauges.read().unwrap();
        for (name, gauge) in gauges.iter() {
            output.push_str(&format!(
                "# HELP {} Custom gauge\n# TYPE {} gauge\n",
                name, name
            ));
            output.push_str(&format!("{} {}\n", name, gauge.value()));
        }

        // Export uptime
        output.push_str("# HELP uptime_seconds Time since startup\n# TYPE uptime_seconds gauge\n");
        output.push_str(&format!("uptime_seconds {}\n", self.get_uptime_seconds()));

        output
    }

    /// Export metrics in JSON format
    pub fn export_json_metrics(&self) -> Result<String, serde_json::Error> {
        let metrics = JsonMetrics {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            uptime_seconds: self.get_uptime_seconds(),
            group_metrics: self.get_group_metrics(),
            resource_metrics: self.get_resource_metrics(),
            operation_latencies: self.export_latency_map(),
            error_counts: self.export_error_counts(),
            custom_counters: self.export_custom_counters(),
            custom_gauges: self.export_custom_gauges(),
        };

        serde_json::to_string_pretty(&metrics)
    }

    fn export_latency_map(&self) -> HashMap<String, LatencyStats> {
        let latencies = self.operation_latencies.read().unwrap();
        latencies
            .iter()
            .map(|(op, hist)| {
                (
                    op.clone(),
                    LatencyStats {
                        count: hist.count(),
                        sum: hist.sum(),
                        average: hist.average(),
                        buckets: hist.bucket_counts().clone(),
                    },
                )
            })
            .collect()
    }

    fn export_error_counts(&self) -> HashMap<String, u64> {
        let counters = self.error_counters.read().unwrap();
        counters
            .iter()
            .map(|(code, counter)| (format!("{:?}", code), counter.value()))
            .collect()
    }

    fn export_custom_counters(&self) -> HashMap<String, u64> {
        let counters = self.counters.read().unwrap();
        counters
            .iter()
            .map(|(name, counter)| (name.clone(), counter.value()))
            .collect()
    }

    fn export_custom_gauges(&self) -> HashMap<String, f64> {
        let gauges = self.gauges.read().unwrap();
        gauges
            .iter()
            .map(|(name, gauge)| (name.clone(), gauge.value()))
            .collect()
    }
}

/// Latency statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub count: u64,
    pub sum: f64,
    pub average: f64,
    pub buckets: Vec<u64>,
}

/// JSON export format for metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonMetrics {
    pub timestamp: u64,
    pub uptime_seconds: f64,
    pub group_metrics: GroupMetrics,
    pub resource_metrics: ResourceMetrics,
    pub operation_latencies: HashMap<String, LatencyStats>,
    pub error_counts: HashMap<String, u64>,
    pub custom_counters: HashMap<String, u64>,
    pub custom_gauges: HashMap<String, f64>,
}

/// Timer for measuring operation duration
pub struct Timer {
    start: Instant,
    operation: String,
    collector: Arc<MetricsCollector>,
}

impl Timer {
    /// Start a new timer
    pub fn start(operation: String, collector: Arc<MetricsCollector>) -> Self {
        Self {
            start: Instant::now(),
            operation,
            collector,
        }
    }

    /// Stop the timer and record the measurement
    pub fn stop(self) {
        let duration = self.start.elapsed();
        self.collector
            .record_operation_latency(&self.operation, duration);
    }
}

/// Global metrics collector
static GLOBAL_METRICS: OnceLock<Arc<MetricsCollector>> = OnceLock::new();

/// Initialize global metrics collector
pub fn init_metrics() -> Arc<MetricsCollector> {
    let collector = Arc::new(MetricsCollector::new());
    if GLOBAL_METRICS.set(collector.clone()).is_ok() {
        collector
    } else {
        GLOBAL_METRICS
            .get()
            .cloned()
            .expect("GLOBAL_METRICS initialized")
    }
}

/// Get global metrics collector
pub fn get_metrics() -> Option<Arc<MetricsCollector>> {
    GLOBAL_METRICS.get().cloned()
}

/// Convenience macro for timing operations
#[macro_export]
macro_rules! time_operation {
    ($operation:expr, $code:block) => {{
        let timer = if let Some(metrics) = crate::metrics::get_metrics() {
            Some(crate::metrics::Timer::start(
                $operation.to_string(),
                metrics,
            ))
        } else {
            None
        };

        let result = $code;

        if let Some(timer) = timer {
            timer.stop();
        }

        result
    }};
}
