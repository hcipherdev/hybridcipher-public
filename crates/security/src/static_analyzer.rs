use crate::audit::{SecurityPattern, SecuritySeverity, StaticAnalysisConfig};
use crate::errors::AuditError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tokio::fs;
use uuid::Uuid;

/// Static code analyzer for security issues
#[derive(Debug)]
pub struct StaticAnalyzer {
    /// Configuration
    config: StaticAnalysisConfig,

    /// Security patterns to match
    security_patterns: Vec<SecurityPattern>,

    /// Code analyzers
    analyzers: Vec<CodeAnalyzer>,
}

/// Code analyzer implementation
#[derive(Debug, Clone)]
pub struct CodeAnalyzer {
    /// Analyzer name
    pub name: String,

    /// Analyzer type
    pub analyzer_type: AnalyzerType,

    /// Command to execute
    pub command: String,

    /// Arguments
    pub args: Vec<String>,

    /// Working directory
    pub working_dir: Option<PathBuf>,

    /// Output parser
    pub parser: AnalyzerOutputParser,
}

/// Type of code analyzer
#[derive(Debug, Clone)]
pub enum AnalyzerType {
    /// Clippy linter
    Clippy,

    /// Custom pattern matcher
    PatternMatcher,

    /// Complexity analyzer
    ComplexityAnalyzer,

    /// Dependency analyzer
    DependencyAnalyzer,

    /// Security scanner
    SecurityScanner,
}

/// Output parser for analyzer results
#[derive(Debug, Clone)]
pub struct AnalyzerOutputParser {
    /// Parser type
    pub parser_type: ParserType,

    /// Patterns for extracting issues
    pub issue_patterns: Vec<IssuePattern>,

    /// Severity mapping
    pub severity_mapping: HashMap<String, SecuritySeverity>,
}

/// Type of output parser
#[derive(Debug, Clone)]
pub enum ParserType {
    /// JSON format
    Json,

    /// Regex pattern matching
    Regex,

    /// Line-based parsing
    LineBased,

    /// Custom parser
    Custom,
}

/// Pattern for extracting security issues
#[derive(Debug, Clone)]
pub struct IssuePattern {
    /// Pattern name
    pub name: String,

    /// Regex pattern
    pub pattern: String,

    /// Capture groups
    pub capture_groups: HashMap<String, usize>,

    /// Default severity if not specified
    pub default_severity: SecuritySeverity,
}

/// Static analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisReport {
    /// Report ID
    pub report_id: Uuid,

    /// Analysis timestamp
    pub timestamp: DateTime<Utc>,

    /// Configuration used
    pub config: StaticAnalysisConfig,

    /// Files analyzed
    pub files_analyzed: Vec<AnalyzedFile>,

    /// Security issues found
    pub security_issues: Vec<SecurityIssue>,

    /// Code quality metrics
    pub quality_metrics: QualityMetrics,

    /// Complexity analysis
    pub complexity_analysis: ComplexityAnalysis,

    /// Pattern matches
    pub pattern_matches: Vec<PatternMatch>,

    /// Analyzer results
    pub analyzer_results: Vec<AnalyzerResult>,

    /// Summary statistics
    pub summary: AnalysisSummary,
}

/// Information about an analyzed file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedFile {
    /// File path
    pub path: String,

    /// File size in bytes
    pub size_bytes: u64,

    /// Lines of code
    pub lines_of_code: usize,

    /// Language detected
    pub language: String,

    /// Analysis status
    pub status: AnalysisStatus,

    /// Issues found in this file
    pub issues_count: usize,

    /// Complexity metrics
    pub complexity: FileComplexity,
}

/// Analysis status for a file
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AnalysisStatus {
    Analyzed,
    Skipped,
    Error,
    NotFound,
}

/// File-level complexity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComplexity {
    /// Cyclomatic complexity
    pub cyclomatic: u32,

    /// Cognitive complexity
    pub cognitive: u32,

    /// Function count
    pub function_count: u32,

    /// Average function length
    pub avg_function_length: f64,

    /// Maximum nesting level
    pub max_nesting_level: u32,
}

/// Security issue found during static analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    /// Issue ID
    pub id: Uuid,

    /// Issue type
    pub issue_type: String,

    /// Severity level
    pub severity: SecuritySeverity,

    /// File location
    pub file: String,

    /// Line number
    pub line: u32,

    /// Column number
    pub column: Option<u32>,

    /// Issue description
    pub description: String,

    /// Code snippet
    pub code_snippet: String,

    /// Context around the issue
    pub context: String,

    /// Rule or pattern that triggered
    pub rule_id: String,

    /// Confidence level (0-1)
    pub confidence: f64,

    /// Recommendation for fixing
    pub recommendation: String,

    /// CWE (Common Weakness Enumeration) ID
    pub cwe_id: Option<String>,

    /// References for more information
    pub references: Vec<String>,
}

/// Code quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    /// Total lines of code
    pub total_loc: usize,

    /// Lines of comments
    pub comment_lines: usize,

    /// Blank lines
    pub blank_lines: usize,

    /// Code coverage percentage
    pub code_coverage: Option<f64>,

    /// Test coverage percentage
    pub test_coverage: Option<f64>,

    /// Documentation coverage
    pub doc_coverage: Option<f64>,

    /// Technical debt ratio
    pub technical_debt_ratio: f64,

    /// Maintainability index
    pub maintainability_index: f64,
}

/// Code complexity analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityAnalysis {
    /// Cyclomatic complexity by function
    pub cyclomatic_complexity: HashMap<String, u32>,

    /// Cognitive complexity by function
    pub cognitive_complexity: HashMap<String, u32>,

    /// Halstead complexity metrics
    pub halstead_metrics: HashMap<String, HalsteadMetrics>,

    /// Overall complexity score
    pub overall_complexity_score: f64,

    /// Functions exceeding complexity thresholds
    pub high_complexity_functions: Vec<ComplexFunction>,
}

/// Halstead complexity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalsteadMetrics {
    /// Program length
    pub program_length: u32,

    /// Program vocabulary
    pub vocabulary: u32,

    /// Program volume
    pub volume: f64,

    /// Program difficulty
    pub difficulty: f64,

    /// Program effort
    pub effort: f64,

    /// Time to implement
    pub time_to_implement: f64,

    /// Bugs predicted
    pub bugs_predicted: f64,
}

/// Function with high complexity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexFunction {
    /// Function name
    pub name: String,

    /// File location
    pub file: String,

    /// Line number
    pub line: u32,

    /// Cyclomatic complexity
    pub cyclomatic: u32,

    /// Cognitive complexity
    pub cognitive: u32,

    /// Recommendation
    pub recommendation: String,
}

/// Pattern match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Pattern that matched
    pub pattern: SecurityPattern,

    /// File location
    pub file: String,

    /// Line number
    pub line: u32,

    /// Column number
    pub column: Option<u32>,

    /// Matched text
    pub matched_text: String,

    /// Context around match
    pub context: String,

    /// Match confidence
    pub confidence: f64,
}

/// Result from a specific analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerResult {
    /// Analyzer name
    pub analyzer_name: String,

    /// Analyzer type
    pub analyzer_type: String,

    /// Execution status
    pub status: ExecutionStatus,

    /// Execution time
    pub execution_time: std::time::Duration,

    /// Issues found by this analyzer
    pub issues_found: usize,

    /// Output from analyzer
    pub output: String,

    /// Error message if failed
    pub error_message: Option<String>,
}

/// Execution status for analyzer
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    Success,
    Failed,
    Timeout,
    Cancelled,
}

/// Analysis summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Total files analyzed
    pub files_analyzed: usize,

    /// Total lines analyzed
    pub lines_analyzed: usize,

    /// Total issues found
    pub total_issues: usize,

    /// Issues by severity
    pub issues_by_severity: HashMap<SecuritySeverity, usize>,

    /// Issues by type
    pub issues_by_type: HashMap<String, usize>,

    /// Analysis duration
    pub analysis_duration: std::time::Duration,

    /// Overall quality score
    pub quality_score: f64,

    /// Risk assessment
    pub risk_level: SecuritySeverity,
}

impl StaticAnalyzer {
    /// Create a new static analyzer
    pub fn new(config: StaticAnalysisConfig) -> Result<Self, AuditError> {
        let security_patterns = config.security_patterns.clone();
        let analyzers = Self::initialize_analyzers(&config)?;

        Ok(Self {
            config,
            security_patterns,
            analyzers,
        })
    }

    /// Run comprehensive static analysis
    pub async fn analyze(&self) -> Result<StaticAnalysisReport, AuditError> {
        let report_id = Uuid::new_v4();
        let timestamp = Utc::now();
        let start_time = std::time::Instant::now();

        tracing::info!("Starting static analysis {}", report_id);

        // Discover files to analyze
        let files_to_analyze = self.discover_source_files().await?;

        // Analyze each file
        let mut analyzed_files = Vec::new();
        let mut all_issues = Vec::new();
        let mut pattern_matches = Vec::new();
        let mut analyzer_results = Vec::new();

        for file_path in &files_to_analyze {
            match self.analyze_file(file_path).await {
                Ok((file_info, issues, matches)) => {
                    analyzed_files.push(file_info);
                    all_issues.extend(issues);
                    pattern_matches.extend(matches);
                }
                Err(e) => {
                    tracing::warn!("Failed to analyze file {}: {}", file_path.display(), e);
                    analyzed_files.push(AnalyzedFile {
                        path: file_path.to_string_lossy().to_string(),
                        size_bytes: 0,
                        lines_of_code: 0,
                        language: "unknown".to_string(),
                        status: AnalysisStatus::Error,
                        issues_count: 0,
                        complexity: FileComplexity {
                            cyclomatic: 0,
                            cognitive: 0,
                            function_count: 0,
                            avg_function_length: 0.0,
                            max_nesting_level: 0,
                        },
                    });
                }
            }
        }

        // Run external analyzers
        for analyzer in &self.analyzers {
            match self.run_analyzer(analyzer).await {
                Ok(result) => {
                    all_issues.extend(self.parse_analyzer_output(analyzer, &result.output)?);
                    analyzer_results.push(result);
                }
                Err(e) => {
                    tracing::warn!("Analyzer {} failed: {}", analyzer.name, e);
                    analyzer_results.push(AnalyzerResult {
                        analyzer_name: analyzer.name.clone(),
                        analyzer_type: format!("{:?}", analyzer.analyzer_type),
                        status: ExecutionStatus::Failed,
                        execution_time: std::time::Duration::from_secs(0),
                        issues_found: 0,
                        output: String::new(),
                        error_message: Some(e.to_string()),
                    });
                }
            }
        }

        // Generate metrics and analysis
        let quality_metrics = self.calculate_quality_metrics(&analyzed_files)?;
        let complexity_analysis = self.calculate_complexity_analysis(&analyzed_files)?;
        let summary = self.generate_summary(&analyzed_files, &all_issues, start_time.elapsed())?;

        let report = StaticAnalysisReport {
            report_id,
            timestamp,
            config: self.config.clone(),
            files_analyzed: analyzed_files,
            security_issues: all_issues,
            quality_metrics,
            complexity_analysis,
            pattern_matches,
            analyzer_results,
            summary,
        };

        tracing::info!(
            "Static analysis {} completed. Found {} issues in {} files",
            report_id,
            report.summary.total_issues,
            report.summary.files_analyzed
        );

        Ok(report)
    }

    /// Discover source files to analyze
    async fn discover_source_files(&self) -> Result<Vec<PathBuf>, AuditError> {
        let mut files = Vec::new();

        // Define source file extensions
        let source_extensions = vec!["rs", "toml", "yaml", "yml", "json", "md"];

        // Walk the source directory
        let src_dir = Path::new(".");
        if src_dir.exists() {
            files.extend(self.walk_directory(src_dir, &source_extensions).await?);
        }

        // Also check crates directory
        let crates_dir = Path::new("crates");
        if crates_dir.exists() {
            files.extend(self.walk_directory(crates_dir, &source_extensions).await?);
        }

        Ok(files)
    }

    /// Recursively walk directory to find source files
    async fn walk_directory(
        &self,
        dir: &Path,
        extensions: &[&str],
    ) -> Result<Vec<PathBuf>, AuditError> {
        let mut files = Vec::new();
        let mut entries = fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                // Skip common non-source directories
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if matches!(
                        dir_name,
                        "target" | ".git" | "node_modules" | ".cargo" | ".vscode"
                    ) {
                        continue;
                    }
                }

                files.extend(Box::pin(self.walk_directory(&path, extensions)).await?);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.contains(&ext) {
                    files.push(path);
                }
            }
        }

        Ok(files)
    }

    /// Analyze a single file
    async fn analyze_file(
        &self,
        file_path: &Path,
    ) -> Result<(AnalyzedFile, Vec<SecurityIssue>, Vec<PatternMatch>), AuditError> {
        let content = fs::read_to_string(file_path).await?;
        let metadata = fs::metadata(file_path).await?;

        let lines_of_code = content.lines().count();
        let language = self.detect_language(file_path);

        // Find security issues using pattern matching
        let mut issues = Vec::new();
        let mut pattern_matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.security_patterns {
                if let Ok(regex) = regex::Regex::new(&pattern.pattern) {
                    if let Some(captures) = regex.captures(line) {
                        let matched_text = captures
                            .get(0)
                            .map(|m| m.as_str())
                            .unwrap_or("")
                            .to_string();

                        pattern_matches.push(PatternMatch {
                            pattern: pattern.clone(),
                            file: file_path.to_string_lossy().to_string(),
                            line: line_num as u32 + 1,
                            column: Some(0),
                            matched_text: matched_text.clone(),
                            context: line.to_string(),
                            confidence: 0.8,
                        });

                        issues.push(SecurityIssue {
                            id: Uuid::new_v4(),
                            issue_type: pattern.name.clone(),
                            severity: pattern.severity,
                            file: file_path.to_string_lossy().to_string(),
                            line: line_num as u32 + 1,
                            column: Some(0),
                            description: pattern.description.clone(),
                            code_snippet: line.to_string(),
                            context: self.get_context(&content, line_num, 2),
                            rule_id: format!("pattern:{}", pattern.name),
                            confidence: 0.8,
                            recommendation: pattern.recommendation.clone(),
                            cwe_id: None,
                            references: Vec::new(),
                        });
                    }
                }
            }
        }

        // Calculate file complexity
        let complexity = self.calculate_file_complexity(&content, &language);

        let file_info = AnalyzedFile {
            path: file_path.to_string_lossy().to_string(),
            size_bytes: metadata.len(),
            lines_of_code,
            language,
            status: AnalysisStatus::Analyzed,
            issues_count: issues.len(),
            complexity,
        };

        Ok((file_info, issues, pattern_matches))
    }

    /// Detect programming language from file extension
    fn detect_language(&self, file_path: &Path) -> String {
        match file_path.extension().and_then(|e| e.to_str()) {
            Some("rs") => "Rust".to_string(),
            Some("toml") => "TOML".to_string(),
            Some("yaml") | Some("yml") => "YAML".to_string(),
            Some("json") => "JSON".to_string(),
            Some("md") => "Markdown".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    /// Get context lines around a specific line
    fn get_context(&self, content: &str, line_num: usize, context_size: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = line_num.saturating_sub(context_size);
        let end = (line_num + context_size + 1).min(lines.len());

        lines[start..end].join("\n")
    }

    /// Calculate file-level complexity metrics
    fn calculate_file_complexity(&self, content: &str, language: &str) -> FileComplexity {
        match language {
            "Rust" => self.calculate_rust_complexity(content),
            _ => FileComplexity {
                cyclomatic: 0,
                cognitive: 0,
                function_count: 0,
                avg_function_length: 0.0,
                max_nesting_level: 0,
            },
        }
    }

    /// Calculate complexity for Rust code
    fn calculate_rust_complexity(&self, content: &str) -> FileComplexity {
        let mut cyclomatic = 1; // Base complexity
        let mut cognitive = 0;
        let mut function_count = 0;
        let mut max_nesting = 0;
        let mut current_nesting: i32 = 0;

        for line in content.lines() {
            let trimmed = line.trim();

            // Count functions
            if trimmed.starts_with("fn ") || trimmed.contains(" fn ") {
                function_count += 1;
            }

            // Count complexity-increasing constructs
            if trimmed.contains("if ") || trimmed.contains("else if ") {
                cyclomatic += 1;
                cognitive += 1;
            }

            if trimmed.contains("match ") || trimmed.contains("while ") || trimmed.contains("for ")
            {
                cyclomatic += 1;
                cognitive += 1;
            }

            if trimmed.contains("loop ") || trimmed.contains("catch ") {
                cyclomatic += 1;
                cognitive += 1;
            }

            // Track nesting level
            if trimmed.contains('{') {
                current_nesting += 1;
                max_nesting = max_nesting.max(current_nesting);
            }
            if trimmed.contains('}') {
                current_nesting = current_nesting.saturating_sub(1);
            }
        }

        let lines_count = content.lines().count();
        let avg_function_length = if function_count > 0 {
            lines_count as f64 / function_count as f64
        } else {
            0.0
        };

        FileComplexity {
            cyclomatic,
            cognitive,
            function_count,
            avg_function_length,
            max_nesting_level: max_nesting as u32,
        }
    }

    /// Run an external analyzer
    async fn run_analyzer(&self, analyzer: &CodeAnalyzer) -> Result<AnalyzerResult, AuditError> {
        let start_time = std::time::Instant::now();

        let mut command = Command::new(&analyzer.command);
        command.args(&analyzer.args);

        if let Some(working_dir) = &analyzer.working_dir {
            command.current_dir(working_dir);
        }

        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let output = command
            .output()
            .map_err(|e| AuditError::StaticAnalysisFailed {
                message: format!("Failed to execute analyzer {}: {}", analyzer.name, e),
            })?;

        let execution_time = start_time.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let status = if output.status.success() {
            ExecutionStatus::Success
        } else {
            ExecutionStatus::Failed
        };

        let combined_output = if stderr.is_empty() {
            stdout
        } else {
            format!("{}\n{}", stdout, stderr)
        };

        Ok(AnalyzerResult {
            analyzer_name: analyzer.name.clone(),
            analyzer_type: format!("{:?}", analyzer.analyzer_type),
            status,
            execution_time,
            issues_found: 0, // Will be calculated by parsing output
            output: combined_output,
            error_message: if status == ExecutionStatus::Failed {
                Some(stderr)
            } else {
                None
            },
        })
    }

    /// Parse analyzer output to extract security issues
    fn parse_analyzer_output(
        &self,
        _analyzer: &CodeAnalyzer,
        _output: &str,
    ) -> Result<Vec<SecurityIssue>, AuditError> {
        // This would implement parsing logic for different analyzer outputs
        // For now, return empty vector
        Ok(Vec::new())
    }

    /// Calculate quality metrics
    fn calculate_quality_metrics(
        &self,
        files: &[AnalyzedFile],
    ) -> Result<QualityMetrics, AuditError> {
        let total_loc = files.iter().map(|f| f.lines_of_code).sum();
        let _total_size = files.iter().map(|f| f.size_bytes).sum::<u64>();

        // These would be calculated from actual analysis
        Ok(QualityMetrics {
            total_loc,
            comment_lines: 0,
            blank_lines: 0,
            code_coverage: None,
            test_coverage: None,
            doc_coverage: None,
            technical_debt_ratio: 0.1,
            maintainability_index: 85.0,
        })
    }

    /// Calculate complexity analysis
    fn calculate_complexity_analysis(
        &self,
        files: &[AnalyzedFile],
    ) -> Result<ComplexityAnalysis, AuditError> {
        let cyclomatic_complexity = HashMap::new();
        let cognitive_complexity = HashMap::new();
        let mut high_complexity_functions = Vec::new();

        let mut total_complexity = 0;
        let mut function_count = 0;

        for file in files {
            total_complexity += file.complexity.cyclomatic;
            function_count += file.complexity.function_count;

            // Check for high complexity functions
            if file.complexity.cyclomatic > 15 {
                high_complexity_functions.push(ComplexFunction {
                    name: format!("Functions in {}", file.path),
                    file: file.path.clone(),
                    line: 1,
                    cyclomatic: file.complexity.cyclomatic,
                    cognitive: file.complexity.cognitive,
                    recommendation: "Consider breaking down complex functions".to_string(),
                });
            }
        }

        let overall_complexity_score = if function_count > 0 {
            total_complexity as f64 / function_count as f64
        } else {
            0.0
        };

        Ok(ComplexityAnalysis {
            cyclomatic_complexity,
            cognitive_complexity,
            halstead_metrics: HashMap::new(),
            overall_complexity_score,
            high_complexity_functions,
        })
    }

    /// Generate analysis summary
    fn generate_summary(
        &self,
        files: &[AnalyzedFile],
        issues: &[SecurityIssue],
        duration: std::time::Duration,
    ) -> Result<AnalysisSummary, AuditError> {
        let files_analyzed = files.len();
        let lines_analyzed = files.iter().map(|f| f.lines_of_code).sum();
        let total_issues = issues.len();

        let mut issues_by_severity = HashMap::new();
        let mut issues_by_type = HashMap::new();

        for issue in issues {
            *issues_by_severity.entry(issue.severity).or_insert(0) += 1;
            *issues_by_type.entry(issue.issue_type.clone()).or_insert(0) += 1;
        }

        // Calculate quality score
        let quality_score = if total_issues == 0 {
            100.0
        } else {
            let penalty = total_issues as f64 * 2.0; // 2 points per issue
            (100.0 - penalty).max(0.0)
        };

        // Determine risk level
        let critical_count = issues_by_severity
            .get(&SecuritySeverity::Critical)
            .unwrap_or(&0);
        let high_count = issues_by_severity
            .get(&SecuritySeverity::High)
            .unwrap_or(&0);

        let risk_level = if *critical_count > 0 {
            SecuritySeverity::Critical
        } else if *high_count > 0 {
            SecuritySeverity::High
        } else if total_issues > 10 {
            SecuritySeverity::Medium
        } else if total_issues > 0 {
            SecuritySeverity::Low
        } else {
            SecuritySeverity::Info
        };

        Ok(AnalysisSummary {
            files_analyzed,
            lines_analyzed,
            total_issues,
            issues_by_severity,
            issues_by_type,
            analysis_duration: duration,
            quality_score,
            risk_level,
        })
    }

    /// Initialize code analyzers
    fn initialize_analyzers(
        config: &StaticAnalysisConfig,
    ) -> Result<Vec<CodeAnalyzer>, AuditError> {
        let mut analyzers = Vec::new();

        if config.run_clippy {
            analyzers.push(CodeAnalyzer {
                name: "Clippy".to_string(),
                analyzer_type: AnalyzerType::Clippy,
                command: "cargo".to_string(),
                args: vec![
                    "clippy".to_string(),
                    "--all-targets".to_string(),
                    "--all-features".to_string(),
                    "--".to_string(),
                    "-W".to_string(),
                    "clippy::all".to_string(),
                    "-D".to_string(),
                    "clippy::suspicious".to_string(),
                ],
                working_dir: Some(PathBuf::from(".")),
                parser: AnalyzerOutputParser {
                    parser_type: ParserType::Regex,
                    issue_patterns: vec![IssuePattern {
                        name: "clippy_warning".to_string(),
                        pattern: r"warning: (.+)".to_string(),
                        capture_groups: HashMap::from([("message".to_string(), 1)]),
                        default_severity: SecuritySeverity::Medium,
                    }],
                    severity_mapping: HashMap::from([
                        ("warning".to_string(), SecuritySeverity::Medium),
                        ("error".to_string(), SecuritySeverity::High),
                    ]),
                },
            });
        }

        Ok(analyzers)
    }
}
