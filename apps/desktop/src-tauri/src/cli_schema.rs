use serde::{Deserialize, Serialize};

/// CLI Schema Manager - Dynamically discovers and exposes CLI commands
pub struct CliSchemaManager {
    commands: Vec<CliCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliCommand {
    pub name: String,
    pub description: String,
    pub subcommands: Vec<CliCommand>,
    pub arguments: Vec<CliArgument>,
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub arg_type: String,
    pub default_value: Option<String>,
    pub possible_values: Option<Vec<String>>,
}

impl CliSchemaManager {
    pub fn new() -> Self {
        Self {
            commands: Self::build_schema(),
        }
    }

    /// Get the full CLI schema
    pub async fn get_full_schema(&self) -> Vec<CliCommand> {
        self.commands.clone()
    }

    /// Get help for a specific command
    pub async fn get_command_help(&self, command_path: &str) -> Option<CliCommand> {
        let parts: Vec<&str> = command_path.split('.').collect();
        Self::find_command(&self.commands, &parts)
    }

    /// Build the complete CLI schema snapshot used by the desktop UI.
    fn build_schema() -> Vec<CliCommand> {
        vec![
            // Authentication commands
            CliCommand {
                name: "auth".to_string(),
                description: "Authentication and user management".to_string(),
                subcommands: vec![
                    CliCommand {
                        name: "register".to_string(),
                        description: "Register a new user with OPAQUE authentication".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "email".to_string(),
                                description: "Email address for registration".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                            CliArgument {
                                name: "device-name".to_string(),
                                description: "Optional name for this device".to_string(),
                                required: false,
                                arg_type: "string".to_string(),
                                default_value: Some("Desktop".to_string()),
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher auth register --email user@example.com".to_string(),
                            "hybridcipher auth register --email user@example.com --device-name \"Work Laptop\"".to_string(),
                        ],
                    },
                    CliCommand {
                        name: "login".to_string(),
                        description: "Login with existing credentials".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "email".to_string(),
                                description: "Email address".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher auth login --email user@example.com".to_string(),
                        ],
                    },
                ],
                arguments: vec![],
                examples: vec![],
            },

            // Group management commands
            CliCommand {
                name: "group".to_string(),
                description: "Group management operations".to_string(),
                subcommands: vec![
                    CliCommand {
                        name: "create".to_string(),
                        description: "Create a new encryption group".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "name".to_string(),
                                description: "Name of the group".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                            CliArgument {
                                name: "description".to_string(),
                                description: "Optional group description".to_string(),
                                required: false,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher group create --name \"Engineering Team\"".to_string(),
                        ],
                    },
                    CliCommand {
                        name: "list".to_string(),
                        description: "List all groups".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "format".to_string(),
                                description: "Output format".to_string(),
                                required: false,
                                arg_type: "string".to_string(),
                                default_value: Some("table".to_string()),
                                possible_values: Some(vec!["table".to_string(), "json".to_string(), "yaml".to_string()]),
                            },
                        ],
                        examples: vec![
                            "hybridcipher group list".to_string(),
                            "hybridcipher group list --format json".to_string(),
                        ],
                    },
                ],
                arguments: vec![],
                examples: vec![],
            },

            // File operations
            CliCommand {
                name: "file".to_string(),
                description: "File encryption and decryption operations".to_string(),
                subcommands: vec![
                    CliCommand {
                        name: "encrypt".to_string(),
                        description: "Encrypt a file with ChaCha20-Poly1305".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "input".to_string(),
                                description: "Path to file to encrypt".to_string(),
                                required: true,
                                arg_type: "path".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                            CliArgument {
                                name: "group".to_string(),
                                description: "Group ID for encryption".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                            CliArgument {
                                name: "output".to_string(),
                                description: "Optional output path".to_string(),
                                required: false,
                                arg_type: "path".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher file encrypt --input document.pdf --group group123".to_string(),
                            "hybridcipher file encrypt --input data.csv --group group123 --output data.encrypted".to_string(),
                        ],
                    },
                    CliCommand {
                        name: "decrypt".to_string(),
                        description: "Decrypt an encrypted file".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "input".to_string(),
                                description: "Path to encrypted file".to_string(),
                                required: true,
                                arg_type: "path".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                            CliArgument {
                                name: "output".to_string(),
                                description: "Optional output path".to_string(),
                                required: false,
                                arg_type: "path".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher file decrypt --input document.encrypted".to_string(),
                        ],
                    },
                ],
                arguments: vec![],
                examples: vec![],
            },

            // Rekey operations
            CliCommand {
                name: "rekey".to_string(),
                description: "Two-phase rekey operations for membership changes".to_string(),
                subcommands: vec![
                    CliCommand {
                        name: "start".to_string(),
                        description: "Initiate a rekey operation".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "group".to_string(),
                                description: "Group ID to rekey".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                            CliArgument {
                                name: "reason".to_string(),
                                description: "Reason for rekey".to_string(),
                                required: false,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: Some(vec![
                                    "member-added".to_string(),
                                    "member-removed".to_string(),
                                    "security-refresh".to_string(),
                                ]),
                            },
                        ],
                        examples: vec![
                            "hybridcipher rekey start --group group123 --reason member-removed".to_string(),
                        ],
                    },
                    CliCommand {
                        name: "status".to_string(),
                        description: "Check rekey migration status".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "group".to_string(),
                                description: "Group ID".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher rekey status --group group123".to_string(),
                        ],
                    },
                    CliCommand {
                        name: "cutover".to_string(),
                        description: "Complete rekey cutover after migration threshold".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "group".to_string(),
                                description: "Group ID".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                            CliArgument {
                                name: "force".to_string(),
                                description: "Force cutover even if threshold not met".to_string(),
                                required: false,
                                arg_type: "bool".to_string(),
                                default_value: Some("false".to_string()),
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher rekey cutover --group group123".to_string(),
                        ],
                    },
                ],
                arguments: vec![],
                examples: vec![],
            },

            // Trust and transparency
            CliCommand {
                name: "trust".to_string(),
                description: "Server trust and transparency operations".to_string(),
                subcommands: vec![
                    CliCommand {
                        name: "verify".to_string(),
                        description: "Verify server identity with safety number".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "safety-number".to_string(),
                                description: "Safety number to verify".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher trust verify --safety-number \"1234 5678 9012 3456\"".to_string(),
                        ],
                    },
                    CliCommand {
                        name: "pin".to_string(),
                        description: "Pin server identity".to_string(),
                        subcommands: vec![],
                        arguments: vec![],
                        examples: vec![
                            "hybridcipher trust pin".to_string(),
                        ],
                    },
                ],
                arguments: vec![],
                examples: vec![],
            },

            // Audit commands
            CliCommand {
                name: "audit".to_string(),
                description: "Audit and diagnostic operations".to_string(),
                subcommands: vec![
                    CliCommand {
                        name: "devices".to_string(),
                        description: "Audit device access".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "stale".to_string(),
                                description: "Show only stale devices".to_string(),
                                required: false,
                                arg_type: "bool".to_string(),
                                default_value: Some("false".to_string()),
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher audit devices".to_string(),
                            "hybridcipher audit devices --stale".to_string(),
                        ],
                    },
                    CliCommand {
                        name: "coverage".to_string(),
                        description: "Check file migration coverage".to_string(),
                        subcommands: vec![],
                        arguments: vec![
                            CliArgument {
                                name: "group".to_string(),
                                description: "Group ID".to_string(),
                                required: true,
                                arg_type: "string".to_string(),
                                default_value: None,
                                possible_values: None,
                            },
                        ],
                        examples: vec![
                            "hybridcipher audit coverage --group group123".to_string(),
                        ],
                    },
                ],
                arguments: vec![],
                examples: vec![],
            },
        ]
    }

    /// Find a command by path
    fn find_command(commands: &[CliCommand], path: &[&str]) -> Option<CliCommand> {
        if path.is_empty() {
            return None;
        }

        for cmd in commands {
            if cmd.name == path[0] {
                if path.len() == 1 {
                    return Some(cmd.clone());
                } else {
                    return Self::find_command(&cmd.subcommands, &path[1..]);
                }
            }
        }

        None
    }
}

impl Default for CliSchemaManager {
    fn default() -> Self {
        Self::new()
    }
}
