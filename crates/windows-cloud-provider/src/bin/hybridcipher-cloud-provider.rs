use hybridcipher_windows_cloud_provider::{
    default_pipe_name, CloudProviderError, CloudProviderHost, CloudRootRegistration,
    ProviderHostConfig,
};
use std::{env, path::PathBuf};
use uuid::Uuid;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), CloudProviderError> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(CloudProviderError::InvalidCommand(usage()));
    };

    match command.as_str() {
        "serve" => {
            let mut user_config_dir: Option<PathBuf> = None;
            let mut pipe_name: Option<String> = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--user-config" => {
                        let value = args.next().ok_or_else(|| {
                            CloudProviderError::InvalidCommand(
                                "--user-config requires a path".to_string(),
                            )
                        })?;
                        user_config_dir = Some(PathBuf::from(value));
                    }
                    "--pipe-name" => {
                        let value = args.next().ok_or_else(|| {
                            CloudProviderError::InvalidCommand(
                                "--pipe-name requires a value".to_string(),
                            )
                        })?;
                        pipe_name = Some(value);
                    }
                    "--status-once" => {
                        let host = CloudProviderHost::new(ProviderHostConfig {
                            user_config_dir: user_config_dir.clone().unwrap_or_default(),
                            pipe_name: pipe_name.clone(),
                        });
                        println!("{}", serde_json::to_string_pretty(&host.status())?);
                        return Ok(());
                    }
                    other => {
                        return Err(CloudProviderError::InvalidCommand(format!(
                            "unknown argument: {other}\n{}",
                            usage()
                        )));
                    }
                }
            }

            let user_config_dir = user_config_dir.ok_or_else(|| {
                CloudProviderError::InvalidCommand("--user-config is required".to_string())
            })?;
            let pipe_name = pipe_name.unwrap_or_else(|| default_pipe_name().to_string());
            let host = CloudProviderHost::new(ProviderHostConfig {
                user_config_dir,
                pipe_name: Some(pipe_name),
            });
            println!("{}", serde_json::to_string_pretty(&host.status())?);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .map_err(CloudProviderError::Io)?;
            runtime.block_on(host.serve_ipc())
        }
        "status" => {
            let host = CloudProviderHost::new(ProviderHostConfig {
                user_config_dir: PathBuf::new(),
                pipe_name: None,
            });
            println!("{}", serde_json::to_string_pretty(&host.status())?);
            Ok(())
        }
        "register-root" => {
            let (user_config_dir, registration, sync_placeholders) =
                parse_root_command(args, true)?;
            let host = CloudProviderHost::new(ProviderHostConfig {
                user_config_dir,
                pipe_name: None,
            });
            host.register_root(&registration)?;
            if sync_placeholders {
                let summary = host.sync_placeholders(&registration)?;
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "root_id": registration.root_id,
                        "sync_root_path": registration.sync_root_path,
                        "registered": true,
                    }))?
                );
            }
            Ok(())
        }
        "sync-placeholders" => {
            let (user_config_dir, registration, _) = parse_root_command(args, false)?;
            let host = CloudProviderHost::new(ProviderHostConfig {
                user_config_dir,
                pipe_name: None,
            });
            let summary = host.sync_placeholders(&registration)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        "unregister-root" => {
            let (user_config_dir, sync_root_path) = parse_unregister_command(args)?;
            let host = CloudProviderHost::new(ProviderHostConfig {
                user_config_dir,
                pipe_name: None,
            });
            host.unregister_root_path(&sync_root_path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "sync_root_path": sync_root_path,
                    "registered": false,
                }))?
            );
            Ok(())
        }
        "dehydrate-root" => {
            let (user_config_dir, sync_root_path) = parse_unregister_command(args)?;
            let host = CloudProviderHost::new(ProviderHostConfig {
                user_config_dir,
                pipe_name: None,
            });
            let summary = host.dehydrate_root_path(&sync_root_path)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        _ => Err(CloudProviderError::InvalidCommand(usage())),
    }
}

fn usage() -> String {
    "usage: hybridcipher-cloud-provider serve --user-config <path> [--pipe-name <name>] [--status-once]\n       hybridcipher-cloud-provider status\n       hybridcipher-cloud-provider register-root --user-config <path> --root-id <uuid> --sync-root <path> --encrypted-root <path> [--display-name <name>] [--sync-placeholders]\n       hybridcipher-cloud-provider sync-placeholders [--user-config <path>] --root-id <uuid> --sync-root <path> --encrypted-root <path> [--display-name <name>]\n       hybridcipher-cloud-provider unregister-root [--user-config <path>] --sync-root <path>\n       hybridcipher-cloud-provider dehydrate-root [--user-config <path>] --sync-root <path>".to_string()
}

fn parse_root_command<I>(
    mut args: I,
    user_config_required: bool,
) -> Result<(PathBuf, CloudRootRegistration, bool), CloudProviderError>
where
    I: Iterator<Item = String>,
{
    let mut user_config_dir: Option<PathBuf> = None;
    let mut root_id: Option<Uuid> = None;
    let mut sync_root_path: Option<PathBuf> = None;
    let mut encrypted_root: Option<PathBuf> = None;
    let mut display_name: Option<String> = None;
    let mut sync_placeholders = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--user-config" => {
                user_config_dir = Some(PathBuf::from(required_value(&mut args, "--user-config")?));
            }
            "--root-id" => {
                root_id = Some(required_value(&mut args, "--root-id")?.parse()?);
            }
            "--sync-root" => {
                sync_root_path = Some(PathBuf::from(required_value(&mut args, "--sync-root")?));
            }
            "--encrypted-root" => {
                encrypted_root = Some(PathBuf::from(required_value(
                    &mut args,
                    "--encrypted-root",
                )?));
            }
            "--display-name" => {
                display_name = Some(required_value(&mut args, "--display-name")?);
            }
            "--sync-placeholders" => {
                sync_placeholders = true;
            }
            other => {
                return Err(CloudProviderError::InvalidCommand(format!(
                    "unknown argument: {other}\n{}",
                    usage()
                )));
            }
        }
    }

    let user_config_dir = match (user_config_dir, user_config_required) {
        (Some(path), _) => path,
        (None, true) => {
            return Err(CloudProviderError::InvalidCommand(
                "--user-config is required".to_string(),
            ));
        }
        (None, false) => PathBuf::new(),
    };

    let root_id = root_id
        .ok_or_else(|| CloudProviderError::InvalidCommand("--root-id is required".to_string()))?;
    let display_name = display_name.unwrap_or_else(|| {
        let short = root_id.to_string();
        format!("HybridCipher {}", &short[..8])
    });
    let registration = CloudRootRegistration {
        root_id,
        sync_root_path: sync_root_path.ok_or_else(|| {
            CloudProviderError::InvalidCommand("--sync-root is required".to_string())
        })?,
        encrypted_root: encrypted_root.ok_or_else(|| {
            CloudProviderError::InvalidCommand("--encrypted-root is required".to_string())
        })?,
        display_name,
    };

    Ok((user_config_dir, registration, sync_placeholders))
}

fn parse_unregister_command<I>(mut args: I) -> Result<(PathBuf, PathBuf), CloudProviderError>
where
    I: Iterator<Item = String>,
{
    let mut user_config_dir = PathBuf::new();
    let mut sync_root_path: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--user-config" => {
                user_config_dir = PathBuf::from(required_value(&mut args, "--user-config")?);
            }
            "--sync-root" => {
                sync_root_path = Some(PathBuf::from(required_value(&mut args, "--sync-root")?));
            }
            other => {
                return Err(CloudProviderError::InvalidCommand(format!(
                    "unknown argument: {other}\n{}",
                    usage()
                )));
            }
        }
    }

    let sync_root_path = sync_root_path
        .ok_or_else(|| CloudProviderError::InvalidCommand("--sync-root is required".to_string()))?;
    Ok((user_config_dir, sync_root_path))
}

fn required_value<I>(args: &mut I, flag: &str) -> Result<String, CloudProviderError>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| CloudProviderError::InvalidCommand(format!("{flag} requires a value")))
}
