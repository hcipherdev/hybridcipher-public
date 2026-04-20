use super::DeviceSubcommand;
use crate::{
    commands::auth,
    error::CliError,
    session::{RegisteredDevice, SessionManager},
    ui,
    ui::formatting::{format_table, format_timestamp},
};

const DEFAULT_DEVICE_DISPLAY: &str = "-";

pub async fn handle_devices_command(
    action: Option<DeviceSubcommand>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    match action {
        Some(DeviceSubcommand::Remove { device_id }) => {
            auth::handle_remove_device(Some(device_id), session_manager).await
        }
        Some(DeviceSubcommand::List) | None => display_registered_devices(session_manager).await,
    }
}

async fn display_registered_devices(session_manager: &SessionManager) -> Result<(), CliError> {
    ui::section("Registered Devices");

    let listing = session_manager.fetch_registered_devices().await?;

    if listing.devices.is_empty() {
        ui::info("No devices are currently registered for this account.");
        ui::info("Log in from a device to register it, or use 'hybridcipher login <email>'.");
        return Ok(());
    }

    let headers = ["Device ID", "Name", "Added", "Last Seen", "Current"];
    let mut rows = Vec::with_capacity(listing.devices.len());

    for device in &listing.devices {
        rows.push(device_to_row(device));
    }

    let table = format_table(&headers, &rows);
    println!("{}", table);

    if listing.remaining_slots == 0 {
        ui::warning(&format!(
            "All {} device slots are in use. Remove an old device before registering a new one.",
            listing.max_devices
        ));
    } else {
        ui::info(&format!(
            "{} of {} device slots in use ({} available).",
            listing.total_devices, listing.max_devices, listing.remaining_slots
        ));
    }

    ui::dim("To remove a device, run 'hybridcipher devices remove <device_id>'.");
    Ok(())
}

fn device_to_row(device: &RegisteredDevice) -> Vec<String> {
    let display_id = if device.is_current_device {
        format!("{} (current)", device.device_id)
    } else {
        device.device_id.clone()
    };

    let name = device
        .device_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_DEVICE_DISPLAY)
        .to_string();

    let added = format_datetime(&device.created_at);
    let last_seen = format_datetime(&device.last_seen);
    let current = if device.is_current_device {
        "Yes".to_string()
    } else {
        String::new()
    };

    vec![display_id, name, added, last_seen, current]
}

fn format_datetime(value: &chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{} ({})",
        ui::formatting::format_local_datetime(value),
        format_timestamp(value)
    )
}
