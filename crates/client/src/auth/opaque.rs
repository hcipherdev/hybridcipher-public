use crate::audit::{audit_logger, AuditOutcome};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use opaque_ke::{
    key_exchange::tripledh::TripleDh, ClientLoginFinishParameters,
    ClientRegistrationFinishParameters, CredentialResponse,
};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginStartResult, ClientRegistration,
    ClientRegistrationStartResult, RegistrationResponse, Ristretto255,
};
use rand::rngs::OsRng;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Default cipher suite for OPAQUE operations using proper CipherSuite implementation
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = Ristretto255;
    type KeGroup = Ristretto255;
    type KeyExchange = TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

/// OPAQUE-PAKE Authentication Implementation for HybridCipher
///
/// Provides production-grade helpers for driving the OPAQUE handshake against
/// the HybridCipher server as well as legacy offline helpers used by older tests.
#[derive(Debug, Clone)]
pub struct OpaqueAuth {
    device_id: String,
    http_client: HttpClient,
}

/// Metadata the client supplies when initiating a login so the server can
/// register or update device state during `login_finish`.
#[derive(Debug, Clone)]
pub struct DeviceLoginMetadata {
    pub identity_public_key_hex: String,
    pub invitation_public_key_hex: String,
    pub device_display_name: Option<String>,
    pub mfa_code: Option<String>,
    pub backup_code: Option<String>,
}

/// Result of initiating a device recovery flow (password + MFA or email OTP).
pub struct DeviceRecoveryChallenge {
    login_id: Uuid,
    otp_required: bool,
    otp_expires_at: Option<DateTime<Utc>>,
    state: ClientLogin<DefaultCipherSuite>,
    credential_response: CredentialResponse<DefaultCipherSuite>,
}

impl DeviceRecoveryChallenge {
    pub fn login_id(&self) -> Uuid {
        self.login_id
    }

    pub fn otp_required(&self) -> bool {
        self.otp_required
    }

    pub fn otp_expires_at(&self) -> Option<DateTime<Utc>> {
        self.otp_expires_at
    }

    pub fn finalize(self, password: &str) -> Result<DeviceRecoveryFinalization, OpaqueError> {
        let finish = self
            .state
            .finish(
                password.as_bytes(),
                self.credential_response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|e| {
                OpaqueError::ProtocolError(format!("ClientLogin::finish failed: {e:?}"))
            })?;

        let mut session_key = [0u8; 32];
        let session_key_slice = finish.session_key.as_slice();
        session_key.copy_from_slice(&session_key_slice[..32]);

        let mut export_key = [0u8; 64];
        export_key.copy_from_slice(finish.export_key.as_slice());

        Ok(DeviceRecoveryFinalization {
            login_id: self.login_id,
            credential_finalization: general_purpose::STANDARD
                .encode(finish.message.serialize().to_vec()),
            session_key,
            export_key,
            server_public_key: finish.server_s_pk.serialize().to_vec(),
        })
    }
}

/// Prepared OPAQUE finalization for device recovery verification.
#[derive(Debug, Clone)]
pub struct DeviceRecoveryFinalization {
    pub login_id: Uuid,
    pub credential_finalization: String,
    pub session_key: [u8; 32],
    pub export_key: [u8; 64],
    pub server_public_key: Vec<u8>,
}

/// Device option returned after recovery verification.
#[derive(Debug, Clone)]
pub struct DeviceRecoveryDeviceOption {
    pub device_selector: String,
    pub masked_device_id: String,
    pub device_name: Option<String>,
    pub last_seen: DateTime<Utc>,
}

/// Verified device recovery session + device list.
#[derive(Debug, Clone)]
pub struct DeviceRecoveryVerified {
    pub recovery_session_id: Uuid,
    pub devices: Vec<DeviceRecoveryDeviceOption>,
    pub session_key: [u8; 32],
    pub export_key: [u8; 64],
    pub server_public_key: Vec<u8>,
}

impl OpaqueAuth {
    /// Create a new OPAQUE authentication instance
    pub fn new(device_id: String) -> Self {
        Self {
            device_id,
            http_client: HttpClient::new(),
        }
    }

    /// Get the device ID associated with this authenticator
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Execute the online OPAQUE registration flow against the HybridCipher server
    /// and return the registration upload payload to submit in the final register
    /// request.
    pub async fn register_with_server(
        &self,
        username: &str,
        email: &str,
        password: &str,
        server_url: &str,
    ) -> Result<OpaqueServerRegistration, OpaqueError> {
        if let Some(logger) = audit_logger() {
            let _ = logger.log_authentication(
                "opaque_register_start",
                Some(self.device_id.clone()),
                AuditOutcome::InProgress,
                None,
            );
        }

        let mut rng = OsRng;
        let ClientRegistrationStartResult { message, state } =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
                .map_err(|e| {
                    OpaqueError::ProtocolError(format!("ClientRegistration::start failed: {e:?}"))
                })?;

        let registration_request_bytes = message.serialize().to_vec();
        let request_body = RegisterStartRequestBody {
            username: username.to_string(),
            email: email.to_string(),
            registration_request: general_purpose::STANDARD.encode(registration_request_bytes),
        };

        let start_response = self
            .http_client
            .post(api_url(server_url, "/auth/register/start"))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| OpaqueError::NetworkError(e.to_string()))?;

        if !start_response.status().is_success() {
            let status = start_response.status();
            let body = start_response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            if let Some(logger) = audit_logger() {
                let _ = logger.log_authentication(
                    "opaque_register_start",
                    Some(self.device_id.clone()),
                    AuditOutcome::Failure {
                        error_code: status.as_str().to_string(),
                        error_message: body.clone(),
                    },
                    None,
                );
            }
            return Err(OpaqueError::RegistrationFailed(format!(
                "Server returned {} during registration start: {}",
                status,
                body.trim()
            )));
        }

        let start_body: RegisterStartResponseBody = start_response.json().await.map_err(|e| {
            OpaqueError::RegistrationFailed(format!(
                "Failed to parse registration start response: {}",
                e
            ))
        })?;

        let server_public_key_hint = general_purpose::STANDARD
            .decode(start_body.server_public_key.trim())
            .map_err(|e| {
                OpaqueError::RegistrationFailed(format!(
                    "Invalid server public key from registration start: {}",
                    e
                ))
            })?;

        let registration_response_bytes = general_purpose::STANDARD
            .decode(start_body.registration_response)
            .map_err(|e| {
                OpaqueError::RegistrationFailed(format!(
                    "Invalid registration response payload: {}",
                    e
                ))
            })?;

        let registration_response =
            RegistrationResponse::<DefaultCipherSuite>::deserialize(&registration_response_bytes)
                .map_err(|e| {
                OpaqueError::ProtocolError(format!(
                    "RegistrationResponse::deserialize failed: {e:?}"
                ))
            })?;

        let finish = state
            .finish(
                &mut rng,
                password.as_bytes(),
                registration_response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|e| {
                OpaqueError::ProtocolError(format!("ClientRegistration::finish failed: {e:?}"))
            })?;

        let registration_upload = finish.message.serialize().to_vec();
        let export_key_slice = finish.export_key.as_slice();
        let mut export_key = [0u8; 64]; // Update to match actual export key size
        export_key.copy_from_slice(export_key_slice);
        let server_public_key = finish.server_s_pk.serialize().to_vec();

        if server_public_key != server_public_key_hint {
            return Err(OpaqueError::RegistrationFailed(
                "Server public key mismatch detected during registration".to_string(),
            ));
        }

        if let Some(logger) = audit_logger() {
            let _ = logger.log_authentication(
                "opaque_register_complete",
                Some(self.device_id.clone()),
                AuditOutcome::Success,
                None,
            );
        }

        Ok(OpaqueServerRegistration {
            registration_upload,
            export_key,
            server_public_key,
        })
    }

    /// Execute the online OPAQUE login flow against the HybridCipher server and
    /// return the issued session tokens together with the derived session key.
    pub async fn login_with_server(
        &self,
        username_or_email: &str,
        password: &str,
        server_url: &str,
        device_metadata: DeviceLoginMetadata,
    ) -> Result<OpaqueServerLogin, OpaqueError> {
        if let Some(logger) = audit_logger() {
            let _ = logger.log_authentication(
                "opaque_login_start",
                Some(self.device_id.clone()),
                AuditOutcome::InProgress,
                None,
            );
        }

        let mut rng = OsRng;
        let ClientLoginStartResult { message, state } =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes()).map_err(
                |e| OpaqueError::ProtocolError(format!("ClientLogin::start failed: {e:?}")),
            )?;

        let credential_request = general_purpose::STANDARD.encode(message.serialize().to_vec());
        let start_request = LoginStartRequestBody {
            username_or_email: username_or_email.to_string(),
            device_id: self.device_id.clone(),
            credential_request,
            identity_public_key: device_metadata.identity_public_key_hex,
            invitation_public_key: device_metadata.invitation_public_key_hex,
            device_display_name: device_metadata.device_display_name,
        };

        let start_response = self
            .http_client
            .post(api_url(server_url, "/auth/login/start"))
            .json(&start_request)
            .send()
            .await
            .map_err(|e| OpaqueError::NetworkError(e.to_string()))?;

        if !start_response.status().is_success() {
            let (status, body) = read_error_response(start_response).await;
            if let Some(logger) = audit_logger() {
                let _ = logger.log_authentication(
                    "opaque_login_start",
                    Some(self.device_id.clone()),
                    AuditOutcome::Failure {
                        error_code: status.to_string(),
                        error_message: body.clone(),
                    },
                    None,
                );
            }
            if is_device_limit_error(&body) {
                return Err(OpaqueError::DeviceLimitReached(body));
            }
            if is_email_confirmation_error(status, &body) {
                return Err(OpaqueError::EmailConfirmationRequired(body));
            }
            if status == 429 {
                return Err(OpaqueError::RateLimited(body));
            }
            return Err(OpaqueError::LoginFailed(format!(
                "Login start rejected ({}): {}",
                status, body
            )));
        }

        let start_body: LoginStartResponseBody = start_response.json().await.map_err(|e| {
            OpaqueError::LoginFailed(format!("Failed to parse login start response: {}", e))
        })?;

        let credential_response_bytes = general_purpose::STANDARD
            .decode(start_body.credential_response)
            .map_err(|e| {
                OpaqueError::LoginFailed(format!("Invalid credential response payload: {}", e))
            })?;

        let credential_response =
            CredentialResponse::<DefaultCipherSuite>::deserialize(&credential_response_bytes)
                .map_err(|e| {
                    OpaqueError::ProtocolError(format!(
                        "CredentialResponse::deserialize failed: {e:?}"
                    ))
                })?;

        let finish = state
            .finish(
                password.as_bytes(),
                credential_response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|e| {
                OpaqueError::ProtocolError(format!("ClientLogin::finish failed: {e:?}"))
            })?;

        let server_public_key = finish.server_s_pk.serialize().to_vec();

        let finalization = general_purpose::STANDARD.encode(finish.message.serialize().to_vec());
        let finish_request = LoginFinishRequestBody {
            login_id: start_body.login_id,
            credential_finalization: finalization,
            mfa_code: device_metadata.mfa_code.clone(),
            backup_code: device_metadata.backup_code.clone(),
        };

        let finish_response = self
            .http_client
            .post(api_url(server_url, "/auth/login"))
            .json(&finish_request)
            .send()
            .await
            .map_err(|e| OpaqueError::NetworkError(e.to_string()))?;

        if !finish_response.status().is_success() {
            let (status, body) = read_error_response(finish_response).await;
            if let Some(logger) = audit_logger() {
                let _ = logger.log_authentication(
                    "opaque_login_finish",
                    Some(self.device_id.clone()),
                    AuditOutcome::Failure {
                        error_code: status.to_string(),
                        error_message: body.clone(),
                    },
                    None,
                );
            }
            if is_mfa_enrollment_error(status, &body) {
                return Err(OpaqueError::MfaEnrollmentRequired(body));
            }
            if is_mfa_required_error(status, &body) {
                return Err(OpaqueError::MfaRequired(body));
            }
            if status == 429 {
                return Err(OpaqueError::RateLimited(body));
            }
            return Err(OpaqueError::LoginFailed(format!(
                "Login finish rejected ({}): {}",
                status, body
            )));
        }

        let finish_body: LoginFinishResponseBody = finish_response.json().await.map_err(|e| {
            OpaqueError::LoginFailed(format!("Failed to parse login finish response: {}", e))
        })?;

        let mut session_key = [0u8; 32];
        // OPAQUE provides 64-byte session key, but we only need first 32 bytes
        let session_key_slice = finish.session_key.as_slice();
        session_key.copy_from_slice(&session_key_slice[..32]);

        let mut export_key = [0u8; 64]; // Update to match actual export key size
        export_key.copy_from_slice(finish.export_key.as_slice());

        if let Some(logger) = audit_logger() {
            let _ = logger.log_authentication(
                "opaque_login_success",
                Some(self.device_id.clone()),
                AuditOutcome::Success,
                None,
            );
        }

        Ok(OpaqueServerLogin {
            user_id: finish_body.user_id,
            username: finish_body.username,
            device_id: finish_body.device_id,
            access_token: finish_body.access_token,
            refresh_token: finish_body.refresh_token,
            expires_in: finish_body.expires_in,
            is_new_device: finish_body.is_new_device,
            device_status: finish_body.device_status,
            last_login: finish_body.last_login,
            session_key,
            export_key,
            server_public_key,
        })
    }

    /// Begin the device recovery flow (password + MFA or email OTP) for a new device.
    pub async fn device_recovery_start(
        &self,
        username_or_email: &str,
        password: &str,
        server_url: &str,
        device_metadata: DeviceLoginMetadata,
    ) -> Result<DeviceRecoveryChallenge, OpaqueError> {
        let mut rng = OsRng;
        let ClientLoginStartResult { message, state } =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes()).map_err(
                |e| OpaqueError::ProtocolError(format!("ClientLogin::start failed: {e:?}")),
            )?;

        let credential_request = general_purpose::STANDARD.encode(message.serialize().to_vec());
        let start_request = DeviceRecoveryStartRequestBody {
            username_or_email: username_or_email.to_string(),
            device_id: self.device_id.clone(),
            credential_request,
            identity_public_key: device_metadata.identity_public_key_hex,
            invitation_public_key: device_metadata.invitation_public_key_hex,
            device_display_name: device_metadata.device_display_name,
        };

        let start_response = self
            .http_client
            .post(api_url(server_url, "/auth/device-recovery/start"))
            .json(&start_request)
            .send()
            .await
            .map_err(|e| OpaqueError::NetworkError(e.to_string()))?;

        if !start_response.status().is_success() {
            let (status, body) = read_error_response(start_response).await;
            if is_email_confirmation_error(status, &body) {
                return Err(OpaqueError::EmailConfirmationRequired(body));
            }
            if status == 429 {
                return Err(OpaqueError::RateLimited(body));
            }
            return Err(OpaqueError::DeviceRecoveryFailed(format!(
                "Recovery start rejected ({}): {}",
                status, body
            )));
        }

        let start_body: DeviceRecoveryStartResponseBody =
            start_response.json().await.map_err(|e| {
                OpaqueError::DeviceRecoveryFailed(format!(
                    "Failed to parse recovery start response: {}",
                    e
                ))
            })?;

        let credential_response_bytes = general_purpose::STANDARD
            .decode(start_body.credential_response)
            .map_err(|e| {
                OpaqueError::DeviceRecoveryFailed(format!(
                    "Invalid credential response payload: {}",
                    e
                ))
            })?;
        let credential_response =
            CredentialResponse::<DefaultCipherSuite>::deserialize(&credential_response_bytes)
                .map_err(|e| {
                    OpaqueError::ProtocolError(format!(
                        "CredentialResponse::deserialize failed: {e:?}"
                    ))
                })?;

        Ok(DeviceRecoveryChallenge {
            login_id: start_body.login_id,
            otp_required: start_body.otp_required,
            otp_expires_at: start_body.otp_expires_at,
            state,
            credential_response,
        })
    }

    /// Verify recovery password/MFA or email OTP and return devices for eviction.
    pub async fn device_recovery_verify(
        &self,
        server_url: &str,
        otp_code: Option<String>,
        finalization: DeviceRecoveryFinalization,
        mfa_code: Option<String>,
        backup_code: Option<String>,
    ) -> Result<DeviceRecoveryVerified, OpaqueError> {
        let verify_request = DeviceRecoveryVerifyRequestBody {
            login_id: finalization.login_id,
            otp_code,
            credential_finalization: finalization.credential_finalization,
            mfa_code,
            backup_code,
        };

        let verify_response = self
            .http_client
            .post(api_url(server_url, "/auth/device-recovery/verify"))
            .json(&verify_request)
            .send()
            .await
            .map_err(|e| OpaqueError::NetworkError(e.to_string()))?;

        if !verify_response.status().is_success() {
            let (status, body) = read_error_response(verify_response).await;
            if is_mfa_enrollment_error(status, &body) {
                return Err(OpaqueError::MfaEnrollmentRequired(body));
            }
            if is_mfa_required_error(status, &body) {
                return Err(OpaqueError::MfaRequired(body));
            }
            if is_email_confirmation_error(status, &body) {
                return Err(OpaqueError::EmailConfirmationRequired(body));
            }
            if status == 429 {
                return Err(OpaqueError::RateLimited(body));
            }
            return Err(OpaqueError::DeviceRecoveryFailed(format!(
                "Recovery verification rejected ({}): {}",
                status, body
            )));
        }

        let verify_body: DeviceRecoveryVerifyResponseBody =
            verify_response.json().await.map_err(|e| {
                OpaqueError::DeviceRecoveryFailed(format!(
                    "Failed to parse recovery verification response: {}",
                    e
                ))
            })?;

        let devices = verify_body
            .devices
            .into_iter()
            .map(|device| DeviceRecoveryDeviceOption {
                device_selector: device.device_selector,
                masked_device_id: device.masked_device_id,
                device_name: device.device_name,
                last_seen: device.last_seen,
            })
            .collect();

        Ok(DeviceRecoveryVerified {
            recovery_session_id: verify_body.recovery_session_id,
            devices,
            session_key: finalization.session_key,
            export_key: finalization.export_key,
            server_public_key: finalization.server_public_key,
        })
    }

    /// Complete recovery by evicting a device and finalizing the login.
    pub async fn device_recovery_complete(
        &self,
        server_url: &str,
        recovery_session_id: Uuid,
        device_selector: &str,
        verified: DeviceRecoveryVerified,
        mfa_code: Option<String>,
        backup_code: Option<String>,
    ) -> Result<OpaqueServerLogin, OpaqueError> {
        let complete_request = DeviceRecoveryCompleteRequestBody {
            recovery_session_id,
            device_selector: device_selector.to_string(),
            mfa_code,
            backup_code,
        };

        let complete_response = self
            .http_client
            .post(api_url(server_url, "/auth/device-recovery/complete"))
            .json(&complete_request)
            .send()
            .await
            .map_err(|e| OpaqueError::NetworkError(e.to_string()))?;

        if !complete_response.status().is_success() {
            let (status, body) = read_error_response(complete_response).await;
            if is_mfa_enrollment_error(status, &body) {
                return Err(OpaqueError::MfaEnrollmentRequired(body));
            }
            if is_mfa_required_error(status, &body) {
                return Err(OpaqueError::MfaRequired(body));
            }
            if is_email_confirmation_error(status, &body) {
                return Err(OpaqueError::EmailConfirmationRequired(body));
            }
            if status == 429 {
                return Err(OpaqueError::RateLimited(body));
            }
            return Err(OpaqueError::DeviceRecoveryFailed(format!(
                "Recovery completion rejected ({}): {}",
                status, body
            )));
        }

        let complete_body: DeviceRecoveryCompleteResponseBody =
            complete_response.json().await.map_err(|e| {
                OpaqueError::DeviceRecoveryFailed(format!(
                    "Failed to parse recovery completion response: {}",
                    e
                ))
            })?;

        Ok(OpaqueServerLogin {
            user_id: complete_body.user_id,
            username: complete_body.username,
            device_id: complete_body.device_id,
            access_token: complete_body.access_token,
            refresh_token: complete_body.refresh_token,
            expires_in: complete_body.expires_in,
            is_new_device: complete_body.is_new_device,
            device_status: Some(complete_body.device_status),
            last_login: Some(complete_body.last_login),
            session_key: verified.session_key,
            export_key: verified.export_key,
            server_public_key: verified.server_public_key,
        })
    }

    /// Legacy offline helper retained for compatibility with older tests.
    /// Returns a synthetic registration record without contacting the server.
    pub async fn register(&self, password: &str) -> Result<Vec<u8>, OpaqueError> {
        if let Some(logger) = audit_logger() {
            let _ = logger.log_authentication(
                "opaque_register",
                Some(self.device_id.clone()),
                AuditOutcome::InProgress,
                None,
            );
        }

        let mut rng = OsRng;
        let _ = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|e| {
                OpaqueError::ProtocolError(format!("ClientRegistration::start failed: {e:?}"))
            })?;

        let record = format!(
            "opaque_registration_record_{}_{}",
            self.device_id,
            password.len()
        );
        Ok(record.into_bytes())
    }

    /// Legacy offline helper retained for compatibility with older tests. The
    /// simulated registration record must have been produced by `register`.
    pub async fn login(
        &self,
        password: &str,
        registration_record: &[u8],
    ) -> Result<OpaqueLoginResult, OpaqueError> {
        if let Some(logger) = audit_logger() {
            let _ = logger.log_authentication(
                "opaque_login_attempt",
                Some(self.device_id.clone()),
                AuditOutcome::InProgress,
                None,
            );
        }

        let mut rng = OsRng;
        let _ = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|e| OpaqueError::ProtocolError(format!("ClientLogin::start failed: {e:?}")))?;

        let record_str = String::from_utf8_lossy(registration_record);
        let expected_record = format!(
            "opaque_registration_record_{}_{}",
            self.device_id,
            password.len()
        );

        let success = record_str == expected_record;
        let session_key = if success { Some([0x42; 32]) } else { None };

        if let Some(logger) = audit_logger() {
            let _ = logger.log_authentication(
                if success {
                    "opaque_login_success"
                } else {
                    "opaque_login_failure"
                },
                Some(self.device_id.clone()),
                if success {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Failure {
                        error_code: "authentication_failed".to_string(),
                        error_message: "Password verification failed".to_string(),
                    }
                },
                None,
            );
        }

        Ok(OpaqueLoginResult {
            success,
            session_key,
            error: if success {
                None
            } else {
                Some("Authentication failed".to_string())
            },
        })
    }
}

/// Registration payload returned by `register_with_server`.
#[derive(Debug, Clone)]
pub struct OpaqueServerRegistration {
    pub registration_upload: Vec<u8>,
    pub export_key: [u8; 64],
    pub server_public_key: Vec<u8>,
}

/// Login payload returned by `login_with_server`.
#[derive(Debug, Clone)]
pub struct OpaqueServerLogin {
    pub user_id: Uuid,
    pub username: String,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub is_new_device: bool,
    pub device_status: Option<String>,
    pub last_login: Option<DateTime<Utc>>,
    pub session_key: [u8; 32],
    pub export_key: [u8; 64],
    pub server_public_key: Vec<u8>,
}

/// Legacy login result retained for older tests.
#[derive(Debug, Clone)]
pub struct OpaqueLoginResult {
    pub success: bool,
    pub session_key: Option<[u8; 32]>,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum OpaqueError {
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),
    #[error("Login failed: {0}")]
    LoginFailed(String),
    #[error("Device limit reached: {0}")]
    DeviceLimitReached(String),
    #[error("Email confirmation required: {0}")]
    EmailConfirmationRequired(String),
    #[error("Rate limited: {0}")]
    RateLimited(String),
    #[error("Device recovery failed: {0}")]
    DeviceRecoveryFailed(String),
    #[error("MFA required: {0}")]
    MfaRequired(String),
    #[error("MFA enrollment required: {0}")]
    MfaEnrollmentRequired(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

#[derive(Serialize)]
struct RegisterStartRequestBody {
    username: String,
    email: String,
    registration_request: String,
}

#[derive(Deserialize)]
struct RegisterStartResponseBody {
    registration_response: String,
    server_public_key: String,
}

#[derive(Serialize)]
struct LoginStartRequestBody {
    username_or_email: String,
    device_id: String,
    credential_request: String,
    identity_public_key: String,
    invitation_public_key: String,
    device_display_name: Option<String>,
}

#[derive(Deserialize)]
struct LoginStartResponseBody {
    login_id: Uuid,
    #[serde(rename = "user_id")]
    _user_id: Uuid,
    #[serde(rename = "is_new_device")]
    _is_new_device: bool,
    #[serde(rename = "mfa_required", default)]
    _mfa_required: bool,
    #[serde(rename = "mfa_enrolled", default)]
    _mfa_enrolled: bool,
    credential_response: String,
}

#[derive(Serialize)]
struct LoginFinishRequestBody {
    login_id: Uuid,
    credential_finalization: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mfa_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_code: Option<String>,
}

#[derive(Deserialize)]
struct LoginFinishResponseBody {
    user_id: Uuid,
    username: String,
    device_id: String,
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    #[serde(default)]
    last_login: Option<DateTime<Utc>>,
    is_new_device: bool,
    #[serde(default)]
    device_status: Option<String>,
}

#[derive(Serialize)]
struct DeviceRecoveryStartRequestBody {
    username_or_email: String,
    device_id: String,
    credential_request: String,
    identity_public_key: String,
    invitation_public_key: String,
    device_display_name: Option<String>,
}

#[derive(Deserialize)]
struct DeviceRecoveryStartResponseBody {
    login_id: Uuid,
    credential_response: String,
    #[serde(default)]
    otp_required: bool,
    #[serde(default, with = "chrono::serde::ts_seconds_option")]
    otp_expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct DeviceRecoveryVerifyRequestBody {
    login_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    otp_code: Option<String>,
    credential_finalization: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mfa_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_code: Option<String>,
}

#[derive(Deserialize)]
struct DeviceRecoveryDeviceOptionResponse {
    device_selector: String,
    masked_device_id: String,
    device_name: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_seen: DateTime<Utc>,
}

#[derive(Deserialize)]
struct DeviceRecoveryVerifyResponseBody {
    recovery_session_id: Uuid,
    devices: Vec<DeviceRecoveryDeviceOptionResponse>,
}

#[derive(Serialize)]
struct DeviceRecoveryCompleteRequestBody {
    recovery_session_id: Uuid,
    device_selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mfa_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_code: Option<String>,
}

#[derive(Deserialize)]
struct DeviceRecoveryCompleteResponseBody {
    user_id: Uuid,
    username: String,
    device_id: String,
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    last_login: DateTime<Utc>,
    is_new_device: bool,
    device_status: String,
}

#[derive(Deserialize)]
struct ErrorResponseBody {
    error: String,
    status: u16,
}

fn api_url(base: &str, path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    // Check if base already contains /api/v1 to avoid duplication
    if trimmed.ends_with("/api/v1") {
        format!("{}{}", trimmed, path)
    } else {
        format!("{}/api/v1{}", trimmed, path)
    }
}

fn is_device_limit_error(message: &str) -> bool {
    message.to_lowercase().contains("device limit")
}

fn is_mfa_required_error(status: u16, message: &str) -> bool {
    status == 401
        && message.to_lowercase().contains("mfa")
        && message.to_lowercase().contains("required")
}

fn is_mfa_enrollment_error(status: u16, message: &str) -> bool {
    status == 403
        && message.to_lowercase().contains("mfa")
        && message.to_lowercase().contains("enrollment")
}

fn is_email_confirmation_error(status: u16, message: &str) -> bool {
    status == 403 && message.to_lowercase().contains("confirmation")
}

async fn read_error_response(response: reqwest::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<no body>".to_string());
    if let Ok(parsed) = serde_json::from_str::<ErrorResponseBody>(&body) {
        let status = if parsed.status == 0 {
            status
        } else {
            parsed.status
        };
        return (status, parsed.error.trim().to_string());
    }
    (status, body.trim().to_string())
}
