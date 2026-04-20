use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const CURRENT_LEGAL_VERSION: &str = "2026-04-05";
pub const LEGAL_UPDATED_AT: &str = "2026-04-05";
const SUPPORT_EMAIL: &str = "support@hybridcipher.com";
const REQUIRED_DOCUMENTS: [(&str, &str, &str); 2] = [
    ("terms", "Terms of Service", "TERMS.md"),
    ("privacy", "Privacy Notice", "PRIVACY.md"),
];
const OPTIONAL_DOCUMENTS: [(&str, &str, &str); 1] = [(
    "third-party-notices",
    "Third-Party Notices",
    "THIRD_PARTY_NOTICES.md",
)];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegalDocument {
    pub id: String,
    pub title: String,
    pub filename: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegalDocumentsPayload {
    pub version: String,
    pub updated_at: String,
    pub support_email: String,
    pub required_acceptance: bool,
    pub documents: Vec<LegalDocument>,
}

pub fn legal_docs_fallback_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("legal")
}

fn read_document(
    base_dir: &Path,
    id: &str,
    title: &str,
    filename: &str,
    required: bool,
) -> Result<Option<LegalDocument>, String> {
    let path = base_dir.join(filename);
    if !path.exists() {
        if required {
            return Err(format!(
                "Missing required legal document: {}",
                path.display()
            ));
        }
        return Ok(None);
    }

    let content = fs::read_to_string(&path).map_err(|error| {
        format!(
            "Failed to read legal document {}: {}",
            path.display(),
            error
        )
    })?;

    Ok(Some(LegalDocument {
        id: id.to_string(),
        title: title.to_string(),
        filename: filename.to_string(),
        content,
    }))
}

pub fn load_legal_documents_from_dir(base_dir: &Path) -> Result<LegalDocumentsPayload, String> {
    let mut documents = Vec::new();

    for (id, title, filename) in REQUIRED_DOCUMENTS {
        let document = read_document(base_dir, id, title, filename, true)?;
        if let Some(document) = document {
            documents.push(document);
        }
    }

    for (id, title, filename) in OPTIONAL_DOCUMENTS {
        if let Some(document) = read_document(base_dir, id, title, filename, false)? {
            documents.push(document);
        }
    }

    Ok(LegalDocumentsPayload {
        version: CURRENT_LEGAL_VERSION.to_string(),
        updated_at: LEGAL_UPDATED_AT.to_string(),
        support_email: SUPPORT_EMAIL.to_string(),
        required_acceptance: true,
        documents,
    })
}

pub fn load_legal_documents(resource_dir: Option<&Path>) -> Result<LegalDocumentsPayload, String> {
    if let Some(resource_dir) = resource_dir {
        let bundled_dir = resource_dir.join("legal");
        if bundled_dir.exists() {
            return load_legal_documents_from_dir(&bundled_dir);
        }
    }

    let fallback_dir = legal_docs_fallback_dir();
    load_legal_documents_from_dir(&fallback_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn loads_required_documents_and_skips_missing_optional_files() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(
            temp_dir.path().join("TERMS.md"),
            "# Terms\n\nThese are the terms.",
        )
        .expect("write terms");
        fs::write(
            temp_dir.path().join("PRIVACY.md"),
            "# Privacy\n\nThese are the privacy terms.",
        )
        .expect("write privacy");

        let payload = load_legal_documents_from_dir(temp_dir.path()).expect("load payload");

        assert_eq!(payload.version, CURRENT_LEGAL_VERSION);
        assert_eq!(payload.updated_at, LEGAL_UPDATED_AT);
        assert!(payload.required_acceptance);
        assert_eq!(payload.documents.len(), 2);
        assert_eq!(payload.documents[0].id, "terms");
        assert_eq!(payload.documents[1].id, "privacy");
    }

    #[test]
    fn returns_error_when_required_document_is_missing() {
        let temp_dir = tempdir().expect("temp dir");
        fs::write(temp_dir.path().join("TERMS.md"), "# Terms").expect("write terms");

        let error = load_legal_documents_from_dir(temp_dir.path()).expect_err("missing privacy");

        assert!(error.contains("PRIVACY.md"));
    }
}
