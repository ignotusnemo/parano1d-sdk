// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Token,
    Collection,
    Nft,
}

impl Kind {
    fn dimension(self) -> u32 {
        if self == Self::Nft {
            2048
        } else {
            512
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub hash: String,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u8,
    pub kind: Kind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub image: Option<Image>,
}

fn safe_text(value: &str, bytes: usize, characters: usize, multiline: bool) -> bool {
    value.len() <= bytes
        && value.chars().count() <= characters
        && value.trim() == value
        && !value.chars().any(|c| {
            (c.is_control() && !(multiline && c == '\n'))
                || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        })
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn content_hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 || self.name.is_empty() || !safe_text(&self.name, 256, 64, false) {
            return Err("Enter a name of up to 64 characters.".into());
        }
        if !safe_text(&self.description, 4096, 1000, true) {
            return Err("Use up to 1,000 characters for the description.".into());
        }
        if self
            .website
            .as_deref()
            .is_some_and(|url| !valid_website(url))
        {
            return Err(
                "Enter a valid https:// project website without a username or password.".into(),
            );
        }
        if self.kind == Kind::Token {
            let symbol = self.symbol.as_deref().unwrap_or_default();
            if symbol.is_empty()
                || symbol.len() > 12
                || !symbol.as_bytes()[0].is_ascii_uppercase()
                || !symbol
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                || symbol == "NOID"
            {
                return Err("Use 1–12 uppercase letters or digits for the ticker, starting with a letter. NOID is reserved.".into());
            }
        } else if self.symbol.is_some() {
            return Err("Only fungible tokens have a ticker.".into());
        }
        if let Some(image) = &self.image {
            if !digest(&image.hash)
                || image.media_type != "image/png"
                || image.width == 0
                || image.height == 0
                || image.width > self.kind.dimension()
                || image.height > self.kind.dimension()
                || image.bytes == 0
                || image.bytes as usize > MAX_IMAGE_BYTES
            {
                return Err("The asset image has an unsupported format or size.".into());
            }
        } else if self.kind == Kind::Nft {
            return Err("Choose an image for this NFT.".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err("The asset description exceeds its size limit.".into());
        }
        Ok(bytes)
    }

    pub fn hash(&self) -> Result<String, String> {
        Ok(content_hash(
            b"Parano1d/native-metadata/v1\0",
            &self.canonical_bytes()?,
        ))
    }
}

pub fn valid_website(value: &str) -> bool {
    safe_text(value, 2048, 2048, false)
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.has_host()
                && url.username().is_empty()
                && url.password().is_none()
        })
}

pub fn checked_manifest(value: &serde_json::Value) -> Result<serde_json::Value, String> {
    let manifest: Manifest =
        serde_json::from_value(value.clone()).map_err(|_| "Invalid asset description")?;
    let hash = manifest.hash()?;
    Ok(
        serde_json::json!({"metadata_hash":hash,"manifest_hex":hex::encode(manifest.canonical_bytes()?),"manifest":manifest}),
    )
}

pub fn image_hash(bytes: &[u8]) -> String {
    content_hash(b"Parano1d/native-image/v1\0", bytes)
}
