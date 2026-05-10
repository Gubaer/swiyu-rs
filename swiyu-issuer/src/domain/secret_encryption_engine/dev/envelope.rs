use super::super::SecretEncryptionError;

pub(super) const FORMAT: u8 = 0x01;
pub(super) const NONCE_LEN: usize = 12;
pub(super) const MAX_KEY_NAME_LEN: usize = 255;

// Parsed view of a Dev-backend ciphertext blob. The blob is self-describing:
// callers persist a single `BYTEA` column and pass it back unchanged on
// decrypt — the format tag, `key_name`, and `key_version` travel inside.
//
// Format `0x01` layout:
//
//   1 byte    format tag (0x01)
//   1 byte    key_name length N (≤ 255)
//   N bytes   key_name (UTF-8)
//   4 bytes   key_version (big-endian u32)
//   12 bytes  nonce
//   …rest     AES-256-GCM ciphertext + 16-byte tag
//
// `decode` borrows directly from the source buffer (zero-copy); `encode`
// serializes back to the same shape.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Envelope<'a> {
    // Mixed into HKDF `info` at encrypt time and checked on decrypt against
    // the caller's `key_name` argument; a mismatch surfaces as
    // `KeyNameMismatch`.
    pub key_name: &'a str,
    // Dev backend always emits `1`; any other value surfaces as
    // `KeyVersionNotFound` so a future master-key rotation has an observable
    // signal at decrypt time.
    pub key_version: u32,
    pub nonce: &'a [u8; NONCE_LEN],
    // Ciphertext concatenated with the 16-byte authentication tag — the
    // single buffer the `aes-gcm` crate emits and consumes.
    pub ct_and_tag: &'a [u8],
}

impl<'a> Envelope<'a> {
    pub(super) fn encode(&self) -> Result<Vec<u8>, SecretEncryptionError> {
        let key_name_bytes = self.key_name.as_bytes();
        if key_name_bytes.len() > MAX_KEY_NAME_LEN {
            return Err(SecretEncryptionError::Backend(
                format!(
                    "key_name exceeds 255-byte envelope bound: {} bytes",
                    key_name_bytes.len()
                )
                .into(),
            ));
        }
        let mut out = Vec::with_capacity(
            1 + 1 + key_name_bytes.len() + 4 + NONCE_LEN + self.ct_and_tag.len(),
        );
        out.push(FORMAT);
        out.push(key_name_bytes.len() as u8);
        out.extend_from_slice(key_name_bytes);
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.extend_from_slice(self.nonce);
        out.extend_from_slice(self.ct_and_tag);
        Ok(out)
    }

    pub(super) fn decode(bytes: &'a [u8]) -> Result<Self, SecretEncryptionError> {
        if bytes.len() < 2 {
            return Err(SecretEncryptionError::MalformedCiphertext);
        }
        if bytes[0] != FORMAT {
            return Err(SecretEncryptionError::MalformedCiphertext);
        }
        let key_name_len = bytes[1] as usize;
        let header_end = 2 + key_name_len + 4 + NONCE_LEN;
        if bytes.len() < header_end {
            return Err(SecretEncryptionError::MalformedCiphertext);
        }
        let key_name = std::str::from_utf8(&bytes[2..2 + key_name_len])
            .map_err(|_| SecretEncryptionError::MalformedCiphertext)?;
        let key_version_bytes: [u8; 4] = bytes[2 + key_name_len..2 + key_name_len + 4]
            .try_into()
            .map_err(|_| SecretEncryptionError::MalformedCiphertext)?;
        let key_version = u32::from_be_bytes(key_version_bytes);
        let nonce_start = 2 + key_name_len + 4;
        let nonce: &[u8; NONCE_LEN] = bytes[nonce_start..nonce_start + NONCE_LEN]
            .try_into()
            .map_err(|_| SecretEncryptionError::MalformedCiphertext)?;
        let ct_and_tag = &bytes[nonce_start + NONCE_LEN..];
        Ok(Envelope {
            key_name,
            key_version,
            nonce,
            ct_and_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_envelope() {
        let nonce = [0xa5_u8; NONCE_LEN];
        let payload = [0x33_u8, 0x44, 0x55, 0x66];
        let env_in = Envelope {
            key_name: "tenant/abc/oauth2_refresh_token",
            key_version: 1,
            nonce: &nonce,
            ct_and_tag: &payload,
        };
        let bytes = env_in.encode().unwrap();
        let env = Envelope::decode(&bytes).unwrap();
        assert_eq!(env.key_name, "tenant/abc/oauth2_refresh_token");
        assert_eq!(env.key_version, 1);
        assert_eq!(env.nonce, &nonce);
        assert_eq!(env.ct_and_tag, &payload);
    }

    #[test]
    fn rejects_unknown_format_byte() {
        let env = Envelope {
            key_name: "k",
            key_version: 1,
            nonce: &[0u8; NONCE_LEN],
            ct_and_tag: &[],
        };
        let mut bytes = env.encode().unwrap();
        bytes[0] = 0x02;
        let err = Envelope::decode(&bytes).unwrap_err();
        assert!(matches!(err, SecretEncryptionError::MalformedCiphertext));
    }

    #[test]
    fn rejects_buffer_smaller_than_preamble() {
        let err = Envelope::decode(&[FORMAT]).unwrap_err();
        assert!(matches!(err, SecretEncryptionError::MalformedCiphertext));
    }

    #[test]
    fn rejects_oversized_key_name_length_in_header() {
        // Header announces a 255-byte key name but the buffer is far shorter.
        let bytes = vec![FORMAT, 0xff, 0x00];
        let err = Envelope::decode(&bytes).unwrap_err();
        assert!(matches!(err, SecretEncryptionError::MalformedCiphertext));
    }

    #[test]
    fn rejects_oversized_key_name_at_encode() {
        let too_long = "a".repeat(MAX_KEY_NAME_LEN + 1);
        let env = Envelope {
            key_name: &too_long,
            key_version: 1,
            nonce: &[0u8; NONCE_LEN],
            ct_and_tag: &[],
        };
        let err = env.encode().unwrap_err();
        // Internal invariant violation maps to Backend rather than to a public error.
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    #[test]
    fn rejects_invalid_utf8_key_name() {
        // Hand-craft a bad envelope: replace the first byte of key_name with
        // an invalid UTF-8 leading byte.
        let env = Envelope {
            key_name: "abc",
            key_version: 1,
            nonce: &[0u8; NONCE_LEN],
            ct_and_tag: &[],
        };
        let mut bytes = env.encode().unwrap();
        bytes[2] = 0xff;
        let err = Envelope::decode(&bytes).unwrap_err();
        assert!(matches!(err, SecretEncryptionError::MalformedCiphertext));
    }
}
