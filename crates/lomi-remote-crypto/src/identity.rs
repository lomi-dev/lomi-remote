use crate::{
    random,
    wire::{self, Id},
    Result, Role,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    kem::{Kem, X25519HkdfSha256},
    Serializable,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicBundle {
    pub version: u32,
    pub account_id: Id,
    pub subject_id: Id,
    pub role: Role,
    pub key_version: u32,
    pub identity_key: [u8; 32],
    pub channel_key: [u8; 32],
    pub mailbox_key: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedBundle {
    pub bundle: PublicBundle,
    pub signature: Vec<u8>,
}
impl PublicBundle {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        if self.version != 1 || self.key_version == 0 {
            return Err("unsupported bundle version".into());
        }
        let mut e = wire::encoder();
        wire::domain(&mut e, 10, "public-bundle");
        wire::number(&mut e, u64::from(self.version));
        wire::bytes(&mut e, &self.account_id);
        wire::bytes(&mut e, &self.subject_id);
        wire::number(&mut e, self.role.code());
        wire::number(&mut e, u64::from(self.key_version));
        wire::bytes(&mut e, &self.identity_key);
        wire::bytes(&mut e, &self.channel_key);
        wire::bytes(&mut e, &self.mailbox_key);
        Ok(e.into_writer())
    }
    pub fn fingerprint(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.canonical()?).into())
    }
}
impl SignedBundle {
    pub fn verify(&self, pinned_fingerprint: &[u8; 32]) -> Result<()> {
        if self.bundle.fingerprint()? != *pinned_fingerprint {
            return Err("pinned bundle mismatch".into());
        }
        verify_signature(
            &self.bundle.identity_key,
            &self.bundle.canonical()?,
            &self.signature,
        )
    }
}
pub(crate) fn verify_signature(key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| "invalid signing key")?;
    let signature = Signature::from_slice(signature).map_err(|_| "invalid signature length")?;
    key.verify_strict(message, &signature)
        .map_err(|_| "invalid signature".into())
}
pub struct Identity {
    pub(crate) signing: SigningKey,
    seeds: Zeroizing<[u8; 96]>,
    pub(crate) disposed: bool,
    pub(crate) channel_secret: Zeroizing<[u8; 32]>,
    pub(crate) mailbox_secret: Zeroizing<Vec<u8>>,
    pub(crate) signed: SignedBundle,
    pub(crate) seen: std::collections::BTreeMap<(Id, Id), u64>,
    pub(crate) last_now: u64,
}
impl Identity {
    pub fn generate(account_id: Id, subject_id: Id, role: Role, key_version: u32) -> Result<Self> {
        Self::from_seeds(
            account_id,
            subject_id,
            role,
            key_version,
            Zeroizing::new(random()?),
            Zeroizing::new(random()?),
            Zeroizing::new(random()?),
        )
    }
    fn from_seeds(
        account_id: Id,
        subject_id: Id,
        role: Role,
        key_version: u32,
        identity_seed: Zeroizing<[u8; 32]>,
        channel_seed: Zeroizing<[u8; 32]>,
        mailbox_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let mut seeds = Zeroizing::new([0u8; 96]);
        seeds[..32].copy_from_slice(&*identity_seed);
        seeds[32..64].copy_from_slice(&*channel_seed);
        seeds[64..].copy_from_slice(&*mailbox_seed);
        use snow::resolvers::{CryptoResolver, DefaultResolver};
        let mut dh = DefaultResolver
            .resolve_dh(&snow::params::DHChoice::Curve25519)
            .ok_or("DH unavailable")?;
        dh.set(channel_seed.as_ref());
        let channel_key = dh.pubkey().try_into().map_err(|_| "DH key length")?;
        let (mailbox_private, mailbox_public) =
            X25519HkdfSha256::derive_keypair(mailbox_seed.as_ref());
        let signing = SigningKey::from_bytes(&identity_seed);
        let bundle = PublicBundle {
            version: 1,
            account_id,
            subject_id,
            role,
            key_version,
            identity_key: signing.verifying_key().to_bytes(),
            channel_key,
            mailbox_key: mailbox_public
                .to_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| "HPKE key length")?,
        };
        let signature = signing.sign(&bundle.canonical()?).to_bytes().to_vec();
        Ok(Self {
            signing,
            seeds,
            disposed: false,
            channel_secret: channel_seed,
            mailbox_secret: Zeroizing::new(mailbox_private.to_bytes().to_vec()),
            signed: SignedBundle { bundle, signature },
            seen: std::collections::BTreeMap::new(),
            last_now: 0,
        })
    }
    pub fn public_bundle(&self) -> SignedBundle {
        self.signed.clone()
    }

}

impl Identity {
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.channel_secret.zeroize();
        self.mailbox_secret.zeroize();
        self.seeds.zeroize();
        // Replacing drops Dalek's old expanded secret with its zeroize feature.
        self.signing = SigningKey::from_bytes(&[0; 32]);
    }
    pub fn export_secret_seed_blob(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.disposed {
            return Err("identity disposed".into());
        }
        let mut blob = Zeroizing::new(Vec::with_capacity(97));
        blob.push(1);
        blob.extend_from_slice(&*self.seeds);
        Ok(blob)
    }
    // Restricted native pending-host import; reuse the historical key derivation.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn pending_host_from_seed_blob(
        blob: &[u8],
        host_id: Id,
        key_version: u32,
    ) -> Result<Self> {
        if blob.len() != 97 || blob[0] != 1 || host_id == [0; 16] || key_version == 0 {
            return Err("invalid pending host seed blob".into());
        }
        Self::from_seeds(
            [0; 16],
            host_id,
            Role::Host,
            key_version,
            Zeroizing::new(blob[1..33].try_into().map_err(|_| "seed length")?),
            Zeroizing::new(blob[33..65].try_into().map_err(|_| "seed length")?),
            Zeroizing::new(blob[65..97].try_into().map_err(|_| "seed length")?),
        )
    }
    pub fn import_secret_seed_blob(blob: &[u8], expected: &SignedBundle) -> Result<Self> {
        if blob.len() != 97 || blob[0] != 1 {
            return Err("invalid identity seed blob".into());
        }
        expected.verify(&expected.bundle.fingerprint()?)?;
        let b = &expected.bundle;
        let identity = Self::from_seeds(
            b.account_id,
            b.subject_id,
            b.role,
            b.key_version,
            Zeroizing::new(blob[1..33].try_into().map_err(|_| "seed length")?),
            Zeroizing::new(blob[33..65].try_into().map_err(|_| "seed length")?),
            Zeroizing::new(blob[65..97].try_into().map_err(|_| "seed length")?),
        )?;
        if identity.signed != *expected {
            return Err("persisted identity bundle mismatch".into());
        }
        Ok(identity)
    }
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.dispose();
    }
}
