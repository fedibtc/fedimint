use semver::{BuildMetadata, Version};

/// Get the  cargo package version of `fedimint-core`
pub fn cargo_pkg() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A validated Fedimint version used to derive DKG compatibility.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DkgVersion {
    /// The complete semantic version supplied by the running binary.
    version: Version,
}

/// The semantic identity used in the consensus-config checksum during DKG.
///
/// Guardians are compatible when their major and minor versions match and
/// their optional vendor identities are exactly equal. Patch and prerelease
/// components do not affect compatibility.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DkgVersionCompatibility {
    /// The Fedimint major version.
    major: u64,
    /// The Fedimint minor version.
    minor: u64,
    /// The exact optional vendor identity.
    vendor: Option<BuildMetadata>,
}

impl DkgVersion {
    /// Parse a semantic Fedimint version.
    pub fn parse(version: &str) -> Result<Self, semver::Error> {
        Ok(Self {
            version: Version::parse(version)?,
        })
    }

    /// Project this version to the identity that must match during DKG.
    pub fn compatibility_version(&self) -> DkgVersionCompatibility {
        DkgVersionCompatibility {
            major: self.version.major,
            minor: self.version.minor,
            vendor: (!self.version.build.is_empty()).then(|| self.version.build.clone()),
        }
    }
}

impl std::fmt::Display for DkgVersionCompatibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if let Some(vendor) = &self.vendor {
            write!(f, "+{vendor}")?;
        }
        Ok(())
    }
}

/// Get the git hash version of `fedimint-core`
///
/// Note, in certain situations this not be accurate (eg. might be all `0`s).
///
/// The return value was injected via `fedimint-build` crate at the compile
/// time.
pub fn git_hash() -> &'static str {
    option_env!("FEDIMINT_BUILD_CODE_VERSION").unwrap_or("0000000000000000000000000000000000000001")
}

#[cfg(test)]
mod tests;
