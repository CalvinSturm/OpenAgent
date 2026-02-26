pub(crate) fn provider_name(provider: crate::gate::ProviderKind) -> &'static str {
    match provider {
        crate::gate::ProviderKind::Lmstudio => "lmstudio",
        crate::gate::ProviderKind::Llamacpp => "llamacpp",
        crate::gate::ProviderKind::Ollama => "ollama",
        crate::gate::ProviderKind::Mock => "mock",
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn add_opt_u32(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.saturating_add(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}
