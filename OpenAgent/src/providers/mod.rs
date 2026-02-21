pub mod ollama;
pub mod openai_compat;

use async_trait::async_trait;

use crate::types::{GenerateRequest, GenerateResponse};

#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn generate(&self, req: GenerateRequest) -> anyhow::Result<GenerateResponse>;
}
