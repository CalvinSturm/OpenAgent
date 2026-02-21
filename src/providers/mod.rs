pub mod ollama;
pub mod openai_compat;

use async_trait::async_trait;

use crate::types::{GenerateRequest, GenerateResponse};

#[derive(Debug, Clone)]
pub enum StreamDelta {
    Content(String),
    ToolCallFragment(ToolCallFragment),
}

#[derive(Debug, Clone)]
pub struct ToolCallFragment {
    pub index: usize,
    pub id: Option<String>,
    pub name: Option<String>,
    pub arguments_fragment: Option<String>,
    pub complete: bool,
}

#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn generate(&self, req: GenerateRequest) -> anyhow::Result<GenerateResponse>;

    fn supports_streaming(&self) -> bool {
        false
    }

    async fn generate_streaming(
        &self,
        req: GenerateRequest,
        _on_delta: &mut (dyn FnMut(StreamDelta) + Send),
    ) -> anyhow::Result<GenerateResponse> {
        self.generate(req).await
    }
}
