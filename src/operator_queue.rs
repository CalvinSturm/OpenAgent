#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueMessageKind {
    Steer,
    FollowUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryBoundary {
    PostTool,
    PostStep,
    TurnIdle,
}

impl DeliveryBoundary {
    pub fn user_phrase(self) -> &'static str {
        match self {
            Self::PostTool => "after current tool finishes",
            Self::PostStep => "after current step finishes",
            Self::TurnIdle => "after this turn completes",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedOperatorMessage {
    pub queue_id: String,
    pub sequence_no: u64,
    pub kind: QueueMessageKind,
    pub content: String,
    pub bytes_loaded: u64,
    pub bytes_kept: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueSubmitRequest {
    pub kind: QueueMessageKind,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueLimits {
    pub max_message_bytes: usize,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMessageQueue {
    next_sequence_no: u64,
    next_id_counter: u64,
    pending: Vec<QueuedOperatorMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSubmitResult {
    pub queued: QueuedOperatorMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueDelivery {
    pub message: QueuedOperatorMessage,
    pub delivery_boundary: DeliveryBoundary,
    pub cancelled_remaining_work: bool,
    pub cancelled_reason: Option<&'static str>,
}

impl PendingMessageQueue {
    pub fn new() -> Self {
        Self {
            next_sequence_no: 1,
            next_id_counter: 1,
            pending: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn pending(&self) -> &[QueuedOperatorMessage] {
        &self.pending
    }

    pub fn clear(&mut self) {
        self.pending.clear();
    }

    pub fn submit(
        &mut self,
        kind: QueueMessageKind,
        content: &str,
        limits: &QueueLimits,
    ) -> QueueSubmitResult {
        let bytes_loaded = content.len() as u64;
        let (capped, truncated) = truncate_utf8_to_bytes(content, limits.max_message_bytes);
        let msg = QueuedOperatorMessage {
            queue_id: format!("q{}", self.next_id_counter),
            sequence_no: self.next_sequence_no,
            kind,
            bytes_loaded,
            bytes_kept: capped.len() as u64,
            truncated,
            content: capped,
        };
        self.next_id_counter = self.next_id_counter.saturating_add(1);
        self.next_sequence_no = self.next_sequence_no.saturating_add(1);
        self.pending.push(msg.clone());
        QueueSubmitResult { queued: msg }
    }

    pub fn deliver_at_boundary(&mut self, boundary: DeliveryBoundary) -> Option<QueueDelivery> {
        let idx = self.select_deliverable_index(boundary)?;
        let msg = self.pending.remove(idx);
        let is_steer = matches!(msg.kind, QueueMessageKind::Steer);
        Some(QueueDelivery {
            message: msg,
            delivery_boundary: boundary,
            cancelled_remaining_work: is_steer,
            cancelled_reason: if is_steer {
                Some("operator_steer")
            } else {
                None
            },
        })
    }

    fn select_deliverable_index(&self, boundary: DeliveryBoundary) -> Option<usize> {
        // Earliest steer always wins when a boundary is eligible.
        let earliest_steer = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, m)| matches!(m.kind, QueueMessageKind::Steer))
            .min_by_key(|(_, m)| m.sequence_no)
            .map(|(idx, _)| idx);
        if earliest_steer.is_some() {
            return earliest_steer;
        }
        if !matches!(boundary, DeliveryBoundary::TurnIdle) {
            return None;
        }
        self.pending
            .iter()
            .enumerate()
            .filter(|(_, m)| matches!(m.kind, QueueMessageKind::FollowUp))
            .min_by_key(|(_, m)| m.sequence_no)
            .map(|(idx, _)| idx)
    }
}

impl Default for PendingMessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate_utf8_to_bytes(input: &str, max_bytes: usize) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input.to_string(), false);
    }
    let mut end = max_bytes.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    (input[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_phrases_are_stable() {
        assert_eq!(
            DeliveryBoundary::PostTool.user_phrase(),
            "after current tool finishes"
        );
        assert_eq!(
            DeliveryBoundary::TurnIdle.user_phrase(),
            "after this turn completes"
        );
    }

    #[test]
    fn follow_up_delivers_only_at_turn_idle() {
        let mut q = PendingMessageQueue::new();
        q.submit(QueueMessageKind::FollowUp, "next", &QueueLimits::default());
        assert!(q.deliver_at_boundary(DeliveryBoundary::PostTool).is_none());
        let d = q
            .deliver_at_boundary(DeliveryBoundary::TurnIdle)
            .expect("delivery");
        assert_eq!(d.message.kind, QueueMessageKind::FollowUp);
        assert!(!d.cancelled_remaining_work);
    }

    #[test]
    fn steer_has_precedence_over_follow_up() {
        let mut q = PendingMessageQueue::new();
        q.submit(QueueMessageKind::FollowUp, "later", &QueueLimits::default());
        q.submit(
            QueueMessageKind::Steer,
            "interrupt",
            &QueueLimits::default(),
        );
        let d = q
            .deliver_at_boundary(DeliveryBoundary::PostTool)
            .expect("delivery");
        assert_eq!(d.message.kind, QueueMessageKind::Steer);
        assert!(d.cancelled_remaining_work);
        assert_eq!(d.cancelled_reason, Some("operator_steer"));

        let d2 = q
            .deliver_at_boundary(DeliveryBoundary::TurnIdle)
            .expect("delivery2");
        assert_eq!(d2.message.kind, QueueMessageKind::FollowUp);
    }

    #[test]
    fn fifo_within_kind_is_preserved() {
        let mut q = PendingMessageQueue::new();
        q.submit(QueueMessageKind::Steer, "a", &QueueLimits::default());
        q.submit(QueueMessageKind::Steer, "b", &QueueLimits::default());
        let d1 = q
            .deliver_at_boundary(DeliveryBoundary::PostTool)
            .expect("d1");
        let d2 = q
            .deliver_at_boundary(DeliveryBoundary::PostTool)
            .expect("d2");
        assert_eq!(d1.message.content, "a");
        assert_eq!(d2.message.content, "b");
        assert!(d1.message.sequence_no < d2.message.sequence_no);
    }

    #[test]
    fn submit_truncates_utf8_safely() {
        let mut q = PendingMessageQueue::new();
        let msg = "abcβγδε";
        let r = q.submit(
            QueueMessageKind::Steer,
            msg,
            &QueueLimits {
                max_message_bytes: 6,
            },
        );
        assert!(r.queued.truncated);
        assert!(std::str::from_utf8(r.queued.content.as_bytes()).is_ok());
        assert_eq!(r.queued.bytes_loaded, msg.len() as u64);
        assert!(r.queued.bytes_kept <= 6);
    }
}
