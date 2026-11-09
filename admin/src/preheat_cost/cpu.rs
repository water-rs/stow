//! Read every uninterrupted CPU capture without retaining its raw profile.

use std::path::Path;

use crate::traffic_cost::ReferenceCpu;
use serde::{Deserialize, Serialize};
use stow_types::stow_error;

use super::{read_json, sorted_entries};

/// CPU covered by the mock wave and its daily resubmit.
#[derive(Debug, Serialize, Deserialize)]
pub struct PreheatCpu {
    pub wave: PhaseCpu,
    pub resubmit: PhaseCpu,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhaseCpu {
    pub initial: SegmentCpu,
    pub resumed: Vec<SegmentCpu>,
}

impl PhaseCpu {
    pub fn total_ms(&self) -> f64 {
        self.resumed
            .iter()
            .map(|segment| segment.cpu_ms)
            .sum::<f64>()
            + self.initial.cpu_ms
    }

    pub const fn segment_count(&self) -> usize {
        self.resumed.len() + 1
    }
}

/// Small summary; the harness preserves raw profiles beside the report.
#[derive(Debug, Serialize, Deserialize)]
pub struct SegmentCpu {
    pub segment: usize,
    pub cpu_ms: f64,
    pub sampling_interval_us: u64,
    pub idle_window_ms: u64,
    pub idle_cpu_ms: f64,
    pub reference: ReferenceCpu,
}

/// Same fields as the sampler output, excluding its large raw artifacts.
#[derive(Deserialize)]
struct Capture {
    cpu_ms: f64,
    sampling_interval_us: u64,
    idle_window_ms: u64,
    idle_cpu_ms: f64,
    reference: ReferenceCpu,
}

async fn phase(dir: &Path, next: &mut usize) -> stow_types::error::Result<PhaseCpu> {
    let entries = sorted_entries(&dir.join("cpu")).await?;
    if entries.is_empty() {
        return Err(stow_error!("no preheat CPU segments in {}", dir.display()));
    }
    let mut segments = Vec::with_capacity(entries.len());
    // Bound one: each profile can be large, so release its input buffer
    // before reading the next; only the small summary is retained.
    for entry in entries {
        let number: usize = entry
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| stow_error!("invalid CPU segment path {}", entry.display()))?
            .parse()?;
        if number != *next {
            return Err(stow_error!(
                "preheat CPU segment sequence expected {}, found {}",
                next,
                entry.display()
            ));
        }
        // Both markers bracket a capture the harness actually started
        // and stopped. A failed stop must never count as zero CPU.
        tokio::try_join!(
            tokio::fs::metadata(entry.join("ready")),
            tokio::fs::metadata(entry.join("stop")),
        )
        .map_err(|error| stow_error!("read CPU markers in {}: {error}", entry.display()))?;
        let capture: Capture = read_json(&entry.join("profile.json")).await?;
        segments.push(SegmentCpu {
            segment: number,
            cpu_ms: capture.cpu_ms,
            sampling_interval_us: capture.sampling_interval_us,
            idle_window_ms: capture.idle_window_ms,
            idle_cpu_ms: capture.idle_cpu_ms,
            reference: capture.reference,
        });
        *next += 1;
    }
    let mut segments = segments.into_iter();
    Ok(PhaseCpu {
        initial: segments.next().expect("nonempty capture directory"),
        resumed: segments.collect(),
    })
}

pub(super) async fn read(dir: &Path) -> stow_types::error::Result<PreheatCpu> {
    let mut next = 1;
    let wave = phase(&dir.join("wave"), &mut next).await?;
    let resubmit = phase(&dir.join("resubmit"), &mut next).await?;
    let restarts = sorted_entries(&dir.join("restarts")).await?.len();
    let captured = wave.segment_count() + resubmit.segment_count();
    let expected = restarts + 2;
    if captured != expected {
        return Err(stow_error!(
            "preheat CPU needs {expected} segments for two phases and {restarts} restarts, found {captured}"
        ));
    }
    Ok(PreheatCpu { wave, resubmit })
}

#[cfg(test)]
fn reference_rounds(values: &[f64]) -> Vec<crate::traffic_cost::ReferenceRound> {
    values
        .iter()
        .map(|&sampled_cpu_ms| crate::traffic_cost::ReferenceRound {
            invocations: std::num::NonZeroU32::new(1).expect("one"),
            sampled_cpu_ms,
        })
        .collect()
}

#[cfg(test)]
pub fn test_cpu(wave_ms: f64, resubmit_ms: f64) -> PreheatCpu {
    let phase = |segment, cpu_ms| PhaseCpu {
        initial: SegmentCpu {
            segment,
            cpu_ms,
            sampling_interval_us: 100,
            idle_window_ms: 3_000,
            idle_cpu_ms: 0.0,
            reference: ReferenceCpu {
                rounds_before: reference_rounds(&[20.0; 3]),
                rounds_after: reference_rounds(&[20.0; 3]),
                cpu_ms: 20.0,
            },
        },
        resumed: Vec::new(),
    };
    PreheatCpu {
        wave: phase(1, wave_ms),
        resubmit: phase(2, resubmit_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::read;
    use std::path::Path;

    async fn capture(root: &Path, phase: &str, number: usize, cpu_ms: f64) {
        let dir = root.join(phase).join("cpu").join(format!("{number:03}"));
        tokio::fs::create_dir_all(&dir).await.expect("capture dir");
        let body = serde_json::to_vec(&serde_json::json!({
            "cpu_ms": cpu_ms,
            "sampling_interval_us": 100,
            "idle_window_ms": 3000,
            "idle_cpu_ms": 0.0,
            "reference": {
                "rounds_before": super::reference_rounds(&[20.0, 21.0, 22.0]),
                "rounds_after": super::reference_rounds(&[22.0, 21.0, 20.0]),
                "cpu_ms": 20.0,
            },
            "profiles": [{"label": "preheat", "profile": {}}],
            "scripts": [],
        }))
        .expect("capture JSON");
        tokio::try_join!(
            tokio::fs::write(dir.join("ready"), b"ready\n"),
            tokio::fs::write(dir.join("stop"), b""),
            tokio::fs::write(dir.join("profile.json"), body),
        )
        .expect("write capture");
    }

    #[tokio::test]
    async fn preheat_cpu_sums_restarts_and_keeps_resubmit_separate() {
        let root = tempfile::tempdir().expect("tempdir");
        capture(root.path(), "wave", 1, 100.0).await;
        capture(root.path(), "wave", 2, 50.0).await;
        capture(root.path(), "resubmit", 3, 7.0).await;
        tokio::fs::create_dir_all(root.path().join("restarts/001"))
            .await
            .expect("restart");
        let cpu = read(root.path()).await.expect("complete CPU");
        assert_eq!(cpu.wave.total_ms(), 150.0);
        assert_eq!(cpu.wave.segment_count(), 2);
        assert_eq!(cpu.resubmit.total_ms(), 7.0);
        assert_eq!(
            cpu.wave.resumed[0].reference.rounds_after,
            super::reference_rounds(&[22.0, 21.0, 20.0])
        );
    }

    #[tokio::test]
    async fn preheat_cpu_rejects_a_failed_capture_and_missing_markers() {
        for missing in ["profile.json", "ready", "stop"] {
            let root = tempfile::tempdir().expect("tempdir");
            capture(root.path(), "wave", 1, 100.0).await;
            capture(root.path(), "resubmit", 2, 7.0).await;
            tokio::fs::remove_file(root.path().join("wave/cpu/001").join(missing))
                .await
                .expect("remove");
            assert!(read(root.path()).await.is_err(), "missing {missing}");
        }
    }

    #[tokio::test]
    async fn preheat_cpu_rejects_missing_segment_directories() {
        let root = tempfile::tempdir().expect("tempdir");
        capture(root.path(), "wave", 1, 100.0).await;
        capture(root.path(), "resubmit", 3, 7.0).await;
        let error = read(root.path())
            .await
            .expect_err("segment 2 missing")
            .to_string();
        assert!(error.contains("expected 2"), "{error}");
    }

    #[tokio::test]
    async fn preheat_cpu_rejects_a_restart_with_no_new_segment() {
        let root = tempfile::tempdir().expect("tempdir");
        capture(root.path(), "wave", 1, 100.0).await;
        capture(root.path(), "resubmit", 2, 7.0).await;
        tokio::fs::create_dir_all(root.path().join("restarts/001"))
            .await
            .expect("restart");
        let error = read(root.path())
            .await
            .expect_err("restart not captured")
            .to_string();
        assert!(error.contains("needs 3 segments"), "{error}");
    }

    #[tokio::test]
    async fn preheat_cpu_requires_both_phases() {
        let root = tempfile::tempdir().expect("tempdir");
        capture(root.path(), "wave", 1, 100.0).await;
        let error = read(root.path())
            .await
            .expect_err("resubmit absent")
            .to_string();
        assert!(error.contains("no preheat CPU segments"), "{error}");
    }
}
