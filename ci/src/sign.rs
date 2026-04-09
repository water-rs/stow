use std::collections::BTreeMap;

use async_process::Command;

pub async fn sign_artifacts(
    digests_by_reference: &BTreeMap<String, String>,
) -> eyre::Result<()> {
    for (reference, digest) in digests_by_reference {
        let image = format!("{reference}@{digest}");
        let status = Command::new("cosign")
            .arg("sign")
            .arg("--yes")
            .arg(&image)
            .status()
            .await?;
        if !status.success() {
            return Err(eyre::eyre!(
                "cosign sign failed for {image} with status {status}"
            ));
        }

        tracing::info!(image = %image, "signed OCI artifact with cosign");
    }

    Ok(())
}
