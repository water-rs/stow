import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

const stowBin = (process.env["INPUT_STOW-BIN"] ?? "").trim();
const maxBytes = (process.env["INPUT_LOCAL-CRATES-IO-MAX-BYTES"] ?? "").trim();

if (!stowBin || !existsSync(stowBin)) {
  console.log(
    `::notice::stow binary not present at '${stowBin}'; skipping daemon drain`,
  );
  process.exit(0);
}

const args = ["daemon", "stop"];
if (maxBytes !== "") {
  if (!/^[0-9]+$/.test(maxBytes)) {
    console.error(
      `::error::local-crates-io-max-bytes must be a non-negative integer, got '${maxBytes}'`,
    );
    process.exit(1);
  }
  args.push("--local-crates-io-max-bytes", maxBytes);
}

execFileSync(stowBin, args, { stdio: "inherit" });
