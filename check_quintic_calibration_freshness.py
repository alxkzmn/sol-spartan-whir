#!/usr/bin/env python3
"""Check that quintic calibration JSON matches the current source fingerprints."""

from __future__ import annotations

import argparse
from pathlib import Path

import quintic_schedule_scorer as scorer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--calibration",
        default="testdata/quintic_calibration.json",
        help="Calibration JSON to check",
    )
    args = parser.parse_args()

    calibration = scorer.read_json(Path(args.calibration))
    scorer.check_calibration_source_fingerprints(calibration)
    fingerprints = scorer.build_calibration_source_fingerprints()
    print(
        "quintic calibration source fingerprints match "
        f"{fingerprints['combined_sha256']}"
    )


if __name__ == "__main__":
    main()
