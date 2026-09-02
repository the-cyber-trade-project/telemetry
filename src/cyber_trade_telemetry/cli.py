"""Command-line interface for the Cybersecurity Trade Telemetry Gateway (`ctl-telemetry`)."""

import sys
import json
import argparse
from pathlib import Path

from cyber_trade_telemetry.models import ShiftRoster, ZeroKnowledgeRatioProof
from cyber_trade_telemetry.engine import TelemetryEngine
from cyber_trade_telemetry.crypto import (
    load_private_key_pem,
    load_public_key_pem,
    generate_keypair,
    export_private_key_pem,
    export_public_key_pem
)


def main():
    parser = argparse.ArgumentParser(
        prog="ctl-telemetry",
        description="Cybersecurity Trade Telemetry Gateway & Underwriter Warranty CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: keygen
    subparsers.add_parser("keygen", help="Generate a new Ed25519 signing keypair")

    # Subcommand: generate
    gen_parser = subparsers.add_parser("generate", help="Generate ZK ratio proof from shift roster JSON")
    gen_parser.add_argument("--input", "-i", required=True, help="Path to input ShiftRoster JSON")
    gen_parser.add_argument("--key", "-k", help="Path to Ed25519 private key PEM")
    gen_parser.add_argument("--output", "-o", help="Path to output proof JSON (default stdout)")

    # Subcommand: verify
    ver_parser = subparsers.add_parser("verify", help="Verify a ZK ratio proof against employer public key")
    ver_parser.add_argument("--proof", "-p", required=True, help="Path to ZeroKnowledgeRatioProof JSON")
    ver_parser.add_argument("--pubkey", "-k", required=True, help="Path to employer public key PEM")

    # Subcommand: evaluate-warranty
    war_parser = subparsers.add_parser("evaluate-warranty", help="Calculate actuarial warranty discount")
    war_parser.add_argument("--proofs", "-p", required=True, help="Path to JSON array of proofs")
    war_parser.add_argument("--employer", "-e", required=True, help="PEC Employer ID")
    war_parser.add_argument("--base-premium", "-b", type=float, default=120000.0, help="Base annual premium")

    args = parser.parse_args()
    engine = TelemetryEngine()

    if args.command == "keygen":
        priv, pub = generate_keypair()
        print("--- PRIVATE KEY (Keep Secret) ---")
        print(export_private_key_pem(priv))
        print("--- PUBLIC KEY (Share with NCTB / Underwriters) ---")
        print(export_public_key_pem(pub))

    elif args.command == "generate":
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
        roster = ShiftRoster(**data)

        priv_key = None
        if args.key:
            with open(args.key, "r", encoding="utf-8") as f:
                priv_key = load_private_key_pem(f.read())

        proof = engine.evaluate_shift_roster(roster, private_key=priv_key)
        out_json = proof.model_dump_json(indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_json)
            print(f"Proof written to {args.output}")
        else:
            print(out_json)

    elif args.command == "verify":
        with open(args.proof, "r", encoding="utf-8") as f:
            proof = ZeroKnowledgeRatioProof(**json.load(f))
        with open(args.pubkey, "r", encoding="utf-8") as f:
            pubkey = load_public_key_pem(f.read())

        valid, msg = engine.verify_proof(proof, pubkey)
        if valid:
            print(f"[PASS] {msg}")
            sys.exit(0)
        else:
            print(f"[FAIL] {msg}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "evaluate-warranty":
        with open(args.proofs, "r", encoding="utf-8") as f:
            proofs_data = json.load(f)
        proofs = [ZeroKnowledgeRatioProof(**p) for p in proofs_data]
        report = engine.evaluate_actuarial_warranty(args.employer, proofs, base_annual_premium=args.base_premium)
        print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
