#!/usr/bin/env python3
"""Measure complete terminal transactions on an owned local Cancun Anvil instance."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    root = project.parent
    fixture = project / "testdata/leanvm_terminal" / args.label
    manifest = json.loads((fixture / "manifest.json").read_text())
    for name, expected in manifest["source_sha256"].items():
        relative = Path(name)
        assert not relative.is_absolute() and ".." not in relative.parts, f"invalid source path: {name}"
        # Generators use project-relative paths; archived snapshots may include
        # the project directory. Both must identify the same local source files.
        source = root / relative if relative.parts[0] == project.name else project / relative
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected, f"source changed: {name}"
    name = manifest["contract"]
    artifact = json.loads((project / "out" / (name + ".sol") / (name + ".json")).read_text())
    initcode = artifact["bytecode"]["object"]
    runtime = artifact["deployedBytecode"]["object"]
    calldata = (fixture / "calldata.bin").read_bytes()
    assert len(calldata) == manifest["calldata_bytes"]
    args.output.mkdir(parents=True, exist_ok=False)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}"

    def rpc(method, params):
        request = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    def receipt(transaction_hash):
        deadline = time.monotonic() + 30
        while True:
            value = rpc("eth_getTransactionReceipt", [transaction_hash])
            if value is not None:
                return value
            if time.monotonic() >= deadline:
                raise RuntimeError("transaction receipt timeout")
            time.sleep(0.1)

    command = ["anvil", "--silent", "--host", "127.0.0.1", "--port", str(port), "--hardfork", "cancun", "--code-size-limit", "65536", "--gas-limit", "1000000000"]
    with (args.output / "anvil.log").open("w") as log:
        node = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert node.poll() is None, "Anvil exited during startup"
                try:
                    accounts = rpc("eth_accounts", [])
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            sender = accounts[0]
            gas_price = rpc("eth_gasPrice", [])
            creation_hash = rpc("eth_sendTransaction", [{"from": sender, "data": initcode, "gas": hex(25_000_000), "gasPrice": gas_price}])
            creation = receipt(creation_hash)
            (args.output / "deployment-receipt.json").write_text(json.dumps(creation, indent=2) + "\n")
            assert int(creation["status"], 16) == 1, "deployment reverted"
            address = creation["contractAddress"]
            assert rpc("eth_getCode", [address, "latest"]) == runtime, "deployed bytecode differs from artifact"
            proof_hash = rpc("eth_sendTransaction", [{"from": sender, "to": address, "data": "0x" + calldata.hex(), "gas": hex(900_000_000), "gasPrice": gas_price}])
            verified = receipt(proof_hash)
            (args.output / "verification-receipt.json").write_text(json.dumps(verified, indent=2) + "\n")
            assert int(verified["status"], 16) == 1, "complete verification transaction reverted"
            used = int(verified["gasUsed"], 16)
            result = {"contract": name, "hardfork": "cancun", "chain_id": int(rpc("eth_chainId", []), 16), "anvil_runtime_size_allowance": 65536, "anvil_block_gas_limit": 1_000_000_000, "runtime_bytes": len(runtime.removeprefix("0x")) // 2, "initcode_bytes": len(initcode.removeprefix("0x")) // 2, "verification_transaction_gas": used, "calldata_bytes": len(calldata), "calldata_gas_4_16": manifest["calldata_gas_4_16"], "transaction_base_gas": 21000, "execution_remainder_gas": used - 21000 - manifest["calldata_gas_4_16"], "calldata_sha256": hashlib.sha256(calldata).hexdigest(), "runtime_sha256": hashlib.sha256(bytes.fromhex(runtime.removeprefix("0x"))).hexdigest(), "source_sha256": manifest["source_sha256"], "anvil_version": subprocess.check_output(["anvil", "--version"], text=True).strip(), "forge_version": subprocess.check_output(["forge", "--version"], text=True).strip(), "verification_boundary": "complete LeanVM root IOP and WHIR, node public digest, and three authenticated fixed bytecode oracle WHIR openings"}
            result["verification_boundary"] = manifest.get("verification_boundary", result["verification_boundary"])
            result["measurement_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            (args.output / "metrics.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps({k: v for k, v in result.items() if k != "source_sha256"}, indent=2))
        finally:
            if node.poll() is None:
                node.terminate()
                try:
                    node.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()


if __name__ == "__main__":
    main()
