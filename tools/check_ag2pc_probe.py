#!/usr/bin/env python3
"""Validate the AG2PC session live-probe JSONL outputs."""

import json
import sys


CASES = [
    "session_setup",
    "input_batch_two_bits",
    "public_true_reveal",
    "xor_reveal",
    "and_reveal",
    "checkpoint_keep_carry_inputs",
    "carried_and_reveal",
    "reveal_to_alice",
    "reveal_to_bob",
]


EXPECTED_RESULTS = {
    "public_true_reveal": {1: True, 2: True},
    "xor_reveal": {1: False, 2: False},
    "and_reveal": {1: True, 2: True},
    "reveal_to_alice": {1: True, 2: None},
    "reveal_to_bob": {1: None, 2: False},
    "carried_and_reveal": {1: False, 2: False},
}


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def check_role(records, role):
    require(len(records) == len(CASES), f"role {role}: wrong record count")
    for seq, (record, case) in enumerate(zip(records, CASES)):
        require(record["schema"] == "shachain2pc.ag2pc_probe.v1",
                f"role {role}: bad schema at seq {seq}")
        require(record["probe"] == "ag2pc_session",
                f"role {role}: bad probe at seq {seq}")
        require(record["seq"] == seq, f"role {role}: bad seq {seq}")
        require(record["case"] == case, f"role {role}: bad case {seq}")
        require(record["party"] == role, f"role {role}: bad party {seq}")
    require(records[0]["process_input_calls"] == 0,
            f"role {role}: setup should not process inputs")
    for record in records[1:]:
        require(record["process_input_calls"] == 1,
                f"role {role}: expected one input batch")
    require(records[4]["num_and"] == 1, f"role {role}: AND count missing")
    require(records[-1]["num_and"] == 2,
            f"role {role}: carried AND count missing")
    for record in records:
        case = record["case"]
        if case in EXPECTED_RESULTS:
            require(record.get("result") == EXPECTED_RESULTS[case][role],
                    f"role {role}: bad result for {case}")


def main():
    require(len(sys.argv) == 3,
            "usage: check_ag2pc_probe.py alice.jsonl bob.jsonl")
    alice = load(sys.argv[1])
    bob = load(sys.argv[2])
    check_role(alice, 1)
    check_role(bob, 2)
    for a, b in zip(alice, bob):
        case = a["case"]
        require(a["case"] == b["case"], f"case mismatch at {case}")
        require(a["main_digest"] == b["main_digest"],
                f"main digest mismatch for {case}")
        require(a["sibling_digest"] == b["sibling_digest"],
                f"sibling digest mismatch for {case}")
        require(a["total_sent"] == b["total_recv"],
                f"sent/recv mismatch for {case}")
        require(a["total_recv"] == b["total_sent"],
                f"recv/sent mismatch for {case}")


if __name__ == "__main__":
    main()
