import re, os

svgs = [
    "flamegraph_WhirGasProfileTest_testFlameParseCommitment.svg",
    "flamegraph_WhirGasProfileTest_testFlameConstraintPreparation.svg",
    "flamegraph_WhirGasProfileTest_testFlameInitialSumcheck.svg",
    "flamegraph_WhirGasProfileTest_testFlameStandaloneFinalSumcheck.svg",
    "flamegraph_WhirGasProfileTest_testFlameConstraintEvaluation.svg",
    "flamegraph_WhirGasProfileTest_testFlameRound0Stir.svg",
    "flamegraph_WhirGasProfileTest_testFlameRound1Stir.svg",
    "flamegraph_WhirGasProfileTest_testFlameFinalStir.svg",
    "flamegraph_WhirGasProfileTest_testFlameSyntheticEqConstraint.svg",
    "flamegraph_WhirGasProfileTest_testFlameSyntheticSelectConstraint.svg",
]

for svg in svgs:
    path = os.path.join("cache", svg)
    if not os.path.exists(path):
        print(f"MISSING: {svg}")
        continue
    with open(path) as f:
        content = f.read()
    entries = re.findall(
        r"<title>([^<]+)\(([0-9,]+) gas, ([0-9.]+)%\)</title>", content
    )
    parsed = [
        (name.strip(), int(gas.replace(",", "")), float(pct))
        for name, gas, pct in entries
    ]
    parsed.sort(key=lambda x: -x[1])

    test_name = svg.replace("flamegraph_WhirGasProfileTest_", "").replace(".svg", "")
    print(f"\n=== {test_name} (top 15) ===")
    for name, gas, pct in parsed[:15]:
        print(f"{gas:>10,}  {pct:>5.1f}%  {name}")
