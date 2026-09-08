#!/usr/bin/env python3
"""Generate promtool cases using a realistic wall clock with short sample series.

Only time() is shifted in the temporary copy of production rules. This avoids
allocating decades of samples and catches the never-successful epoch-zero bug.
"""

import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
epoch = 1_700_000_000
source = pathlib.Path(__file__).with_name("rules.yaml").read_text()
(out / "rules.yaml").write_text(source.replace("time()", f"(time() + {epoch})"))
identity = {
    "cluster": "example",
    "namespace": "default",
    "policy": "app",
    "uid": "uid-1",
}


def series(name, values, **labels):
    tags = identity | labels
    return {
        "series": name + "{" + ",".join(f'{k}="{v}"' for k, v in tags.items()) + "}",
        "values": values,
    }


def inventory(mode="apply", approval="auto", interval="5m", values="1x45"):
    return series(
        "pgroles_policy_info", values, mode=mode, approval=approval, interval=interval
    )


def check(name, at, firing):
    summaries = {
        "PgrolesPolicyNotReady": "Policy has not been ready for 10 minutes.",
        "PgrolesPolicyReconcileStale": "Policy has exceeded its reconciliation grace period.",
    }
    return {
        "eval_time": at,
        "alertname": name,
        "exp_alerts": [
            {
                "exp_labels": identity | {"severity": "warning"},
                "exp_annotations": {"summary": summaries[name]},
            }
        ]
        if firing
        else [],
    }


def case(name, inputs, checks):
    return {
        "name": name,
        "interval": "1m",
        "input_series": inputs,
        "alert_rule_test": checks,
    }


notready = "PgrolesPolicyNotReady"
stale = "PgrolesPolicyReconcileStale"
created = series("pgroles_policy_created_seconds", f"{epoch}x45")
tests = [
    case(
        "changing reasons preserves continuous unready timer",
        [
            inventory(),
            created,
            series(
                "pgroles_policy_condition",
                "0x5 stale",
                type="Ready",
                reason="DatabaseConnectionFailed",
            ),
            series(
                "pgroles_policy_condition",
                "_ _ _ _ _ _ 0x20",
                type="Ready",
                reason="SecretFetchFailed",
            ),
        ],
        [check(notready, "9m", False), check(notready, "10m", True)],
    ),
    case(
        "missing status gets creation grace at real Unix epoch",
        [inventory(), created],
        [
            check(notready, "10m", True),
            check(stale, "5m", False),
            check(stale, "30m", False),
            check(stale, "35m", False),
            check(stale, "36m", True),
        ],
    ),
    case(
        "zero last success also falls back to creation",
        [inventory(), created, series("pgroles_policy_last_success_seconds", "0x45")],
        [check(stale, "5m", False), check(stale, "36m", True)],
    ),
    case(
        "recovery clears both alerts",
        [
            inventory(),
            created,
            series(
                "pgroles_policy_condition",
                "0x36 1x8",
                type="Ready",
                reason="Reconciled",
            ),
            series("pgroles_policy_last_success_seconds", f"0x36 {epoch + 2220}x8"),
        ],
        [
            check(notready, "36m", True),
            check(notready, "37m", False),
            check(stale, "37m", False),
        ],
    ),
    case(
        "deletion clears alerts",
        [inventory(values="1x11 stale"), created],
        [
            check(notready, "11m", True),
            check(notready, "12m", False),
            check(stale, "40m", False),
        ],
    ),
    case(
        "manual approval is healthy without refreshing last success",
        [
            inventory(approval="manual"),
            created,
            series("pgroles_policy_condition", "1x45", type="Ready", reason="Planned"),
            series(
                "pgroles_policy_condition",
                "1x45",
                type="Drifted",
                reason="AwaitingApproval",
            ),
            series("pgroles_policy_last_success_seconds", f"{epoch}x45"),
        ],
        [check(notready, "40m", False), check(stale, "40m", False)],
    ),
    case(
        "long interval explicit grace avoids false stale alert",
        [
            inventory(interval="1h"),
            created,
            series(
                "pgroles_policy_condition", "1x45", type="Ready", reason="Reconciled"
            ),
            series("pgroles_policy_stale_after_seconds", "7200x45"),
        ],
        [check(stale, "40m", False)],
    ),
]
tests.append(
    case(
        "manual approval failure still alerts on readiness",
        [inventory(approval="manual"), created],
        [check(notready, "40m", True), check(stale, "40m", False)],
    )
)
tests.append(
    case(
        "recreated name gets fresh readiness hold from new UID",
        [
            inventory(values="1x11 stale"),
            series(
                "pgroles_policy_info",
                "_ _ _ _ _ _ _ _ _ _ _ _ 1x10",
                uid="uid-2",
                mode="apply",
                approval="auto",
                interval="5m",
            ),
        ],
        [
            check(notready, "11m", True),
            check(notready, "12m", False),
            check(notready, "20m", False),
        ],
    )
)
for mode in ("observe", "plan"):
    tests.append(
        case(
            f"{mode} excluded",
            [inventory(mode=mode), created],
            [check(notready, "40m", False), check(stale, "40m", False)],
        )
    )
tests.append(
    case(
        "suspended excluded",
        [inventory(), created, series("pgroles_policy_suspended", "1x45")],
        [check(notready, "40m", False), check(stale, "40m", False)],
    )
)
for expected, present, name in [
    (True, False, "expected installation absent"),
    (False, False, "unconfigured installation"),
    (True, True, "healthy empty installation"),
]:
    inputs = []
    if expected:
        inputs.append(
            {
                "series": 'pgroles_monitoring_expected{cluster="example"}',
                "values": "1x15",
            }
        )
    if present:
        inputs += [
            {
                "series": 'pgroles_runtime_scheduling_lag_count{cluster="example"}',
                "values": "1+1x15",
            },
            {
                "series": 'up{job="pgroles-policy-state",cluster="example"}',
                "values": "1x15",
            },
        ]
    checks = []
    for alert, summary in [
        ("PgrolesTelemetryMissing", "Expected operator runtime telemetry is missing."),
        (
            "PgrolesPolicyCollectionDown",
            "Expected policy state collector is unavailable.",
        ),
    ]:
        checks.append(
            {
                "eval_time": "6m",
                "alertname": alert,
                "exp_alerts": [
                    {
                        "exp_labels": {"cluster": "example", "severity": "warning"},
                        "exp_annotations": {"summary": summary},
                    }
                ]
                if expected and not present
                else [],
            }
        )
    tests.append(case(name, inputs, checks))
# Explicit stale markers model a previously healthy scrape losing its series.
# Recovery must clear firing alerts immediately rather than wait another hold.
checks = []
for alert, summary in [
    ("PgrolesTelemetryMissing", "Expected operator runtime telemetry is missing."),
    ("PgrolesPolicyCollectionDown", "Expected policy state collector is unavailable."),
]:
    for at, firing in [
        ("2m", False),
        ("7m", False),
        ("8m", True),
        ("9m", True),
        ("10m", False),
    ]:
        checks.append(
            {
                "eval_time": at,
                "alertname": alert,
                "exp_alerts": [
                    {
                        "exp_labels": {"cluster": "example", "severity": "warning"},
                        "exp_annotations": {"summary": summary},
                    }
                ]
                if firing
                else [],
            }
        )
tests.append(
    case(
        "previously healthy telemetry disappears and recovers",
        [
            {
                "series": 'pgroles_monitoring_expected{cluster="example"}',
                "values": "1x15",
            },
            {
                "series": 'pgroles_runtime_scheduling_lag_count{cluster="example"}',
                "values": "1+1x2 stale _ _ _ _ _ _ 12+1x5",
            },
            {
                "series": 'up{job="pgroles-policy-state",cluster="example"}',
                "values": "1x2 stale _ _ _ _ _ _ 1x5",
            },
        ],
        checks,
    )
)
for present in (True, False):
    inputs = [
        {
            "series": 'pgroles_policy_expected{cluster="example",namespace="default",policy="app"}',
            "values": "1x15",
        },
        {
            "series": 'up{job="pgroles-policy-state",cluster="example"}',
            "values": "1x15",
        },
    ]
    if present:
        inputs.append(inventory())
    tests.append(
        case(
            "independent policy inventory present=" + str(present),
            inputs,
            [
                {
                    "eval_time": "6m",
                    "alertname": "PgrolesExpectedPolicyMissing",
                    "exp_alerts": []
                    if present
                    else [
                        {
                            "exp_labels": {
                                "cluster": "example",
                                "namespace": "default",
                                "policy": "app",
                                "severity": "warning",
                            },
                            "exp_annotations": {
                                "summary": "An independently inventoried policy is absent from collected state."
                            },
                        }
                    ],
                }
            ],
        )
    )
(out / "tests.yaml").write_text(
    json.dumps(
        {"rule_files": ["rules.yaml"], "evaluation_interval": "1m", "tests": tests},
        indent=2,
    )
)
