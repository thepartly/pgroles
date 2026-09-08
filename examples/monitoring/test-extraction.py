#!/usr/bin/env python3
"""Exercise actual KSM against the API and OTLP through the reference Collector."""

import contextlib
import datetime
import json
import os
import pathlib
import queue
import re
import subprocess
import threading
import time
import urllib.request


def kube(*args, data=None):
    return subprocess.check_output(
        ["kubectl", "--request-timeout=30s", *args],
        input=None if data is None else json.dumps(data).encode(),
        timeout=60,
    ).decode()


@contextlib.contextmanager
def forward(service, remote):
    proc = subprocess.Popen(
        [
            "kubectl",
            "-n",
            "pgroles-monitoring",
            "port-forward",
            f"service/{service}",
            f":{remote}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    address = queue.Queue(maxsize=1)

    def drain_output():
        # Keep consuming kubectl's per-connection messages while the caller
        # scrapes. An unread pipe eventually fills and blocks port-forward.
        announced = False
        for line in proc.stdout:
            match = re.search(r"127\.0\.0\.1:(\d+) ->", line)
            if match and not announced:
                address.put(f"http://127.0.0.1:{match[1]}")
                announced = True
        if not announced:
            address.put(None)

    reader = threading.Thread(target=drain_output, daemon=True)
    reader.start()
    try:
        try:
            endpoint = address.get(timeout=30)
        except queue.Empty as error:
            raise RuntimeError(
                "port-forward did not start within 30 seconds"
            ) from error
        if endpoint is None:
            raise RuntimeError("port-forward exited before announcing an address")
        yield endpoint
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        reader.join(timeout=5)


def get(url):
    return urllib.request.urlopen(url, timeout=5).read().decode()


def samples(text, name, **labels):
    found = []
    for line in text.splitlines():
        if not line.startswith(name + "{") and not line.startswith(name + " "):
            continue
        tags = dict(re.findall(r'(\w+)="([^"\\]*)"', line))
        if all(tags.get(k) == v for k, v in labels.items()):
            found.append(
                (
                    tags,
                    float(line.split("} ")[-1].split()[0])
                    if "}" in line
                    else float(line.split()[1]),
                )
            )
    return found


def eventually(check, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        try:
            check()
            return
        except (AssertionError, urllib.error.URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def assert_value(text, name, value, **labels):
    got = samples(text, name, **labels)
    assert len(got) == 1 and got[0][1] == value, (name, labels, value, got, text)


policy = {
    "apiVersion": "pgroles.io/v1alpha1",
    "kind": "PostgresPolicy",
    "metadata": {
        "name": "monitoring-example",
        "namespace": "default",
        "annotations": {"monitoring.pgroles.io/stale-after-seconds": "7200"},
    },
    "spec": {
        "connection": {"secretRef": {"name": "unused"}},
        "mode": "apply",
        "approval": "manual",
        "interval": "1h",
        "suspend": False,
    },
}
kube("apply", "-f", "-", data=policy)
obj = json.loads(kube("get", "postgrespolicy", "monitoring-example", "-o", "json"))
labels = {
    "namespace": "default",
    "policy": "monitoring-example",
    "uid": obj["metadata"]["uid"],
}
created = datetime.datetime.fromisoformat(
    obj["metadata"]["creationTimestamp"].replace("Z", "+00:00")
).timestamp()
with forward("pgroles-policy-state", 8080) as ksm:

    def initial():
        text = get(ksm + "/metrics")
        assert_value(
            text,
            "pgroles_policy_info",
            1,
            **labels,
            mode="apply",
            approval="manual",
            interval="1h",
        )
        assert_value(text, "pgroles_policy_created_seconds", created, **labels)
        assert_value(text, "pgroles_policy_suspended", 0, **labels)
        assert_value(text, "pgroles_policy_stale_after_seconds", 7200, **labels)
        assert_value(text, "pgroles_policy_last_success_seconds", 0, **labels)
        assert not samples(text, "pgroles_policy_condition", **labels)

    eventually(initial)
    for ready, reason in [
        ("False", "DatabaseConnectionFailed"),
        ("False", "SecretFetchFailed"),
        ("True", "Planned"),
    ]:
        kube(
            "patch",
            "postgrespolicy",
            "monitoring-example",
            "--subresource=status",
            "--type=merge",
            "-p",
            json.dumps(
                {
                    "status": {
                        "conditions": [
                            {
                                "type": "Ready",
                                "status": ready,
                                "reason": reason,
                                "message": "fixture",
                                "last_transition_time": "2026-01-01T00:00:00Z",
                            }
                        ],
                        "last_successful_reconcile_time": "2026-01-01T00:00:00Z",
                    }
                }
            ),
        )

        def status():
            text = get(ksm + "/metrics")
            assert_value(
                text,
                "pgroles_policy_condition",
                int(ready == "True"),
                **labels,
                type="Ready",
                reason=reason,
            )
            assert_value(
                text, "pgroles_policy_last_success_seconds", 1767225600, **labels
            )

        eventually(status)
    kube(
        "patch",
        "postgrespolicy",
        "monitoring-example",
        "--type=merge",
        "-p",
        '{"spec":{"suspend":true,"mode":"observe"}}',
    )

    def suspended():
        text = get(ksm + "/metrics")
        assert_value(text, "pgroles_policy_suspended", 1, **labels)
        assert_value(text, "pgroles_policy_info", 1, **labels, mode="observe")

    eventually(suspended)
    kube("delete", "postgrespolicy", "monitoring-example", "--wait=true")

    def deleted():
        assert not samples(get(ksm + "/metrics"), "pgroles_policy_info", **labels)

    eventually(deleted)

with (
    forward("pgroles-collector", 4318) as otlp,
    forward("pgroles-collector", 8889) as prom,
):
    attributes = {
        "service.name": "pgroles-operator",
        "service.instance.id": "fixture-instance",
        "k8s.namespace.name": "example-system",
    }
    payload = {
        "resourceMetrics": [
            {
                "resource": {
                    "attributes": [
                        {"key": k, "value": {"stringValue": v}}
                        for k, v in attributes.items()
                    ]
                },
                "scopeMetrics": [
                    {
                        "scope": {"name": "pgroles-operator"},
                        "metrics": [
                            {
                                "name": "pgroles.runtime.scheduling_lag",
                                "unit": "ms",
                                "histogram": {
                                    "aggregationTemporality": 2,
                                    "dataPoints": [
                                        {
                                            "startTimeUnixNano": str(
                                                time.time_ns() - 1000000000
                                            ),
                                            "timeUnixNano": str(time.time_ns()),
                                            "count": "2",
                                            "sum": 12,
                                            "bucketCounts": ["1", "1"],
                                            "explicitBounds": [5],
                                        }
                                    ],
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    }
    req = urllib.request.Request(
        otlp + "/v1/metrics",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    response = json.loads(urllib.request.urlopen(req, timeout=5).read())
    assert not response.get("partialSuccess"), response

    def exported():
        text = get(prom + "/metrics")
        assert_value(
            text,
            "pgroles_runtime_scheduling_lag_count",
            2,
            service_name="pgroles-operator",
            service_instance_id="fixture-instance",
            k8s_namespace_name="example-system",
        )
        assert_value(
            text,
            "pgroles_runtime_scheduling_lag_sum",
            12,
            service_instance_id="fixture-instance",
        )

    eventually(exported)
# Exercise the production Rust SDK/provider path as well as protocol conversion.
root = pathlib.Path(__file__).resolve().parents[2]
version_match = re.search(
    r'\[workspace\.package\]\s+version = "([^"]+)"',
    (root / "Cargo.toml").read_text(),
)
assert version_match, "workspace package version missing"
version = version_match.group(1)
emitter = pathlib.Path(
    os.environ.get(
        "PGROLES_TELEMETRY_SMOKE_BIN", root / "target/debug/examples/telemetry-smoke"
    )
)
if not emitter.is_file():
    raise RuntimeError("Build the telemetry-smoke example before running this test")
with (
    forward("pgroles-collector", 4317) as grpc,
    forward("pgroles-collector", 8889) as prom,
):
    env = os.environ.copy()
    # Prevent an inherited signal-specific endpoint from redirecting the test.
    for key in list(env):
        if key.startswith("OTEL_"):
            del env[key]
    env.update(
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": grpc,
            "OTEL_LOGS_EXPORTER": "none",
            "OTEL_SERVICE_NAME": "pgroles-smoke",
            "OTEL_RESOURCE_ATTRIBUTES": "service.instance.id=smoke-instance,k8s.namespace.name=operators",
        }
    )
    subprocess.run([str(emitter)], env=env, check=True, timeout=60)

    def rust_exported():
        text = get(prom + "/metrics")
        assert_value(
            text,
            "pgroles_reconcile_total",
            1,
            service_name="pgroles-smoke",
            service_instance_id="smoke-instance",
            k8s_namespace_name="operators",
            service_version=version,
            result="success",
            reason="TelemetrySmoke",
        )

    eventually(rust_exported)

    # Scraping must not keep a dead producer's cumulative samples alive. Use
    # the reference configuration's real two-minute expiration, with margin
    # for batching and scheduling rather than asserting an exact deadline.
    print(
        "Waiting for the reference Collector to expire inactive samples...", flush=True
    )

    def expired():
        text = get(prom + "/metrics")
        for name, instance in [
            ("pgroles_reconcile_total", "smoke-instance"),
            ("pgroles_runtime_scheduling_lag_count", "fixture-instance"),
            ("pgroles_runtime_scheduling_lag_sum", "fixture-instance"),
        ]:
            remaining = samples(text, name, service_instance_id=instance)
            assert not remaining, ("inactive metric did not expire", name, remaining)

    eventually(expired, timeout=180)
print(
    "Actual KSM extraction, updates, deletion, Collector conversion, Rust export and metric expiration passed."
)
