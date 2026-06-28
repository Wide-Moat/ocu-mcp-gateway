#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# IaC-policy gate for invariant #4 NETWORK half (NFR-SEC-52): assert the rendered
# deploy manifests grant the MCP gateway NO network route to the operator ingress
# on EITHER shelf. Deny-by-default: fails CLOSED if a manifest is missing or
# unparseable, and fails if any rule would permit gateway->operator.
#
# Structural YAML parsing (not regex) so a comment that merely mentions the
# operator label is never a false positive, and a real egress peer / network
# membership is never missed. Uses PyYAML if present, else a vendored minimal
# parse fallback is avoided by requiring PyYAML in CI (ubuntu-latest ships it via
# pip; the workflow installs it pinned).
#
# Two-sided red-probe: `--self-test` copies each manifest, plants an operator
# route, and asserts the checks go RED.
import sys
import os
import copy

try:
    import yaml
except ImportError:
    print("::error::iac-policy: PyYAML not available; cannot parse manifests (fail-closed)", file=sys.stderr)
    sys.exit(1)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K8S_NP = os.path.join(ROOT, "deploy", "k8s", "networkpolicy.yaml")
COMPOSE = os.path.join(ROOT, "deploy", "compose", "docker-compose.yaml")

OPERATOR_INGRESS_LABEL = ("ocu.dev/ingress", "operator")
OPERATOR_NETWORK = "ocu-operator-net"
GATEWAY_SERVICE = "ocu-mcp-gateway"


def fail(msg):
    print(f"::error::iac-policy: {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    if not os.path.isfile(path):
        fail(f"manifest not found at {path} (fail-closed)")
    with open(path) as f:
        try:
            # KNOWN LIMITATION: single-document parse. The shipped manifests are
            # single-document. A multi-document YAML (`---`-separated) makes
            # safe_load raise a ComposerError, which fails CLOSED here (a parse
            # error reds the gate) — so a second operator-egress document does NOT
            # bypass the gate; it is refused as unparseable rather than detected.
            # If multi-document manifests are ever legitimized, switch to
            # `yaml.safe_load_all` and iterate every document so a benign second
            # document does not give a false RED.
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            fail(f"manifest {path} is not parseable YAML (fail-closed): {e}")


def k8s_permits_operator(doc):
    """Return True if any egress peer selects the operator ingress label."""
    spec = (doc or {}).get("spec", {}) or {}
    for rule in spec.get("egress", []) or []:
        for peer in rule.get("to", []) or []:
            for sel_key in ("podSelector", "namespaceSelector"):
                sel = peer.get(sel_key) or {}
                if _selector_targets_operator(sel):
                    return True
    return False


def _selector_targets_operator(sel):
    """Return True if a k8s label selector targets the operator ingress.

    A k8s podSelector/namespaceSelector supports BOTH `matchLabels` (an equality
    map) AND `matchExpressions` (a list of {key, operator, values}). Reading only
    matchLabels would be a selector-island: an operator egress written as
    `matchExpressions: [{key: ocu.dev/ingress, operator: In, values: [operator]}]`
    is the SAME gateway->operator route and must be caught (NFR-SEC-52).
    """
    key, val = OPERATOR_INGRESS_LABEL

    # matchLabels: an equality map.
    labels = sel.get("matchLabels") or {}
    if labels.get(key) == val:
        return True

    # matchExpressions: list of set-based requirements.
    for expr in sel.get("matchExpressions") or []:
        if expr.get("key") != key:
            continue
        op = expr.get("operator")
        values = expr.get("values") or []
        # `In [..., operator, ...]` selects the operator ingress.
        if op == "In" and val in values:
            return True
        # `Exists` on the operator-ingress key selects every pod that carries it,
        # including the operator ingress — treat as a match (fail-closed).
        if op == "Exists":
            return True
        # KNOWN LIMITATION: a `NotIn`/`DoesNotExist` requirement that excludes
        # everything EXCEPT the operator ingress would semantically select it too,
        # but that inversion is not decidable from this rule alone (it depends on
        # the cluster's full label space). It is not flagged here; an operator
        # route is realistically expressed as In/Exists/matchLabels, all of which
        # ARE caught. Documented so the gap is declared, not silent.
    return False


def compose_gateway_joins_operator(doc):
    """Return True if the gateway service joins the operator network."""
    services = (doc or {}).get("services", {}) or {}
    gw = services.get(GATEWAY_SERVICE) or {}
    nets = gw.get("networks") or []
    # networks may be a list or a mapping (compose supports both forms).
    if isinstance(nets, dict):
        names = list(nets.keys())
    else:
        names = list(nets)
    return OPERATOR_NETWORK in names


def assert_k8s_wellformed(doc):
    """Positive structural assertion (CR#3 fail-open fix): the gate must NOT pass
    on an empty/None/structureless manifest. A manifest that does not even carry
    the expected gateway NetworkPolicy shape is no proof of deny-by-default — it
    fails CLOSED rather than passing by absence. Required: a NetworkPolicy kind, a
    podSelector targeting the gateway, and an Egress policyType (the deny-by-default
    egress posture this gate reasons about)."""
    if not isinstance(doc, dict) or not doc:
        fail("k8s manifest is empty or not a mapping; no proof of deny-by-default (fail-closed)")
    if doc.get("kind") != "NetworkPolicy":
        fail("k8s manifest is not a NetworkPolicy; the gateway egress posture is unproven (fail-closed)")
    spec = doc.get("spec") or {}
    sel_labels = ((spec.get("podSelector") or {}).get("matchLabels")) or {}
    if sel_labels.get("app.kubernetes.io/name") != "ocu-mcp-gateway":
        fail("k8s NetworkPolicy podSelector does not target the gateway; posture unproven (fail-closed)")
    if "Egress" not in (spec.get("policyTypes") or []):
        fail("k8s NetworkPolicy declares no Egress policyType; egress is not deny-by-default (fail-closed)")


def assert_compose_wellformed(doc):
    """Positive structural assertion (CR#3): the Compose manifest must carry the
    gateway service with an explicit networks list, or there is no proof the
    gateway is off the operator network — fail CLOSED rather than pass by absence."""
    if not isinstance(doc, dict) or not doc:
        fail("Compose manifest is empty or not a mapping; gateway network membership unproven (fail-closed)")
    services = doc.get("services") or {}
    gw = services.get(GATEWAY_SERVICE)
    if not isinstance(gw, dict):
        fail(f"Compose manifest has no {GATEWAY_SERVICE} service; network membership unproven (fail-closed)")
    if not gw.get("networks"):
        fail(f"Compose {GATEWAY_SERVICE} declares no networks; membership unproven (fail-closed)")


def check_all():
    k8s = load(K8S_NP)
    compose = load(COMPOSE)
    # Positive structural assertions FIRST (fail-closed on an empty/malformed
    # manifest), so the gate cannot pass by absence of an operator route on a
    # manifest that proves nothing.
    assert_k8s_wellformed(k8s)
    assert_compose_wellformed(compose)
    if k8s_permits_operator(k8s):
        fail("k8s NetworkPolicy egress permits the operator ingress (gateway->operator route); NFR-SEC-52 violated")
    if compose_gateway_joins_operator(compose):
        fail(f"Compose gateway service joins {OPERATOR_NETWORK} (gateway->operator route); NFR-SEC-52 violated")
    print("iac-policy: gateway has no network route to the operator ingress on either shelf (NFR-SEC-52)")


def self_test():
    key, val = OPERATOR_INGRESS_LABEL

    # k8s neuter: plant an operator egress in EVERY selector form a real manifest
    # could use. A two-sided red-probe MUST cover every form the gate claims to
    # check, or it is green-by-omission for the form it does not itself plant
    # (this is exactly the matchExpressions selector-island that slipped through
    # an earlier matchLabels-only self-test). Each form is planted in isolation
    # and must be independently detected.
    k8s_neuters = {
        "matchLabels": {"to": [{"podSelector": {"matchLabels": {key: val}}}]},
        "matchExpressions In": {"to": [{"podSelector": {"matchExpressions": [
            {"key": key, "operator": "In", "values": [val]}]}}]},
        "matchExpressions Exists": {"to": [{"podSelector": {"matchExpressions": [
            {"key": key, "operator": "Exists"}]}}]},
        "namespaceSelector matchExpressions In": {"to": [{"namespaceSelector": {"matchExpressions": [
            {"key": key, "operator": "In", "values": [val]}]}}]},
    }
    for form, egress_rule in k8s_neuters.items():
        np = copy.deepcopy(load(K8S_NP))
        np.setdefault("spec", {}).setdefault("egress", []).append(egress_rule)
        if not k8s_permits_operator(np):
            print(f"::error::self-test: k8s check did NOT detect a planted operator egress via {form} "
                  f"(gate is a no-op / selector-island for this form)", file=sys.stderr)
            sys.exit(1)

    # Compose neuter: join the operator network.
    cp = copy.deepcopy(load(COMPOSE))
    gw = cp["services"][GATEWAY_SERVICE]
    nets = gw.get("networks") or []
    if isinstance(nets, dict):
        nets[OPERATOR_NETWORK] = None
    else:
        nets = list(nets) + [OPERATOR_NETWORK]
    gw["networks"] = nets
    if not compose_gateway_joins_operator(cp):
        print("::error::self-test: Compose check did NOT detect a planted operator network (gate is a no-op)", file=sys.stderr)
        sys.exit(1)

    # CR#3 fail-open red-probe: an empty/None/structureless manifest must FAIL the
    # positive structural assertion (fail-closed), not pass by absence. Each
    # neuter must raise SystemExit (fail() exits non-zero).
    empties = {
        "k8s None": (assert_k8s_wellformed, None),
        "k8s empty dict": (assert_k8s_wellformed, {}),
        "k8s not-NetworkPolicy": (assert_k8s_wellformed, {"kind": "Pod"}),
        "k8s no-Egress": (assert_k8s_wellformed,
                          {"kind": "NetworkPolicy",
                           "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "ocu-mcp-gateway"}},
                                    "policyTypes": ["Ingress"]}}),
        "compose None": (assert_compose_wellformed, None),
        "compose no-gateway": (assert_compose_wellformed, {"services": {}}),
    }
    for name, (fn, doc) in empties.items():
        try:
            fn(doc)
        except SystemExit:
            continue  # correctly failed closed
        print(f"::error::self-test: structural assertion did NOT fail closed on {name} "
              f"(empty/malformed manifest would PASS the gate — fail-open)", file=sys.stderr)
        sys.exit(1)

    # And the un-neutered manifests must PASS (the gate is not stuck-red either),
    # INCLUDING the positive structural assertions.
    assert_k8s_wellformed(load(K8S_NP))
    assert_compose_wellformed(load(COMPOSE))
    if k8s_permits_operator(load(K8S_NP)):
        print("::error::self-test: shipped k8s manifest unexpectedly flagged (false positive)", file=sys.stderr)
        sys.exit(1)
    if compose_gateway_joins_operator(load(COMPOSE)):
        print("::error::self-test: shipped Compose manifest unexpectedly flagged (false positive)", file=sys.stderr)
        sys.exit(1)

    print("iac-policy self-test: selector forms + empty-manifest fail-open all RED-when-neutered, GREEN-as-shipped")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
    else:
        check_all()
