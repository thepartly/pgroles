"""Turn examples/microservices fragments into attached PostgresPolicy objects."""
import copy, sys, yaml
repo, out = sys.argv[1], sys.argv[2]

def load(name):
    with open(f"{repo}/examples/microservices/policies/{name}.yaml") as f:
        return yaml.safe_load(f)

def strip(fragment):
    fragment = copy.deepcopy(fragment)
    fragment.pop("policy", None)
    fragment.pop("scope", None)
    for role in fragment.get("roles", []):
        role.pop("password", None)  # the operator generates or references passwords differently
    for grant in fragment.get("grants", []):
        if grant["object"].get("name") == "pgroles_test":
            grant["object"]["name"] = "appdb"
    return fragment

def policy(namespace, name, spec):
    spec = dict(spec)
    spec["databaseRef"] = {"name": "appdb", "namespace": "platform"}
    return {"apiVersion": "pgroles.io/v1alpha1", "kind": "PostgresPolicy",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}

platform = strip(load("platform"))
moved = []
teams = {}
for team in ("billing", "shipping"):
    fragment = strip(load(team))
    keep = []
    for grant in fragment["grants"]:
        # A team may only grant database access to roles it creates; the
        # platform team owns team_* roles, so their CONNECT moves there.
        if grant["object"]["type"] == "database" and grant["role"].startswith("team_"):
            moved.append(grant)
        else:
            keep.append(grant)
    fragment["grants"] = keep
    teams[team] = fragment
platform.setdefault("grants", []).extend(moved)

docs = {
  "10-platform.yaml": [policy("platform", "team-roles", platform)],
  "20-billing.yaml": [policy("billing", "billing", teams["billing"])],
  "30-shipping.yaml": [policy("shipping", "shipping", teams["shipping"])],
}
for filename, objs in docs.items():
    with open(f"{out}/{filename}", "w") as f:
        yaml.safe_dump_all(objs, f, sort_keys=False)
print("moved CONNECT grants:", [g["role"] for g in moved])
