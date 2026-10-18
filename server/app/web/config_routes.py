"""Configurations: aliases, firewall rules and inbound NAT (port forwards) managed from ComSense, plus
firewall groups to assign them to. Stored as policies (models.Policy) and enforced by the agent;
services/policies.py validates them and works out which firewalls get what.

Aliases, rules and port forwards are edited in forms (one row per item). The other policy types
(system settings, packages, raw config values) stay JSON documents under Advanced.

Editing and assigning always works. Configurations are only sent to firewalls while firewall
changes are enabled (CSFM_ENABLE_FIREWALL_CHANGES) and the firewall allows policies.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import Device, DeviceGroup, Organization, Policy, PolicyAssignment, PolicyType, Role, User, utcnow
from ..services.policies import TYPE_LABELS, PolicyError, desired_policies, policy_hash, validate_policy
from ..services.policy_examples import EXAMPLES
from .auth import flash, require, verify_csrf
from .routes import _ip, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
viewer = require(Role.viewer)
operator = require(Role.operator)

# (path, label, policy types shown there)
SECTIONS = [
    ("aliases", "Aliases", (PolicyType.aliases,)),
    ("rules", "Firewall rules", (PolicyType.firewall_rules,)),
    ("nat", "NAT (inbound)", (PolicyType.port_forward,)),
    ("groups", "Firewall groups", ()),
    ("advanced", "Advanced", (PolicyType.system, PolicyType.packages, PolicyType.config_set)),
]
SECTION_OF = {t: path for path, _, types in SECTIONS for t in types}
FORM_TYPES = (PolicyType.aliases, PolicyType.firewall_rules, PolicyType.port_forward)
ALIAS_FORM_TYPES = ("host", "network", "port", "url", "urltable")
RULE_PROTOCOLS = ("any", "tcp", "udp", "tcp/udp", "icmp")
NAT_PROTOCOLS = ("tcp", "udp", "tcp/udp")


def _render(request: Request, template: str, section: str, settings: Settings, **ctx: Any):
    return render(
        request, template, section=section, config_sections=SECTIONS, type_labels=TYPE_LABELS,
        changes_enabled=settings.enable_firewall_changes, **ctx,
    )


# ------------------------------------------------------------ endpoints

def endpoint_text(ep: dict[str, Any] | None) -> str:
    """{"network": "lan"} -> "lan net", {"network": "wanip"} -> "wan address", ..."""
    ep = ep or {}
    neg = "!" if ep.get("not") else ""
    if ep.get("address"):
        return neg + ep["address"]
    net = ep.get("network")
    if net == "(self)":
        return neg + "this firewall"
    if net:
        return neg + (f"{net[:-2]} address" if net.endswith("ip") else f"{net} net")
    return neg + "any"


def parse_endpoint(text: str, port: str = "") -> dict[str, Any]:
    text = text.strip()
    ep: dict[str, Any] = {}
    if text.startswith("!"):
        ep["not"] = True
        text = text[1:].strip()
    words = text.lower().split()
    if not text or text.lower() == "any":
        ep["any"] = True
    elif text.lower() == "this firewall":
        ep["network"] = "(self)"
    elif len(words) == 2 and words[1] == "net":
        ep["network"] = words[0]
    elif len(words) == 2 and words[1] == "address":
        ep["network"] = words[0] + "ip"
    else:
        ep["address"] = text
    if port.strip():
        ep["port"] = port.strip()
    return ep


# ------------------------------------------------------------ form <-> content

def _rows(form, prefix: str, fields: tuple[str, ...]) -> list[dict[str, str]]:
    """Rows of a repeated-row table. Each row posts a hidden "<prefix>row" key; checkboxes post that key."""
    keys = form.getlist(f"{prefix}row")
    columns = {f: form.getlist(f"{prefix}{f}") for f in fields}
    rows = []
    for i, key in enumerate(keys):
        row = {f: str(columns[f][i]).strip() if i < len(columns[f]) else "" for f in fields}
        row["_key"] = str(key)
        rows.append(row)
    return rows


def _checked(form, prefix: str, name: str) -> set[str]:
    return {str(v) for v in form.getlist(f"{prefix}{name}")}


def content_from_form(ptype: PolicyType, form) -> dict[str, Any]:
    if ptype == PolicyType.aliases:
        aliases = []
        for row in _rows(form, "a_", ("name", "type", "address", "descr")):
            if not row["name"] and not row["address"]:
                continue
            addresses, details = [], []
            for line in row["address"].replace(",", "\n").splitlines():
                value, _, note = line.strip().partition(" ")
                if value:
                    addresses.append(value)
                    details.append(note.strip())
            alias: dict[str, Any] = {"name": row["name"], "type": row["type"], "address": addresses,
                                     "descr": row["descr"] or "Managed by ComSense"}
            if any(details):
                alias["detail"] = details
            aliases.append(alias)
        return {"aliases": aliases, "remove_unlisted": True, "adopt_existing": form.get("adopt_existing") == "true"}

    if ptype == PolicyType.firewall_rules:
        fields = ("interface", "type", "ipprotocol", "protocol", "src", "srcport", "dst", "dstport", "descr")
        log, disabled = _checked(form, "r_", "log"), _checked(form, "r_", "disabled")
        rules = []
        for row in _rows(form, "r_", fields):
            if not row["interface"] and not row["descr"] and not row["dst"] and not row["src"]:
                continue
            rule: dict[str, Any] = {
                "interface": row["interface"].lower() or "wan",
                "type": row["type"] or "pass",
                "ipprotocol": row["ipprotocol"] or "inet",
                "protocol": row["protocol"] or "any",
                "source": parse_endpoint(row["src"], row["srcport"]),
                "destination": parse_endpoint(row["dst"], row["dstport"]),
                "descr": row["descr"],
            }
            if row["_key"] in log:
                rule["log"] = True
            if row["_key"] in disabled:
                rule["disabled"] = True
            rules.append(rule)
        return {"position": form.get("position") or "top", "rules": rules}

    if ptype == PolicyType.port_forward:
        fields = ("interface", "protocol", "src", "dst", "dstport", "target", "localport", "descr")
        disabled = _checked(form, "n_", "disabled")
        rules = []
        for row in _rows(form, "n_", fields):
            if not row["dstport"] and not row["target"] and not row["descr"]:
                continue
            rule = {
                "interface": row["interface"].lower() or "wan",
                "protocol": row["protocol"] or "tcp",
                "source": parse_endpoint(row["src"]),
                "destination": parse_endpoint(row["dst"] or "wan address", row["dstport"]),
                "target": row["target"],
                "local_port": row["localport"] or row["dstport"],
                "descr": row["descr"],
                "disabled": row["_key"] in disabled,
            }
            rules.append(rule)
        return {"position": form.get("position") or "top", "rules": rules}

    raw = str(form.get("content", ""))
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"Content is not valid JSON: {exc}") from exc


def rows_for(ptype: PolicyType, content: dict[str, Any]) -> list[dict[str, Any]]:
    """The editor's rows for stored content."""
    if ptype == PolicyType.aliases:
        rows = []
        for a in content.get("aliases", []):
            details = a.get("detail") or []
            lines = [f"{v} {details[i]}".strip() if i < len(details) else v for i, v in enumerate(a.get("address", []))]
            rows.append({"name": a.get("name", ""), "type": a.get("type", "host"), "address": "\n".join(lines),
                         "descr": a.get("descr", "")})
        return rows
    if ptype == PolicyType.firewall_rules:
        return [{
            "interface": r.get("interface", "wan"), "type": r.get("type", "pass"),
            "ipprotocol": r.get("ipprotocol", "inet"), "protocol": r.get("protocol", "any"),
            "src": endpoint_text(r.get("source")), "srcport": (r.get("source") or {}).get("port", ""),
            "dst": endpoint_text(r.get("destination")), "dstport": (r.get("destination") or {}).get("port", ""),
            "descr": r.get("descr", ""), "log": bool(r.get("log")), "disabled": bool(r.get("disabled")),
        } for r in content.get("rules", [])]
    if ptype == PolicyType.port_forward:
        return [{
            "interface": r.get("interface", "wan"), "protocol": r.get("protocol", "tcp"),
            "src": endpoint_text(r.get("source")), "dst": endpoint_text(r.get("destination") or {"network": "wanip"}),
            "dstport": (r.get("destination") or {}).get("port", ""), "target": r.get("target", ""),
            "localport": r.get("local_port", ""), "descr": r.get("descr", ""),
            "disabled": bool(r.get("disabled")),
        } for r in content.get("rules", [])]
    return []


def _interfaces(db: Session) -> list[str]:
    names = {"wan", "lan"}
    for inv in db.scalars(select(Device.inventory)):
        for iface in (inv or {}).get("interfaces", []) or []:
            name = str(iface.get("name", "")).lower()
            if name and len(name) <= 16:
                names.add(name)
    return sorted(names, key=lambda n: (n not in ("wan", "lan"), n != "wan", n))


def _get_policy(db: Session, policy_id: int) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "Configuration not found")
    return policy


def _targets(db: Session, policy: Policy) -> list[tuple[Device, bool]]:
    digest = policy_hash(policy)
    out = []
    for device in db.scalars(select(Device).order_by(Device.name)):
        if any(p.id == policy.id for p in desired_policies(db, device)):
            out.append((device, (device.applied_policies or {}).get(str(policy.id)) == digest))
    return out


def _editor(request: Request, settings: Settings, db: Session, policy: Policy | None, ptype: PolicyType,
            content: dict[str, Any], status_code: int = 200, **extra: Any):
    ctx: dict[str, Any] = dict(
        policy=policy, ptype=ptype, rows=rows_for(ptype, content), content=content,
        content_json=json.dumps(content, indent=2), interfaces=_interfaces(db),
        alias_types=ALIAS_FORM_TYPES, rule_protocols=RULE_PROTOCOLS, nat_protocols=NAT_PROTOCOLS,
        advanced_types=[t for t in PolicyType if t not in FORM_TYPES],
    )
    if policy is not None:
        ctx.update(
            targets=_targets(db, policy),
            orgs=db.scalars(select(Organization).order_by(Organization.name)).all(),
            groups=db.scalars(select(DeviceGroup).order_by(DeviceGroup.name)).all(),
            devices=db.scalars(select(Device).order_by(Device.name)).all(),
        )
    ctx.update(extra)
    response = _render(request, "configuration.html", SECTION_OF[ptype], settings, **ctx)
    response.status_code = status_code
    return response


# ------------------------------------------------------------ pages

@router.get("/configurations")
def configurations_index(user: User = Depends(viewer)):
    return redirect("/configurations/aliases")


@router.get("/policies")
def old_policies_page(user: User = Depends(viewer)):
    return redirect("/configurations/aliases")


@router.get("/policies/{policy_id:int}")
def old_policy_page(policy_id: int, user: User = Depends(viewer)):
    return redirect(f"/configurations/{policy_id}")


@router.get("/configurations/groups", response_class=HTMLResponse)
def groups_page(request: Request, settings: Settings = Depends(get_settings), user: User = Depends(viewer),
                db: Session = Depends(get_db)):
    groups = db.scalars(select(DeviceGroup).order_by(DeviceGroup.name)).all()
    counts = {g.id: len([a for a in db.scalars(select(PolicyAssignment).where(PolicyAssignment.group_id == g.id))])
              for g in groups}
    return _render(request, "config_groups.html", "groups", settings, groups=groups, assignment_counts=counts)


@router.post("/configurations/groups")
def group_create(request: Request, name: str = Form(...), description: str = Form(""),
                 user: User = Depends(operator), db: Session = Depends(get_db)):
    name = name.strip()[:128]
    if not name:
        flash(request, "Give the group a name.", "error")
        return redirect("/configurations/groups")
    group = DeviceGroup(name=name, description=description.strip())
    db.add(group)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        flash(request, "A group with that name already exists.", "error")
        return redirect("/configurations/groups")
    audit(db, user.username, "group.created", target=name, ip=_ip(request))
    db.commit()
    flash(request, "Group created. Pick its firewalls below.", "success")
    return redirect(f"/configurations/groups/{group.id}")


def _get_group(db: Session, group_id: int) -> DeviceGroup:
    group = db.get(DeviceGroup, group_id)
    if group is None:
        raise HTTPException(404, "Group not found")
    return group


@router.get("/configurations/groups/{group_id:int}", response_class=HTMLResponse)
def group_page(group_id: int, request: Request, settings: Settings = Depends(get_settings),
               user: User = Depends(viewer), db: Session = Depends(get_db)):
    group = _get_group(db, group_id)
    assignments = db.scalars(select(PolicyAssignment).where(PolicyAssignment.group_id == group.id)).all()
    devices = db.scalars(select(Device).order_by(Device.name)).all()
    return _render(request, "config_group.html", "groups", settings, group=group, devices=devices,
                   members={d.id for d in group.devices}, assignments=assignments)


@router.post("/configurations/groups/{group_id:int}")
async def group_update(group_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    group = _get_group(db, group_id)
    form = await request.form()
    name = str(form.get("name", "")).strip()[:128]
    if name and name != group.name:
        if db.scalar(select(DeviceGroup.id).where(DeviceGroup.name == name, DeviceGroup.id != group.id)):
            flash(request, "A group with that name already exists.", "error")
            return redirect(f"/configurations/groups/{group_id}")
        group.name = name
    group.description = str(form.get("description", "")).strip()
    wanted = {str(v) for v in form.getlist("device_ids")}
    group.devices = list(db.scalars(select(Device).where(Device.id.in_(wanted)))) if wanted else []
    audit(db, user.username, "group.updated", target=group.name, detail=f"{len(group.devices)} firewall(s)",
          ip=_ip(request))
    db.commit()
    flash(request, "Group saved. Its firewalls pick up the group's configurations at their next check-in.", "success")
    return redirect(f"/configurations/groups/{group_id}")


@router.post("/configurations/groups/{group_id:int}/delete")
def group_delete(group_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    group = _get_group(db, group_id)
    # Explicitly: databases upgraded in place have no foreign key on policy_assignments.group_id.
    for a in db.scalars(select(PolicyAssignment).where(PolicyAssignment.group_id == group.id)):
        db.delete(a)
    audit(db, user.username, "group.deleted", target=group.name, ip=_ip(request))
    db.delete(group)
    db.commit()
    flash(request, "Group deleted. Its firewalls remove the group's configurations at their next check-in.", "success")
    return redirect("/configurations/groups")


@router.get("/configurations/new", response_class=HTMLResponse)
def configuration_new(request: Request, type: str = "aliases", settings: Settings = Depends(get_settings),
                      user: User = Depends(operator), db: Session = Depends(get_db)):
    ptype = PolicyType(type) if type in PolicyType.__members__ else PolicyType.aliases
    content = {"position": "top", "rules": []} if ptype in (PolicyType.firewall_rules, PolicyType.port_forward) \
        else {"aliases": []} if ptype == PolicyType.aliases else EXAMPLES[ptype]
    return _editor(request, settings, db, None, ptype, content)


@router.post("/configurations")
async def configuration_create(request: Request, settings: Settings = Depends(get_settings),
                               user: User = Depends(operator), db: Session = Depends(get_db)):
    form = await request.form()
    raw_type = str(form.get("type", ""))
    if raw_type not in PolicyType.__members__:
        raise HTTPException(400, "Unknown configuration type")
    ptype = PolicyType(raw_type)
    name = str(form.get("name", "")).strip()[:128]
    description = str(form.get("description", "")).strip()
    content: dict[str, Any] = {}
    try:
        if not name:
            raise PolicyError("Give the configuration a name.")
        content = content_from_form(ptype, form)
        validate_policy(ptype, content)
    except PolicyError as exc:
        flash(request, str(exc), "error")
        return _editor(request, settings, db, None, ptype, content or {}, status_code=400, name=name,
                       description=description, raw_content=str(form.get("content", "")))
    policy = Policy(name=name, type=ptype, description=description, content=content, updated_by=user.username)
    db.add(policy)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        flash(request, "A configuration with that name already exists.", "error")
        return _editor(request, settings, db, None, ptype, content, status_code=400, name=name, description=description)
    audit(db, user.username, "policy.created", target=policy.name, ip=_ip(request))
    db.commit()
    flash(request, "Saved. Assign it to firewalls, groups or customers below.", "success")
    return redirect(f"/configurations/{policy.id}")


@router.get("/configurations/{policy_id:int}", response_class=HTMLResponse)
def configuration_page(policy_id: int, request: Request, settings: Settings = Depends(get_settings),
                       user: User = Depends(viewer), db: Session = Depends(get_db)):
    policy = _get_policy(db, policy_id)
    return _editor(request, settings, db, policy, policy.type, policy.content)


@router.post("/configurations/{policy_id:int}")
async def configuration_update(policy_id: int, request: Request, settings: Settings = Depends(get_settings),
                               user: User = Depends(operator), db: Session = Depends(get_db)):
    policy = _get_policy(db, policy_id)
    form = await request.form()
    try:
        content = content_from_form(policy.type, form)
        validate_policy(policy.type, content)
    except PolicyError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/configurations/{policy_id}")
    name = str(form.get("name", "")).strip()[:128] or policy.name
    if name != policy.name and db.scalar(select(Policy.id).where(Policy.name == name, Policy.id != policy.id)):
        flash(request, "A configuration with that name already exists.", "error")
        return redirect(f"/configurations/{policy_id}")
    if content != policy.content:
        policy.revision += 1
    policy.name = name
    policy.description = str(form.get("description", "")).strip()
    policy.content = content
    policy.enabled = form.get("enabled") == "true"
    policy.updated_at = utcnow()
    policy.updated_by = user.username
    audit(db, user.username, "policy.updated", target=policy.name, detail=f"rev={policy.revision}", ip=_ip(request))
    db.commit()
    flash(request, f"Saved revision {policy.revision}. Assigned firewalls update at their next check-in.", "success")
    return redirect(f"/configurations/{policy_id}")


@router.post("/configurations/{policy_id:int}/delete")
def configuration_delete(policy_id: int, request: Request, user: User = Depends(operator),
                         db: Session = Depends(get_db)):
    policy = _get_policy(db, policy_id)
    section = SECTION_OF[policy.type]
    audit(db, user.username, "policy.deleted", target=policy.name, ip=_ip(request))
    db.delete(policy)
    db.commit()
    flash(request, "Deleted. Firewalls remove what it created at their next check-in.", "success")
    return redirect(f"/configurations/{section}")


@router.post("/configurations/{policy_id:int}/assign")
def configuration_assign(policy_id: int, request: Request, target: str = Form(...), user: User = Depends(operator),
                         db: Session = Depends(get_db)):
    policy = _get_policy(db, policy_id)
    kind, _, ident = target.partition(":")
    q = select(PolicyAssignment.id).where(PolicyAssignment.policy_id == policy.id)
    if kind == "all":
        values: dict[str, Any] = {"all_devices": True}
        q = q.where(PolicyAssignment.all_devices.is_(True))
    elif kind == "group" and ident.isdigit() and db.get(DeviceGroup, int(ident)):
        values = {"group_id": int(ident)}
        q = q.where(PolicyAssignment.group_id == int(ident))
    elif kind == "org" and ident.isdigit() and db.get(Organization, int(ident)):
        values = {"organization_id": int(ident)}
        q = q.where(PolicyAssignment.organization_id == int(ident))
    elif kind == "device" and db.get(Device, ident):
        values = {"device_id": ident}
        q = q.where(PolicyAssignment.device_id == ident)
    else:
        raise HTTPException(400, "Invalid assignment target")
    if db.scalar(q) is not None:
        flash(request, "That assignment already exists.", "error")
        return redirect(f"/configurations/{policy_id}")
    db.add(PolicyAssignment(policy_id=policy.id, **values))
    audit(db, user.username, "policy.assigned", target=policy.name, detail=target, ip=_ip(request))
    db.commit()
    flash(request, "Assigned.", "success")
    return redirect(f"/configurations/{policy_id}")


@router.post("/assignments/{assignment_id:int}/delete")
def assignment_delete(assignment_id: int, request: Request, user: User = Depends(operator),
                      db: Session = Depends(get_db)):
    assignment = db.get(PolicyAssignment, assignment_id)
    if assignment is None:
        raise HTTPException(404, "Assignment not found")
    policy_id = assignment.policy_id
    db.delete(assignment)
    audit(db, user.username, "policy.unassigned", target=str(policy_id), ip=_ip(request))
    db.commit()
    back = request.headers.get("referer", "")
    if "/configurations/groups/" in back:
        return redirect(back[back.index("/configurations/groups/"):])
    return redirect(f"/configurations/{policy_id}")


# Last: "/configurations/<section>" would otherwise match the numeric and fixed paths above.
@router.get("/configurations/{section}", response_class=HTMLResponse)
def configurations_section(section: str, request: Request, settings: Settings = Depends(get_settings),
                           user: User = Depends(viewer), db: Session = Depends(get_db)):
    found = [s for s in SECTIONS if s[0] == section and s[2]]
    if not found:
        raise HTTPException(404, "Not found")
    _, label, types = found[0]
    policies = db.scalars(select(Policy).where(Policy.type.in_(types)).order_by(Policy.name)).all()
    return _render(request, "configurations.html", section, settings, label=label, types=types, policies=policies)
