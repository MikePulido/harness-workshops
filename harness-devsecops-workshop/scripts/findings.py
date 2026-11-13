#!/usr/bin/env python3
"""Hand the agent its raw material: this execution's scan findings and what
OSV knows about each. Nothing else.

Embedded into the `findings` Run step of the critical-fix step group, right
after the OSV scan. The agent cannot call APIs (its secrets are placeholders),
so this step makes the two network calls and writes FINDINGS_FILE:

  {"execution": "...", "min_severity": "Info", "findings": [
     {"sto_issue_id", "title", "package", "version", "ecosystem" (PyPI|npm|null),
      "severity_code", "cvss", "file_name", "locations": [{"file_name", "version"}],
      "description", "cve_ids",
      "osv": [{"id", "aliases", "summary", "introduced": [...], "fixed_in": [...]}]}]}

One entry per issue the SCANNER product reported (OSV-Scanner reports one
issue per vulnerability, so a package appears once per vulnerability), at or
above MIN_SEVERITY (default Info, every severity: the agent fixes one per run,
highest CVSS first, and each run yields the next). Sorted by CVSS. `osv` is
the OSV records behind that issue: the ones matching its CVE ids, or every
record for the package when none match. No ranking beyond that, no choice of
fix, no edit: which one line in which manifest fixes one of these is the
agent's call, and the publish step checks it.

STO fills details.libraryName/currentVersion/fileName for ingested reports;
OSV-Scanner leaves them empty and says "Package 'name@version' is vulnerable
to ..." in each occurrence, with the file as a file:// URI. Both are read.
An issue can have many occurrences (copies of a manifest, a `~=` pin
expanded to several versions): `locations` lists them nearest the repository
root first, lowest version per file, and package/version/file_name are the
first one.

It also records the workspace state (git status) to baseline.json next to
FINDINGS_FILE, so the publish step can tell the agent's change from whatever
earlier steps left behind (build output, lockfiles rewritten by an install).

Inputs: HARNESS_API_URL, HARNESS_API_KEY, HARNESS_ACCOUNT_ID, HARNESS_ORG_ID,
HARNESS_PROJECT_ID, EXECUTION_ID, SCANNER (default osv-scanner), ROOT_DIR,
FINDINGS_FILE, MIN_SEVERITY (default Info), OSV_API_URL (default
https://api.osv.dev).
Last stdout line: RESULT=<n> findings. Exit 1 only when an API call fails.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info']
NPM_FILES = {'package-lock.json', 'package.json', 'yarn.lock', 'pnpm-lock.yaml'}
PYPI_FILES = {'requirements.txt', 'Pipfile.lock', 'poetry.lock', 'pyproject.toml'}
IGNORED = ('.artifacts/', '.agent/', '.claude/')  # ours, and what the agent runtime writes for itself
MAX_FINDINGS = 50
PKG = re.compile(r"Package '(.+)@([^@']+)' is vulnerable")


class ApiError(Exception):
    pass


def http(method, url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}, **{'Content-Type': 'application/json', 'User-Agent': 'critical-fix'}))
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            status, text = res.status, res.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors='replace')
        e.close()
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return status, parsed if parsed is not None else text


def norm(name, eco):
    return re.sub(r'[-_.]+', '-', name).lower() if eco == 'PyPI' else name


def vkey(v):
    v = str(v or '').strip().lstrip('^~=<>!v ')
    nums, suffix = [], ''
    for part in re.split(r'[.\-+]', v):
        if part.isdigit() and not suffix:
            nums.append(int(part))
        else:
            suffix += part
    return (tuple(nums + [0] * (8 - len(nums))), 0 if not suffix else -1, suffix)


def strip_uri(file_name):
    return re.sub(r'^file://', '', file_name or '')


class Harness:
    def __init__(self, env):
        self.api = env.get('HARNESS_API_URL', 'https://app.harness.io').rstrip('/')
        self.key = env.get('HARNESS_API_KEY', '')
        self.scope = {'accountId': env.get('HARNESS_ACCOUNT_ID', ''), 'orgId': env.get('HARNESS_ORG_ID', ''), 'projectId': env.get('HARNESS_PROJECT_ID', '')}

    def _get(self, path, **params):
        q = urllib.parse.urlencode(dict(self.scope, **params))
        status, body = http('GET', '%s%s?%s' % (self.api, path, q), {'x-api-key': self.key})
        if status != 200:
            raise ApiError('%s -> %s %s' % (path, status, str(body)[:200]))
        return body or {}

    def issues(self, execution_id):
        out, page = [], 0
        while True:
            body = self._get('/sto/api/v2/issues', executionId=execution_id, page=page, pageSize=100)
            out += body.get('results') or []
            page += 1
            if page >= ((body.get('pagination') or {}).get('totalPages') or 1):
                return out


def ecosystem_of(file_name):
    base = os.path.basename((file_name or '').split('?')[0])
    return 'npm' if base in NPM_FILES else 'PyPI' if base in PYPI_FILES else None


def located(issue):
    """Package name and the places the scanner saw it, nearest the repository
    root first and at the lowest version per file (OSV-Scanner expands a
    `~=` pin to several versions, and a repository may hold copies of a
    manifest). STO fills details for ingested reports; OSV-Scanner puts each
    place in an occurrence message; a pkg@version title is the last resort."""
    d = issue.get('details') or {}
    name, spots = d.get('libraryName') or '', {}
    if d.get('currentVersion'):
        spots[strip_uri(d.get('fileName'))] = d['currentVersion']
    for occ in issue.get('occurrences') or []:
        m = PKG.search(occ.get('issueDescription') or '')
        if not m:
            continue
        name = name or m.group(1)
        f = strip_uri(occ.get('fileName'))
        if f not in spots or vkey(m.group(2)) < vkey(spots[f]):
            spots[f] = m.group(2)
    title = issue.get('title') or ''
    if not spots and re.fullmatch(r'\S+@[^\s@]+', title):
        name, version = title.rsplit('@', 1)
        spots[strip_uri(d.get('fileName'))] = version
    places = [{'file_name': f, 'version': v} for f, v in sorted(spots.items(), key=lambda kv: (kv[0].count('/'), kv[0]))]
    return name, places


def cve_ids(issue):
    refs = list((issue.get('details') or {}).get('referenceIdentifiers') or [])
    for occ in issue.get('occurrences') or []:
        refs += occ.get('referenceIdentifiers') or []
    out = set()
    for r in refs:
        if isinstance(r, dict) and str(r.get('type', '')).lower() == 'cve' and r.get('id'):
            i = str(r['id'])
            out.add(i if i.upper().startswith('CVE-') else 'CVE-' + i)
    return sorted(out)


def osv_record(osv_url, name, eco, version):
    """What OSV knows about name@version: each vulnerability with the versions
    that introduce and fix it for this package. Raw facts, trimmed."""
    status, body = http('POST', osv_url.rstrip('/') + '/v1/query', body={'package': {'name': name, 'ecosystem': eco}, 'version': version})
    if status != 200:
        raise ApiError('OSV %s for %s %s: %s' % (status, name, version, str(body)[:200]))
    out = []
    for v in (body or {}).get('vulns') or []:
        introduced, fixed = [], []
        for aff in v.get('affected') or []:
            p = aff.get('package') or {}
            if p.get('ecosystem') != eco or norm(p.get('name', ''), eco) != norm(name, eco):
                continue
            for rng in aff.get('ranges') or []:
                for ev in rng.get('events') or []:
                    if ev.get('introduced') is not None:
                        introduced.append(ev['introduced'])
                    if ev.get('fixed'):
                        fixed.append(ev['fixed'])
        out.append({'id': v.get('id'), 'aliases': v.get('aliases') or [], 'summary': (v.get('summary') or v.get('details') or '')[:200], 'introduced': introduced, 'fixed_in': fixed})
    return out


def osv_lookup(osv_url):
    """One OSV query per package@version, however many issues name it."""
    seen = {}

    def lookup(name, eco, version):
        key = (norm(name, eco), eco, version)
        if key not in seen:
            seen[key] = osv_record(osv_url, name, eco, version)
        return seen[key]
    return lookup


def finding(issue, lookup):
    d = issue.get('details') or {}
    name, places = located(issue)
    version, file_name = (places[0]['version'], places[0]['file_name']) if places else ('', '')
    eco = ecosystem_of(file_name)
    cves = set(cve_ids(issue))
    records = lookup(name, eco, version) if name and version and eco else []
    behind = [v for v in records if cves & ({v['id']} | set(v['aliases']))]
    return {'sto_issue_id': issue.get('id'), 'title': issue.get('title') or '', 'package': name, 'version': version, 'ecosystem': eco,
            'severity_code': issue.get('severityCode'), 'cvss': issue.get('severity'), 'file_name': file_name, 'locations': places,
            'description': (d.get('issueDescription') or '')[:600], 'cve_ids': sorted(cves), 'osv': behind or records}


def baseline(root):
    """What is already dirty before the agent runs: untracked paths, and
    modified tracked files with their current content hash."""
    out = {'untracked': [], 'modified': {}}
    r = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root, capture_output=True, text=True)
    if r.returncode != 0:
        return out
    for ln in r.stdout.splitlines():
        if len(ln) < 4:
            continue
        code, path = ln[:2], ln[3:].strip()
        if path.startswith(IGNORED):
            continue
        if code == '??':
            out['untracked'].append(path)
        else:
            h = subprocess.run(['git', 'hash-object', '--', path], cwd=root, capture_output=True, text=True)
            out['modified'][path] = h.stdout.strip() if h.returncode == 0 else ''
    return out


def run(env, out=print):
    out_file = env.get('FINDINGS_FILE') or '/harness/.artifacts/fix/findings.json'
    root = env.get('ROOT_DIR', '/harness')
    min_sev = env.get('MIN_SEVERITY', 'Info')  # Info keeps every severity: one fix per run, highest CVSS first
    keep = set(SEVERITIES[:SEVERITIES.index(min_sev) + 1]) if min_sev in SEVERITIES else {min_sev}
    execution = env.get('EXECUTION_ID', '')
    scanner = env.get('SCANNER', 'osv-scanner')
    issues = Harness(env).issues(execution)
    mine = [i for i in issues if (i.get('details') or {}).get('productName') == scanner]
    out('%d issues in execution %s; %d from %s' % (len(issues), execution, len(mine), scanner))
    if mine:
        issues = mine
    else:
        out('warning: no issue from %s; using every issue of the execution' % scanner)
    issues = [i for i in issues if i.get('severityCode') in keep]
    issues.sort(key=lambda i: (-float(i.get('severity') or 0), i.get('title') or ''))
    lookup = osv_lookup(env.get('OSV_API_URL', 'https://api.osv.dev'))
    findings = [finding(i, lookup) for i in issues[:MAX_FINDINGS]]
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, 'w', encoding='utf-8') as fh:
        json.dump({'execution': execution, 'generated': int(time.time()), 'min_severity': min_sev, 'findings': findings}, fh, indent=2)
    for f in findings:
        fixed = sorted({x for v in f['osv'] for x in v['fixed_in']})
        where = (f['file_name'] or '')[-26:] + (' +%d' % (len(f['locations']) - 1) if len(f['locations']) > 1 else '')
        out('%-8s %-32s %-16s %-29s fixed in: %s' % (f['severity_code'] or '', '%s@%s' % (f['package'], f['version']), (f['cve_ids'] or [''])[0], where, ', '.join(fixed) or 'nothing known'))
    before = baseline(root)
    with open(os.path.join(os.path.dirname(out_file), 'baseline.json'), 'w', encoding='utf-8') as fh:
        json.dump(before, fh, indent=2)
    out('baseline: %d untracked and %d modified path(s) already in the workspace; publish ignores them' % (len(before['untracked']), len(before['modified'])))
    out('RESULT=%d findings (%s) written to %s' % (len(findings), 'all severities' if min_sev == 'Info' else min_sev + ' and above', out_file))
    return 0


def main():
    try:
        return run(os.environ)
    except ApiError as e:
        print('RESULT=error %s' % e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
