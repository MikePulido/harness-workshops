"""Unit tests for findings.py and publish.py, the scripts install.py embeds
into the critical-fix step group, and for install.py's rendering.

  python3 -m unittest discover -s harness-devsecops-workshop/scripts -p 'test_*.py'
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import findings as fnd  # noqa: E402
import publish as pub  # noqa: E402
import install  # noqa: E402

REQUIREMENTS = 'asgiref==3.7.2\nDjango~=5.0.3\nsqlparse==0.4.2\n'
PACKAGE_JSON = {'name': 'web', 'dependencies': {'@angular/ssr': '^17.1.1', 'rxjs': '~7.8.0'}}
PACKAGE_LOCK = {'lockfileVersion': 3, 'packages': {'node_modules/@angular/ssr': {'version': '17.3.12'}, 'node_modules/tar': {'version': '6.1.11'}}}


def issue(name, version, file_name, sev='Critical', cvss=9.8, cves=()):
    """An ingested report's issue (OWASP here): STO fills details."""
    return {'id': 'i-' + name, 'title': '%s@%s' % (name, version), 'severityCode': sev, 'severity': cvss, 'productId': 'P0',
            'details': {'libraryName': name, 'currentVersion': version, 'fileName': file_name, 'productName': 'owasp',
                        'issueDescription': 'desc of %s' % name, 'referenceIdentifiers': [{'id': c.replace('CVE-', ''), 'type': 'cve'} for c in cves]}}


def osv_issue(name, version, file_name, cve, sev='Critical', cvss=9.8, places=None):
    """An OSV-Scanner issue as STO stores it: one per vulnerability, a CVE
    title, no libraryName/currentVersion/fileName; package and file are only
    in the occurrences, one per place (file, version) in no fixed order."""
    def text(v):
        return "Package '%s@%s' is vulnerable to '%s' (also known as 'GHSA-x')." % (name, v, cve)
    refs = [{'id': cve.replace('CVE-', ''), 'type': 'cve'}, {'id': 'x', 'type': 'ghsa'}]
    title = '%s: %s does something bad' % (cve, name)
    return {'id': 'i-%s-%s' % (name, cve), 'title': title, 'severityCode': sev, 'severity': cvss, 'productId': 'P1',
            'details': {'productName': 'osv-scanner', 'title': title, 'issueDescription': text(version), 'referenceIdentifiers': refs},
            'occurrences': [{'fileName': 'file://' + f, 'issueDescription': text(v), 'referenceIdentifiers': refs} for f, v in (places or [(file_name, version)])]}


# What OSV-Scanner reports for `Django~=5.0.3` in a repository that also
# holds a copy of the manifest: both files, the pin and the top of its range.
DJANGO_PLACES = [('/harness/python-tests/backend/requirements.txt', '5.0.9'), ('/harness/python-tests/backend/requirements.txt', '5.0.3'),
                 ('/harness/backend/requirements.txt', '5.0.9'), ('/harness/backend/requirements.txt', '5.0.3')]


def vuln(vid, aliases, name, eco, fixed):
    return {'id': vid, 'aliases': aliases, 'summary': 'summary of ' + vid,
            'affected': [{'package': {'name': name, 'ecosystem': eco}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}] + [{'fixed': f} for f in fixed]}]}]}


# Keyed by lowercase name: the findings step queries with the scanner's
# spelling (django), the publish step with the manifest's (Django).
OSV = {
    ('django', '5.0.3'): [vuln('GHSA-A', ['CVE-2024-42005'], 'django', 'PyPI', ['4.2.15', '5.0.8']), vuln('GHSA-B', ['CVE-2024-99999'], 'django', 'PyPI', ['5.1.2'])],
    ('django', '5.0.5'): [vuln('GHSA-A', ['CVE-2024-42005'], 'django', 'PyPI', ['4.2.15', '5.0.8']), vuln('GHSA-B', ['CVE-2024-99999'], 'django', 'PyPI', ['5.1.2'])],
    ('django', '5.0.8'): [vuln('GHSA-B', ['CVE-2024-99999'], 'django', 'PyPI', ['5.1.2'])],
    ('django', '5.1.2'): [],
    ('@angular/ssr', '17.3.12'): [vuln('GHSA-C', ['CVE-2025-59052'], '@angular/ssr', 'npm', ['19.2.28'])],
    ('tar', '6.1.11'): [vuln('GHSA-D', ['CVE-2024-28863'], 'tar', 'npm', ['6.2.1'])],
    ('sqlparse', '0.4.2'): [vuln('GHSA-E', [], 'sqlparse', 'PyPI', ['0.4.4'])],
    ('sqlparse', '0.4.4'): [],
}


class Fake(BaseHTTPRequestHandler):
    calls = []

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path.split('?')[0]
        Fake.calls.append(('GET', p))
        if p == '/sto/api/v2/issues':
            return self._send(200, {'pagination': {'totalPages': 1}, 'results': [
                osv_issue('sqlparse', '0.4.2', '/harness/backend/requirements.txt', 'CVE-2023-30608', cvss=9.0),
                osv_issue('django', '5.0.3', '/harness/backend/requirements.txt', 'CVE-2024-42005', places=DJANGO_PLACES),
                osv_issue('django', '5.0.3', '/harness/backend/requirements.txt', 'CVE-2024-99999', sev='High', cvss=7.5, places=DJANGO_PLACES),
                osv_issue('@angular/ssr', '17.3.12', '/harness/frontend/package-lock.json', 'CVE-2025-59052', cvss=9.9),
                osv_issue('tar', '6.1.11', '/harness/frontend/package-lock.json', 'CVE-2024-28863', cvss=9.1),
                osv_issue('rxjs', '7.8.1', '/harness/frontend/package-lock.json', 'CVE-2024-00001', sev='High', cvss=7.4),
                issue('cryptiles', '0.2.2', '/code/package-lock.json?cryptiles'),
            ]})
        if p.startswith('/code/api/v1/repos/') and p.endswith('/pullreq'):
            return self._send(200, [])
        if p.startswith('/code/api/v1/repos/'):
            return self._send(200, {'identifier': p.split('/')[5]})
        self._send(404, {'message': 'no route ' + p})

    def do_POST(self):
        p = self.path.split('?')[0]
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0)) or b'{}') or '{}')
        Fake.calls.append(('POST', p, body))
        if p == '/v1/query':
            return self._send(200, {'vulns': OSV.get((body['package']['name'].lower(), body['version']), [])})
        if p.endswith('/pullreq'):
            return self._send(201, {'number': 7})
        self._send(404, {'message': 'no route ' + p})


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), Fake)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.api = 'http://127.0.0.1:%d' % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Fake.calls = []
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, 'backend'))
        os.makedirs(os.path.join(self.root, 'frontend'))
        with open(os.path.join(self.root, 'backend', 'requirements.txt'), 'w') as fh:
            fh.write(REQUIREMENTS)
        with open(os.path.join(self.root, 'frontend', 'package.json'), 'w') as fh:
            json.dump(PACKAGE_JSON, fh, indent=2)
        with open(os.path.join(self.root, 'frontend', 'package-lock.json'), 'w') as fh:
            json.dump(PACKAGE_LOCK, fh, indent=2)
        for args in (['init', '-q', '-b', 'main'], ['add', '-A'], ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', 'init']):
            subprocess.run(['git'] + args, cwd=self.root, check=True, capture_output=True)
        self.out_dir = os.path.join(self.root, '.artifacts', 'fix')
        self.lines = []
        self.env = {'ROOT_DIR': self.root, 'OUTPUT_DIR': self.out_dir, 'FINDINGS_FILE': os.path.join(self.out_dir, 'findings.json'),
                    'EXECUTION_ID': 'exec1', 'HARNESS_API_URL': self.api, 'OSV_API_URL': self.api, 'HARNESS_API_KEY': 'pat.' + 'x' * 40,
                    'HARNESS_ACCOUNT_ID': 'acct', 'HARNESS_ORG_ID': 'o', 'HARNESS_PROJECT_ID': 'p', 'HARNESS_REPO': 'harness-devsecops',
                    'HARNESS_GIT_URL': 'https://git.example.invalid/acct/o/p/harness-devsecops.git', 'HARNESS_GIT_USERNAME': 'u@example.invalid',
                    'PIPELINE_ID': 'workshop', 'PIPELINE_URL': 'https://app/exec/1', 'RUN_SEQUENCE': '12', 'BASE_BRANCH': 'main'}

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def findings(self):
        self.assertEqual(fnd.run(self.env, out=self.lines.append), 0)
        with open(self.env['FINDINGS_FILE']) as fh:
            return json.load(fh)['findings']

    def edit(self, rel, old, new):
        p = os.path.join(self.root, rel)
        with open(p) as fh:
            text = fh.read()
        self.assertIn(old, text)
        with open(p, 'w') as fh:
            fh.write(text.replace(old, new, 1))

    def publish(self, dry=True):
        env = dict(self.env, DRY_RUN='1') if dry else self.env
        return pub.run(env, out=self.lines.append)

    def leave_behind(self):
        """What Compile and Test leave in the workspace before the agent runs."""
        for rel in ('frontend/node_modules/left/index.js', 'frontend/dist/main.js'):
            os.makedirs(os.path.dirname(os.path.join(self.root, rel)), exist_ok=True)
            with open(os.path.join(self.root, rel), 'w') as fh:
                fh.write('// build output\n')
        with open(os.path.join(self.root, 'frontend', 'package-lock.json'), 'a') as fh:
            fh.write('\n')


class FindingsTests(Base):
    def test_dumps_the_scanner_findings_with_osv_facts_and_no_judgement(self):
        f = self.findings()
        self.assertEqual([x['package'] for x in f], ['@angular/ssr', 'django', 'tar', 'sqlparse', 'django', 'rxjs'], 'one entry per vulnerability, highest CVSS first, every severity; the other scanner\'s issues dropped')
        dj, dj2 = [x for x in f if x['package'] == 'django']
        self.assertEqual((dj['version'], dj['ecosystem'], dj['file_name'], dj['cve_ids']), ('5.0.3', 'PyPI', '/harness/backend/requirements.txt', ['CVE-2024-42005']),
                         'package, version and file come from the occurrences, not the CVE title: nearest the root, lowest version')
        self.assertEqual(dj['locations'], [{'file_name': '/harness/backend/requirements.txt', 'version': '5.0.3'},
                                           {'file_name': '/harness/python-tests/backend/requirements.txt', 'version': '5.0.3'}])
        self.assertEqual([(v['id'], v['fixed_in']) for v in dj['osv']], [('GHSA-A', ['4.2.15', '5.0.8'])], 'only the OSV records behind this vulnerability')
        self.assertEqual([v['id'] for v in dj2['osv']], ['GHSA-B'])
        self.assertEqual([v['id'] for v in next(x for x in f if x['package'] == 'sqlparse')['osv']], ['GHSA-E'], 'ids OSV does not know: every record for the package')
        self.assertEqual(len([c for c in Fake.calls if c[1] == '/v1/query' and c[2]['package']['name'] == 'django']), 1, 'one OSV query per package@version')
        self.assertNotIn(('GET', '/sto/api/v2/scans'), Fake.calls)
        for key in ('fixable', 'fix_version', 'manifest', 'new_line', 'rank'):
            self.assertNotIn(key, dj, 'the choice is the agent\'s, not the script\'s')
        self.assertTrue(self.lines[-1].startswith('RESULT=6 findings (all severities)'), self.lines[-1])
        self.assertEqual(fnd.run(dict(self.env, MIN_SEVERITY='Critical'), out=self.lines.append), 0)
        self.assertTrue(self.lines[-1].startswith('RESULT=4 findings (Critical and above)'), self.lines[-1])

    def test_unknown_scanner_falls_back_to_every_issue(self):
        self.assertEqual(fnd.run(dict(self.env, SCANNER='nope'), out=self.lines.append), 0)
        self.assertTrue(any(l.startswith('warning: no issue from nope') for l in self.lines), self.lines)
        self.assertTrue(self.lines[-1].startswith('RESULT=7 findings'), self.lines[-1])

    def test_records_what_the_workspace_already_contains(self):
        self.leave_behind()
        self.findings()
        with open(os.path.join(self.out_dir, 'baseline.json')) as fh:
            b = json.load(fh)
        self.assertEqual(b['untracked'], ['frontend/dist/main.js', 'frontend/node_modules/left/index.js'])
        self.assertEqual(list(b['modified']), ['frontend/package-lock.json'])


class PublishTests(Base):
    def test_smallest_fix_for_the_scanner_cve_is_verified_and_opened(self):
        self.findings()
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=5.0.8')
        with open(os.path.join(self.out_dir, 'summary.md'), 'w') as fh:
            fh.write('Bumped Django.\n')
        original = pub.push
        pub.push = lambda root, branch, backend: 'origin'
        try:
            code, doc = self.publish(dry=False)
        finally:
            pub.push = original
        self.assertEqual((code, doc['action'], doc['branch']), (0, 'opened', 'agent/fix/django/12'), doc)
        self.assertTrue(doc['pr_url'].endswith('/repos/harness-devsecops/pulls/7'))
        self.assertEqual((doc['verification']['closed'], doc['verification']['remaining_vulns']), (['GHSA-A'], 1), 'GHSA-B stays open for 5.0.8 and is reported, not hidden')
        pr = [c for c in Fake.calls if c[0] == 'POST' and c[1].endswith('/pullreq')][-1][2]
        self.assertEqual(pr['source_branch'], 'agent/fix/django/12')
        self.assertIn('Bumped Django.', pr['description'])
        self.assertIn('sqlparse@0.4.2', pr['description'], 'the other findings are listed as still open')
        still_open = next(l for l in pr['description'].splitlines() if l.startswith('**Still open:**'))
        self.assertNotIn('django@5.0.3', still_open, 'the fixed package is not listed as still open; the OSV remaining count covers it')
        self.assertEqual(subprocess.run(['git', 'log', '-1', '--format=%s'], cwd=self.root, capture_output=True, text=True).stdout.strip(), 'fix(deps): Django 5.0.3 -> 5.0.8')

    def test_ids_osv_does_not_know_must_clear_every_osv_entry(self):
        self.findings()
        self.edit('backend/requirements.txt', 'sqlparse==0.4.2', 'sqlparse==0.4.4')
        code, doc = self.publish()
        self.assertEqual((code, doc['action'], doc['verification']['closed']), (0, 'opened', ['GHSA-E']), doc)
        self.assertIn('the agent wrote no summary.md', doc['reasons'])

    def test_what_earlier_steps_left_behind_does_not_block(self):
        self.leave_behind()
        self.findings()
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=5.0.8')
        code, doc = self.publish()
        self.assertEqual((code, doc['action'], doc['files']), (0, 'opened', ['backend/requirements.txt']), doc)

    def test_agent_runtime_scaffolding_is_not_the_agents_doing(self):
        self.findings()
        for rel in ('.claude/skills/__init__.py', '.agent/output/agent-combined-out.txt'):
            os.makedirs(os.path.dirname(os.path.join(self.root, rel)), exist_ok=True)
            with open(os.path.join(self.root, rel), 'w') as fh:
                fh.write('runtime\n')
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=5.0.8')
        code, doc = self.publish()
        self.assertEqual((code, doc['action'], doc['files']), (0, 'opened', ['backend/requirements.txt']), doc)

    def test_files_created_by_the_agent_block(self):
        self.findings()
        with open(os.path.join(self.root, 'backend', 'notes.txt'), 'w') as fh:
            fh.write('scratch\n')
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=5.0.8')
        code, doc = self.publish()
        self.assertEqual((code, doc['action']), (1, 'blocked'))
        self.assertIn('new files were created: backend/notes.txt', doc['reasons'][0])

    def test_still_vulnerable_blocked(self):
        self.findings()
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=5.0.5')
        code, doc = self.publish()
        self.assertEqual((code, doc['action']), (1, 'blocked'))
        self.assertIn('still affected by GHSA-A', doc['reasons'][0])

    def test_two_lines_blocked(self):
        self.findings()
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=5.0.8')
        self.edit('backend/requirements.txt', 'sqlparse==0.4.2', 'sqlparse==0.4.4')
        code, doc = self.publish()
        self.assertEqual((code, doc['action']), (1, 'blocked'))
        self.assertIn('exactly one line', doc['reasons'][0])

    def test_two_files_blocked(self):
        self.findings()
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=5.0.8')
        self.edit('frontend/package.json', '"rxjs": "~7.8.0"', '"rxjs": "~7.8.2"')
        code, doc = self.publish()
        self.assertEqual((code, doc['action']), (1, 'blocked'))
        self.assertIn('2 files changed', doc['reasons'][0])

    def test_package_that_is_not_a_finding_blocked(self):
        self.findings()
        self.edit('backend/requirements.txt', 'asgiref==3.7.2', 'asgiref==3.8.1')
        code, doc = self.publish()
        self.assertEqual((code, doc['action']), (1, 'blocked'))
        self.assertIn("not one of the scanner's findings", doc['reasons'][0])

    def test_downgrade_or_rename_blocked(self):
        self.findings()
        self.edit('backend/requirements.txt', 'Django~=5.0.3', 'Django~=4.2.15')
        code, doc = self.publish()
        self.assertEqual((code, doc['action']), (1, 'blocked'))
        self.assertIn('not an upgrade', doc['reasons'][0])

    def test_no_change_is_none(self):
        self.findings()
        with open(os.path.join(self.out_dir, 'summary.md'), 'w') as fh:
            fh.write('Nothing qualifies: every critical is transitive.\n')
        code, doc = self.publish(dry=False)
        self.assertEqual((code, doc['action'], doc['reasons'], doc['summary']), (0, 'none', ['the agent changed nothing'], 'Nothing qualifies: every critical is transitive.'))


class InstallTests(unittest.TestCase):
    def test_render_embeds_both_scripts_and_leaves_no_tokens(self):
        s = install.settings({'HARNESS_ACCOUNT_ID': 'acct', 'HARNESS_API_KEY': 'k', 'HARNESS_ORG_ID': 'o', 'HARNESS_PROJECT_ID': 'p', 'HARNESS_GIT_USERNAME': 'u@example.invalid'})
        y = install.render(s)
        self.assertIn("python3 - <<'FINDINGS_PY'\n              #!/usr/bin/env python3", y)
        self.assertIn("python3 - <<'PUBLISH_PY'\n              #!/usr/bin/env python3", y)
        self.assertIn('\n              FINDINGS_PY\n', y)
        self.assertIn('\n              PUBLISH_PY\n', y)
        self.assertIn('agentName: devsecops_critical_fix', y)
        self.assertIn('identifier: devsecops_critical_fix_loop', y)
        self.assertNotEqual(s['template'], s['agent'], 'the agent is stored as a Step template under its own identifier')
        self.assertIn('HARNESS_GIT_URL: https://git.harness.io/acct/o/p/harness-devsecops.git', y)
        self.assertNotIn('{{', y)
        for name in ('findings.py', 'publish.py'):
            with open(os.path.join(HERE, name)) as fh:
                self.assertNotIn('{{', fh.read())

    def test_lab_yaml_is_tokenised_for_the_target_project(self):
        s = install.settings({'HARNESS_ACCOUNT_ID': 'acct', 'HARNESS_API_KEY': 'k', 'HARNESS_ORG_ID': 'o', 'HARNESS_PROJECT_ID': 'p', 'HARNESS_GIT_USERNAME': 'u@example.invalid'})
        pipeline = install.lab_yaml(s, 'pipeline.yaml')
        self.assertIn('  identifier: workshop\n  projectIdentifier: p\n  orgIdentifier: o\n', pipeline)
        self.assertIn('repoName: harness-devsecops', pipeline)
        for ref in ('templateRef: Compile_Application', 'templateRef: fortify', 'templateRef: owasp', 'connectorRef: dockerhub_devsecops', 'serviceRef: frontend', 'serviceRef: backend', 'environmentRef: prod'):
            self.assertIn(ref, pipeline)
        service = install.lab_yaml(s, 'service-frontend.yaml')
        self.assertIn('  orgIdentifier: o\n  projectIdentifier: p\n', service)
        self.assertIn('repoName: harness-devsecops', service)
        for text in (pipeline, service):
            self.assertNotIn('{{', text)
            self.assertNotIn('rap1hws263', text, 'no project baked in')
            self.assertNotIn('event_hws263', text, 'no org baked in')

    def test_add_step_group_appends_to_the_ci_stage(self):
        pipeline = ('pipeline:\n  stages:\n    - stage:\n        type: CI\n        spec:\n          execution:\n            steps:\n'
                    '              - step:\n                  identifier: OWASP\n                  template:\n                    templateRef: owasp\n'
                    '    - stage:\n        type: Deployment\n')
        out = install.add_step_group(pipeline, 'devsecops_critical_fix_loop')
        self.assertIn('                    templateRef: owasp\n              - stepGroup:\n                  name: Critical fix\n', out)
        self.assertIn('                    templateRef: devsecops_critical_fix_loop\n                    versionLabel: v0.1\n    - stage:\n', out)
        self.assertIsNone(install.add_step_group(out, 'devsecops_critical_fix_loop'), 'idempotent')


if __name__ == '__main__':
    unittest.main()
