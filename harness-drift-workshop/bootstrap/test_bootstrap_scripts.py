"""Unit tests for publish.py and inject.py, the scripts the bootstrap embeds
into the drift and inject pipelines.

  python3 -m unittest discover -s bootstrap -p 'test_*.py'
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
import inject as inj  # noqa: E402
import publish as pub  # noqa: E402

MAIN_TF = '''locals {
  common_tags = {
    managedby = "harness-iacm"
    workshop  = "drift"
  }

  environments = {
    "drift_workshop_dev" = {
      name = "drift_workshop dev"
      type = "PreProduction"
      tags = { tier = "dev" }
    }
  }
}

resource "harness_platform_environment" "this" {
  for_each = local.environments

  identifier = each.key
  name       = each.value.name
  type       = each.value.type
  tags       = [for k, v in merge(local.common_tags, each.value.tags) : "${k}:${v}"]
}
'''


def plan_fixture():
    return {'format_version': '1.2', 'resource_drift': [
        {'address': 'harness_platform_environment.this["drift_workshop_dev"]', 'mode': 'managed', 'type': 'harness_platform_environment', 'name': 'this', 'index': 'drift_workshop_dev',
         'change': {'actions': ['update'],
                    'before': {'id': 'drift_workshop_dev', 'tags': ['workshop:drift', 'managedby:harness-iacm', 'tier:dev']},
                    'after': {'id': 'drift_workshop_dev', 'tags': ['workshop:drift', 'managedby:harness-iacm', 'tier:dev-manual-change']}}},
        {'address': 'harness_platform_variables.this["x"]', 'type': 'harness_platform_variables', 'name': 'this',
         'change': {'actions': ['no-op'], 'before': {'a': 1}, 'after': {'a': 1}}},
    ]}


class FakeHarness(BaseHTTPRequestHandler):
    mode = 'ok'
    calls = []

    def log_message(self, *args):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        FakeHarness.calls.append(('GET', self.path, None))
        path = self.path.split('?')[0]
        if path == '/code/api/v1/repos/drift_workshop_repo':
            return self._send(401, {'message': 'Unauthorized'}) if FakeHarness.mode == 'badkey' else self._send(200, {'identifier': 'drift_workshop_repo'})
        if path == '/code/api/v1/repos/drift_workshop_repo/pullreq':
            return self._send(200, [{'number': 4}])
        if path == '/ng/api/environmentsV2/drift_workshop_dev':
            return self._send(200, {'status': 'SUCCESS', 'data': {'environment': {'identifier': 'drift_workshop_dev', 'orgIdentifier': 'o', 'projectIdentifier': 'p', 'name': 'drift_workshop dev', 'type': 'PreProduction', 'tags': {'tier': 'dev', 'workshop': 'drift'}, 'description': 'd'}}})
        if path == '/ng/api/variables/drift_workshop_replicas':
            return self._send(200, {'status': 'SUCCESS', 'data': {'variable': {'identifier': 'drift_workshop_replicas', 'name': 'drift_workshop_replicas', 'orgIdentifier': 'o', 'projectIdentifier': 'p', 'type': 'String', 'spec': {'valueType': 'FIXED', 'fixedValue': '2'}}}})
        self._send(404, {'message': 'nope'})

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(n) or b'{}')
        FakeHarness.calls.append(('POST', self.path, body))
        if self.path.split('?')[0] == '/code/api/v1/repos/drift_workshop_repo/pullreq':
            if FakeHarness.mode == 'exists':
                return self._send(409, {'message': 'pull request already exists'})
            return self._send(201, {'number': 9})
        self._send(404, {'message': 'nope'})

    def do_PUT(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(n) or b'{}')
        FakeHarness.calls.append(('PUT', self.path, body))
        if self.path.split('?')[0] in ('/ng/api/environmentsV2', '/ng/api/variables'):
            return self._send(200, {'status': 'SUCCESS'})
        self._send(404, {'message': 'nope'})


class PublishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), FakeHarness)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.api = 'http://127.0.0.1:%d' % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        FakeHarness.mode = 'ok'
        FakeHarness.calls = []
        self.root = tempfile.mkdtemp(prefix='kit-pub-')
        self.tf = os.path.join(self.root, 'terraform')
        os.makedirs(self.tf)
        with open(os.path.join(self.tf, 'main.tf'), 'w') as fh:
            fh.write(MAIN_TF)
        with open(os.path.join(self.root, 'README.md'), 'w') as fh:
            fh.write('readme\n')
        with open(os.path.join(self.root, '.gitignore'), 'w') as fh:
            fh.write('plan.json\n*.tfstate\n.artifacts/\n')
        g = lambda *a: subprocess.run(['git'] + list(a), cwd=self.root, check=True, capture_output=True, text=True)  # noqa: E731
        g('init', '-q')
        g('symbolic-ref', 'HEAD', 'refs/heads/main')
        g('add', '-A')
        g('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'base')
        # what detect-drift leaves behind, untracked
        with open(os.path.join(self.tf, 'plan.json'), 'w') as fh:
            json.dump(plan_fixture(), fh)
        with open(os.path.join(self.tf, 'terraform.tfstate'), 'w') as fh:
            fh.write('{}')
        self.out = os.path.join(self.root, '.artifacts', 'drift')
        os.environ['no_proxy'] = '127.0.0.1'
        self.env = {'ROOT_DIR': self.root, 'OUTPUT_DIR': self.out, 'WORKSPACE': 'drift_workshop', 'PIPELINE_URL': 'https://app.harness.io/x/executions/abc', 'RUN_SEQUENCE': '3',
                    'HARNESS_API_URL': self.api, 'HARNESS_API_KEY': 'sat.' + 'x' * 40,
                    'HARNESS_ACCOUNT_ID': 'acct', 'HARNESS_ORG_ID': 'o', 'HARNESS_PROJECT_ID': 'p', 'HARNESS_REPO': 'drift_workshop_repo',
                    'HARNESS_GIT_URL': 'https://git.harness.io/acct/o/p/drift_workshop_repo.git', 'HARNESS_GIT_USERNAME': 'me@example.com'}
        self.lines = []

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def edit(self):
        p = os.path.join(self.tf, 'main.tf')
        with open(p) as fh:
            text = fh.read()
        with open(p, 'w') as fh:
            fh.write(text.replace('tags = { tier = "dev" }', 'tags = { tier = "dev-manual-change" }'))

    def summary(self, text='Overrode tier on drift_workshop_dev; common_tags untouched since only one environment drifted.\n'):
        os.makedirs(self.out, exist_ok=True)
        with open(os.path.join(self.out, 'summary.md'), 'w') as fh:
            fh.write(text)

    def test_flatten_drift_from_plan(self):
        entries = pub.flatten_drift(plan_fixture())
        self.assertEqual([(e['path'], e['before'], e['after'], e['computed']) for e in entries], [('tags[2]', 'tier:dev', 'tier:dev-manual-change', False)])

    def test_none_without_edits(self):
        code, doc = pub.run(self.env, out=self.lines.append)
        self.assertEqual((code, doc['action'], doc['scm']), (0, 'none', 'harness_code'))
        self.assertIn('the agent wrote no summary.md', doc['reasons'])

    def test_blocked_without_plan(self):
        os.remove(os.path.join(self.tf, 'plan.json'))
        code, doc = pub.run(self.env, out=self.lines.append)
        self.assertEqual((code, doc['action']), (1, 'blocked'))

    def test_blocked_outside_scope(self):
        self.edit()
        with open(os.path.join(self.root, 'README.md'), 'a') as fh:
            fh.write('x\n')
        code, doc = pub.run(self.env, out=self.lines.append)
        self.assertEqual((code, doc['action']), (1, 'blocked'))
        self.assertIn('README.md', doc['reasons'][0])

    def test_dry_run_commits_only_terraform(self):
        self.edit()
        self.summary()
        code, doc = pub.run(dict(self.env, DRIFT_PUBLISH_DRY_RUN='1'), out=self.lines.append)
        self.assertEqual((code, doc['action'], doc['branch'], doc['files']), (0, 'opened', 'agent/drift/drift_workshop/3', ['terraform/main.tf']))
        shown = subprocess.run(['git', 'show', '--stat', '--format=%B', 'HEAD'], cwd=self.root, capture_output=True, text=True).stdout
        self.assertIn('Pipeline-Execution: https://app.harness.io/x/executions/abc', shown)
        self.assertNotIn('plan.json', shown)
        self.assertNotIn('summary.md', shown)
        self.assertEqual(doc['resources_changed'], [{'address': 'harness_platform_environment.this["drift_workshop_dev"]', 'attribute': 'tags[2]', 'from': 'tier:dev', 'to': 'tier:dev-manual-change'}])

    def test_harness_code_opens_pr_with_summary(self):
        self.edit()
        self.summary()
        original = pub.push
        pushed = []
        pub.push = lambda root, branch, backend: pushed.append((branch, backend.push_url())) or 'fake'
        try:
            code, doc = pub.run(self.env, out=self.lines.append)
        finally:
            pub.push = original
        self.assertEqual(code, 0, self.lines)
        self.assertEqual(doc['pr_url'], '%s/ng/account/acct/module/code/orgs/o/projects/p/repos/drift_workshop_repo/pulls/9' % self.api)
        self.assertEqual(doc['reasons'], [])
        self.assertEqual(pushed[0][1], 'https://me%40example.com:sat.' + 'x' * 40 + '@git.harness.io/acct/o/p/drift_workshop_repo.git')
        post = [c for c in FakeHarness.calls if c[0] == 'POST'][0]
        self.assertIn('accountIdentifier=acct', post[1])
        self.assertEqual((post[2]['source_branch'], post[2]['target_branch']), ('agent/drift/drift_workshop/3', 'main'))
        self.assertIn('**Agent summary**', post[2]['description'])
        self.assertIn('Overrode tier on drift_workshop_dev', post[2]['description'])
        self.assertIn('`tags[2]`', post[2]['description'])
        self.assertTrue(any('credential check (harness_code): 200 as drift_workshop_repo (HARNESS_API_KEY is 44 chars, prefix sat.)' in l for l in self.lines), self.lines)

    def test_reuses_existing_pr_and_reports_bad_key(self):
        self.edit()
        FakeHarness.mode = 'exists'
        original = pub.push
        pub.push = lambda *a: 'fake'
        try:
            code, doc = pub.run(self.env, out=self.lines.append)
            self.assertEqual((code, doc['action'], doc['pr_url'].endswith('/pulls/4')), (0, 'opened', True))
            FakeHarness.mode = 'badkey'
            subprocess.run(['git', 'checkout', '-q', 'main'], cwd=self.root, check=True)
            self.edit()
            code, doc = pub.run(self.env, out=self.lines.append)
        finally:
            pub.push = original
        self.assertTrue(any('harness_code rejected the credential: 401' in r for r in doc['reasons']), doc)

    def test_harness_code_is_the_only_backend(self):
        self.assertEqual(pub.backend_for({}).name, 'harness_code')
        self.assertFalse(hasattr(pub, 'GitHub'))

    def test_inject_environment_and_variable(self):
        h = inj.Harness({'HARNESS_API_URL': self.api, 'HARNESS_API_KEY': 'k', 'HARNESS_ACCOUNT_ID': 'acct', 'HARNESS_ORG_ID': 'o', 'HARNESS_PROJECT_ID': 'p'})
        r = inj.inject(h, 'environment', 'drift_workshop_dev', 'tier', 'dev-manual-change', out=self.lines.append)
        self.assertEqual(r, {'target': 'environment', 'identifier': 'drift_workshop_dev', 'attribute': 'tags.tier', 'before': 'dev', 'after': 'dev-manual-change'})
        put = [c for c in FakeHarness.calls if c[0] == 'PUT'][-1]
        self.assertEqual(put[2]['tags'], {'tier': 'dev-manual-change', 'workshop': 'drift'})
        self.assertEqual((put[2]['name'], put[2]['type'], put[2]['description']), ('drift_workshop dev', 'PreProduction', 'd'))
        r = inj.inject(h, 'variable', 'drift_workshop_replicas', None, '3', out=self.lines.append)
        self.assertEqual((r['before'], r['after']), ('2', '3'))
        self.assertEqual([c for c in FakeHarness.calls if c[0] == 'PUT'][-1][2]['variable']['spec'], {'valueType': 'FIXED', 'fixedValue': '3'})

    def test_scripts_contain_no_template_syntax(self):
        # bootstrap/main.tf embeds both files through templatefile(); a literal
        # "${" or "%{" in either would be interpreted by HCL.
        for name in ('publish.py', 'inject.py'):
            with open(os.path.join(HERE, name)) as fh:
                text = fh.read()
            self.assertNotIn('${', text, name)
            self.assertNotIn('%{', text, name)


if __name__ == '__main__':
    unittest.main()
