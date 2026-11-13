"""Unit tests for the one-command project setup (no network).

  python3 -m unittest discover -s harness-workshops -p 'test_*.py'
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import install  # noqa: E402

FILE_VARS = {'WORKSHOP_ACCOUNT_ID': 'acct', 'WORKSHOP_ORG_ID': 'org', 'WORKSHOP_PROJECT_ID': 'p1', 'WORKSHOP_API_KEY': 'pat.file',
             'anthropic_api_key': 'sk-file', 'aws-access-key': 'AKIAFILE', 'aws-secret-key': 'secret-file'}


class Args:
    project = token = account = org = git_username = model = None

    def __init__(self, **kw):
        self.__dict__.update(kw)


class EnvFileTests(unittest.TestCase):
    def test_reads_key_value_lines_and_skips_the_rest(self):
        text = ('PORT=3000\n# comment=no\nquoted="a b"\naws-access-key=AKIA1\nkey=-----BEGIN PRIVATE KEY-----\n'
                'MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgBdovt0E2QCbASaG2\nw1bl/yYNX==\n-----END PRIVATE KEY-----\nWORKSHOP_ACCOUNT_ID = acct \n')
        with tempfile.NamedTemporaryFile('w', suffix='.env', delete=False) as fh:
            fh.write(text)
        try:
            v = install.read_env_file(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(v['PORT'], '3000')
        self.assertEqual(v['quoted'], 'a b')
        self.assertEqual(v['aws-access-key'], 'AKIA1')
        self.assertEqual(v['WORKSHOP_ACCOUNT_ID'], 'acct')
        self.assertNotIn('# comment', v)
        self.assertNotIn('-----BEGIN PRIVATE KEY-----', v)
        self.assertEqual(install.read_env_file('/nonexistent/.env'), {})


class SettingsTests(unittest.TestCase):
    def test_flags_beat_environment_beats_file(self):
        s = install.settings(Args(project='p2', token='pat.flag'), {'ANTHROPIC_API_KEY': 'sk-env'}, FILE_VARS)
        self.assertEqual((s['account'], s['org'], s['project'], s['token']), ('acct', 'org', 'p2', 'pat.flag'))
        self.assertEqual(s['anthropic_key'], 'sk-env')
        self.assertEqual((s['aws_access_key'], s['aws_secret_key'], s['aws_region']), ('AKIAFILE', 'secret-file', 'us-east-2'))
        self.assertEqual(s['git_username'], 'p2@harnessevents.com', 'the workshop convention, unless told otherwise')
        self.assertEqual(s['model'], 'claude-sonnet-4-6')

    def test_file_defaults_and_overrides(self):
        s = install.settings(Args(git_username='me@example.invalid', model='claude-opus-5-5'), {}, FILE_VARS)
        self.assertEqual((s['project'], s['token'], s['git_username'], s['model']), ('p1', 'pat.file', 'me@example.invalid', 'claude-opus-5-5'))
        s = install.settings(Args(), {}, dict(FILE_VARS, WORKSHOP_GIT_USERNAME='facilitator@example.invalid'))
        self.assertEqual(s['git_username'], 'facilitator@example.invalid')
        s = install.settings(Args(), {}, {})
        self.assertEqual([k for k in install.NEEDED if not s[k]], list(install.NEEDED), 'everything missing is reported')


class BodiesTests(unittest.TestCase):
    def setUp(self):
        self.s = install.settings(Args(project='p2', token='pat.x'), {}, FILE_VARS)

    def test_connectors_point_at_the_secrets(self):
        a = install.anthropic_connector(self.s)['connector']
        self.assertEqual((a['identifier'], a['type'], a['orgIdentifier'], a['projectIdentifier']), ('anthropic_api', 'Anthropic', 'org', 'p2'))
        self.assertEqual(a['spec']['authentication']['spec']['tokenRef'], 'anthropic_api_key')
        self.assertEqual(a['spec']['model'], 'claude-sonnet-4-6')
        w = install.aws_connector(self.s)['connector']
        self.assertEqual((w['identifier'], w['type']), ('aws_creds', 'Aws'))
        self.assertEqual(w['spec']['credential']['spec'], {'accessKey': 'AKIAFILE', 'secretKeyRef': 'aws_secret_key', 'secretInputMethod': 'INDIVIDUAL'})
        self.assertEqual(w['spec']['credential']['region'], 'us-east-2')
        sec = install.secret_body(self.s, 'aws_secret_key', 'secret-file')['secret']
        self.assertEqual((sec['identifier'], sec['projectIdentifier'], sec['spec']['value']), ('aws_secret_key', 'p2', 'secret-file'))

    def test_kits_get_the_project_and_the_connectors(self):
        kits = install.kit_commands(self.s)
        self.assertEqual([k[0][:5] for k in kits], ['drift', 'DevSe'])
        drift, devsecops = kits
        self.assertTrue(drift[1][0].endswith(os.path.join('harness-drift-workshop', 'bootstrap', 'install.sh')))
        self.assertTrue(os.path.isfile(drift[1][0]))
        self.assertEqual((drift[2]['PROVIDER_CONNECTOR'], drift[2]['MODEL_CONNECTOR']), ('aws_creds', 'anthropic_api'))
        self.assertTrue(devsecops[1][-1].endswith(os.path.join('harness-devsecops-workshop', 'install.py')))
        self.assertTrue(os.path.isfile(devsecops[1][-1]))
        for _, _, env in kits:
            self.assertEqual((env['HARNESS_ACCOUNT_ID'], env['HARNESS_ORG_ID'], env['HARNESS_PROJECT_ID'], env['HARNESS_API_KEY'], env['HARNESS_GIT_USERNAME']),
                             ('acct', 'org', 'p2', 'pat.x', 'p2@harnessevents.com'))
        self.assertEqual([k[0][:5] for k in install.kit_commands(self.s, drift=False)], ['DevSe'])


if __name__ == '__main__':
    unittest.main()
