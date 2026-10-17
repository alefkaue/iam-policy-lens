import unittest
from iam_policy_lens import audit


def policy(**overrides):
    statement = dict(Effect='Allow', Action='s3:GetObject', Resource='arn:aws:s3:::lab-example/*')
    statement.update(overrides)
    return dict(Version='2012-10-17', Statement=statement)


class PolicyTests(unittest.TestCase):
    def rules(self, value):
        return {f['rule'] for f in audit(value)['findings']}

    def test_scoped_read_and_deny(self):
        self.assertEqual(self.rules(policy()), set())
        self.assertEqual(self.rules(policy(Effect='Deny', Action='*', Resource='*')), set())

    def test_admin_and_sensitive_wildcards(self):
        report = audit(policy(Action='IAM:*', Resource='*'))
        self.assertEqual({f['rule'] for f in report['findings']},
                         {'wildcard_action', 'all_resources', 'sensitive_identity_action'})
        sensitive = next(f for f in report['findings'] if f['rule'] == 'sensitive_identity_action')
        self.assertIn('iam:PassRole', sensitive['evidence'])

    def test_inverse_allow_and_condition(self):
        value = dict(Statement=[dict(Effect='Allow', NotAction='iam:*', NotResource='arn:aws:s3:::lab/*',
                                    Condition={'StringEquals': {'aws:PrincipalOrgID': 'o-example'}})])
        self.assertEqual(self.rules(value), {'allow_not_action', 'allow_not_resource', 'condition_not_evaluated'})
        self.assertTrue(all(f['conditional'] for f in audit(value)['findings']))
        self.assertEqual(audit(value)['findings'][0]['location'], '/Statement/0')

    def test_principal_string_and_list(self):
        for principal in ['*', {'AWS': ['*']}]:
            self.assertIn('wildcard_principal', self.rules(policy(Principal=principal)))

    def test_malformed_input(self):
        for value in [[], {}, {'Statement': []}, policy(Effect='Maybe'), policy(Action=[]),
                      policy(NotAction='iam:*'), policy(Condition='bad'), policy(Resource=23)]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit(value)

    def test_sensitive_is_not_every_action(self):
        self.assertNotIn('sensitive_identity_action', self.rules(policy(Action='iam:ListRoles', Resource='*')))
