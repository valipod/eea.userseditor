import unittest
from copy import deepcopy
import ldap
from mock import Mock

from eea.userseditor.ldap_agent import LdapAgent, user_attr_map


class StubbedLdapAgent(LdapAgent):
    def connect(self, server):
        return Mock()

class LdapAgentTest(unittest.TestCase):
    def setUp(self):
        self.agent = StubbedLdapAgent('ldap.example.com')
        self.mock_conn = self.agent.conn

    def test_user_dn_conversion(self):
        user_values = {
            'usertwo': 'uid=usertwo,ou=Users,o=EIONET,l=Europe',
            'blahsdfsd': 'uid=blahsdfsd,ou=Users,o=EIONET,l=Europe',
            'x': 'uid=x,ou=Users,o=EIONET,l=Europe',
            '12': 'uid=12,ou=Users,o=EIONET,l=Europe',
            '-': 'uid=-,ou=Users,o=EIONET,l=Europe',
        }
        for user_id, user_dn in user_values.iteritems():
            assert self.agent._user_dn(user_id) == user_dn

    def test_get_user_info(self):
        old_attrs = {
            'givenName': ["Joe"],
            'sn': ["Smith"],
            'cn': ["Joe Smith"],
            'mail': ["jsmith@example.com"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]

        user_info = self.agent.user_info('jsmith')

        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', ldap.SCOPE_BASE,
            filterstr='(objectClass=organizationalPerson)')
        self.assertEqual(user_info['first_name'], u"Joe")
        self.assertEqual(user_info['last_name'], u"Smith")
        self.assertEqual(user_info['email'], u"jsmith@example.com")
        self.assertEqual(user_info['full_name'], u"Joe Smith")

    def test_get_user_info_missing_fields(self):
        data_dict = {
            'mail': ["jsmith@example.com"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        info = self.agent.user_info('jsmith')

        self.assertEqual(info['email'], "jsmith@example.com")
        self.assertEqual(info['uri'], "")

    def test_get_user_info_extra_fields(self):
        data_dict = {
            'mail': ["jsmith@example.com"],
            'uid': ["jsmith"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        info = self.agent.user_info('jsmith')

        for name, value in info.iteritems():
            if name == 'email':
                self.assertEqual(value, "jsmith@example.com")
            else:
                self.assertEqual(value, "")

    def test_bind_success(self):
        self.mock_conn.simple_bind_s.return_value = (ldap.RES_BIND, [])
        self.agent.bind('jsmith', 'some_pw')
        self.mock_conn.simple_bind_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 'some_pw')

    def test_bind_failure(self):
        self.mock_conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
        self.assertRaises(ValueError, self.agent.bind, 'jsmith', 'some_pw')
        self.mock_conn.simple_bind_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 'some_pw')

    def test_set_user_password(self):
        self.mock_conn.passwd_s.return_value = (ldap.RES_EXTENDED, [])
        self.agent.set_user_password('jsmith', 'the_old_pw', 'some_new_pw')
        self.mock_conn.passwd_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe',
            'the_old_pw', 'some_new_pw')

    def test_set_user_password_failure(self):
        self.mock_conn.passwd_s.side_effect = ldap.UNWILLING_TO_PERFORM
        self.assertRaises(ValueError, self.agent.set_user_password,
                          'jsmith', 'bad_old_pw', 'some_new_pw')
        self.mock_conn.passwd_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe',
            'bad_old_pw', 'some_new_pw')

class LdapAgentEditingTest(unittest.TestCase):
    def setUp(self):
        self.agent = StubbedLdapAgent('ldap.example.com')
        self.mock_conn = self.agent.conn

    def test_user_info_diff(self):
        old_info = {
            'uri': u"http://example.com/~jsmith",
            'postal_address': u"old address",
            'telephone_number': u"555 1234",
        }
        new_info = {
            'email': u"jsmith@example.com",
            'postal_address': u"Kongens Nytorv 6, Copenhagen, Denmark",
            'telephone_number': u"555 1234",
        }

        diff = self.agent._user_info_diff('jsmith', old_info, new_info)

        self.assertEqual(diff, {'uid=jsmith,ou=Users,o=EIONET,l=Europe': [
            (ldap.MOD_ADD, 'mail', ['jsmith@example.com']),
            (ldap.MOD_DELETE, 'labeledURI', ['http://example.com/~jsmith']),
            (ldap.MOD_REPLACE, 'postalAddress', [
                                    'Kongens Nytorv 6, Copenhagen, Denmark']),
        ]})

    def test_update_full_name(self):
        old_info = {'first_name': u"Joe", 'last_name': u"Smith"}
        self.agent._update_full_name(old_info) # that's what we expect in LDAP
        user_info = {'first_name': u"Tester", 'last_name': u"Smith"}

        diff = self.agent._user_info_diff('jsmith', old_info, user_info)

        self.assertEqual(diff, {'uid=jsmith,ou=Users,o=EIONET,l=Europe': [
            (ldap.MOD_REPLACE, 'givenName', ['Tester']),
            (ldap.MOD_REPLACE, 'cn', ['Tester Smith']),
        ]})

    def test_change_nothing(self):
        old_attrs = {'mail': ['jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', {'email': u'jsmith@example.com'})

        assert self.mock_conn.modify_s.call_count == 0

    def test_add_one(self):
        old_attrs = {}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', {'email': u'jsmith@example.com'})

        modify_statements = (
            (ldap.MOD_ADD, 'mail', ["jsmith@example.com"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)

    def test_remove_one(self):
        old_attrs = {'mail': ['jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', {})

        modify_statements = (
            (ldap.MOD_DELETE, 'mail', ["jsmith@example.com"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)

    def test_update_one(self):
        old_attrs = {'mail': ['jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', {'email': u'jsmith@x.example.com'})

        modify_statements = (
            (ldap.MOD_REPLACE, 'mail', ["jsmith@x.example.com"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)

    def test_unicode(self):
        old_attrs = {'postalAddress': ['The old address']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        china = u"\u4e2d\u56fd"
        user_info = {'postal_address': u"Somewhere in " + china}

        self.agent.set_user_info('jsmith', user_info)

        modify_statements = (
            (ldap.MOD_REPLACE, 'postalAddress', [
                "Somewhere in " + china.encode('utf-8')]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)
