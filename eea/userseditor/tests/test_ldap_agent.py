import unittest
from copy import deepcopy
import ldap
from mock import Mock

from eea.userseditor.ldap_agent import (LdapAgent, user_attr_map,
                                        editable_field_names)

user_data_fixture = {
    'first_name': u"Joe",
    'last_name': u"Smith",
    'email': u"jsmith@example.com",
    'organisation': u"Smithy Factory",
    'uri': u"http://example.com/~jsmith",
    'postal_address': u"13 Smithsonian Way, Copenhagen, DK",
    'telephone_number': u"555 1234",
}

user_data_fixture_with_name = dict(user_data_fixture, full_name=u"Joe Smith")


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
        data_dict = dict( (user_attr_map[name], [user_data_fixture[name]])
                          for name in editable_field_names )
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        info = self.agent.user_info('jsmith')

        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', ldap.SCOPE_BASE,
            filterstr='(objectClass=organizationalPerson)')
        for name in editable_field_names:
            self.assertEqual(info[name], user_data_fixture[name])

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
        data_dict = dict( (user_attr_map[name], [value]) for name, value
                          in user_data_fixture_with_name.iteritems() )
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

    def test_user_info_diff(self):
        old_info = deepcopy(user_data_fixture_with_name)
        old_info['email'] = ''
        new_info = deepcopy(user_data_fixture)
        new_info['uri'] = ''
        new_info['postal_address'] = "Kongens Nytorv 6, Copenhagen, Denmark"

        diff = self.agent._user_info_diff(old_info, new_info)

        self.assertEqual(diff, [
            (ldap.MOD_ADD, 'mail', ['jsmith@example.com']),
            (ldap.MOD_DELETE, 'labeledURI', ['http://example.com/~jsmith']),
            (ldap.MOD_REPLACE, 'postalAddress', [
                                    'Kongens Nytorv 6, Copenhagen, Denmark']),
        ])

    def test_change_all(self):
        new_values = dict( (name, user_data_fixture[name] + "-new")
                           for name in editable_field_names )
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', new_values)

        modify_statements = tuple(
            (ldap.MOD_REPLACE, user_attr_map[name], [new_values[name]])
            for name in editable_field_names)
        modify_statements += (
            (ldap.MOD_REPLACE, 'cn', ["Joe-new Smith-new"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)

    def test_change_nothing(self):
        new_values = dict( (name, user_data_fixture[name])
                           for name in editable_field_names )

        self.agent.set_user_info('jsmith', new_values)

        assert self.mock_conn.modify_s.call_count == 0

    def test_change_one(self):
        new_info = deepcopy(user_data_fixture)
        new_info['uri'] = "http://example.com/other-url"
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', new_info)

        modify_statements = (
            (ldap.MOD_REPLACE, 'labeledURI', ["http://example.com/other-url"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)

    def test_update_full_name(self):
        new_info = deepcopy(user_data_fixture)
        new_info['first_name'] = "Morpheus"
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', new_info)

        modify_statements = (
            (ldap.MOD_REPLACE, 'givenName', ["Morpheus"]),
            (ldap.MOD_REPLACE, 'cn', ["Morpheus Smith"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)

    def test_unicode(self):
        china = u"\u4e2d\u56fd"
        new_info = deepcopy(user_data_fixture)
        new_info['postal_address'] = u"Somewhere in " + china
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', new_info)

        modify_statements = (
            (ldap.MOD_REPLACE, 'postalAddress', [
                "Somewhere in " + china.encode('utf-8')]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)
