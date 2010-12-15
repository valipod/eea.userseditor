import unittest
import ldap
from mock import Mock

from eea.userseditor.ldap_agent import (LdapAgent, user_attr_map,
                                        editable_field_names)

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

    def test_set_user_info(self):
        new_values = dict( (name, user_data_fixture[name] + "-new")
                           for name in editable_field_names )
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', new_values)

        modify_statements = tuple(
            (ldap.MOD_REPLACE, user_attr_map[name], [new_values[name]])
            for name in editable_field_names)
        self.mock_conn.modify_s.assert_called_once_with(
            self.agent._user_dn('jsmith'), modify_statements)

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
        self.mock_conn.passwd_s.return_value = (ldap.RES_MODIFY, [])
        self.agent.set_user_password('jsmith', 'some_new_pw')
        self.mock_conn.passwd_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 'some_new_pw')


user_data_fixture = {
    #'first_name': "Joe",
    #'last_name': "Smith",
    'name': "Joe Smith",
    'uid': 'jsmith',
    'email': "jsmith@example.com",
    'organisation': 'Smithy Factory',
    'uri': 'http://example.com/~jsmith',
    'postal_address': '13 Smithsonian Way, Copenhagen, DK',
    'telephone_number': '555 1234',
}

