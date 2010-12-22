import unittest
from copy import deepcopy
import ldap
from mock import Mock

from eea.userseditor.ldap_agent import (LdapAgent, user_attr_map,
                                        ORG_LITERAL, ORG_BY_ID, BLANK_ORG)


class StubbedLdapAgent(LdapAgent):
    def connect(self, server):
        return Mock()

    def _search_user_in_orgs(self, user_id):
        return []

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

    def test_org_dn_conversion(self):
        org_values = {
            'air_agency': 'cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
            'blahsdfsd': 'cn=blahsdfsd,ou=Organisations,o=EIONET,l=Europe',
            'x': 'cn=x,ou=Organisations,o=EIONET,l=Europe',
            '12': 'cn=12,ou=Organisations,o=EIONET,l=Europe',
            '-': 'cn=-,ou=Organisations,o=EIONET,l=Europe',
        }
        for org_id, org_dn in org_values.iteritems():
            assert self.agent._org_dn(org_id) == org_dn
            assert self.agent._org_id(org_dn) == org_id
        bad_org_dns = [
            'asdf',
            'cn=a,cn=xxx,ou=Organisations,o=EIONET,l=Europe',
            'cn=a,ou=Groups,o=EIONET,l=Europe',
            'a,ou=Organisations,o=EIONET,l=Europe',
        ]
        for bad_dn in bad_org_dns:
            self.assertRaises(AssertionError, self.agent._org_id, bad_dn)

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

        user_info = self.agent.user_info('jsmith')

        self.assertEqual(user_info['email'], "jsmith@example.com")
        self.assertEqual(user_info['uri'], "")

    def test_get_user_info_extra_fields(self):
        data_dict = {
            'mail': ["jsmith@example.com"],
            'uid': ["jsmith"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.agent.user_info('jsmith')

        for name, value in user_info.iteritems():
            if name == 'email':
                self.assertEqual(value, u"jsmith@example.com")
            elif name == 'organisation':
                self.assertEqual(value, BLANK_ORG)
            else:
                self.assertEqual(value, u"")

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

    def test_get_all_organisations(self):
        self.mock_conn.search_s.return_value = [
            ('cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': ["Bridge club"]}),
            ('cn=poker_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': ["P\xc3\xb6ker club"]})
        ]

        orgs = self.agent.all_organisations()

        self.assertEqual(orgs, {'bridge_club': u"Bridge club",
                                'poker_club': u"P\xf6ker club"})
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Organisations,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            filterstr='(objectClass=organizationGroup)', attrlist=('o',))

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

        diff = self.agent._user_info_diff('jsmith', old_info, new_info, [])

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

        diff = self.agent._user_info_diff('jsmith', old_info, user_info, [])

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


class LdapAgentOrganisationsTest(unittest.TestCase):
    def setUp(self):
        self.agent = StubbedLdapAgent('ldap.example.com')
        self.mock_conn = self.agent.conn

    def test_get_literal_org(self):
        # get organisation from user's `o` attribute
        data_dict = {'o': ['My bridge club']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.agent.user_info('jsmith')

        self.assertEqual(user_info['organisation'],
                         (ORG_LITERAL, u"My bridge club"))

    def test_set_literal_org(self):
        jsmith_dn = self.agent._user_dn('jsmith')
        self.mock_conn.search_s.return_value = [(jsmith_dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith', {
            'organisation': (ORG_LITERAL, u"Ze new organisation")})

        modify_statements = (
            (ldap.MOD_ADD, 'o', ["Ze new organisation"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            jsmith_dn, modify_statements)

    def test_search_user_in_orgs(self):
        self.mock_conn.search_s.return_value = [
            ('cn=org_one,ou=Organisations,o=EIONET,l=Europe', {}),
            ('cn=org_two,ou=Organisations,o=EIONET,l=Europe', {}),
        ]

        org_ids = LdapAgent._search_user_in_orgs(self.agent, 'jsmith')

        filterstr = ('(&(objectClass=organizationGroup)'
                       '(uniqueMember=uid=jsmith,ou=Users,o=EIONET,l=Europe))')
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Organisations,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            filterstr=filterstr, attrlist=())
        self.assertEqual(org_ids, ['org_one', 'org_two'])

    def test_get_member_org(self):
        jsmith_dn = self.agent._user_dn('jsmith')
        self.mock_conn.search_s.return_value = [(jsmith_dn, {})]
        self.agent._search_user_in_orgs = Mock(return_value=['bridge_club',
                                                             'poker_club'])

        user_info = self.agent.user_info('jsmith')

        self.assertEqual(user_info['organisation'],
                         (ORG_BY_ID, 'bridge_club'))

    def test_set_member_org(self):
        jsmith_dn = self.agent._user_dn('jsmith')
        bridge_club_dn = self.agent._org_dn('bridge_club')
        self.mock_conn.search_s.return_value = [(jsmith_dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.agent.set_user_info('jsmith',
                                 {'organisation': (ORG_BY_ID, 'bridge_club')})

        self.mock_conn.modify_s.assert_called_once_with(
            bridge_club_dn, ((ldap.MOD_ADD, 'uniqueMember', [jsmith_dn]),))

    def test_change_member_org(self):
        jsmith_dn = self.agent._user_dn('jsmith')
        bridge_club_dn = self.agent._org_dn('bridge_club')
        poker_club_dn = self.agent._org_dn('poker_club')
        yachting_club_dn = self.agent._org_dn('yachting_club')
        self.agent._search_user_in_orgs = Mock(return_value=['bridge_club',
                                                             'poker_club'])

        diff = self.agent._user_info_diff('jsmith',
                {'organisation': (ORG_LITERAL, u"My own little club")},
                {'organisation': (ORG_BY_ID, 'yachting_club')},
                ['bridge_club', 'poker_club'])

        self.assertEqual(diff, {
            jsmith_dn: [(ldap.MOD_DELETE, 'o', [u"My own little club"])],
            bridge_club_dn: [(ldap.MOD_DELETE, 'uniqueMember', [jsmith_dn])],
            poker_club_dn: [(ldap.MOD_DELETE, 'uniqueMember', [jsmith_dn])],
            yachting_club_dn: [(ldap.MOD_ADD, 'uniqueMember', [jsmith_dn])],
        })
