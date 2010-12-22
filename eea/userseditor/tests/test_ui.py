import unittest
from datetime import datetime
import re
from lxml.html.soupparser import fromstring
from mock import Mock, patch
from eea.userseditor.users_editor import UsersEditor
from eea.userseditor.ldap_agent import ORG_LITERAL, ORG_BY_ID

def parse_html(html):
    return fromstring(re.sub(r'\s+', ' ', html))

user_data_fixture = {
    'first_name': u"Joe",
    'last_name': u"Smith",
    'email': u"jsmith@example.com",
    'uri': u"http://example.com/~jsmith",
    'postal_address': u"13 Smithsonian Way, Copenhagen, DK",
    'telephone_number': u"555 1234",
    'organisation': (ORG_LITERAL, u"My company"),
}

class MockLdapAgent(Mock):
    def __init__(self, *args, **kwargs):
        super(MockLdapAgent, self).__init__(*args, **kwargs)
        self._user_info = dict(user_data_fixture)

    def user_info(self, user_id):
        return self._user_info

    def all_organisations(self):
        return {}


class StubbedUsersEditor(UsersEditor):
    def _render_template(self, name, **options):
        from eea.userseditor.users_editor import load_template
        return "<html>%s</html>" % load_template(name)(**options)

    def absolute_url(self):
        return "URL"

def mock_user(user_id, user_pw):
    user = Mock()
    user.getId.return_value = user_id
    user.__ = user_pw
    return user

def mock_request():
    request = Mock()
    request.SESSION = {}
    return request

class AccountUITest(unittest.TestCase):
    def setUp(self):
        self.ui = StubbedUsersEditor('users')
        self.request = mock_request()
        self.request.AUTHENTICATED_USER = mock_user('jsmith', 'asdf')
        self.mock_agent = MockLdapAgent()
        self.ui._get_ldap_agent = Mock(return_value=self.mock_agent)

    def test_edit_form(self):
        page = parse_html(self.ui.edit_account_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text.strip()
        val = lambda xp: page.xpath(xp)[0].attrib['value']
        self.assertEqual(txt('//h1'), "Modify Eionet account")
        self.assertEqual(val('//form//input[@name="first_name:utf8:ustring"]'),
                         user_data_fixture['first_name'])
        self.assertEqual(val('//form//input[@name="last_name:utf8:ustring"]'),
                         user_data_fixture['last_name'])
        self.assertEqual(val('//form//input[@name="email:utf8:ustring"]'),
                         user_data_fixture['email'])
        self.assertEqual(val('//form//input[@name="uri:utf8:ustring"]'),
                         user_data_fixture['uri'])
        self.assertEqual(txt('//form//textarea'
                                '[@name="postal_address:utf8:ustring"]'),
                         "13 Smithsonian Way, Copenhagen, DK")
        self.assertEqual(val('//form'
                             '//input[@name="telephone_number:utf8:ustring"]'),
                         user_data_fixture['telephone_number'])

    @patch('eea.userseditor.users_editor.datetime')
    def test_submit_edit(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2010, 12, 16, 13, 45, 21)
        self.request.form = dict(user_data_fixture)
        self.request.form['org_literal'] = user_data_fixture['organisation'][1]

        self.ui.edit_account(self.request)

        self.mock_agent.bind.assert_called_with('jsmith', 'asdf')
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/edit_account_html')
        self.mock_agent.set_user_info.assert_called_with('jsmith',
                                                         user_data_fixture)

        page = parse_html(self.ui.edit_account_html(self.request))
        txt = lambda xp: page.xpath(xp)[0].text.strip()
        self.assertEqual(txt('//div[@class="system-msg"]'),
                         "Profile saved (2010-12-16 13:45:21)")

    def test_password_form(self):
        page = parse_html(self.ui.change_password_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text.strip()
        exists = lambda xp: len(page.xpath(xp)) > 0
        self.assertEqual(txt('//h1'), "Change Eionet account password")
        self.assertEqual(txt('//p/tt'), "jsmith")
        self.assertTrue(exists('//form//input[@type="password"]'
                                            '[@name="old_password"]'))
        self.assertTrue(exists('//form//input[@type="password"]'
                                            '[@name="new_password"]'))
        self.assertTrue(exists('//form//input[@type="password"]'
                                            '[@name="new_password_confirm"]'))

    def test_submit_new_password(self):
        self.request.form = {
            'old_password': "asdf",
            'new_password': "zxcv",
            'new_password_confirm': "zxcv",
        }

        self.ui.change_password(self.request)

        self.mock_agent.bind.assert_called_with('jsmith', 'asdf')
        self.mock_agent.set_user_password.assert_called_with('jsmith',
                                                             "asdf", "zxcv")
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/password_changed_html')

        page = parse_html(self.ui.password_changed_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text.strip()
        self.assertEqual(txt('//div[@class="system-msg"]'),
                 "Password changed successfully. You must log in again.")

    def test_submit_new_password_bad_old_password(self):
        self.request.form = {
            'old_password': "qwer",
            'new_password': "zxcv",
            'new_password_confirm': "zxcv",
        }
        self.mock_agent.bind.side_effect = ValueError

        self.ui.change_password(self.request)

        self.mock_agent.bind.assert_called_with('jsmith', 'qwer')
        assert self.mock_agent.set_user_password.call_count == 0
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/change_password_html')

        page = parse_html(self.ui.change_password_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text.strip()
        self.assertEqual(txt('//div[@class="error-msg"]'),
                         "Old password is wrong")

    def test_submit_new_password_mismatch(self):
        self.request.form = {
            'old_password': "asdf",
            'new_password': "zxcv",
            'new_password_confirm': "not quite zxcv",
        }

        self.ui.change_password(self.request)

        assert self.mock_agent.set_user_password.call_count == 0
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/change_password_html')

        page = parse_html(self.ui.change_password_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text.strip()
        self.assertEqual(txt('//div[@class="error-msg"]'),
                         "New passwords do not match")

class NotLoggedInTest(unittest.TestCase):
    def setUp(self):
        self.ui = StubbedUsersEditor('users')
        self.request = mock_request()
        self.request.AUTHENTICATED_USER = mock_user(None, '')

    def _assert_error_msg_on_index(self):
        page = parse_html(self.ui.index_html(self.request))
        txt = lambda xp: page.xpath(xp)[0].text.strip()
        self.assertEqual(txt('//div[@class="error-msg"]'),
                         "You must be logged in to edit your profile.")

    def test_edit_form(self):
        self.ui.edit_account_html(self.request)
        self.request.RESPONSE.redirect.assert_called_with('URL/')
        self._assert_error_msg_on_index()

    def test_password_form(self):
        self.ui.change_password_html(self.request)
        self.request.RESPONSE.redirect.assert_called_with('URL/')
        self._assert_error_msg_on_index()

class EditOrganisationTest(unittest.TestCase):
    def setUp(self):
        self.ui = StubbedUsersEditor('users')
        self.request = mock_request()
        self.request.AUTHENTICATED_USER = mock_user('jsmith', 'asdf')
        self.mock_agent = MockLdapAgent()
        self.ui._get_ldap_agent = Mock(return_value=self.mock_agent)
        all_orgs = {'bridge_club': u"Bridge club", 'poker_club': u"Poker club"}
        self.mock_agent.all_organisations = Mock(return_value=all_orgs)

    def test_show_literal(self):
        self.mock_agent._user_info['organisation'] = (ORG_LITERAL, u"My club")

        page = parse_html(self.ui.edit_account_html(self.request))

        checked_radio = page.xpath('//form//input[@name="org_type"]'
                                                '[@checked="checked"]')
        self.assertEqual(len(checked_radio), 1)
        self.assertEqual(checked_radio[0].attrib['value'], ORG_LITERAL)

        literal_input = page.xpath('//form'
                                   '//input[@name="org_literal:utf8:ustring"]')
        self.assertEqual(len(literal_input), 1)
        self.assertEqual(literal_input[0].attrib['value'], u"My club")

    def test_show_by_id(self):
        self.mock_agent._user_info['organisation'] = (ORG_BY_ID, 'bridge_club')

        page = parse_html(self.ui.edit_account_html(self.request))

        checked_radio = page.xpath('//form//input[@name="org_type"]'
                                                '[@checked="checked"]')
        self.assertEqual(len(checked_radio), 1)
        self.assertEqual(checked_radio[0].attrib['value'], ORG_BY_ID)
        select_by_id = page.xpath('//form//select[@name="org_id"]')[0]
        options = select_by_id.xpath('option')
        self.assertEqual(len(options), 3)
        self.assertEqual(options[0].text, u"--")
        self.assertEqual(options[1].text, u"Bridge club")
        self.assertEqual(options[1].attrib['value'], 'bridge_club')
        self.assertEqual(options[1].attrib['selected'], 'selected')
        self.assertEqual(options[2].text, u"Poker club")
        self.assertEqual(options[2].attrib['value'], 'poker_club')
        self.assertTrue('selected' not in options[2].attrib)

    def test_submit_literal(self):
        self.request.form = {
            'org_type': 'literal',
            'org_literal': u"My own little club",
        }

        self.ui.edit_account(self.request)

        user_info = dict( (name, u"") for name in user_data_fixture )
        user_info['organisation'] = (ORG_LITERAL, u"My own little club")
        self.mock_agent.set_user_info.assert_called_with('jsmith', user_info)

    def test_submit_by_id(self):
        self.request.form = {
            'org_type': 'by_id',
            'org_id': 'bridge_club',
        }

        self.ui.edit_account(self.request)

        user_info = dict( (name, u"") for name in user_data_fixture )
        user_info['organisation'] = (ORG_BY_ID, 'bridge_club')
        self.mock_agent.set_user_info.assert_called_with('jsmith', user_info)
