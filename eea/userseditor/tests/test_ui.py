import unittest
from datetime import datetime
import re
from lxml.html.soupparser import fromstring
from mock import Mock, patch
from eea.userseditor.users_editor import UsersEditor

def parse_html(html):
    return fromstring(re.sub(r'\s+', ' ', html))

from test_ldap_agent import user_data_fixture

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

    def test_edit_form(self):
        agent_mock = Mock()
        agent_mock.user_info.return_value = dict(user_data_fixture)
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

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
        self.assertEqual(val('//form'
                             '//input[@name="organisation:utf8:ustring"]'),
                         user_data_fixture['organisation'])
        self.assertEqual(val('//form//input[@name="uri:utf8:ustring"]'),
                         user_data_fixture['uri'])
        self.assertEqual(txt('//form//textarea'
                                '[@name="postal_address:utf8:ustring"]'),
                         "13 Smithsonian Way, Copenhagen, DK")
        self.assertEqual(val('//form'
                             '//input[@name="telephone_number:utf8:ustring"]'),
                         user_data_fixture['telephone_number'])

    def test_submit_edit(self):
        self.request.form = dict(user_data_fixture)
        agent_mock = Mock()
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

        self.ui.edit_account(self.request)

        agent_mock.bind.assert_called_with('jsmith', 'asdf')
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/edit_account_html')
        agent_mock.set_user_info.assert_called_with('jsmith',
                                                    user_data_fixture)

    def test_password_form(self):
        page = parse_html(self.ui.change_password_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text.strip()
        exists = lambda xp: len(page.xpath(xp)) > 0
        self.assertEqual(txt('//h1'), "Change Eionet account password")
        self.assertEqual(txt('//form/p'), "You are logged in as \"jsmith\".")
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
        agent_mock = Mock()
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

        self.ui.change_password(self.request)

        agent_mock.bind.assert_called_with('jsmith', 'asdf')
        agent_mock.set_user_password.assert_called_with('jsmith',
                                                        "asdf", "zxcv")
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/password_changed_html')

        page = parse_html(self.ui.password_changed_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text.strip()
        self.assertEqual(txt('//p').strip(),
                 "Password changed successfully. You must log in again.")

    def test_submit_new_password_bad_old_password(self):
        self.request.form = {
            'old_password': "qwer",
            'new_password': "zxcv",
            'new_password_confirm': "zxcv",
        }
        agent_mock = Mock()
        agent_mock.bind.side_effect = ValueError
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

        self.ui.change_password(self.request)

        agent_mock.bind.assert_called_with('jsmith', 'qwer')
        assert agent_mock.set_user_password.call_count == 0
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
        agent_mock = Mock()
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

        self.ui.change_password(self.request)

        assert agent_mock.set_user_password.call_count == 0
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
