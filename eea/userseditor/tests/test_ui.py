import unittest
from datetime import datetime
from mock import Mock, patch
from eea.userseditor.users_editor import NewUsersEditor as UsersEditor

def parse_html(html):
    from cStringIO import StringIO
    from lxml.html.soupparser import fromstring
    return fromstring(html)

user_data_fixture = {
    #'first_name': "Joe",
    #'last_name': "Smith",
    'uid': 'jsmith',
    'email': "jsmith@example.com",
    'organisation': 'Smithy Factory',
    'uri': 'http://example.com/~jsmith',
    'postal_address': '13 Smithsonian Way, Copenhagen, DK',
    'telephone_number': '555 1234',
}

def stubbed_ui():
    ui = UsersEditor('users')
    ui.standard_html_header = "<html>"
    ui.standard_html_footer = "</html>"
    ui.absolute_url = Mock(return_value="URL")
    return ui

class AccountUITest(unittest.TestCase):
    def setUp(self):
        self.ui = stubbed_ui()
        self.request = Mock()
        self.request.AUTHENTICATED_USER.getId.return_value = 'jsmith'
        self.request.SESSION = {}

    def test_edit_form(self):
        agent_mock = Mock()
        agent_mock.user_info.return_value = dict(user_data_fixture)
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

        page = parse_html(self.ui.edit_account_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text
        val = lambda xp: page.xpath(xp)[0].attrib['value']
        self.assertEqual(txt('//h1'), "Modify Eionet account")
        self.assertEqual(val('//form//input[@name="uri"]'),
                         "http://example.com/~jsmith")
        self.assertEqual(txt('//form//textarea'
                                '[@name="postal_address:utf8:ustring"]'),
                         "13 Smithsonian Way, Copenhagen, DK")
        self.assertEqual(val('//form//input[@name="telephone_number"]'),
                         "555 1234")

    def test_submit_edit(self):
        self.request.form = dict(user_data_fixture)
        agent_mock = Mock()
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

        self.ui.edit_account(self.request)

        self.request.RESPONSE.redirect.assert_called_with(
                'URL/edit_account_html')
        agent_mock.set_user_info.assert_called_with('jsmith',
                                                    user_data_fixture)

    def test_password_form(self):
        page = parse_html(self.ui.change_password_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text
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

        agent_mock.set_user_password.assert_called_with('jsmith', "zxcv")
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/password_changed_html')

        page = parse_html(self.ui.password_changed_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text
        self.assertEqual(txt('//p').strip(), "Password changed successfully")

    def test_submit_new_password_bad_old_password(self):
        self.request.form = {
            'old_password': "asdf",
            'new_password': "zxcv",
            'new_password_confirm': "zxcv",
        }
        agent_mock = Mock()
        agent_mock.perform_bind.side_effect = ValueError
        self.ui._get_ldap_agent = Mock(return_value=agent_mock)

        self.ui.change_password(self.request)

        assert agent_mock.set_user_password.call_count == 0
        self.request.RESPONSE.redirect.assert_called_with(
                'URL/change_password_html')

        page = parse_html(self.ui.change_password_html(self.request))

        txt = lambda xp: page.xpath(xp)[0].text
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

        txt = lambda xp: page.xpath(xp)[0].text
        self.assertEqual(txt('//div[@class="error-msg"]'),
                         "New passwords do not match")
