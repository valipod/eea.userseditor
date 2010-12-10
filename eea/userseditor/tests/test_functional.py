"""
Functional tests depend on code in `eea.roleseditor` to avoid duplication.
"""

import unittest
import re

from eea.roleseditor.tests.test_functional import (SeleniumWrapper,
                                                   login, logout)

def create_users_editor(S):
    login(S)
    S.open('/manage_addProduct'
                  '/EionetUsersEditor/manage_addUsersEditor_html')
    S.type('id', 'users')
    S.click('//input[@type="submit"]')
    S.wait_for_page_to_load(1000)
    logout(S)

def remove_users_editor(S):
    login(S)
    S.open('/manage_workspace')
    S.wait_for_page_to_load(1000)
    S.click('//input[@name="ids:list"][@value="users"]')
    S.click('//input[@type="submit"][@name="manage_delObjects:method"]')
    S.wait_for_page_to_load(1000)
    logout(S)


def setUpModule():
    global _selenium_wrapper
    _selenium_wrapper = SeleniumWrapper()
    _selenium_wrapper.start_up_selenium()
    create_users_editor(_selenium_wrapper.selenium)

def tearDownModule():
    remove_users_editor(_selenium_wrapper.selenium)
    _selenium_wrapper.shut_down_selenium()

def fetch_and_clear_mail(config):
    from urllib import urlencode
    from urllib2 import urlopen, Request
    import simplejson as json
    mail_json = urlopen(config['test_site_url'] + 'mock_mail_dump').read()
    clear_rq = Request(config['test_site_url'] + 'mock_mail_clear',
                       urlencode({}))
    assert urlopen(clear_rq).read() == 'ok'
    return json.loads(mail_json)

class CreateAccountTests(unittest.TestCase):
    def setUp(self):
        self.selenium = _selenium_wrapper.selenium
        self.config = _selenium_wrapper.config

    def test_create_account(self):
        S = self.selenium
        is_elem = S.is_element_present
        txt = S.get_text

        fetch_and_clear_mail(self.config)
        S.open('/users')
        S.click('//a[text()="Create account"]')
        S.type('first_name:utf8:ustring', "Tester")
        S.type('last_name:utf8:ustring', "Person")
        S.type('uid', "persotes")
        S.type('email', "tester@example.com")
        S.click('//input[@value="Add"]')
        S.wait_for_page_to_load(3000)
        assert txt('//p') == (
            "An e-mail has been sent to your address (tester@example.com). "
            "Follow the instructions in that message to confirm your account.")
        mails = fetch_and_clear_mail(self.config)
        assert len(mails) == 1
        assert mails[0]['subject'] == 'Confirm your Eionet account "persotes"'
        assert mails[0]['to'] == "tester@example.com"
        assert "please click the link below" in mails[0]['body']

        link = re.search(r'(http://\S+)', mails[0]['body']).group(1)
        #S.open(link)
