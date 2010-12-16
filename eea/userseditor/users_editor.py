from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from OFS.SimpleItem import SimpleItem
from OFS.PropertyManager import PropertyManager
from AccessControl.Permissions import view

from persistent.list import PersistentList
from persistent.mapping import PersistentMapping

from ldap_agent import LdapAgent
from templates import z3_tmpl

SESSION_MESSAGES = 'eea.userseditor.messages'

manage_addUsersEditor_html = PageTemplateFile('zpt/add', globals())
def manage_addUsersEditor(parent, id, REQUEST=None):
    """ Adds a new Eionet Users Editor object """
    parent._setObject(id, UsersEditor(id))
    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(parent.absolute_url() + '/manage_workspace')

def _get_session_messages(request):
    session = request.SESSION
    if SESSION_MESSAGES in session.keys():
        msgs = session[SESSION_MESSAGES]
        del session[SESSION_MESSAGES]
    else:
        msgs = {}
    return msgs

def _set_session_message(request, msg_type, msg):
    session = request.SESSION
    if SESSION_MESSAGES not in session.keys():
        session[SESSION_MESSAGES] = PersistentMapping()
    # TODO: allow for more than one message of each type
    session[SESSION_MESSAGES][msg_type] = msg

def _get_user_password(request):
    return request.AUTHENTICATED_USER.__

def _get_user_id(request):
    return request.AUTHENTICATED_USER.getId()

def _is_logged_in(request):
    if _get_user_id(request) is None:
        return False
    else:
        return True

class UsersEditor(SimpleItem, PropertyManager):
    meta_type = 'Eionet Users Editor'
    icon = 'misc_/EionetUsersEditor/users_editor.gif'
    manage_options = PropertyManager.manage_options + (
        {'label':'View', 'action':''},
    ) + SimpleItem.manage_options
    _properties = (
        {'id':'ldap_server', 'type': 'string', 'mode':'w',
         'label': 'LDAP Server'},
    )
    security = ClassSecurityInfo()

    def __init__(self, id):
        self.id = id
        self.ldap_server = ""

    _form_fields = ['uid', 'email', 'organisation', 'uri',
                    'postal_address', 'telephone_number']

    def _get_ldap_agent(self):
        return LdapAgent(self.ldap_server)

    standard_html_header = ""
    standard_html_footer = ""
    def _render_template(self, name, options):
        tmpl = z3_tmpl(name)
        zope2_wrapper = PageTemplateFile('zpt/zope2_wrapper.zpt', globals())
        return zope2_wrapper.__of__(self)(body_html=tmpl(**options))

    security.declareProtected(view, 'index_html')
    def index_html(self, REQUEST):
        """ view """
        options = {
            '_global': {'here': self}, # TODO: get rid of the 'here' reference
            'base_url': self.absolute_url(),
        }
        options.update(_get_session_messages(REQUEST))
        return self._render_template('zpt/index.zpt', options)

    security.declareProtected(view, 'edit_account_html')
    def edit_account_html(self, REQUEST):
        """ view """
        if not _is_logged_in(REQUEST):
            _set_session_message(REQUEST, 'error',
                                 "You must be logged in to edit your profile.")
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        user_id = _get_user_id(REQUEST)
        user_data = self._get_ldap_agent().user_info(user_id)
        options = {
            '_global': {'here': self},
            'form_data': user_data,
        }
        return self._render_template('zpt/edit_account.zpt', options)

    security.declareProtected(view, 'edit_account')
    def edit_account(self, REQUEST):
        """ view """
        user_id = _get_user_id(REQUEST)
        form = REQUEST.form
        user_data = dict( (n, form.get(n, '')) for n in self._form_fields )
        agent = self._get_ldap_agent()
        agent.bind(user_id, _get_user_password(REQUEST))
        agent.set_user_info(form['uid'], user_data)
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/edit_account_html')

    security.declareProtected(view, 'change_password_html')
    def change_password_html(self, REQUEST):
        """ view """
        if not _is_logged_in(REQUEST):
            _set_session_message(REQUEST, 'error',
                                 "You must be logged in to edit your profile.")
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        options = {
            '_global': {'here': self},
            'form_data': {'uid': _get_user_id(REQUEST)},
        }
        options.update(_get_session_messages(REQUEST))
        return self._render_template('zpt/change_password.zpt', options)

    security.declareProtected(view, 'change_password')
    def change_password(self, REQUEST):
        """ view """
        form = REQUEST.form
        user_id = _get_user_id(REQUEST)
        agent = self._get_ldap_agent()

        if form['new_password'] != form['new_password_confirm']:
            _set_session_message(REQUEST, 'error',
                                 "New passwords do not match")
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/change_password_html')

        try:
            agent.bind(user_id, form['old_password'])
            agent.set_user_password(user_id, form['old_password'],
                                             form['new_password'])
        except ValueError:
            _set_session_message(REQUEST, 'error', "Old password is wrong")
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/change_password_html')

        REQUEST.RESPONSE.redirect(self.absolute_url() +
                                  '/password_changed_html')

    security.declareProtected(view, 'password_changed_html')
    def password_changed_html(self, REQUEST):
        """ view """
        options = {
            '_global': {'here': self},
            'messages': [
                "Password changed successfully. You must log in again."],
        }
        return self._render_template('zpt/result_page.zpt', options)

InitializeClass(UsersEditor)
