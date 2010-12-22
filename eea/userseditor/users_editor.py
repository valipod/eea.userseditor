from datetime import datetime
from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from OFS.SimpleItem import SimpleItem
from OFS.PropertyManager import PropertyManager
from AccessControl.Permissions import view

from persistent.list import PersistentList
from persistent.mapping import PersistentMapping

from ldap_agent import LdapAgent, editable_fields


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
        msgs = dict(session[SESSION_MESSAGES])
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

def load_template(name, _memo={}):
    if name not in _memo:
        from zope.pagetemplate.pagetemplatefile import PageTemplateFile
        _memo[name] = PageTemplateFile(name, globals())
    return _memo[name]


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

    def _get_ldap_agent(self):
        return LdapAgent(self.ldap_server)

    _zope2_wrapper = PageTemplateFile('zpt/zope2_wrapper.zpt', globals())

    def _render_template(self, name, **options):
        tmpl = load_template(name)
        return self._zope2_wrapper(body_html=tmpl(**options))

    security.declareProtected(view, 'index_html')
    def index_html(self, REQUEST):
        """ view """
        return self._render_template('zpt/index.zpt',
                                     base_url=self.absolute_url(),
                                     **_get_session_messages(REQUEST))

    security.declareProtected(view, 'edit_account_html')
    def edit_account_html(self, REQUEST):
        """ view """
        if not _is_logged_in(REQUEST):
            _set_session_message(REQUEST, 'error',
                                 "You must be logged in to edit your profile.")
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        user_id = _get_user_id(REQUEST)
        user_data = self._get_ldap_agent().user_info(user_id)
        return self._render_template('zpt/edit_account.zpt',
                                     form_data=user_data,
                                     **_get_session_messages(REQUEST))

    security.declareProtected(view, 'edit_account')
    def edit_account(self, REQUEST):
        """ view """
        user_id = _get_user_id(REQUEST)
        form = REQUEST.form
        user_data = {}
        for name in editable_fields:
            value = form.get(name, u'')
            assert isinstance(value, unicode), repr( (name, value) )
            user_data[name] = value
        agent = self._get_ldap_agent()
        agent.bind(user_id, _get_user_password(REQUEST))
        agent.set_user_info(user_id, user_data)
        when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _set_session_message(REQUEST, 'message', "Profile saved (%s)" % when)
        REQUEST.RESPONSE.redirect(self.absolute_url() + '/edit_account_html')

    security.declareProtected(view, 'change_password_html')
    def change_password_html(self, REQUEST):
        """ view """
        if not _is_logged_in(REQUEST):
            _set_session_message(REQUEST, 'error',
                                 "You must be logged in to edit your profile.")
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        return self._render_template('zpt/change_password.zpt',
                                     user_id=_get_user_id(REQUEST),
                                     **_get_session_messages(REQUEST))

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
        return self._render_template('zpt/result_page.zpt', messages=[
            "Password changed successfully. You must log in again.",
        ])

InitializeClass(UsersEditor)
