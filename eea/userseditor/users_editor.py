from datetime import datetime
from AccessControl import ClassSecurityInfo
from App.class_init import InitializeClass
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from OFS.SimpleItem import SimpleItem
from OFS.PropertyManager import PropertyManager
from AccessControl.Permissions import view

from persistent.list import PersistentList
from persistent.mapping import PersistentMapping
import deform

from eea import usersdb

user_info_schema = usersdb.user_info_schema.clone()
user_info_schema['postal_address'].widget = deform.widget.TextAreaWidget()

SESSION_MESSAGES = 'eea.userseditor.messages'
SESSION_FORM_DATA = 'eea.userseditor.form_data'
SESSION_FORM_ERRORS = 'eea.userseditor.form_errors'

manage_addUsersEditor_html = PageTemplateFile('zpt/add', globals())
def manage_addUsersEditor(parent, id, title="", ldap_server="", REQUEST=None):
    """ Adds a new Eionet Users Editor object """
    ob = UsersEditor(title, ldap_server)
    ob._setId(id)
    parent._setObject(id, ob)
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

def _session_pop(request, name, default):
    session = request.SESSION
    if name in session.keys():
        value = session[name]
        del session[name]
        return value
    else:
        return default

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

CIRCA_USER_SCHEMA = dict(usersdb.db_agent.EIONET_USER_SCHEMA, fax='fax')
CIRCA_USERS_DN_SUFFIX = 'ou=Users,ou=DATA,ou=eea,o=IRCusers,l=CIRCA'

class DualLDAPProxy(object):
    """
    while CIRCA is still online, we need to write stuff to both LDAP
    servers. CIRCA first.
    """

    def __init__(self, current_ldap, legacy_ldap):
        self._current_ldap = current_ldap
        self._legacy_ldap = legacy_ldap

    def bind_user(self, user_id, user_pw):
        self._legacy_ldap.bind_user(user_id, user_pw)
        self._current_ldap.bind_user(user_id, user_pw)

    def set_user_info(self, user_id, new_info):
        self._legacy_ldap.set_user_info(user_id, new_info)
        self._current_ldap.set_user_info(user_id, new_info)

    def set_user_password(self, user_id, old_pw, new_pw):
        self._legacy_ldap.set_user_password(user_id, old_pw, new_pw)
        self._current_ldap.set_user_password(user_id, old_pw, new_pw)

    def __getattr__(self, name):
        # patch all other methods straight to front-end ldap
        return getattr(self._current_ldap, name)


class CircaUsersDB(usersdb.UsersDB):
    user_schema = CIRCA_USER_SCHEMA

    def _user_dn(self, user_id):
        return super(CircaUsersDB, self)._user_dn('%s@circa' % user_id)

    def _user_id(self, user_dn):
        circa_user_id = super(CircaUsersDB, self)._user_id(user_dn)
        assert '@' in circa_user_id
        return circa_user_id.split('@')[0]

    def _search_user_in_orgs(self, user_id):
        return []


class UsersEditor(SimpleItem, PropertyManager):
    meta_type = 'Eionet Users Editor'
    icon = '++resource++eea.userseditor-www/users_editor.gif'
    manage_options = PropertyManager.manage_options + (
        {'label':'View', 'action':''},
    ) + SimpleItem.manage_options
    _properties = (
        {'id':'title', 'type': 'string', 'mode':'w', 'label': 'Title'},
        {'id':'ldap_server', 'type': 'string', 'mode':'w',
         'label': 'LDAP Server'},
    )
    security = ClassSecurityInfo()

    legacy_ldap_server = ""
    _properties += (
        {'id':'legacy_ldap_server', 'type': 'string', 'mode':'w',
         'label': 'Legacy LDAP Server (CIRCA)'},
    )

    def __init__(self, title, ldap_server):
        self.title = title
        self.ldap_server = ldap_server

    def _get_ldap_agent(self, write=False):
        #return usersdb.UsersDB(ldap_server=self.ldap_server)

        # temporary fix while CIRCA is still online
        current_agent = usersdb.UsersDB(ldap_server=self.ldap_server)
        if write and self.legacy_ldap_server != "":
            legacy_agent = CircaUsersDB(ldap_server=self.legacy_ldap_server,
                                        users_dn=CIRCA_USERS_DN_SUFFIX,
                                        encoding="ISO-8859-1")
            return DualLDAPProxy(current_agent, legacy_agent)
        else:
            return current_agent

    _zope2_wrapper = PageTemplateFile('zpt/zope2_wrapper.zpt', globals())

    def _render_template(self, name, **options):
        tmpl = load_template(name)
        return self._zope2_wrapper(body_html=tmpl(**options))

    security.declareProtected(view, 'index_html')
    def index_html(self, REQUEST):
        """ view """
        options = {
            'base_url': self.absolute_url(),
        }
        if _is_logged_in(REQUEST):
            agent = self._get_ldap_agent()
            user_id = _get_user_id(REQUEST)
            options['user_info'] = agent.user_info(user_id)
        else:
            options['user_info'] = None
        options.update(_get_session_messages(REQUEST))
        return self._render_template('zpt/index.zpt', **options)

    security.declareProtected(view, 'edit_account_html')
    def edit_account_html(self, REQUEST):
        """ view """
        if not _is_logged_in(REQUEST):
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        agent = self._get_ldap_agent()
        user_id = _get_user_id(REQUEST)
        all_orgs = agent.all_organisations()
        sort_key = lambda org_id: all_orgs[org_id].strip().lower()

        errors = _session_pop(REQUEST, SESSION_FORM_ERRORS, {})
        form_data = _session_pop(REQUEST, SESSION_FORM_DATA, None)
        if form_data is None:
            form_data = agent.user_info(user_id)

        options = {
            'base_url': self.absolute_url(),
            'form_data': form_data,
            'all_organisations': all_orgs,
            'sorted_org_ids': sorted(all_orgs, key=sort_key),
            'errors': errors,
            'schema': user_info_schema,
        }
        options.update(_get_session_messages(REQUEST))
        return self._render_template('zpt/edit_account.zpt', **options)

    security.declareProtected(view, 'edit_account')
    def edit_account(self, REQUEST):
        """ view """
        user_id = _get_user_id(REQUEST)

        user_form = deform.Form(user_info_schema)

        class CircaError(Exception): pass
        try:
            user_data = user_form.validate(REQUEST.form.items())

            bad = {}
            for name, value in user_data.items():
                try:
                    value.encode('latin-1')
                except UnicodeEncodeError:
                    bad[name] = (u"Until CIRCA is phased out, please use only "
                            "Western European characters in profile fields.")
            if bad:
                raise CircaError(bad)

        except deform.ValidationFailure, e:
            session = REQUEST.SESSION
            errors = {}
            for field_error in e.error.children:
                errors[field_error.node.name] = field_error.msg
            session[SESSION_FORM_ERRORS] = errors
            session[SESSION_FORM_DATA] = dict(REQUEST.form)
            msg = u"Please correct the errors below and try again."
            _set_session_message(REQUEST, 'error', msg)

        except CircaError, e:
            session = REQUEST.SESSION
            session[SESSION_FORM_ERRORS] = e.args[0]
            session[SESSION_FORM_DATA] = dict(REQUEST.form)
            msg = u"Please correct the errors below and try again."
            _set_session_message(REQUEST, 'error', msg)

        else:
            agent = self._get_ldap_agent(write=True)
            agent.bind_user(user_id, _get_user_password(REQUEST))
            agent.set_user_info(user_id, user_data)
            when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _set_session_message(REQUEST, 'message', "Profile saved (%s)" % when)

        REQUEST.RESPONSE.redirect(self.absolute_url() + '/edit_account_html')

    security.declareProtected(view, 'change_password_html')
    def change_password_html(self, REQUEST):
        """ view """
        if not _is_logged_in(REQUEST):
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        return self._render_template('zpt/change_password.zpt',
                                     user_id=_get_user_id(REQUEST),
                                     base_url=self.absolute_url(),
                                     **_get_session_messages(REQUEST))

    security.declareProtected(view, 'change_password')
    def change_password(self, REQUEST):
        """ view """
        form = REQUEST.form
        user_id = _get_user_id(REQUEST)
        agent = self._get_ldap_agent(write=True)

        if form['new_password'] != form['new_password_confirm']:
            _set_session_message(REQUEST, 'error',
                                 "New passwords do not match")
            return REQUEST.RESPONSE.redirect(self.absolute_url() +
                                             '/change_password_html')

        try:
            agent.bind_user(user_id, form['old_password'])
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
            'messages': [
                "Password changed successfully. You must log in again."],
            'base_url': self.absolute_url(),
        }
        return self._render_template('zpt/result_page.zpt', **options)

InitializeClass(UsersEditor)
