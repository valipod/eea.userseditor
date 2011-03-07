from datetime import datetime
from AccessControl import ClassSecurityInfo
from App.class_init import InitializeClass
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from OFS.SimpleItem import SimpleItem
from OFS.PropertyManager import PropertyManager
from AccessControl.Permissions import view

from persistent.list import PersistentList
from persistent.mapping import PersistentMapping

from ldap_agent import LdapAgent, editable_fields, ORG_LITERAL, ORG_BY_ID


SESSION_MESSAGES = 'eea.userseditor.messages'

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

    def __init__(self, title, ldap_server):
        self.title = title
        self.ldap_server = ldap_server

    def _get_ldap_agent(self):
        return LdapAgent(self.ldap_server)

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
            if options['user_info']['organisation'][0] == ORG_BY_ID:
                options['all_organisations'] = agent.all_organisations()
        else:
            options['user_info'] = None
        options.update(_get_session_messages(REQUEST))
        return self._render_template('zpt/index.zpt', **options)

    security.declareProtected(view, 'edit_account_html')
    def edit_account_html(self, REQUEST):
        """ view """
        if not _is_logged_in(REQUEST):
            return REQUEST.RESPONSE.redirect(self.absolute_url() + '/')

        user_id = _get_user_id(REQUEST)
        agent = self._get_ldap_agent()
        all_orgs = agent.all_organisations()
        sort_key = lambda org_id: all_orgs[org_id].strip().lower()
        options = {
            'base_url': self.absolute_url(),
            'form_data': agent.user_info(user_id),
            'all_organisations': all_orgs,
            'sorted_org_ids': sorted(all_orgs, key=sort_key),
        }
        options.update(_get_session_messages(REQUEST))
        return self._render_template('zpt/edit_account.zpt', **options)

    security.declareProtected(view, 'edit_account')
    def edit_account(self, REQUEST):
        """ view """
        user_id = _get_user_id(REQUEST)
        form = REQUEST.form
        def get_form_field(name, check_unicode=True):
            value = form.get(name, u"")
            if check_unicode:
                assert isinstance(value, unicode), repr( (name, value) )
            return value
        user_data = {}
        for name in editable_fields:
            if name == 'organisation':
                org_type = form.get('org_type', ORG_LITERAL)
                if org_type == ORG_LITERAL:
                    value = (ORG_LITERAL, get_form_field('org_literal'))
                elif org_type == ORG_BY_ID:
                    value = (ORG_BY_ID, get_form_field('org_id', False))
                else:
                    raise ValueError("Unknown organisation type %r" % org_type)
            else:
                value = get_form_field(name)
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
            'messages': [
                "Password changed successfully. You must log in again."],
            'base_url': self.absolute_url(),
        }
        return self._render_template('zpt/result_page.zpt', **options)

InitializeClass(UsersEditor)
