import logging
from functools import wraps
import ldap, ldap.filter

log = logging.getLogger(__name__)

user_attr_map = {
    'first_name': 'givenName',
    'last_name': 'sn',
    'full_name': 'cn',
    'email': 'mail',
    'phone': 'telephoneNumber',
    'organisation': 'o',
    'postal_address': 'postalAddress',
    'fax': 'facsimileTelephoneNumber',
    'url': 'labeledURI',
}

editable_fields = ['first_name', 'last_name', 'email', 'organisation', 'url',
                   'postal_address', 'phone']

ORG_LITERAL = 'literal'
ORG_BY_ID = 'by_id'
BLANK_ORG = (ORG_LITERAL, u"")

def log_ldap_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ldap.LDAPError:
            log.exception("Uncaught exception from LDAP")
            raise
    return wrapper

class LdapAgent(object):
    _user_dn_suffix = 'ou=Users,o=EIONET,l=Europe'
    _org_dn_suffix = 'ou=Organisations,o=EIONET,l=Europe'
    _encoding = 'utf-8'

    def __init__(self, server):
        self.conn = self.connect(server)

    @log_ldap_exceptions
    def connect(self, server):
        conn = ldap.initialize('ldap://' + server)
        conn.protocol_version = ldap.VERSION3
        return conn

    def _user_dn(self, user_id):
        assert ',' not in user_id
        return 'uid=' + user_id + ',' + self._user_dn_suffix

    def _org_dn(self, org_id):
        assert ',' not in org_id
        return 'cn=' + org_id + ',' + self._org_dn_suffix

    def _org_id(self, org_dn):
        assert org_dn.endswith(',' + self._org_dn_suffix)
        assert org_dn.startswith('cn=')
        org_id = org_dn[len('cn=') : - (len(self._org_dn_suffix) + 1)]
        assert ',' not in org_id
        return org_id

    def _unpack_user_info(self, dn, attr):
        out = {}
        for name, ldap_name in user_attr_map.iteritems():
            if ldap_name in attr:
                assert len(attr[ldap_name]) == 1
                py_value = attr[ldap_name][0].decode(self._encoding)
            else:
                py_value = u""

            if name == 'organisation':
                out[name] = (ORG_LITERAL, py_value)
            else:
                out[name] = py_value

        return out

    @log_ldap_exceptions
    def user_info(self, user_id):
        query_dn = self._user_dn(user_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                        filterstr='(objectClass=organizationalPerson)')

        assert len(result) == 1
        dn, attr = result[0]
        assert dn == query_dn

        user_info = self._unpack_user_info(dn, attr)
        if user_info['organisation'] == BLANK_ORG:
            org_ids = self._search_user_in_orgs(user_id)
            if org_ids:
                user_info['organisation'] = (ORG_BY_ID, org_ids[0])

        return user_info

    def _update_full_name(self, user_info):
        full_name = '%s %s' % (user_info.get('first_name', u""),
                               user_info.get('last_name', u""))
        user_info['full_name'] = full_name.strip()

    def _user_info_diff(self, user_id, old_info, new_info, existing_orgs):
        def pack(value):
            return [value.encode(self._encoding)]

        def unpack_org_tuple(org_tuple):
            v_type, v_value = org_tuple
            if v_type == ORG_LITERAL:
                return v_value, []
            elif v_type == ORG_BY_ID:
                return u"", [v_value]
            else:
                raise ValueError('Unknown organisation type: %r' % v_type)

        # normalize user_info dictionaries
        old_info = dict(old_info)
        new_info = dict(new_info)
        old_info.setdefault('organisation', BLANK_ORG)
        new_info.setdefault('organisation', BLANK_ORG)
        self._update_full_name(new_info)

        # special case for the `organisation` field
        old_info['organisation'], _ignored = \
                unpack_org_tuple(old_info['organisation'])
        new_info['organisation'], new_org_ids = \
                unpack_org_tuple(new_info['organisation'])

        # compute delta
        modify_statements = []
        def do(*args):
            modify_statements.append(args)

        for name in editable_fields + ['full_name']:
            old_value = old_info.get(name, u"")
            new_value = new_info.get(name, u"")
            ldap_name = user_attr_map[name]

            if old_value == new_value == '':
                pass

            elif old_value == '':
                do(ldap.MOD_ADD, ldap_name, pack(new_value))

            elif new_value == '':
                do(ldap.MOD_DELETE, ldap_name, pack(old_value))

            elif old_value != new_value:
                do(ldap.MOD_REPLACE, ldap_name, pack(new_value))

        # we allow for multiple values coming from LDAP but we only save a
        # single organisation (literal or by id)
        add_to_orgs = set(new_org_ids) - set(existing_orgs)
        remove_from_orgs = set(existing_orgs) - set(new_org_ids)

        # compose output for ldap calls
        out = {}
        user_dn = self._user_dn(user_id)
        if modify_statements:
            out[user_dn] = modify_statements
        for org_id in add_to_orgs:
            out[self._org_dn(org_id)] = [
                (ldap.MOD_ADD, 'uniqueMember', [user_dn]),
            ]
        for org_id in remove_from_orgs:
            out[self._org_dn(org_id)] = [
                (ldap.MOD_DELETE, 'uniqueMember', [user_dn]),
            ]

        return out

    @log_ldap_exceptions
    def set_user_info(self, user_id, new_info):
        old_info = self.user_info(user_id)
        existing_orgs = self._search_user_in_orgs(user_id)
        diff = self._user_info_diff(user_id, old_info, new_info, existing_orgs)
        if not diff:
            return

        log.info("Modifying info for user %r", user_id)
        for dn, modify_statements in diff.iteritems():
            result = self.conn.modify_s(dn, tuple(modify_statements))
            assert result == (ldap.RES_MODIFY, [])

    @log_ldap_exceptions
    def bind_user(self, user_id, user_pw):
        try:
            result = self.conn.simple_bind_s(self._user_dn(user_id), user_pw)
        except (ldap.INVALID_CREDENTIALS,
                ldap.UNWILLING_TO_PERFORM):
            raise ValueError("Authentication failure")
        assert result == (ldap.RES_BIND, [])

    @log_ldap_exceptions
    def set_user_password(self, user_id, old_pw, new_pw):
        log.info("Changing password for user %r", user_id)
        try:
            result = self.conn.passwd_s(self._user_dn(user_id), old_pw, new_pw)
        except ldap.UNWILLING_TO_PERFORM:
            raise ValueError("Authentication failure")
        assert result == (ldap.RES_EXTENDED, [])

    def _search_user_in_orgs(self, user_id):
        user_dn = self._user_dn(user_id)
        query_filter = ldap.filter.filter_format(
            '(&(objectClass=organizationGroup)(uniqueMember=%s))', (user_dn,))

        result = self.conn.search_s(self._org_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query_filter, attrlist=())
        return [self._org_id(dn) for dn, attr in result]

    @log_ldap_exceptions
    def all_organisations(self):
        result = self.conn.search_s(self._org_dn_suffix, ldap.SCOPE_ONELEVEL,
                    filterstr='(objectClass=organizationGroup)',
                    attrlist=('o',))
        return dict( (self._org_id(dn),
                      attr.get('o', [u""])[0].decode(self._encoding))
                     for dn, attr in result )
