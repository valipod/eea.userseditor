import ldap

user_attr_map = {
    'first_name': 'givenName',
    'last_name': 'sn',
    'full_name': 'cn',
    'email': 'mail',
    'telephone_number': 'telephoneNumber',
    'organisation': 'o',
    'postal_address': 'postalAddress',
    'fax': 'facsimileTelephoneNumber',
    'uri': 'labeledURI',
}

editable_field_names = ['first_name', 'last_name',
                        'email', 'organisation', 'uri',
                        'postal_address', 'telephone_number']

class LdapAgent(object):
    _user_dn_suffix = 'ou=Users,o=EIONET,l=Europe'
    _encoding = 'utf-8'

    def __init__(self, server):
        self.conn = self.connect(server)

    def connect(self, server):
        conn = ldap.initialize('ldap://' + server)
        conn.protocol_version = ldap.VERSION3
        return conn

    def _user_dn(self, user_id):
        assert ',' not in user_id
        return 'uid=' + user_id + ',' + self._user_dn_suffix

    def _unpack_user_info(self, dn, attr):
        out = {}
        for name, ldap_name in user_attr_map.iteritems():
            if ldap_name in attr:
                assert len(attr[ldap_name]) == 1
                out[name] = attr[ldap_name][0].decode(self._encoding)
            else:
                out[name] = ''
        return out

    def user_info(self, user_id):
        query_dn = self._user_dn(user_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                        filterstr='(objectClass=organizationalPerson)')

        assert len(result) == 1
        dn, attr = result[0]
        assert dn == query_dn
        return self._unpack_user_info(dn, attr)

    def _user_info_diff(self, old_info, new_info):
        modify_statements = []
        def do(*args):
            modify_statements.append(args)

        def pack(value):
            return [value.encode(self._encoding)]

        new_info = dict(new_info)
        new_info['full_name'] = '%s %s' % (new_info['first_name'],
                                           new_info['last_name'])
        for name in editable_field_names + ['full_name']:
            old_value = old_info[name]
            new_value = new_info[name]
            ldap_name = user_attr_map[name]

            if old_value == new_value == '':
                pass

            elif old_value == '':
                do(ldap.MOD_ADD, ldap_name, pack(new_value))

            elif new_value == '':
                do(ldap.MOD_DELETE, ldap_name, pack(old_value))

            elif old_value != new_value:
                do(ldap.MOD_REPLACE, ldap_name, pack(new_value))

        return modify_statements

    def set_user_info(self, user_id, new_info):
        old_info = self.user_info(user_id)
        modify_statements = self._user_info_diff(old_info, new_info)
        if not modify_statements:
            return

        result = self.conn.modify_s(self._user_dn(user_id),
                                    tuple(modify_statements))
        assert result == (ldap.RES_MODIFY, [])

    def bind(self, user_id, user_pw):
        try:
            result = self.conn.simple_bind_s(self._user_dn(user_id), user_pw)
        except (ldap.INVALID_CREDENTIALS,
                ldap.UNWILLING_TO_PERFORM):
            raise ValueError("Authentication failure")
        assert result == (ldap.RES_BIND, [])

    def set_user_password(self, user_id, old_pw, new_pw):
        try:
            result = self.conn.passwd_s(self._user_dn(user_id), old_pw, new_pw)
        except ldap.UNWILLING_TO_PERFORM:
            raise ValueError("Authentication failure")
        assert result == (ldap.RES_EXTENDED, [])