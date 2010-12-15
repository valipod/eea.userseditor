import ldap

user_attr_map = {
    'name': 'cn',
    'email': 'mail',
    'telephone_number': 'telephoneNumber',
    'organisation': 'o',
    'postal_address': 'postalAddress',
    'fax': 'facsimileTelephoneNumber',
    'uri': 'labeledURI',
}

editable_field_names = ['name', 'email', 'organisation', 'uri',
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
        #out = {'dn': dn, 'id': self._user_id(dn)}
        out = {}
        for name, ldap_name in user_attr_map.iteritems():
            if ldap_name in attr:
                out[name] = attr[ldap_name][0].decode(self._encoding)
            else:
                out[name] = None
        return out

    def user_info(self, user_id):
        query_dn = self._user_dn(user_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                        filterstr='(objectClass=organizationalPerson)')

        assert len(result) == 1
        dn, attr = result[0]
        assert dn == query_dn
        return self._unpack_user_info(dn, attr)

    def set_user_info(self, user_id, new_info):
        assert set(new_info.keys()) == set(editable_field_names)

        modify_statemens = []
        for name in editable_field_names:
            # TODO: some values may be missing in LDAP
            stmt = (ldap.MOD_REPLACE,
                    user_attr_map[name], [new_info.get(name, '')])
            modify_statemens.append(stmt)

        result = self.conn.modify_s(self._user_dn(user_id),
                                    tuple(modify_statemens))
        assert result == (ldap.RES_MODIFY, [])

    def bind(self, user_id, user_pw):
        try:
            result = self.conn.simple_bind_s(self._user_dn(user_id), user_pw)
        except ldap.INVALID_CREDENTIALS:
            raise ValueError("Invalid username or password")
        assert result == (ldap.RES_BIND, [])

    def set_user_password(self, user_id, new_pw):
        result = self.conn.passwd_s(self._user_dn(user_id), new_pw)
        assert result == (ldap.RES_MODIFY, [])
