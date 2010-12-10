"""
This product is simply an entry point to load the real `eea.userseditor` code,
because it must run on Zope 2.8, where Five does not support the
`registerPackage` directive.
"""
from eea.userseditor import users_editor, initialize

from App.ImageFile import ImageFile
from os import path
_www_path = path.join(path.dirname(users_editor.__file__), 'www')
misc_ = {
    'users_editor.gif': ImageFile(path.join(_www_path, 'users_editor.gif')),
}
