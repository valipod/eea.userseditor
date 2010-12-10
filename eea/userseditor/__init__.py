def initialize(context):
    import users_editor
    constructors = (
        ('manage_addUsersEditor_html', users_editor.manage_addUsersEditor_html),
        ('manage_addUsersEditor', users_editor.manage_addUsersEditor),
    )
    context.registerClass(users_editor.UsersEditor, constructors=constructors)
