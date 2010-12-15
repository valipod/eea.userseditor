from zope.pagetemplate.pagetemplatefile import PageTemplateFile

class PatchedPageTemplateFile(PageTemplateFile):
    def pt_getContext(self, args, kwargs):
        rval = super(PageTemplateFile, self).pt_getContext(args, kwargs)
        rval.update(rval['options'].pop('_global', {}))
        return rval

def z3_tmpl(name):
    return PatchedPageTemplateFile(name, globals())
