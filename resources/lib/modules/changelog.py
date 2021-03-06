# -*- coding: utf-8 -*-
"""
	Venom Add-on
"""

from resources.lib.modules import control

venom_path = control.addonPath(control.addonId())
venom_version = control.addonVersion(control.addonId())
changelogfile = control.joinPath(venom_path, 'changelog.txt')


def get():
	r = open(changelogfile)
	text = r.read()
	r.close()
	control.dialog.textviewer('[COLOR red]Venom[/COLOR] -  v%s - %s' % (venom_version, 'changelog.txt'), text)