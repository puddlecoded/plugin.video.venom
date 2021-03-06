# -*- coding: utf-8 -*-
"""
	Venom Add-on
"""

try: #PY2
	from urllib.request import urlopen, Request
except ImportError: # PY3
	from urllib2 import urlopen, Request
from resources.lib.modules import control

venom_path = control.addonPath(control.addonId())
news_file = 'https://raw.githubusercontent.com/123Venom/zips/master/plugin.video.venom/newsinfo.txt'
local_news = control.joinPath(venom_path, 'newsinfo.txt')


def news():
	message = open_news_url(news_file)
	compfile = open(local_news).read()
	if len(message) > 1:
		if compfile == message: pass
		else:
			text_file = open(local_news, "wb")
			text_file.write(message)
			text_file.close()
			compfile = message
	showText('[B][COLOR red]News and Info[/COLOR][/B]', compfile)

def open_news_url(url):
	req = Request(url)
	req.add_header('User-Agent', 'klopp')
	response = urlopen(req)
	link = response.read()
	response.close()
	return link

def news_local():
	compfile = open(local_news).read()
	showText('[B][COLOR red]News and Info[/COLOR][/B', compfile)

def showText(heading, text):
	return control.dialog.textviewer(heading, text)