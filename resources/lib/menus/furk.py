# -*- coding: utf-8 -*-
'''
	Venom Add-on
'''

import sys
import json
import requests

try:
	from urllib import quote_plus
except:
	from urllib.parse import quote_plus

from resources.lib.modules import control
from resources.lib.modules import log_utils
from resources.lib.modules.source_utils import supported_video_extensions

accepted_extensions = tuple(supported_video_extensions())


class Furk:
	def __init__(self):
		self.base_link = "https://www.furk.net"
		self.account_info_link = "/api/account/info?api_key=%s"
		# self.search_link = "/api/plugins/metasearch?api_key=%s&q=%s"
		self.search_link = "/api/plugins/metasearch?api_key=%s&q=%s&cached=all" \
								"&sort=cached&type=video&offset=0&limit=200"
		# self.search_link = "/api/plugins/metasearch?api_key=%s&q=%s&cached=all" \
								# "&match=%s&moderated=%s%s&sort=relevance&type=video&offset=0&limit=200"

		# self.get_user_files_link = "/api/file/get?api_key=%s"
		self.get_user_files_link = "/api/file/get?api_key=%s&type=video"
		self.file_info_link = "/api/file/info?api_key%s"
		self.file_link_link = "/api/file/link?"
		self.protect_file_link = "/api/file/protect?"
		self.user_feeds_link = "/api/feed/get?"
		self.add_download_link = "/api/dl/add?"
		self.api_key = control.setting('furk.api')
		self.list = []


	def user_files(self):
		if self.api_key == '': return ''
		try:
			s = requests.Session()
			url = self.base_link + self.get_user_files_link % self.api_key
			# log_utils.log('url = %s' % url, __name__, log_utils.LOGNOTICE)
			p = s.get(url)
			p = json.loads(p.text)
			files = p['files']
		except:
			log_utils.error()
			return ''

		for i in files:
			try:
				name = control.strip_non_ascii_and_unprintable(i['name'])
				url_dl = ''
				for x in accepted_extensions:
					if i['url_dl'].endswith(x): url_dl = i['url_dl']
					else: continue
				if url_dl == '': continue

				if not int(i['files_num_video_player']) > 1:
					if int(i['ss_num']) > 0: thumb = i['ss_urls'][0]
					else: thumb = ''
					self.addDirectoryItem(name , url_dl, thumb, '', False)
				else: pass
			except:
				log_utils.error()
		self.endDirectory()
		return ''


	def search(self):
		from resources.lib.menus import navigator
		navigator.Navigator().addDirectoryItem('New Search', 'furkSearchNew', 'search.png', 'DefaultAddonsSearch.png')
		try:
			from sqlite3 import dbapi2 as database
		except:
			from pysqlite2 import dbapi2 as database
		try:
			dbcon = database.connect(control.searchFile)
			dbcur = dbcon.cursor()
			dbcur.executescript("CREATE TABLE IF NOT EXISTS furk (ID Integer PRIMARY KEY AUTOINCREMENT, term);")
			dbcur.execute("SELECT * FROM furk ORDER BY ID DESC")
			dbcur.connection.commit()
			lst = []
			delete_option = False
			for (id, term) in dbcur.fetchall():
				if term not in str(lst):
					delete_option = True
					navigator.Navigator().addDirectoryItem(term, 'furkMetaSearch&url=%s' % term, 'search.png', 'DefaultAddonsSearch.png', isSearch=True, table='furk')
					lst += [(term)]
		except:
			log_utils.error()
		finally:
			dbcur.close() ; dbcon.close()
		if delete_option:
			navigator.Navigator().addDirectoryItem(32605, 'cache_clearSearch', 'tools.png', 'DefaultAddonProgram.png', isFolder=False)
		navigator.Navigator().endDirectory()


	def search_new(self):
			control.hide()
			t = control.lang(32010)
			k = control.keyboard('', t)
			k.doModal()
			q = k.getText() if k.isConfirmed() else None
			if not q: return
			try:
				from sqlite3 import dbapi2 as database
			except:
				from pysqlite2 import dbapi2 as database
			try:
				dbcon = database.connect(control.searchFile)
				dbcur = dbcon.cursor()
				dbcur.execute("INSERT INTO furk VALUES (?,?)", (None, q))
				dbcur.connection.commit()
			except:
				log_utils.error()
			finally:
				dbcur.close() ; dbcon.close()
			url = quote_plus(q)
			if control.getKodiVersion() >= 18:
				self.furk_meta_search(url)
			else:
				url = '%s?action=furkMetaSearch&url=%s' % (sys.argv[0], quote_plus(url))
				control.execute('Container.Update(%s)' % url)


	def furk_meta_search(self, url):
		if self.api_key == '': return ''
		control.busy()
		try:
			s = requests.Session()
			url = (self.base_link + self.search_link % (self.api_key, url)).replace(' ', '+')
			# url = (self.base_link + self.search_link % (self.api_key, url, 'extended', 'full', '')).replace(' ', '+')
			p = s.get(url)
			p = json.loads(p.text)
			files = p['files']
		except:
			log_utils.error()
			return ''

		for i in files:
			try:
				name = control.strip_non_ascii_and_unprintable(i['name'])
				url_dl = ''
				for x in accepted_extensions:
					if 'url_dl' in i:
						if i['url_dl'].endswith(x): url_dl = i['url_dl']
						else: continue
					else: continue

				if url_dl == '': continue
				if not int(i['files_num_video_player']) > 1:
					if int(i['ss_num']) > 0: thumb = i['ss_urls'][0]
					else: thumb = ''
					self.addDirectoryItem(name, url_dl, thumb, '', False)
				else:
					# self.addDirectoryItem(i['name'].encode('utf-8'), i['url_dl'], '', '')
					continue
			except:
				log_utils.error()
		control.hide()
		self.endDirectory()
		return ''


	def addDirectoryItem(self, name, query, thumb, icon, isAction=True):
		sysaddon = sys.argv[0]
		syshandle = int(sys.argv[1])
		try:
			if type(name) is str or type(name) is unicode: 	name = str(name)
			if type(name) is int: name = control.lang(name)
		except:
			log_utils.error()
		url = '%s?action=%s' % (sysaddon, query) if isAction else query
		item = control.item(label=name)
		item.setArt({'icon': thumb, 'poster': thumb, 'thumb': thumb})
		control.addItem(handle=syshandle, url=url, listitem=item)


	def endDirectory(self):
		syshandle = int(sys.argv[1])
		control.content(syshandle, 'addons')
		control.directory(syshandle, cacheToDisc=True)
		control.sleep(200)