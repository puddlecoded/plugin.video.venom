# -*- coding: utf-8 -*-

'''
	Venom Add-on
'''

import re
import requests
import json
try:
	from urllib import quote_plus, urlencode, unquote
except:
	from urllib.parse import quote_plus, urlencode, unquote

from resources.lib.modules import control
from resources.lib.modules import log_utils

try:
	from resolveurl.plugins.premiumize_me import PremiumizeMeResolver
	token = PremiumizeMeResolver.get_setting('token')
except:
	pass

CLIENT_ID = '522962560'
USER_AGENT = 'ResolveURL for Kodi/%s' % control.getKodiVersion()

BaseUrl = "https://www.premiumize.me/api"
DirectDownload = '%s/transfer/directdl' % BaseUrl
AccountURL = "%s/account/info" % BaseUrl
ListFolder = "%s/folder/list" % BaseUrl
ItemDetails = "%s/item/details" % BaseUrl
TransferList = "%s/transfer/list" % BaseUrl
TransferCreate = "%s/transfer/create" % BaseUrl
TransferDelete = "%s/transfer/delete" % BaseUrl
CacheCheck = '%s/cache/check' % BaseUrl


class Premiumize:
	def __init__(self):
		self.hosts = []
		self.patterns = []
		self.headers = {'User-Agent': USER_AGENT, 'Authorization': 'Bearer %s' % token}


	def get_media_url(self, host, media_id, cached_only=False):
		torrent = False
		cached = self.check_cache(media_id)
		media_id_lc = media_id.lower()

		if cached:
			log_utils.log('Premiumize.me: %s is readily available to stream' % media_id, __name__, log_utils.LOGDEBUG)
			if media_id_lc.endswith('.torrent') or media_id_lc.startswith('magnet:'):
				torrent = True
		elif media_id_lc.endswith('.torrent') or media_id_lc.startswith('magnet:'):
			if self.get_setting('cached_only') == 'true' or cached_only:
				raise ResolverError('Premiumize.me: Cached torrents only allowed to be initiated')

			torrent = True
			log_utils.log('Premiumize.me: initiating transfer to cloud for %s' % media_id, __name__, log_utils.LOGDEBUG)
			self.__initiate_transfer(media_id)
			self.__clear_finished()
			# self.__delete_folder()

		link = self.__direct_dl(media_id, torrent=torrent)
		if link:
			log_utils.log('Premiumize.me: Resolved to %s' % link, __name__, log_utils.LOGDEBUG)
			return link + self.append_headers(self.headers)
		raise ResolverError('Link Not Found')


	def append_headers(self, headers):
		return '|%s' % '&'.join(['%s=%s' % (key, quote_plus(headers[key])) for key in headers])


	def get_url(self, host, media_id):
		return media_id


	def get_host_and_id(self, url):
		return 'premiumize.me', url


	# @common.cache.cache_method(cache_limit=8)
	def get_all_hosters(self):
		try:
			result = request.get(list_services_path, headers=self.headers).json()
			aliases = result.get('aliases', {})
			patterns = result.get('regexpatterns', {})

			tldlist = []
			for tlds in aliases.values():
				for tld in tlds:
					tldlist.append(tld)
			if self.get_setting('torrents') == 'true':
				tldlist.extend([u'torrent', u'magnet'])
			regex_list = []
			for regexes in patterns.values():
				for regex in regexes:
					try:
						regex_list.append(re.compile(regex))
					except:
						log_utils.log('Throwing out bad Premiumize regex: %s' % regex, __name__, log_utils.LOGDEBUG)
			log_utils.log('Premiumize.me patterns: %s regex: (%d) hosts: %s' % (patterns, len(regex_list), tldlist), __name__, log_utils.LOGDEBUG)
			return tldlist, regex_list
		except Exception as e:
			log_utils.log('Error getting Premiumize hosts: %s' % e, __name__, log_utils.LOGDEBUG)
		return [], []


	def valid_url(self, url, host):
		if url and self.get_setting('torrents') == 'true':
			url_lc = url.lower()
			if url_lc.endswith('.torrent') or url_lc.startswith('magnet:'):
				return True
		if not self.patterns or not self.hosts:
			self.hosts, self.patterns = self.get_all_hosters()
		if url:
			if not url.endswith('/'):
				url += '/'
			for pattern in self.patterns:
				if pattern.findall(url):
					return True
		elif host:
			if host.startswith('www.'):
				host = host.replace('www.', '')
			if any(host in item for item in self.hosts):
				return True
		return False


	def resolve_magnet_pack(self, media_id, season, episode, ep_title):
		from resources.lib.modules.source_utils import seas_ep_filter, episode_extras_filter, supported_video_extensions
		try:

			file_url = None
			correct_files = []
			
			extensions = supported_video_extensions()
			extras_filtering_list = episode_extras_filter()
			
			data = {'src': media_id}
			url = '%s/transfer/directdl' % BaseUrl
			result = requests.post(url, data=data, headers=self.headers, timeout=5).text
			result = json.loads(result)
			
			if not 'status' in result or result['status'] != 'success': return None
			
			valid_results = [i for i in result.get('content')if any(i.get('path').lower().endswith(x) for x in extensions) and not i.get('link', '') == '']
			if len(valid_results) == 0: return

			for item in valid_results:

				if seas_ep_filter(season, episode, re.sub('[^A-Za-z0-9]+', '.', unquote(item['path'].split('/')[-1])).lower()):
					correct_files.append(item)
				
				if len(correct_files) == 0: continue
				
				episode_title = re.sub('[^A-Za-z0-9]+', '.', ep_title).lower()
				
				for i in correct_files:
					
					compare_link = re.sub('[^A-Za-z0-9]+', '.', unquote(i['path'])).lower()
					compare_link = seas_ep_filter(season, episode, compare_link, split=True)
					compare_link = re.sub(episode_title, '', compare_link)
					
					if not any(x in compare_link for x in extras_filtering_list):
						file_url = i['link']
						break
			
			if file_url:
				return self.add_headers_to_url(file_url)
		
		except Exception as e:
			log_utils.log('Error resolve_magnet_pack: %s' % str(e), __name__, log_utils.LOGDEBUG)
			return None


	def display_magnet_pack(self, magnet_url, info_hash):
		from resources.lib.modules.source_utils import supported_video_extensions
		try:
			end_results = []
			extensions = supported_video_extensions()
			
			data = {'src': magnet_url}
			url = '%s/transfer/directdl' % BaseUrl
			result = requests.post(url, data=data, headers=self.headers, timeout=5).text
			result = json.loads(result)
			
			if not 'status' in result or result['status'] != 'success': return None
			
			for item in result.get('content'):
				if any(item.get('path').lower().endswith(x) for x in extensions) and not item.get('link', '') == '':
					try: path = item['path'].split('/')[-1]
					except: path = item['path']
					end_results.append({'link': item['link'], 'filename': path, 'size': float(item['size'])/1073741824})
			
			return end_results
		except Exception as e:
			log_utils.log('Error display_magnet_pack: %s' % str(e), __name__, log_utils.LOGDEBUG)
			return None
	

	def add_headers_to_url(self, url):
		return url + '|' + urlencode(self.headers)


	def check_cache_item(self, media_id):
		try:
			media_id = media_id.encode('ascii', errors='ignore').decode('ascii', errors='ignore')
			media_id = media_id.replace(' ', '')
			url = '%s?items[]=%s' % (CacheCheck, media_id)
			result = requests.get(url, headers=self.headers).json()
			if 'status' in result:
				if result.get('status') == 'success':
					response = result.get('response', False)
					# log_utils.log('response = %s' % response, __name__, log_utils.LOGDEBUG)
					if isinstance(response, list):
						return response[0]
		except:
			log_utils.error()
			pass
		return False


	def check_cache_list(self, hashList):
		try:
			url = '%s' % CacheCheck
			postData = {'items[]': hashList}
			result = requests.post(url, data=postData, headers=self.headers, timeout=10).json()
			if 'status' in result:
				if result.get('status') == 'success':
					response = result.get('response', False)
					# log_utils.log('response = %s' % response, __name__, log_utils.LOGDEBUG)
					if isinstance(response, list):
						return response
		except:
			log_utils.error()
			pass
		return False


	def create_transfer(self, media_id):
		folder_id = self.__create_folder()
		if not folder_id == "":
			try:
				data = urlencode({'src': media_id, 'folder_id': folder_id})
				result = request.post(TransferCreate, data=data, headers=self.headers).json()
				if 'status' in result:
					if result.get('status') == 'success':
						log_utils.log('Transfer successfully started to the Premiumize.me cloud', __name__, log_utils.LOGDEBUG)
						return result.get('id', "")
			except:
				log_utils.error()
				pass
		return ""

