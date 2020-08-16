# -*- coding: utf-8 -*-

'''
	Venom Add-on
'''

import json
import re
import requests
try:
	from urllib import unquote
except:
	from urllib.parse import unquote

from resources.lib.modules import control
from resources.lib.modules import log_utils
from resources.lib.modules import workers

try:
	token = control.addon('script.module.resolveurl').getSetting('RealDebridResolver_token')
except:
	pass


CLIENT_ID = 'X245A4XAIBGVM' # used to auth and using resolveURL accnt setup
rest_base_url = 'https://api.real-debrid.com/rest/1.0/'
oauth_base_url = 'https://api.real-debrid.com/oauth/v2'
unrestrict_link_path = 'unrestrict/link'
device_endpoint_path = 'device/code'
token_endpoint_path = 'token'
authorize_endpoint_path = 'auth'
credentials_endpoint_path = 'device/credentials'
hosts_regexes_path = 'hosts/regex'
hosts_domains_path = 'hosts/domains'
add_magnet_path = 'torrents/addMagnet'
torrents_info_path = 'torrents/info'
select_files_path = 'torrents/selectFiles'
torrents_delete_path = 'torrents/delete'
check_cache_path = 'torrents/instantAvailability'


class RealDebrid:
	def __init__(self):
		self.token = token
		self.hosters = None
		self.hosts = None
		self.headers = {'Authorization': 'Bearer %s' % self.token}
		self.cache_check_results = {}


	def get_url(self, url, fail_check=False, token_ck=False):
		original_url = url
		url = rest_base_url + url
		if self.token == '':
			log_utils.log('No Real Debrid Token Found', __name__, log_utils.LOGDEBUG)
			return None
		# if not fail_check: # with fail_check=True new token does not get added
		if '?' not in url:
			url += "?auth_token=%s" % self.token
		else:
			url += "&auth_token=%s" % self.token

		response = requests.get(url, timeout=12).text

		if 'bad_token' in response or 'Bad Request' in response:
			if not fail_check:
				if self.refresh_token() and token_ck:
					return
				response = self.get_url(original_url, fail_check=True)
		try:
			return json.loads(response)
		except:
			return response


	def post_url(self, url, data):
		original_url = url
		url = rest_base_url + url
		if self.token == '': return None
		if '?' not in url:
			url += "?auth_token=%s" % self.token
		else:
			url += "&auth_token=%s" % self.token
		response = requests.post(url, data=data, timeout=5).text
		if 'bad_token' in response or 'Bad Request' in response:
			self.refresh_token()
			response = self.post_url(original_url, data)
		try:
			return json.loads(response)
		except:
			return response


	def user_info(self):
		return self.get_url('user', token_ck=True)


	def check_cache_list(self, hashList):
		if isinstance(hashList, list):
			hashList = [hashList[x:x+100] for x in range(0, len(hashList), 100)]
			# Need to check token, and refresh if needed, before blasting threads at it
			ck_token = self.get_url('user', token_ck=True)

			threads = []
			for section in hashList:
				threads.append(workers.Thread(self.check_hash_thread, section))
			[i.start() for i in threads]
			[i.join() for i in threads]

			return self.cache_check_results
		else:
			hashString = "/" + hashList
			return self.get_url("torrents/instantAvailability" + hashString)


	def check_hash_thread(self, hashes):
		try:
			hashString = '/' + '/'.join(hashes)
			response = self.get_url("torrents/instantAvailability" + hashString)
			# log_utils.log('response = %s' % response, __name__, log_utils.LOGDEBUG)
			self.cache_check_results.update(response)
		except:
			log_utils.error()
			pass


	def resolve_magnet_pack(self, media_id, info_hash, season, episode, ep_title):
		from resources.lib.modules.source_utils import seas_ep_filter, episode_extras_filter, supported_video_extensions
		try:
			info_hash = info_hash.lower()
			torrent_id = None
			rd_url = None
			match = False

			extensions = supported_video_extensions()
			extras_filtering_list = episode_extras_filter()

			info_hash = info_hash.lower()

			torrent_files = self.get_url(check_cache_path + '/' + info_hash)
			if not info_hash in torrent_files:
				return None

			torrent_id = self.create_transfer(media_id)
			torrent_files = torrent_files[info_hash]['rd']

			for item in torrent_files:
				video_only = self.video_only(item, extensions)
				if not video_only:
					continue

				correct_file_check = False

				item_values = [i['filename'] for i in item.values()]
				for value in item_values:
					correct_file_check = seas_ep_filter(season, episode, re.sub('[^A-Za-z0-9]+', '.', unquote(value)).lower())
					if correct_file_check:
						break

				if not correct_file_check:
					continue

				torrent_keys = item.keys()
				if len(torrent_keys) == 0:
					continue

				torrent_keys = ','.join(torrent_keys)
				self.select_file(torrent_id, torrent_keys)

				torrent_info = self.torrent_info(torrent_id)

				selected_files = [(idx, i) for idx, i in enumerate([i for i in torrent_info['files'] if i['selected'] == 1])]

				correct_files = []
				correct_file_check = False

				for value in selected_files:
					checker = re.sub('[^A-Za-z0-9]+', '.', unquote(value[1]['path'])).lower()
					correct_file_check = seas_ep_filter(season, episode, checker)
					if correct_file_check:
						correct_files.append(value[1])
						break

				if len(correct_files) == 0:
					continue

				episode_title = re.sub('[^A-Za-z0-9-]+', '.', ep_title.replace("\'", '')).lower()

				for i in correct_files:
					compare_link = re.sub('[^A-Za-z0-9-]+', '.', unquote(i['path'].replace("\'", ''))).lower()
					compare_link = seas_ep_filter(season, episode, compare_link, split=True)
					compare_link = re.sub(episode_title, '', compare_link)

					if any(x in compare_link for x in extras_filtering_list):
						continue
					else:
						match = True
						break

				if match:
					index = [i[0] for i in selected_files if i[1]['path'] == correct_files[0]['path']][0]


				rd_link = torrent_info['links'][index]
				rd_url = self.unrestrict_link(rd_link)

				self.delete_torrent(torrent_id)

				return rd_url

			self.delete_torrent(torrent_id)
		except Exception as e:
			if torrent_id: self.delete_torrent(torrent_id)
			log_utils.log('Real-Debrid Error: RESOLVE MAGNET PACK | %s' % e, __name__, log_utils.LOGDEBUG)
			raise


	def display_magnet_pack(self, magnet_url, info_hash):
		from resources.lib.modules.source_utils import supported_video_extensions
		try:
			torrent_id = None
			rd_url = None
			match = False
			video_only_items = []
			list_file_items = []
			info_hash = info_hash.lower()
			extensions = supported_video_extensions()

			torrent_files = self.get_url(check_cache_path + '/' + info_hash)
			if not info_hash in torrent_files:
				return None

			torrent_id = self.create_transfer(magnet_url)

			if not torrent_id:
				return None

			torrent_files = torrent_files[info_hash]['rd']

			for item in torrent_files:
				video_only = self.video_only(item, extensions)
				if not video_only: continue

				torrent_keys = item.keys()
				if len(torrent_keys) == 0: continue

				video_only_items.append(torrent_keys)

			video_only_items = max(video_only_items, key=len)

			torrent_keys = ','.join(video_only_items)

			self.select_file(torrent_id, torrent_keys)

			torrent_info = self.torrent_info(torrent_id)

			list_file_items = [dict(i, **{'link':torrent_info['links'][idx]})  for idx, i in enumerate([i for i in torrent_info['files'] if i['selected'] == 1])]
			list_file_items = [{'link': i['link'], 'filename': i['path'].replace('/', ''), 'size': float(i['bytes'])/1073741824} for i in list_file_items]

			self.delete_torrent(torrent_id)

			return list_file_items
		except Exception as e:
			if torrent_id: self.delete_torrent(torrent_id)
			log_utils.log('Real-Debrid Error: DISPLAY MAGNET PACK | %s' % str(e), __name__, log_utils.LOGDEBUG)
			raise


	def torrent_info(self, torrent_id):
		try:
			url = torrents_info_path + "/%s" % torrent_id
			return self.get_url(url)
		except Exception as e:
			log_utils.log('Real-Debrid Error: TORRENT INFO | %s' % e, __name__, log_utils.LOGDEBUG)
			raise


	def create_transfer(self, media_id):
		try:
			data = {'magnet': media_id}
			js_result = self.post_url(add_magnet_path, data)
			log_utils.log('Real-Debrid: Sending MAGNET URL to the real-debrid cloud', __name__, log_utils.LOGDEBUG)
			return js_result.get('id', "")
		except Exception as e:
			log_utils.log('Real-Debrid Error: ADD MAGNET | %s' % e, __name__, log_utils.LOGDEBUG)
			raise


	def select_file(self, torrent_id, file_id):
		try:
			url = '%s/%s' % (select_files_path, torrent_id)
			data = {'files': file_id}
			self.post_url(url, data)
			log_utils.log('Real-Debrid: Selected file ID %s from Torrent ID %s to transfer' % (file_id, torrent_id), __name__, log_utils.LOGDEBUG)
			return True
		except Exception as e:
			log_utils.log('Real-Debrid Error: SELECT FILE | %s' % e, __name__, log_utils.LOGDEBUG)
			return False


	def unrestrict_link(self, link):
		post_data = {'link': link}
		response = self.post_url(unrestrict_link_path, post_data)
		try: return response['download']
		except: return None


	def delete_torrent(self, torrent_id):
		try:
			url = torrents_delete_path + "/%s&auth_token=%s" % (torrent_id, self.token)
			response = requests.delete(rest_base_url + url)
			log_utils.log('Real-Debrid: Torrent ID %s was removed from your active torrents' % torrent_id, __name__, log_utils.LOGDEBUG)
			return True
		except Exception as e:
			log_utils.log('Real-Debrid Error: DELETE TORRENT | %s' % e, __name__, log_utils.LOGDEBUG)
			raise


	def get_link(self, link):
		if 'download' in link:
			if 'quality' in link:
				label = '[%s] %s' % (link['quality'], link['download'])
			else:
				label = link['download']
			return label, link['download']


	def video_only(self, storage_variant, extensions):
		return False if len([i for i in storage_variant.values() if not i['filename'].lower().endswith(tuple(extensions))]) > 0 else True


	def refresh_token(self):
		try:
			client_id = control.addon('script.module.resolveurl').getSetting('RealDebridResolver_client_id')
			client_secret = control.addon('script.module.resolveurl').getSetting('RealDebridResolver_client_secret')
			refresh_token = control.addon('script.module.resolveurl').getSetting('RealDebridResolver_refresh')
			log_utils.log('Refreshing Expired Real Debrid Token: |%s|%s|' % (client_id, refresh_token), __name__, log_utils.LOGDEBUG)

			if not self.get_token(client_id, client_secret, refresh_token):
				# empty all auth settings to force a re-auth on next use
				self.reset_authorization()
				log_utils.log('Unable to Refresh Real Debrid Token', __name__, log_utils.LOGDEBUG)
			else:
				log_utils.log('Real Debrid Token Successfully Refreshed', __name__, log_utils.LOGDEBUG)
				return True
		except:
			return False


	def get_token(self, client_id, client_secret, code):
		try:
			url = '%s/%s' % (oauth_base_url, token_endpoint_path)
			postData = {'client_id': client_id, 'client_secret': client_secret, 'code': code, 'grant_type': 'http://oauth.net/grant_type/device/1.0'}

			control.addon('script.module.resolveurl').setSetting('RealDebridResolver_client_id', client_id)
			control.addon('script.module.resolveurl').setSetting('RealDebridResolver_client_secret', client_secret)
			# log_utils.log('Authorizing Real Debrid: %s' % client_id, __name__, log_utils.LOGDEBUG)

			response = requests.post(url, data=postData).text
			response = json.loads(response)

			# log_utils.log('Authorizing Real Debrid Result: |%s|' % response, __name__, log_utils.LOGDEBUG)
			self.token = response['access_token']
			control.addon('script.module.resolveurl').setSetting('RealDebridResolver_token', self.token)
			control.addon('script.module.resolveurl').setSetting('RealDebridResolver_refresh', response['refresh_token'])
			return True
		except Exception as e:
			log_utils.log('Real Debrid Authorization Failed: %s' % e, __name__, log_utils.LOGDEBUG)
			return False


	def reset_authorization(self):
		control.addon('script.module.resolveurl').setSetting('RealDebridResolver_client_id', '')
		control.addon('script.module.resolveurl').setSetting('RealDebridResolver_client_secret', '')
		control.addon('script.module.resolveurl').setSetting('RealDebridResolver_token', '')
		control.addon('script.module.resolveurl').setSetting('RealDebridResolver_refresh', '')