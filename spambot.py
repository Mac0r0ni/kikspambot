from typing import Union
import pickle
import logging
import re
import json
#import enchant
#d = enchant.Dict("en_US")
permission_pattern = re.compile("permission \d")
lurk_time_pattern = re.compile("lurktime \d")
import re
regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

trigger_sympol = "=>"
cap_48_pattern = re.compile("cap48 \d")
from datetime import datetime
import os.path
from os import path
import logging
from threading import Thread
import sys
import time
import copy
import math
import kik_unofficial.datatypes.xmpp.chatting as chatting
from kik_unofficial.client import KikClient
from kik_unofficial.callbacks import KikClientCallback
from kik_unofficial.datatypes.xmpp.errors import SignUpError, LoginError
from kik_unofficial.datatypes.xmpp.roster import FetchRosterResponse, PeersInfoResponse
from kik_unofficial.datatypes.xmpp.sign_up import RegisterResponse, UsernameUniquenessResponse
from kik_unofficial.datatypes.xmpp.login import LoginResponse, ConnectionFailedResponse
from kik_unofficial.datatypes.peers import Group, Peer, User
import kik_unofficial.datatypes.xmpp.roster as roster
import kik_unofficial.datatypes.xmpp.xiphias as xiphias
username ="BotTestName"
password = "iam1337"
my_username = ["dude"]
bot_name = "Renegade"
max_name_len = 10

def main():
	# set up logging
	logger = logging.getLogger()
	logger.setLevel(logging.INFO)
	stream_handler = logging.StreamHandler(sys.stdout)
	stream_handler.setFormatter(logging.Formatter(KikClient.log_format()))
	logger.addHandler(stream_handler)

	# create the bot
	bot = EchoBot()
def jid_to_username(jid):
	return jid.split('@')[0][0:-4]

class EchoBot(KikClientCallback):
	message_queue = []
	user_group_jids = {}
	current_user = ""
	temp_jid = ""
	group_jid = None
	welcome_user = False
#	bot_usernames = ["BotTestName", "TesterBoop"]
	bot_jids = ["bottestname_rqp@talk.kik.com", "testerboop_5dz@talk.kik.com"]
	def __init__(self):
		self.lag_codes = []
		if path.exists("lag_codes.p"):
			self.lag_codes = pickle.load( open( "lag_codes.p", "rb" ) )
		self.client = KikClient(self, username, password)
		self.nicknames = {}
		if path.exists("nicknames.p"):
			self.nicknames = pickle.load( open( "nicknames.p", "rb" ) )
		self.groups_greeting_messeges = {}
		if path.exists("groups_greeting_messeges.p"):
			self.groups_greeting_messeges = pickle.load( open( "groups_greeting_messeges.p", "rb" ) )
		self.groups_permissions = {}
		if path.exists("groups_permissions.p"):
			self.groups_permissions = pickle.load( open( "groups_permissions.p", "rb" ) )
		self.groups_goodbye_messeges = {}
		if path.exists("groups_goodbye_messeges.p"):
			self.groups_goodbye_messeges = pickle.load( open( "groups_goodbye_messeges.p", "rb" ) )
		self.groups_triggers = {}
		if path.exists("groups_triggers.p"):
			self.groups_triggers = pickle.load( open( "groups_triggers.p", "rb" ) )
		self.groups_blacklist  = {}
		if path.exists("groups_blacklist.p"):
			self.groups_blacklist = pickle.load( open( "groups_blacklist.p", "rb" ) )
			#print("loaded black list group from pickle file =>", self.groups_blacklist)
		self.rules = {}
		if path.exists("rules.p"):
			self.rules = pickle.load( open( "rules.p", "rb" ) )
		self.prohipited_groups = set()
		if path.exists("prohipited_groups.p"):
			self.prohipited_groups = pickle.load( open( "prohipited_groups.p", "rb" ) )
		self.groups_spam_mute_time={}
		if path.exists('mut_users.p'):
			self.groups_spam_mute_time=pickle.load(open("mut_users.p","rb"))
		if path.exists("activity_times.p") and os.path.getsize('activity_times.p') > 0:
			self.groups_active_time = pickle.load(open("activity_times.p","rb"))
		else:
			self.groups_active_time = {}
		if path.exists("groups_spam_time.p") and os.path.getsize('groups_spam_time.p') > 0:
			self.groups_spam_time = pickle.load(open("groups_spam_time.p","rb"))
		else:
			self.groups_spam_time = {}
		if path.exists("peers_info.p") and os.path.getsize('peers_info.p') > 0:
			self.peers_info = pickle.load(open("peers_info.p","rb"))
		else:
			self.peers_info = {}
		if path.exists("groups_members.p") and os.path.getsize('groups_members.p') > 0:
			self.groups_members = pickle.load(open("groups_members.p","rb"))
		else:
			self.groups_members = {}

		self.groups_last_msg = {}
		self.groups_spam_score = {}
		
		self.groups = {}
		self.friends = {}
		self.lurks = {}
		self.lurks_enabled = {}
		self.lurks_wait_time = {}
		self.is_locked = {}
		self.new_groups_lock = {}
		self.message_48 = "While 48 mode is enabled, "+bot_name+" will remove the last talking non-admin members to keep spots open for new members.\n\nUsage:\nEnable 48 \nDisable 48 \n\nThe capacity can be changed from 48 to anything between 1 and 99 with the following command: \n\nCap48 40"
		if path.exists("is_locked.p"):
			self.is_locked = pickle.load( open( "is_locked.p", "rb" ) )
		
		self.lock_messages = {}
		if path.exists("lock_messages.p"):
			self.lock_messages = pickle.load( open( "lock_messages.p", "rb" ) )
		self.is_48 = {}
		if path.exists("is_48.p"):
			self.is_48 = pickle.load( open( "is_48.p", "rb" ) )
		self.cap_48 = {}
		if path.exists("cap_48.p"):
			self.cap_48 = pickle.load( open( "cap_48.p", "rb" ) )
		self.help_msg = "~ Chat Commands ~\n- \"Ping\" pong (for checking if "+bot_name+" is up)\n- \"Admins\" lists admins\n- \"Active\" lists lurker activity\n- \"Talkers\" lists talker activity\n- \"Help\" lists commands\n- \"Trigger\" lists substitutions\n- \"Blacklist\" lists censored words\n- \"Trigger => Response\" when someone says Trigger, " +bot_name+" will answer with Response (substitutions)\n- \"Delete Trigger\" removes the substitution\n- \"Greeting\" lists the greeting\n- \"Rules\" lists the rules\n- \"GIF\" GIF Cat posts a cat GIF or use any other term after GIF\n- \"" +bot_name+" call me [Name]\" " +bot_name+" will respond with \"Hello [Name]\" if you say \"hey\" or \"hi\"\n\n ~ Admin Commands ~\n- \"Set greeting Hello and welcome\" when someone joins, " +bot_name+" will say Hello and welcome\n- \"Delete greeting\" removes the Hello and welcome\n- \"Set the rules Don't spam\" when someone joins, " +bot_name+" will say Don't spam\n- \"Rules delete\" removes the rules\n- \"Set goodbye Goodbye\" when someone leaves, " +bot_name+" will say Goodbye\n- \"Delete goodbye\" removes the goodbye message\n- \"Blacklist [word]\" removes a user if they say the censored word or if their name contains the censored word when they join a group\n- \"Blacklist delete [word]\" removes the censored word\n- \"Close\" locks the group. Say \"Close message + your custom message\" to set a custom lock message\n- \"Open\" unlocks the group\n- \"48 Mode\" lists the usage of 48 Mode (keeps a spot open for new people that join a group)\n- \"Enable lurks\" removes users that join and don't say anything within 5 minutes. Can be adjusted to 1-15 minutes. \"Disable lurks\" to disable it.\n- \"Enable Profile Picture\" removes users who join without a profile picture. \"Disable Profile Picture\" to disable it.\n- \"Noobs Disallow\" \"Noobs Disallow 1\" or any number you set from 1 and above will remove users who have less than this number of days on their account. \"Noobs Disallow 0\" to disable it.\n- \"Permissions\" change what non-admins can do\n- \"" +bot_name+" leave\" makes " +bot_name+" leave\n\nPlease note all the commands have to be written without the \" \" "
	
	def on_authenticated(self):
		print("Now I'm Authenticated, let's request roster")
		for jid in self.bot_jids:
#			bot_jid = self.client.get_jid(username)
			self.client.add_friend(jid)
			self.added_bot = True
#			self.bot_jids.append(bot_jid)
		self.client.request_roster()

	def on_login_ended(self, response: LoginResponse):
		print("Full name: {} {}".format(response.first_name, response.last_name))

	def on_chat_message_received(self, chat_message: chatting.IncomingChatMessage):
		print("[+] '{}' says: {}".format(chat_message.from_jid, chat_message.body))
		try:
			group_id = chat_message.group_jid
		except:
			group_id='a'
		user_id = chat_message.from_jid
		try:
			data=self.groups_spam_mute_time[group_id][user_id]
			if(data[-1]):
				if((datetime.now()-data[0]).seconds > 60):
					del self.groups_spam_mute_time[group_id][user_id]
					pickle.dump( self.groups_spam_mute_time, open( "mut_users.p", "wb" ) )
				else:
					return
			else:
				pass
		except:
			pass
		msg = str(chat_message.body).strip()
		if   jid_to_username(chat_message.from_jid) in my_username  and msg.lower().startswith("mass "):

			for group in self.groups_members:
				self.client.send_chat_message(group,chat_message.body.strip()[len("mass "):])
		elif jid_to_username(chat_message.from_jid) in my_username  and msg.lower().startswith("blacklist "):
			self.lag_codes.append(bytes(chat_message.body[len("blacklist "):], 'utf-8'))
			pickle.dump( self.lag_codes, open( "lag_codes.p", "wb" ) )
			self.client.send_chat_message(chat_message.from_jid,"Word blacklisted.")
		elif jid_to_username(chat_message.from_jid) in my_username  and msg.lower().startswith("group blacklist "):
			group_jid = chat_message.body[len("group blacklist "):]
			self.client.leave_group(group_jid)
			self.prohipited_groups.add(group_jid)
			pickle.dump( self.prohipited_groups, open( "prohipited_groups.p", "wb" ) )
			self.client.send_chat_message(chat_message.from_jid,"Group blacklisted.")
		elif jid_to_username(chat_message.from_jid) in my_username  and msg.lower().startswith("delete group blacklist "):
			group_jid = chat_message.body[len("delete group blacklist "):]
			if group_jid in self.prohipited_groups:
				self.prohipited_groups.remove(group_jid)
				pickle.dump( self.prohipited_groups, open( "prohipited_groups.p", "wb" ) )
				self.client.send_chat_message(chat_message.from_jid,"Group is whitelisted.")
			else:
				self.client.send_chat_message(chat_message.from_jid,"Group is not blacklisted.")
		else:
			if msg.lower() == 'friend':
				print("[+] Request friend.")
				#self.client.send_chat_message(chat_message.from_jid, "Your JID is {}".format(chat_message.from_jid))
				self.client.add_friend(chat_message.from_jid)
				time.sleep(1)
				self.client.send_chat_message(chat_message.from_jid, "I'll be your friend! You can now add me to groups.")
			elif msg.lower() == "ping":
				print("hereeeeeeee")
				self.client.send_chat_message(chat_message.from_jid,"Pong")
				return
			elif msg.lower() == "help":
				self.client.send_chat_message(chat_message.from_jid,self.help_msg)
			else:
				self.client.send_chat_message(chat_message.from_jid,"Say Help for commands, say Friend to add me to your group.")

	def on_message_delivered(self, response: chatting.IncomingMessageDeliveredEvent):

		print("[+] Chat message with ID {} is delivered.".format(response.message_id))

	def on_message_read(self, response: chatting.IncomingMessageReadEvent):
		print("[+] Human has read the message with ID {}.".format(response.message_id))
	def enable_48(self,chat_message: chatting.IncomingGroupChatMessage):
		# get important variables
		group_id = chat_message.group_jid
		
		
		self.is_48[group_id] = True
		pickle.dump( self.is_48, open( "is_48.p", "wb" ) )

		if group_id not in self.cap_48:
			self.cap_48[group_id] = 48
			pickle.dump( self.cap_48, open( "cap_48.p", "wb" ) )
		self.client.send_chat_message(group_id,"48 Mode is now enabled with capacity "+str(self.cap_48[group_id]))
		if group_id in self.groups_spam_time:
			if len(self.groups_spam_time[group_id]) < len(self.groups_members[group_id]):
				self.client.send_chat_message(group_id,"If you only just added " +bot_name+" into your group, I recommend you wait a day or two before enabling this feature so " +bot_name+" has time to accumulate a correct list of who is talking and who isn't.")
		else:
			self.client.send_chat_message(group_id,"If you only just added " +bot_name+" into your group, I recommend you wait a day or two before enabling this feature so " +bot_name+" has time to accumulate a correct list of who is talking and who isn't.")

		# check the group capacity
		
		


	def remove_48(self,group_id):	
		group_members = self.groups_members[group_id]
		group_members_num = len(group_members)		
		if group_id not in self.cap_48:
			self.cap_48[group_id] = 48
			pickle.dump( self.cap_48, open( "cap_48.p", "wb" ) )
		
		group_cap = self.cap_48[group_id]
		plus_members_num = group_members_num - group_cap
		print("group_members_num {}".format(group_members_num))
		#if the number is already exceeding
		are_talkers = True
		
		if plus_members_num > 0:
			talkers = {}
			k = -100
			if len(self.groups_members[group_id]) > len(self.groups_spam_time[group_id]):
				for member in self.groups_members[group_id]:
					if not self.groups_members[group_id][member].is_admin:
						if group_id in self.groups_spam_time:
							if len(self.groups_spam_time[group_id]) > 0:
								max_time = (datetime.now()-self.groups_spam_time[group_id][max(self.groups_spam_time[group_id], key=self.groups_spam_time[group_id].get)]).seconds
								if member in self.groups_spam_time[group_id]:
									talkers[member] = (datetime.now()-self.groups_spam_time[group_id][member]).seconds
								else:
									k+=1
									talkers[member] = max_time+k
							else:
								talkers[member] = k
								k+=1
								
						else:
							talkers[member] = k
							k+=1

			print("talkers are {}".format(talkers))
			if path.exists("talkers.p") and os.path.getsize('talkers.p') > 0:
				talkersfile = open('talkers.p','rb')
				talkers_data = pickle.load(talkersfile)
				talkersfile.close()
			else:
				talkers_data = {}
			talkers_data[group_id] = talkers
			open('talkers.p','w').close()
			talkersfile = open('talkers.p','wb')
			
			pickle.dump(talkers_data, talkersfile)
			talkersfile.close()
			
			for i in range(plus_members_num):

				least_talker =max(talkers, key=talkers.get)
				print("least_talker is {}".format(least_talker))
				self.client.remove_peer_from_group(group_id,least_talker)
				if group_id in self.groups_spam_time:
					if least_talker in self.groups_spam_time[group_id]:
						del self.groups_spam_time[group_id][least_talker]
				del talkers[least_talker]
				if group_id in self.groups_members:
					if least_talker in self.groups_members[group_id]:
						del self.groups_members[group_id][least_talker]


			self.client.send_chat_message(group_id,"There are "+ str(group_members_num) +" people here, removing last active member.")
			
	def list_admins(self,chat_message: chatting.IncomingGroupChatMessage):
		group_id = chat_message.group_jid
		admins = []
		# get admins
		if group_id in self.groups:
			for member in self.groups_members[group_id]:
				if self.groups_members[group_id][member].is_admin:
					admins.append(self.groups_members[group_id][member].jid)
			# add lockdown and queue the groups
			
			m=""
			for admin in admins:
				m+="\n- "
				if  admin in self.peers_info:
					name = self.peers_info[admin].display_name
					m+= name[:min(max_name_len,len(name))]#jid_to_username(member.jid)
				
			self.client.send_chat_message(group_id,"Admins:\n "+m)
	def list_active(self,chat_message: chatting.IncomingGroupChatMessage,are_talkers,first_half):
		group_id = chat_message.group_jid
		records = []
		no_hist = []
		times_persons = []

		if group_id in self.groups_members:
			members = [self.groups_members[group_id][m] for m in self.groups_members[group_id]]
			
			if are_talkers:
				time_dict = self.groups_spam_time
				word = 'Talker'
			else:
				time_dict = self.groups_active_time
				word = 'Active'
			
			for member in members:
				if self.peers_info[member.jid].username != self.client.username:
					if group_id in time_dict:
						if member.jid in time_dict[group_id]:

							time_d = (datetime.now()-time_dict[group_id][member.jid])
							name = self.peers_info[member.jid].display_name
							name = name[:min(max_name_len,len(name))]
							times_persons.append((time_d.seconds,name))
						else:
							name = self.peers_info[member.jid].display_name
							name = name[:min(max_name_len,len(name))]
							times_persons.append((math.inf,name))
					else:			
						self.client.send_chat_message(group_id,"No "+word.lower() +"s yet")
						return
			times_persons.sort(key = lambda x: x[0]) 
			dd = 1
			print("self.peers_info")
			print(self.peers_info)


			# print(times_persons)
			if first_half:
				start_point = 0
				end_point = 51
			else:
				start_point = 51
				end_point = 101
			for i in range(start_point,end_point):

				if i <len(times_persons):
					time_person = times_persons[i]
				else:
					break
					
				if time_person[0]!= math.inf:
					time_diff = time_person[0]
					if time_diff > 60*60*24:
						days = round(time_diff/(60*60*24))
						if days>1:
							time_str = str(days)+" days ago"
						else:
							time_str = str(days)+" day ago"
					elif time_diff > 60*60:
						hours = round(time_diff/(60*60))
						if hours>1:
							time_str = str(hours)+" hours ago"
						else:
							time_str = str(hours)+" hour ago"
					elif time_diff > 60:
						mins = round(time_diff/60)
						if mins >1:
							time_str = str(mins)+" minutes ago"
						else:
							time_str = str(mins)+" minute ago"

						
					else:
						if time_diff>1:
							time_str = str(time_diff)+" seconds ago"
						else:
							time_str = str(time_diff)+" second ago"
					if time_person[1] is None:
						records.append((" ",time_str))
					else:
						records.append((time_person[1],time_str))
				else:
					if time_person[1] is None:
						no_hist.append((" ","No history"))
					else:
						no_hist.append((time_person[1],"No history"))

				
			m=""
			# print("Active dictionary is {}".format(self.groups_active_time))

			# print("Active dictionary is {}".format(time_dict))
			print("group_members are {}".format(members))
			print("records are {}".format(records))
			print("nohist are {}".format(no_hist))

			for record in records:

				m+="\n- "
				m+= record[1]+" : "+record[0]#jid_to_username(member.jid)
			for n in no_hist:
				m+="\n- "
				m+= n[1]+" : "+n[0]#jid_to_username(member.jid)
			
			if path.exists("activity.p") and os.path.getsize('activity.p') > 0:
				activityfile = open('activity.p','rb')
				activities = pickle.load(activityfile)
				activityfile.close()
			else:
				activities = {}
			activities[group_id] = {"records" : records, "hist": no_hist}
			open('activity.p','w').close()
			activityfile = open('activity.p','wb')
			
			pickle.dump(activities, activityfile)
			activityfile.close()


			self.client.send_chat_message(group_id,word +"s:\n "+m)
			if first_half and len(members)>50:
				self.client.send_chat_message(group_id,"Say "+ word+"s More to list more "+ word+"s.")
		# add lockdown and queue the groups
		
	def is_spam(self,message):
		length = len(message)
		if length < 50:
			return False
		wordlist = message.split()
		list_length = len(wordlist);
		if len(wordlist) == 1:
			return True
		for word in wordlist:
			if (wordlist.count(word) * 100 / list_length) > 50:
				return True
		return False
	
	def response_actively(self,chat_message: chatting.IncomingGroupChatMessage):
		try:
			group_id = chat_message.group_jid
		except:
			group_id='a'
		user_id = chat_message.from_jid
		try:
			data=self.groups_spam_mute_time[group_id][user_id]
			if(data[-1]):
				if((datetime.now()-data[0]).seconds > 60):
					del self.groups_spam_mute_time[group_id][user_id]
					pickle.dump( self.groups_spam_mute_time, open( "mut_users.p", "wb" ) )
				else:
					return
			else:
				pass
		except:
			pass
		group_id = chat_message.group_jid
		msg = chat_message.body.strip().lower()
		if msg == "ping":
			try:
				if(self.groups_permissions[chat_message.group_jid] != 3):
					self.client.send_chat_message(chat_message.group_jid,"Pong")
				elif(self.groups_members[chat_message.group_jid][chat_message.from_jid].is_admin):
					self.client.send_chat_message(chat_message.group_jid,"Pong")
			except:
				self.client.send_chat_message(chat_message.group_jid,"Pong")

		if msg == "active":
			try:
				if(self.groups_permissions[chat_message.group_jid] != 3):
					self.list_active(chat_message,False,True)
				elif(self.groups_members[chat_message.group_jid][chat_message.from_jid].is_admin):
					self.list_active(chat_message,False,True)
			except:
				self.list_active(chat_message,False,True)	  

		if msg == "actives more":
			try:
				if(self.groups_permissions[chat_message.group_jid] != 3):
					self.list_active(chat_message,False,False)
				elif(self.groups_members[chat_message.group_jid][chat_message.from_jid].is_admin):
					self.list_active(chat_message,False,False)
			except:
				self.list_active(chat_message,False,False)

		elif msg == "talkers":
			try:
				if(self.groups_permissions[chat_message.group_jid] != 3):
					self.list_active(chat_message,True,True)
				elif(self.groups_members[chat_message.group_jid][chat_message.from_jid].is_admin):
					self.list_active(chat_message,True,True)
			except:
				self.list_active(chat_message,True,True)

		elif msg == "talkers more":
			try:
				if(self.groups_permissions[chat_message.group_jid] != 3):
					self.list_active(chat_message,True,False)
				elif(self.groups_members[chat_message.group_jid][chat_message.from_jid].is_admin):
					self.list_active(chat_message,True,False)
			except:
				self.list_active(chat_message,True,False)
				
		elif msg == "renegade":
				self.client.send_chat_message(chat_message.group_jid,"Hello, I'm "+bot_name+". You called?")
		elif msg == "admins":
			self.list_admins(chat_message)
		#elif msg == "talkers more":
		#	self.list_active(chat_message,True,False)
		#elif msg == "actives more":
		#	self.list_active(chat_message,False,False)
		#elif msg == "talkers":
		#	self.list_active(chat_message,True,True)
		#elif msg == "active":
		#	self.list_active(chat_message,False,True)
		elif "fuck you " +bot_name.lower() in msg:
			self.client.remove_peer_from_group(group_id,chat_message.from_jid)
		elif msg == "48 mode":
			self.client.send_chat_message(group_id,self.message_48)
		elif msg.startswith( bot_name.lower()+" call me "):
			if group_id not in self.nicknames:
				self.nicknames[group_id] = {}
			self.nicknames[group_id][chat_message.from_jid] = chat_message.body.strip()[len(bot_name.lower()+" call me "):]
			self.client.send_chat_message(group_id,"Okay, "+self.nicknames[group_id][chat_message.from_jid])
			pickle.dump( self.nicknames, open( "nicknames.p", "wb" ) )
		elif msg == "hey" or msg == "hi":
			if group_id in self.nicknames:
				if chat_message.from_jid in self.nicknames[group_id]:
					self.client.send_chat_message(group_id,"Hello "+self.nicknames[group_id][chat_message.from_jid])
				else:
					self.client.send_chat_message(group_id,"Hello.")
			else:
				self.client.send_chat_message(group_id,"Hello.")

	def is_flooding(self, chat_message: chatting.IncomingGroupChatMessage):
		found_flooding = False
		ms = chat_message.raw_element.select('request>g>m')
		if(len(ms) > 1):
			found_flooding = True
		return found_flooding

	def on_group_message_received(self, chat_message: chatting.IncomingGroupChatMessage):
		print("Group message");
		msg = chat_message.body.strip().lower()

		# print(msg in self.groups_triggers[chat_message.group_jid])
		# if  msg.startswith("permission") or "->" in msg or msg.startswith("set greetings") or msg.startswith("set goodbye"):
		# get updated info
		# self.get_updated_info(chat_message)
		group_id = chat_message.group_jid
		#print("chat message body =>", chat_message.body)
		#print("lag code in chat message => ",  re.sub('[^a-zA-Z0-9.]', '', chat_message.body))
		# print("Lag code =>", self.lag_codes)
		# if group_id not in self.new_groups_lock:
			# self.new_groups_lock[group_id] = False
		if group_id in self.prohipited_groups:
			print("blacklisted")
			self.client.leave_group(group_id)
			return

		group = chat_message.group_jid
		#self.message_queue.append({"group": group, "message": chat_message})
		#if group_id not in self.groups_members:
			# self.new_groups_lock[group_id] = False
		#	self.client.request_roster()
			#print("new group requesting roster")
		#elif  chat_message.from_jid not in self.groups_members[group_id]:
		self.client.request_roster()

		# while self.new_groups_lock[group_id] == False:
		# 	time.sleep(0.5)
		# print("passed")
		
		if chat_message.group_jid not in self.lurks_enabled:
			self.lurks_enabled[group_id] = False
		if group_id in self.lurks:
			if chat_message.from_jid in self.lurks[group_id]:
				self.lurks[group_id][chat_message.from_jid] = False
		 
		# if group_id not in self.groups_triggers:
		# 	self.groups_triggers[group_id] ={}
		ip_filter_chat_message = re.sub('(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}', '', chat_message.body)

		#filter_chat_message = re.sub('[^a-zA-Z0-9 !?:;]{8,}', '', ip_filter_chat_message)

		filter_chat_message = re.sub('', '', ip_filter_chat_message)

		#print(filter_chat_message)
		# valid_chat_message = True
		# if filter_chat_message:
		# 	valid_chat_message = d.check(filter_chat_message)
		
		# print(valid_chat_message)
		if group_id not in self.groups_permissions:
			self.groups_permissions[group_id] = 1

		elif bytes(chat_message.body, 'utf-8') in self.lag_codes or len(filter_chat_message) != len(chat_message.body) or len(ip_filter_chat_message) != len(chat_message.body) or self.is_spam(chat_message.body) or self.is_flooding(chat_message): 
			if (not group_id in self.groups_members or not chat_message.from_jid in self.groups_members[group_id] or not self.groups_members[group_id][chat_message.from_jid].is_admin):
				#self.client.remove_peer_from_group(group_id,chat_message.from_jid)
				#self.client.send_chat_message(group_id,"Prohibited code, removing.")
				if (len(filter_chat_message) != len(chat_message.body) and len(ip_filter_chat_message) != len(filter_chat_message)):
					self.client.send_chat_message(group_id, 'Possible crash code, removing.')
				elif self.is_spam(chat_message.body):
					if len(group_id in self.groups and self.groups[group_id].banned_members)<100 and group_id in self.groups_members and self.groups_members[group_id][self.client.kik_node+'@talk.kik.com'].is_admin:
						self.client.ban_member_from_group(group_id,chat_message.from_jid)
						if group_id in self.groups_spam_score:
							del self.groups_spam_score[group_id][chat_message.from_jid]
						# del self.groups_spam_time[group_id][user_id]
						if group_id in self.groups_last_msg:
							del self.groups_last_msg[group_id][chat_message.from_jid]
						self.client.send_chat_message(group_id,"Removing for spamming.")
					elif self.groups_members[group_id][self.client.kik_node+'@talk.kik.com'].is_admin:
						self.client.send_chat_message(group_id,"Your ban list is full, please clear some people off the list so "+bot_name+" can ban people.")
						self.client.remove_peer_from_group(group_id,chat_message.from_jid)
						self.client.send_chat_message(group_id,"Removing for spamming.")
		self.response_actively(chat_message)
		c = 1
		while chat_message.group_jid not in self.groups_members :
			c+=1
			time.sleep(0.5)
			if c>100:
				return
		c = 1
		while  chat_message.from_jid not in self.groups_members[chat_message.group_jid]:
			c+=1
			time.sleep(0.5)
			if c>100:
				return
		if chat_message.group_jid in self.groups_members:
			#print("passed first check")
			if chat_message.from_jid in self.groups_members[chat_message.group_jid]:
				#print("passed second check")
				sender =self.groups_members[chat_message.group_jid][chat_message.from_jid]
				
				if sender.is_admin:
					self.admin_behaviour(chat_message)
				else:
					self.user_behaviour(chat_message)
			else:
				self.client.request_roster()


	def on_peer_info_received(self, response: PeersInfoResponse):
		#if(self.welcome_user and len(response.users) > 0):
		#	self.client.send_chat_message(self.current_group_jid, "Welcome, {}. We're happy to see you here!".format(response.users[0].username))
		#	self.welcome_user = False;
		for user in response.users:
			if user.display_name is not None:
				self.peers_info[user.jid] = user
			else:
				self.client.request_info_of_users(user.jid)
		if path.exists("peers_info.p") and os.path.getsize('peers_info.p') > 0:
			peers_info_file = open('peers_info.p','w').close();
		peers_info_file = open('peers_info.p','wb')
	
		pickle.dump(self.peers_info, peers_info_file)
		peers_info_file.close()


		# print("[+] Peer info: " + str(response.users))


		# print(chat_message.__dict__)
		# self.client.send_chat_message(chat_message.group_jid, "Hi "+jid_to_username(chat_message.from_jid)+" You said \"" + chat_message.body + "\"!")

		# print("[+] '{}' from group ID {} says: {}".format(chat_message.from_jid, chat_message.group_jid,
		# 												  chat_message.body))

	def on_is_typing_event_received(self, response: chatting.IncomingIsTypingEvent):
		print("[+] {} is now {}typing.".format(response.from_jid, "not " if not response.is_typing else ""))

	def on_group_is_typing_event_received(self, response: chatting.IncomingGroupIsTypingEvent):
		# if not response.group_jid in self.groups:
		# 	self.groups[response.group_jid] = response.group
		# print("response group is")
		# print(response.group)
		if response.is_typing:
			if response.group_jid not in self.groups_active_time:
				self.groups_active_time[response.group_jid] = {}
			self.groups_active_time[response.group_jid][response.from_jid] = datetime.now()
			if path.exists("activity_times.p") and os.path.getsize('activity_times.p') > 0:
				activityfile = open('activity_times.p','w').close();
			activityfile = open('activity_times.p','wb')
			
			pickle.dump(self.groups_active_time, activityfile)
			activityfile.close()
		print("[+] {} is now {}typing in group {}".format(response.from_jid, "not " if not response.is_typing else "",
														  response.group_jid))

	def on_roster_received(self, response: FetchRosterResponse):
		#if(len(self.message_queue) > 0):
		#	current_message = self.message_queue.pop(0)
		#	if(self.is_command(current_message['message'])):
		#		for peer in response.peers:
		#			if(peer.jid == current_message['group']):
		#				for member in peer.members:
		#					if(member.jid == current_message['message'].from_jid and (member.is_admin or member.is_owner)):
		#						self.execute_command(current_message['message'], peer)
		#						break
		#					elif(member.jid == current_message['message'].from_jid):
		#						self.client.send_chat_message(peer.jid, 'Only admins can do this.')
		#				break
		#else:
		print("[+] Chat partners:\n" + '\n'.join([str(member) for member in response.peers]))
		for member in response.peers:
			if isinstance(member,Group):
				self.groups[member.jid] = member
				self.groups_members[member.jid] = {}
#					self.client.send_chat_message(member.jid, "bot_jids: {}".format(self.bot_jids))
				for m in member.members:
#						self.client.send_chat_message(member.jid, "JID is {}".format(m.jid))
					if(m.jid != self.client.kik_node+'@talk.kik.com' and m.jid in self.bot_jids):
						self.client.leave_group(member.jid)
					self.groups_members[member.jid][m.jid] = m
					
				self.new_groups_lock[member.jid] = True
				self.client.request_info_of_users([g_member.jid for g_member in member.members if g_member.jid not in self.peers_info])	
			else:
				self.friends[member.jid] = member
		if path.exists("groups_members.p") and os.path.getsize('groups_members.p') > 0:
			groups_members_file = open('groups_members.p','w').close();
		groups_members_file = open('groups_members.p','wb')
	
		pickle.dump(self.groups_members, groups_members_file)
		groups_members_file.close()

	def on_friend_attribution(self, response: chatting.IncomingFriendAttribution):
		print("[+] Friend attribution request from " + response.referrer_jid)

	def on_image_received(self, image_message: chatting.IncomingImageMessage):
		print("[+] Image message was received from {}".format(image_message.from_jid))

	def on_group_status_received(self, response: chatting.IncomingGroupStatus):
		print("status received")
		print(response.status)
		if response.group_jid not in self.groups_members:
			self.groups_members[response.group_jid] = {}
		# self.client.request_roster()
		# self.groups[response.group_jid] = response.group
		self.client.request_info_of_users(response.status_jid)
		self.user_group_jids[response.status_jid] = response.group_jid
		if response.group is None:
			group_name = "".encode()
		else:
			if response.group.name is None:
				group_name = "".encode()
			else:
				group_name =response.group.name.encode()
		if "joined" in response.status:

			print(response)
			if response.group_jid not in self.is_48:
				self.is_48[response.group_jid] = False
				pickle.dump( self.is_48, open( "is_48.p", "wb" ) )
			if response.group_jid not in self.is_locked:
				self.is_locked[response.group_jid] = False
				pickle.dump( self.is_locked, open( "is_locked.p", "wb" ) )

			if self.is_locked[response.group_jid]:
				if response.group_jid in self.lock_messages:
					self.client.send_chat_message(response.group_jid,self.lock_messages[response.group_jid])
				else:
					self.client.send_chat_message(response.group_jid,"Group is locked.")
				# time.sleep(0.1)
				self.client.remove_peer_from_group(response.group_jid,response.status_jid)

			else:
				self.current_user = response.status_jid
				#self.client.send_chat_message(response.group_jid,"status JID: {}".format(response.status_jid))
				self.client.xiphias_get_users_by_alias(response.status_jid)
#				for user in response.users:
#					self.client.send_chat_message(response.group_jid,"JID: {}".format(user.jid))
#				if(self.removal_check and len(response.users) > 0 and response.users[0].jid is not None):
#					self.client.send_chat_message(self.current_group_jid,"User jid: {}".format(response.users[0].jid))
#					self.client.xiphias_get_users(response.users[0].jid)
				## update group members
				#print("updating ...")
				#print("Groups ==> ", self.groups)
				# self.on_roster_received(FetchRosterResponse)
				self.client.request_roster()
				group_found = self.groups.get(response.group_jid, None)
				#print("Groups ==> ", self.groups)
				#print("Group ID =>", response.group_jid)

				if group_found:
					current_member = copy.deepcopy(self.groups[response.group_jid].members[0])
					current_member.jid = response.status_jid
					current_member.is_admin = False
					# self.groups[response.group_jid].members.append(current_member)
					if response.group_jid not in self.groups_members:
						self.groups_members[response.group_jid] = {}
					self.groups_members[response.group_jid][response.status_jid] = current_member
					if self.is_48[response.group_jid]:
						self.remove_48(response.group_jid)
					## greeting part
					print("greeting")
					if "chat" in response.status:
						new_member_name = response.status.encode()[0:response.status.encode().find("has joined the chat".encode())]
					else:
						new_member_name = response.status.encode()[0:response.status.encode().find("has joined the group".encode())]

					if len(self.groups_greeting_messeges) != 0 and response.group_jid in self.groups_greeting_messeges:
						self.client.send_chat_message(response.group_jid, self.groups_greeting_messeges[response.group_jid])
					else:
						mess = "Welcome ".encode()+new_member_name +"to ".encode()  +group_name + "".encode()
						self.client.send_chat_message(response.group_jid, mess.decode())
					if response.group_jid in self.rules:
						self.client.send_chat_message(response.group_jid, self.rules[response.group_jid])
					ID =response.status_jid
					if "chat" in response.status:
						new_member_name = response.status.encode()[0:response.status.encode().find("has joined the chat".encode())]
						uname = new_member_name.decode("utf-8").strip().lower()
						# print("Black_list Group ==> ", self.groups_blacklist)
						# print("Group Jid ==> ", response.group_jid)
						print(uname)
						print(type(uname))
						blacklist_group_found = self.groups_blacklist.get(response.group_jid, None)

						if blacklist_group_found:
							for word in self.groups_blacklist[response.group_jid]:
								print(word)
							if any([word in uname for word in self.groups_blacklist[response.group_jid]]) :
								self.client.remove_peer_from_group(response.group_jid,response.status_jid)
								self.client.send_chat_message(response.group_jid,"Name contains a censored word, removing.")
								print("here",new_member_name)

					else:
						new_member_name = response.status.encode()[0:response.status.encode().find("has joined the group".encode())]	

						uname = new_member_name.decode("utf-8").strip().lower()
						if(response.group_jid in self.groups_blacklist):
							print(self.groups_blacklist[response.group_jid])
							print(uname)
							print(type(uname))
							for word in self.groups_blacklist[response.group_jid]:
								print(word)
							if any([word in uname for word in self.groups_blacklist[response.group_jid]]) :
								self.client.remove_peer_from_group(response.group_jid,response.status_jid)
								self.client.send_chat_message(response.group_jid,"Name contains a censored word, removing.")
								print("here",new_member_name)
					## tell if it lurks`
					if response.group_jid not in self.lurks_enabled:
						self.lurks_enabled[response.group_jid] = False
					if self.lurks_enabled[response.group_jid]:
						print("lurking...")
						if response.group_jid not in self.lurks:
							self.lurks[response.group_jid] = {}
						self.lurks[response.group_jid][ID] = True
						if response.group_jid not in self.lurks_wait_time:
							self.lurks_wait_time[response.group_jid] = 5
						lurking = True
						for i in range(self.lurks_wait_time[response.group_jid]):
							time.sleep(60)
							if response.group_jid not in self.lurks:
								lurking = False
								break
							if ID not in self.lurks[response.group_jid]:
								lurking = False
								break
							if not self.lurks[response.group_jid][ID]:
								lurking = False
								break
						if lurking:

							if self.lurks[response.group_jid][ID]:
								self.client.remove_peer_from_group(response.group_jid,ID)
								del self.lurks[response.group_jid][ID]
								self.client.send_chat_message(response.group_jid,'Removing for lurking.')

		elif  "left" in response.status:

			if response.group_jid in self.groups_members:
				if response.status_jid in self.groups_members[response.group_jid]:

					del self.groups_members[response.group_jid][response.status_jid] 

			ID =response.status_jid
			if len(self.groups_goodbye_messeges) != 0 and response.group_jid in self.groups_goodbye_messeges:
				self.client.send_chat_message(response.group_jid, self.groups_goodbye_messeges[response.group_jid])
			else:
				self.client.send_chat_message(response.group_jid, "Goodbye!")
			if response.group_jid  in self.lurks:
				if ID in self.lurks[response.group_jid]:
					del self.lurks[response.group_jid][ID]
		elif "admin"in response.status:
			if "promoted" in response.status:

				self.groups_members[response.group_jid][response.status_jid].is_admin = True
			elif "removed" in response.status:
				self.groups_members[response.group_jid][response.status_jid].is_admin = False
		elif "removed"in response.status:
			if response.status_jid in self.groups_members[response.group_jid]:
				del self.groups_members[response.group_jid][response.status_jid]
			ID =response.status_jid
			if response.group_jid  in self.lurks:
				if ID in self.lurks[response.group_jid]:
					del self.lurks[response.group_jid][ID]
		
		elif "added" in response.status:
			if response.group_jid in self.prohipited_groups:
				print("blacklisted")
				self.client.leave_group(response.group_jid )
			else:
				group = response.group
				self.groups_members[response.group_jid] = {}
				for m in group.members:
					self.groups_members[group.jid][m.jid] = m
				self.new_groups_lock[group.jid] = True
				self.client.request_info_of_users([g_member.jid for g_member in group.members if g_member.jid not in self.peers_info])	
		print("status received")
		print(response.status)
		if path.exists("groups_members.p") and os.path.getsize('groups_members.p') > 0:
			groups_members_file = open('groups_members.p','w').close();
		groups_members_file = open('groups_members.p','wb')
	
		pickle.dump(self.groups_members, groups_members_file)
		groups_members_file.close()
			# spam removal

	def on_group_receipts_received(self, response: chatting.IncomingGroupReceiptsEvent):
		if response.type=='read':
			if response.group_jid not in self.groups_active_time:
				self.groups_active_time[response.group_jid] = {}
			self.groups_active_time[response.group_jid][response.from_jid] = datetime.now()

		print("[+] Received receipts in group {}: {}".format(response.group_jid, ",".join(response.receipt_ids)))

	def on_status_message_received(self, response: chatting.IncomingStatusResponse):
		print("[+] Status message from {}: {}".format(response.from_jid, response.status))

	def on_username_uniqueness_received(self, response: UsernameUniquenessResponse):
		print("Is {} a unique username? {}".format(response.username, response.unique))

	def on_sign_up_ended(self, response: RegisterResponse):
		print("[+] Registered as " + response.kik_node)

	# Error handling

	def on_connection_failed(self, response: ConnectionFailedResponse):
		print("[-] Connection failed: " + response.message)

	def on_login_error(self, login_error: LoginError):
		if login_error.is_captcha():
			login_error.solve_captcha_wizard(self.client)

#	def get_string_permissions(self):
#		return "ZW1lcmFsZA=="

	def on_register_error(self, response: SignUpError):
		print("[-] Register error: {}".format(response.message))
	def spam_remove(self,chat_message: chatting.IncomingGroupChatMessage,can_be_removed=True):
		msg = chat_message.body.strip().lower()
		group_id = chat_message.group_jid
		user_id = chat_message.from_jid
		banned = False
		if group_id not in self.groups_active_time:
			self.groups_active_time[group_id] = {}
		if user_id not in self.groups_active_time[group_id]:
			self.groups_active_time[group_id][user_id] = datetime.now()
		if group_id not in self.groups_spam_score:
			self.groups_spam_score[group_id] = {}
		if user_id not in self.groups_spam_score[group_id]:
			self.groups_spam_score[group_id][user_id] = 1
		if group_id not in self.groups_last_msg:
			self.groups_last_msg[group_id] = {}
		if group_id not in self.groups_spam_time:
			self.groups_spam_time[group_id] = {}
		if user_id not in self.groups_spam_time[group_id]:
			self.groups_spam_time[group_id][user_id] = datetime.now()
		if group_id not in self.groups_spam_mute_time:
			self.groups_spam_mute_time[group_id] = {}
		if user_id not in self.groups_spam_mute_time[group_id]:
			self.groups_spam_mute_time[group_id][user_id] = [datetime.now(),False] 
		

		print(self.client.kik_node)	
		if (datetime.now() - self.groups_spam_time[group_id][user_id]).seconds <2:
			if user_id in self.groups_last_msg[group_id]:
				if msg==self.groups_last_msg[group_id][user_id]:
					self.groups_spam_score[group_id][user_id] += 1
					if self.groups_spam_score[group_id][user_id] == 5 and can_be_removed==False:
						self.client.send_chat_message(group_id,"You have been muted.")
						#self.mut_users[group_id][user_id]=datetime.now()
						self.groups_spam_mute_time[group_id][user_id]=[datetime.now(),True]
						pickle.dump( self.groups_spam_mute_time, open( "mut_users.p", "wb" ) )
						return
					if self.groups_spam_score[group_id][user_id] == 5 and can_be_removed:
						if(self.groups_members[group_id][self.client.kik_node+'@talk.kik.com'].is_admin):
							pass
						else:
							self.client.send_chat_message(group_id,"You have been muted.")
							self.groups_spam_mute_time[group_id][user_id]=[datetime.now(),True]
							pickle.dump( self.groups_spam_mute_time, open( "mut_users.p", "wb" ) )
							return
						if len(self.groups[group_id].banned_members)<100 and self.groups_members[group_id][self.client.kik_node+'@talk.kik.com'].is_admin:
							self.client.ban_member_from_group(group_id,user_id)
							del self.groups_spam_score[group_id][user_id]
							# del self.groups_spam_time[group_id][user_id]
							del self.groups_last_msg[group_id][user_id]
							self.client.send_chat_message(group_id,"Removing for spamming.")
							banned = True
						elif self.groups_members[group_id][self.client.kik_node+'@talk.kik.com'].is_admin:
							self.client.send_chat_message(group_id,"Your ban list is full, please clear some people off the list so "+bot_name+" can ban people.")
							self.client.remove_peer_from_group(group_id,user_id)
							self.client.send_chat_message(group_id,"Removing for spamming.")
		else:
			if group_id in self.groups_spam_score:
				if user_id in self.groups_spam_score[group_id]:
					self.groups_spam_score[group_id][user_id] = 1
		# print( self.groups_spam_time[group_id][user_id])
		if not banned:		
			self.groups_spam_time[group_id][user_id] = datetime.now()
			self.groups_active_time[group_id][user_id] = datetime.now()
			self.groups_last_msg[group_id][user_id] = msg
		
		if path.exists("groups_spam_time.p") and os.path.getsize('groups_spam_time.p') > 0:
			groups_spam_time_file = open('groups_spam_time.p','w').close();
		groups_spam_time_file = open('groups_spam_time.p','wb')
		pickle.dump(self.groups_spam_time, groups_spam_time_file)
		groups_spam_time_file.close()
		
		if path.exists("activity_times.p") and os.path.getsize('activity_times.p') > 0:
			groups_active_time_file = open('activity_times.p','w').close();
		groups_active_time_file = open('activity_times.p','wb')
		pickle.dump(self.groups_active_time, groups_active_time_file)
		groups_active_time_file.close()
		
	def get_updated_info(self,chat_message: chatting.IncomingGroupChatMessage):
		if chat_message.group_jid not in self.groups_triggers:
			self.groups_triggers[chat_message.group_jid] = {}

		if chat_message.group_jid not in self.groups_permissions:
			self.groups_permissions[chat_message.group_jid] = 1
		self.groups_waiting_roaster.append(chat_message.group_jid)
		self.roaster_finished[chat_message.group_jid] = False
		self.client.request_roster()	
		while not self.roaster_finished[chat_message.group_jid]:
			time.sleep(1)
	def set_greetings(self,chat_message: chatting.IncomingGroupChatMessage):
		self.groups_greeting_messeges[chat_message.group_jid] = chat_message.body[13:]
		self.client.send_chat_message(chat_message.group_jid, "Greeting set.")
		pickle.dump( self.groups_greeting_messeges, open( "groups_greeting_messeges.p", "wb" ) )
	def set_rules(self,chat_message: chatting.IncomingGroupChatMessage):
		self.rules[chat_message.group_jid] = chat_message.body.strip()[len("set the rules "):]
		self.client.send_chat_message(chat_message.group_jid, "Rules set.")
		pickle.dump( self.rules, open( "rules.p", "wb" ) )
	def set_goodbye(self,chat_message: chatting.IncomingGroupChatMessage):
		self.groups_goodbye_messeges[chat_message.group_jid] = chat_message.body[12:]
		self.client.send_chat_message(chat_message.group_jid, "Goodbye message set.")
		pickle.dump( self.groups_goodbye_messeges, open( "groups_goodbye_messeges.p", "wb" ) )
	def delete_greetings(self,chat_message: chatting.IncomingGroupChatMessage):
		if chat_message.group_jid in self.groups_greeting_messeges:
			del self.groups_greeting_messeges[chat_message.group_jid] 
			self.client.send_chat_message(chat_message.group_jid, "Greeting deleted.")
			pickle.dump( self.groups_greeting_messeges, open( "groups_greeting_messeges.p", "wb" ) )
		else:
			self.client.send_chat_message(chat_message.group_jid, "No greeting set, admins can set a greeting through \"set greeting Hi\"")

	def delete_rules(self,chat_message: chatting.IncomingGroupChatMessage):
		if chat_message.group_jid in self.rules:
			del self.rules[chat_message.group_jid] 
			self.client.send_chat_message(chat_message.group_jid, "Rules deleted.")
			pickle.dump( self.rules, open( "rules.p", "wb" ) )
		else:
			self.client.send_chat_message(chat_message.group_jid, "No rules set, admins can set rules through \"set the rules Hi\"")

	def delete_goodbye(self,chat_message: chatting.IncomingGroupChatMessage):
		if chat_message.group_jid in self.groups_goodbye_messeges:
			del self.groups_goodbye_messeges[chat_message.group_jid] 
			self.client.send_chat_message(chat_message.group_jid, "Goodbye message deleted.")
			pickle.dump( self.groups_goodbye_messeges, open( "groups_goodbye_messeges.p", "wb" ) )
		else:
			self.client.send_chat_message(chat_message.group_jid, "No goodbye message set, admins can set a goodbye message through \"set goodbye Bye\"")
	def set_permissions(self,chat_message):
		msg = chat_message.body.strip().lower()
		if "1" in msg:
			self.groups_permissions[chat_message.group_jid] = 1
			self.client.send_chat_message(chat_message.group_jid,"Permission set to 1\n\nPermission set to default.")
			pickle.dump( self.groups_permissions, open( "groups_permissions.p", "wb" ) )
		elif "2" in msg:
			self.groups_permissions[chat_message.group_jid] = 2
			self.client.send_chat_message(chat_message.group_jid,"Permission set to 2\n\nNon-admins can't create/edit or delete substitutions.")
			pickle.dump( self.groups_permissions, open( "groups_permissions.p", "wb" ) )
		elif "3" in msg:
			self.groups_permissions[chat_message.group_jid] = 3
			self.client.send_chat_message(chat_message.group_jid,"Permission set to 3\n\nNon-admins can't create/edit or delete substitutions, and they cannot use any commands.")
			pickle.dump( self.groups_permissions, open( "groups_permissions.p", "wb" ) )

		
	def set_trigger(self,chat_message):
		msg = chat_message.body.strip().lower()
		not_lower_msg = chat_message.body.strip()
		if not_lower_msg == '==':
			return
		key = msg[0:msg.find(trigger_sympol)].strip()
		if key =="greeting" or key =="rules" or key =="goodbye":
			self.client.send_chat_message(chat_message.group_jid,"To set a greeting, say \"set greeting Hi\"\n\nTo set rules, say \"set the rules Hi\"\n\nTo set a goodbye message, say \"set goodbye Bye\"")
		else:
			val = not_lower_msg[not_lower_msg.find(trigger_sympol)+3:].strip()
			if chat_message.group_jid not in self.groups_triggers:
				self.groups_triggers[chat_message.group_jid] = {}
			self.groups_triggers[chat_message.group_jid][key] = val
			self.client.send_chat_message(chat_message.group_jid,"You say "+not_lower_msg[0:msg.find(trigger_sympol)].strip()+", I say "+not_lower_msg[not_lower_msg.find(trigger_sympol)+3:])
			pickle.dump( self.groups_triggers, open( "groups_triggers.p", "wb" ) )

	def delete_trigger(self,chat_message):
		msg = chat_message.body.strip().lower()
		key = msg[len("delete"):].strip()
		del self.groups_triggers[chat_message.group_jid][key]
		self.client.send_chat_message(chat_message.group_jid,"Trigger "+ key+" deleted.")
		pickle.dump( self.groups_triggers, open( "groups_triggers.p", "wb" ) )
	def add_blacklist(self,chat_message):
		msg = chat_message.body.strip().lower()
		blacklist = msg[len("blacklist"):].strip()
		if chat_message.group_jid not in self.groups_blacklist:
			self.groups_blacklist[chat_message.group_jid] = set()
		if blacklist in self.groups_blacklist[chat_message.group_jid]:
			self.client.send_chat_message(chat_message.group_jid,"Blacklist word is already added.")
			return
		self.groups_blacklist[chat_message.group_jid].add(blacklist)
		self.client.send_chat_message(chat_message.group_jid,"Blacklist word added.")
		pickle.dump( self.groups_blacklist, open( "groups_blacklist.p", "wb" ) )
	def delete_blacklist(self,chat_message):
		msg = chat_message.body.strip().lower()
		blacklist = msg[len("delete blacklist"):].strip()
		if chat_message.group_jid not in self.groups_blacklist:
			self.client.send_chat_message(chat_message.group_jid,"No blacklist words yet.")
		else:
			if blacklist in self.groups_blacklist[chat_message.group_jid]:
				self.groups_blacklist[chat_message.group_jid].remove(blacklist)
				pickle.dump( self.groups_blacklist, open( "groups_blacklist.p", "wb" ) )
				self.client.send_chat_message(chat_message.group_jid,"Blacklist word deleted.")
			else:
				self.client.send_chat_message(chat_message.group_jid,"Blacklist word doesn't exist.")
	def list_black(self,chat_message: chatting.IncomingGroupChatMessage):
		if chat_message.group_jid in self.groups_blacklist:
				blacks = ""
				for bl in self.groups_blacklist[chat_message.group_jid]:
					blacks+=str(bl)
					blacks+=', '
				self.client.send_chat_message(chat_message.group_jid,"Blacklists: \n"+blacks[:-2])
		else:
			self.client.send_chat_message(chat_message.group_jid,"No blacklists set.")
	def list_trigger(self,chat_message: chatting.IncomingGroupChatMessage):
		if chat_message.group_jid in self.groups_triggers:
				trigs = ""
				for tr in self.groups_triggers[chat_message.group_jid]:
					trigs+=str(tr)
					trigs+=', '
				self.client.send_chat_message(chat_message.group_jid,"Triggers: \n"+trigs[:-2])
		else:
			self.client.send_chat_message(chat_message.group_jid,"No triggers set.")
	def close_group(self,chat_message:chatting.IncomingGroupChatMessage):
		if chat_message.group_jid not in self.is_locked:
			self.is_locked[chat_message.group_jid] = False
			pickle.dump( self.is_locked, open( "is_locked.p", "wb" ) )

		if self.is_locked[chat_message.group_jid]:
			self.client.send_chat_message(chat_message.group_jid,"Group is already locked.")
			return

		self.is_locked[chat_message.group_jid] = True
		pickle.dump( self.is_locked, open( "is_locked.p", "wb" ) )
		self.client.send_chat_message(chat_message.group_jid,"Group is locked.")
	def open_group(self,chat_message:chatting.IncomingGroupChatMessage):
		if chat_message.group_jid not in self.is_locked:
			self.is_locked[chat_message.group_jid] = False
			pickle.dump( self.is_locked, open( "is_locked.p", "wb" ) )
		if not self.is_locked[chat_message.group_jid]:
			self.client.send_chat_message(chat_message.group_jid,"Group is already unlocked.")
			return
		self.is_locked[chat_message.group_jid] = False
		pickle.dump( self.is_locked, open( "is_locked.p", "wb" ) )
		self.client.send_chat_message(chat_message.group_jid,"Group is unlocked.")

	def admin_behaviour(self,chat_message: chatting.IncomingGroupChatMessage):
		#  prepare the message
		msg = chat_message.body.strip().lower()
		not_lower_msg = chat_message.body.strip()
		# actions that can be done
		self.spam_remove(chat_message,False)
		
		if msg == bot_name.lower()+" leave":
			self.client.send_chat_message(chat_message.group_jid,bot_name.lower()+" will leave now, bye.")
			self.client.leave_group(chat_message.group_jid)
		elif msg.startswith('ban user'):
			self.ban_user(chat_message)
		elif msg.startswith('unban user'):
			self.unban_user(chat_message)
		elif msg.startswith('banned list'):
			self.list_banned(chat_message)
		elif msg =="close":
			self.close_group(chat_message)
		elif msg == "enable 48":
			self.enable_48(chat_message)
		elif msg == "disable 48":
			
			self.is_48[chat_message.group_jid] = False
			pickle.dump( self.is_48, open( "is_48.p", "wb" ) )

			self.client.send_chat_message(chat_message.group_jid,"48 mode is now disabled.")
		elif msg =="open":
			self.open_group(chat_message)
		elif msg == "permission":
			self.client.send_chat_message(chat_message.group_jid,"Permissions can be set with the following commands:\n \n- \"Permission 1\" Default. \n- \"Permission 2\" Non-admins can't create/edit or delete substitutions. \n- \"Permission 3\" Non-admins can't create/edit or delete substitutions, and they cannot use any commands.")
		elif msg == "help":
			self.client.send_chat_message(chat_message.group_jid,self.help_msg)
		elif msg == "trigger":
			self.list_trigger(chat_message)
		elif msg == "blacklist":
			self.list_black(chat_message)
		elif msg.startswith("gif"):
			self.send_gif(chat_message, chat_message.group_jid);
		elif msg == "lurktime":
			if self.lurks_enabled[chat_message.group_jid]:
				if chat_message.group_jid not in self.lurks_wait_time:
					self.lurks_wait_time[chat_message.group_jid ] = 5
				self.client.send_chat_message(chat_message.group_jid,'Lurking time is '+str(self.lurks_wait_time[chat_message.group_jid])+" minutes.")
		elif msg == "enable lurks":
			self.lurks_enabled[chat_message.group_jid] = True
			self.client.send_chat_message(chat_message.group_jid,"Users who join the group and don't talk will be removed within 5 minutes.\n\nSay \"lurktime + a number from 1-15\" to set a custom lurk time.")
		elif msg == "disable lurks":

			self.lurks_enabled[chat_message.group_jid] = False
			self.client.send_chat_message(chat_message.group_jid,"Users who join the group and don't talk will not be removed.")
		elif lurk_time_pattern.match(msg)is not None:
			if self.lurks_enabled[chat_message.group_jid]:
				self.lurks_wait_time[chat_message.group_jid] = min(max(int(msg.split()[1]),1),15)
				self.client.send_chat_message(chat_message.group_jid,'Users who join the group and don\'t talk within '+str(self.lurks_wait_time[chat_message.group_jid])+' minutes will be removed.')
		elif msg.startswith("set greeting"):
			self.set_greetings(chat_message)
		elif msg.startswith("set the rules"):
			self.set_rules(chat_message)
		elif msg.startswith("set goodbye"):
			self.set_goodbye(chat_message)
		elif msg=="delete greeting":
			self.delete_greetings(chat_message)
		elif msg=="rules delete":
			self.delete_rules(chat_message)

		elif msg=="delete goodbye":
			self.delete_goodbye(chat_message)
		elif msg=="greeting":
			if chat_message.group_jid in self.groups_greeting_messeges:
				self.client.send_chat_message(chat_message.group_jid,self.groups_greeting_messeges[chat_message.group_jid] )
			else:
				self.client.send_chat_message(chat_message.group_jid,'No greeting set, admins can set a greeting through \"Set greeting Hi\"')
		elif msg=="rules":
			if chat_message.group_jid in self.rules:
				self.client.send_chat_message(chat_message.group_jid,self.rules[chat_message.group_jid] )
			else:
				self.client.send_chat_message(chat_message.group_jid,'No rules set, admins can set rules through \"set the rules Hi\"')
		elif self.is_command(chat_message):
			self.execute_command(chat_message, chat_message.group_jid)
		elif permission_pattern.match(msg)is not None:
			self.set_permissions(chat_message)
		elif cap_48_pattern.match(msg)is not None:
			cap = int(msg.split()[1])
			if cap <1:
				cap = 48
			elif cap >99:
				cap = 98

			self.cap_48[chat_message.group_jid] = cap
			pickle.dump( self.cap_48, open( "cap_48.p", "wb" ) )

			self.client.send_chat_message(chat_message.group_jid,"48 mode capacity now is "+str(self.cap_48[chat_message.group_jid]))

		elif trigger_sympol in msg and msg.find('for checking if Renegade is up') < msg.find(trigger_sympol): 
			pass
			self.set_trigger(chat_message)
		
		# print(msg in self.groups_triggers[chat_message.group_jid])
		elif msg.startswith("blacklist delete"):
			self.delete_blacklist(chat_message)
		elif msg.startswith("delete"):
			if chat_message.group_jid in self.groups_triggers:
				if msg[len("delete"):].strip() in self.groups_triggers[chat_message.group_jid]:
					self.delete_trigger(chat_message)
				else:
					self.client.send_chat_message(chat_message.group_jid,"Trigger doesn't exist.")
			else:
				self.client.send_chat_message(chat_message.group_jid,"No triggers to delete yet.")
		elif msg.startswith("blacklist"):
			self.add_blacklist(chat_message)
		elif msg == "close message":

			if chat_message.group_jid in self.lock_messages:
				self.client.send_chat_message(chat_message.group_jid,self.lock_messages[chat_message.group_jid])
			else:
				self.client.send_chat_message(chat_message.group_jid,"No message set, admins can use close message + your message to set a message.")
		elif msg.startswith("close message"):
			self.close_group(chat_message)
			self.lock_messages[chat_message.group_jid] = chat_message.body[len("close message "):]
			pickle.dump( self.lock_messages, open( "lock_messages.p", "wb" ) )
			self.client.send_chat_message(chat_message.group_jid,"Lock message is set.")
		elif chat_message.group_jid in self.groups_triggers:
			if msg in self.groups_triggers[chat_message.group_jid]:
				if re.match(regex,self.groups_triggers[chat_message.group_jid][msg]) is not None:
					self.client.send_link(chat_message.group_jid,self.groups_triggers[chat_message.group_jid][msg], self.groups_triggers[chat_message.group_jid][msg], text='', app_name='Webpage')
				else:
					self.client.send_chat_message(chat_message.group_jid,self.groups_triggers[chat_message.group_jid][msg])

	def on_xiphias_get_users_response(self, response: Union[xiphias.UsersResponse, xiphias.UsersByAliasResponse]):

		for user in response.users:
			user_jid = user.jid;
			if user_jid is not None:
				if(user_jid in self.bot_jids):
					group_jid = self.user_group_jids[user_jid]
					self.client.leave_group(group_jid);
#					self.client.send_chat_message(self.current_group_jid,"Got it! JID is {}".format(user_jid))
	
		if(len(response.users) > 0):
			group_jid = self.user_group_jids[self.current_user]
			if path.exists("username_greeter.p") and os.path.getsize('username_greeter.p') > 0:
				greeterfile = open('username_greeter.p','rb')
				greeterconfig = pickle.load(greeterfile)
				greeterfile.close()
			else:
				greeterconfig = {}
				greeterconfig[group_jid] = {"setting": "off"}
			
			if path.exists("mandatory_avatar.p") and os.path.getsize('mandatory_avatar.p') > 0:
				avatarfile = open('mandatory_avatar.p','rb')
				avatarconfig = pickle.load(avatarfile)
				avatarfile.close()
			else:
				avatarconfig = {}
				avatarconfig[group_jid] = {"setting": "disable"}

			if (path.exists("days.p") and os.path.getsize('days.p') > 0):
				configfile = open('days.p','rb')
				config = pickle.load(configfile)
				configfile.close()

				for user in response.users:
					signup_date = datetime.fromtimestamp(user.creation_date_seconds)
					today = datetime.today()
					delta = today - signup_date
					minutes, seconds = divmod(delta.seconds, 60)
					
					config_group_found = config.get(self.user_group_jids[self.current_user], None)
					group_jid = self.user_group_jids[self.current_user]

					if ((config_group_found and config[group_jid]['removal_days'] > 0 and delta.days < config[group_jid]['removal_days'])):
						self.client.send_chat_message(group_jid,"Account less than {} days, removing.".format(config[group_jid]['removal_days']))
						#doesn't work, cannot get jid
						#self.client.remove_peer_from_group(self.current_group_jid, user.jid)
						self.client.remove_peer_from_group(group_jid, self.current_user)
			if ((group_jid in greeterconfig) and (greeterconfig[group_jid]['setting'] == "on")):
				self.welcome_user = True
				#self.client.send_chat_message(self.current_group_jid,"User {}".format(user.jid))#json.dumps(user.__dict__)))
	#					self.client.add_friend(user.jid)

	#		if ((self.current_group_jid in avatarconfig) and (avatarconfig[self.current_group_jid]['setting'] == "enable")):
	#			for user in response.users:
	#				user_avatar = user.background_pic_full_sized;
	#				if user_avatar is None or not 'http' in user_avatar:
	#					self.client.send_chat_message(self.current_group_jid,"Empty profile picture, removing.")
	#					self.client.remove_peer_from_group(self.current_group_jid, self.current_user)

	def is_command(self, chat_message):
		available_commands = ["noobs disallow","!username_greeter","enable", "disable"]
		body = chat_message.body.lower()
		for command in available_commands:
			if body.find(command) == 0:
				return True
		return False

	def send_gif(self, chat_message, group):
		body = chat_message.body.lower()
		commands = body.split("gif", 1)
		if(len(commands) == 2):
			commands[1] = commands[1].strip();
			self.client.send_gif_image(group, commands[1])

	def execute_command(self, chat_message, group):
		body = chat_message.body.lower()
		available_commands = ["noobs disallow","!username_greeter","enable","disable"]
		commands = []
		for command in available_commands:
			if body.find(command) == 0:
				commands = body.split(command, 1)
				commands[0] = command;
				if(len(commands) == 2):
					commands[1] = commands[1].strip();
				break;
		if(commands[0] == 'noobs disallow' and len(commands) == 2 and commands[1].isdigit()):
			if path.exists("days.p") and os.path.getsize('days.p') > 0:
				configfile = open('days.p','rb')
				config = pickle.load(configfile)
			else:
				config = {};
			if(group not in config):
				config[group] = {"removal_days" : int(commands[1])}
			else:
				config[group]['removal_days'] = int(commands[1])
			outfile = open('days.p','wb')
			if os.path.getsize('days.p') > 0:
				configfile.close()
			pickle.dump(config,outfile)
			outfile.close()
			if(config[group]['removal_days'] > 0):
				self.client.send_chat_message(group, 'Accounts less than {} days will be removed.'.format(commands[1]))
			else:
				self.client.send_chat_message(group, 'Recent accounts removal disabled.'.format(commands[1]))
		elif(commands[0] == '!username_greeter' and len(commands) == 2 and (commands[1] == "off" or commands[1] == "on")):
			pass
#			if path.exists("username_greeter.p") and os.path.getsize('username_greeter.p') > 0:
#				greeterconfigfile = open('username_greeter.p','rb')
#				greeterconfig = pickle.load(greeterconfigfile)
#			else:
#				greeterconfig = {};
#			if(group.jid not in greeterconfig):
#				greeterconfig[group.jid] = {"setting" : commands[1]}
#			else:
#				greeterconfig[group.jid]['setting'] = commands[1]
#			outfile = open('username_greeter.p','wb')
#			if os.path.getsize('username_greeter.p') > 0:
#				greeterconfigfile.close()
#			pickle.dump(greeterconfig,outfile)
#			outfile.close()
#			if(greeterconfig[group.jid]['setting'] == 'on'):
#				self.client.send_chat_message(group.jid, 'Accounts will be greeted by display name.')
#			else:
#				self.client.send_chat_message(group.jid, 'Accounts will not be greeted by display name.')
		elif((commands[0] == "enable" or commands[0] == "disable") and len(commands) == 2 and commands[1] == 'profile picture'):
			if path.exists("mandatory_avatar.p") and os.path.getsize('mandatory_avatar.p') > 0:
				avatarconfigfile = open('mandatory_avatar.p','rb')
				avatarconfig = pickle.load(avatarconfigfile)
			else:
				avatarconfig = {};
			if(group.jid not in avatarconfig):
				avatarconfig[group.jid] = {"setting" : commands[0]}
			else:
				avatarconfig[group.jid]['setting'] = commands[0]
			outfile = open('mandatory_avatar.p','wb')
			if os.path.getsize('mandatory_avatar.p') > 0:
				avatarconfigfile.close()
			pickle.dump(avatarconfig,outfile)
			outfile.close()
			if(avatarconfig[group.jid]['setting'] == 'enable'):
				self.client.send_chat_message(group.jid, 'Users who join the group without a profile picture will be removed.')
			else:
				self.client.send_chat_message(group.jid, 'Users who join the group without a profile picture will not be removed.')
		#else:
			#self.client.send_chat_message(group.jid, 'Unknown command: {}'.format(chat_message.body))


	def user_behaviour(self,chat_message: chatting.IncomingGroupChatMessage):
		#group_id = chat_message.group_jid
		try:
			group_id = chat_message.group_jid
		except:
			group_id='a'
		user_id = chat_message.from_jid
		try:
			data=self.groups_spam_mute_time[group_id][user_id]
			if(data[-1]):
				if((datetime.now()-data[0]).seconds > 60):
					del self.groups_spam_mute_time[group_id][user_id]
					pickle.dump( self.groups_spam_mute_time, open( "mut_users.p", "wb" ) )
				else:
					return
			else:
				pass
		except:
			pass
		self.spam_remove(chat_message)

		msg = chat_message.body.strip().lower()
		not_lower_msg = chat_message.body.strip()
		if chat_message.group_jid in self.groups_blacklist:
			if any([word in msg for word in self.groups_blacklist[chat_message.group_jid]]) :
				self.client.remove_peer_from_group(chat_message.group_jid,chat_message.from_jid)
				self.client.send_chat_message(chat_message.group_jid,"Removing for saying a censored word.")
				return

		if  permission_pattern.match(msg) is not None:
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif msg=="delete greeting":
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif msg=="rules delete":
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif msg=="delete goodbye":
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif lurk_time_pattern.match(msg)is not None:
			
			self.client.send_chat_message(chat_message.group_jid,'Only admins can do this.')
		elif msg.startswith("set greeting "):
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif msg.startswith("set the rules "):
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif msg.startswith("set goodbye "):
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif msg.startswith("blacklist delete"):
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		elif msg.startswith("blacklist") and msg!="blacklist":
			self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
		
		else:
			if self.groups_permissions[chat_message.group_jid]>1:
				if msg=="greeting"and self.groups_permissions[chat_message.group_jid]==3:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
				if msg=="greeting"and self.groups_permissions[chat_message.group_jid]==2:
					if chat_message.group_jid in self.groups_greeting_messeges:
						self.client.send_chat_message(chat_message.group_jid,self.groups_greeting_messeges[chat_message.group_jid] )
					else:
						self.client.send_chat_message(chat_message.group_jid,'No greeting set, admins can set a greeting through \"Set greeting Hi\"')
				
				if msg=="rules"and self.groups_permissions[chat_message.group_jid]==3:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
				if msg=="rules"and self.groups_permissions[chat_message.group_jid]==2:
					if chat_message.group_jid in self.rules:
						self.client.send_chat_message(chat_message.group_jid,self.rules[chat_message.group_jid] )
					else:
						self.client.send_chat_message(chat_message.group_jid,'No rules set, admins can set rules through \"set the rules Hi\"')

				if msg.startswith("gif") and self.groups_permissions[chat_message.group_jid]==3:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
				if msg.startswith("gif") and self.groups_permissions[chat_message.group_jid]==2:
					self.send_gif(chat_message, chat_message.group_jid);

			if self.groups_permissions[chat_message.group_jid]>1:
				if msg=="active"and self.groups_permissions[chat_message.group_jid]==3:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")

			if self.groups_permissions[chat_message.group_jid]>1:
				if msg=="actives more"and self.groups_permissions[chat_message.group_jid]==3:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")

			if self.groups_permissions[chat_message.group_jid]>1:
				if msg=="talkers"and self.groups_permissions[chat_message.group_jid]==3:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")

			if self.groups_permissions[chat_message.group_jid]>1:
				if msg=="talkers more"and self.groups_permissions[chat_message.group_jid]==3:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")


				if trigger_sympol in msg :
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
				elif permission_pattern.match(msg)is not None:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
				
				
				elif msg.startswith("delete") :
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
				elif chat_message.group_jid in self.groups_triggers:
					if msg in self.groups_triggers[chat_message.group_jid] and self.groups_permissions[chat_message.group_jid]==3:
						self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
					elif self.groups_permissions[chat_message.group_jid] ==2 and msg in self.groups_triggers[chat_message.group_jid]:
						if re.match(regex,self.groups_triggers[chat_message.group_jid][msg]) is not None:
							self.client.send_link(chat_message.group_jid,self.groups_triggers[chat_message.group_jid][msg], self.groups_triggers[chat_message.group_jid][msg], text='', app_name='Webpage')
						else:
							self.client.send_chat_message(chat_message.group_jid,self.groups_triggers[chat_message.group_jid][msg])

			else:
				
				if msg == "permission":
					self.client.send_chat_message(chat_message.group_jid,"Permissions can be set with the following commands: \n- \"Permission 1\" Default. \n- \"Permission 2\" Non-admins can't create/edit or delete substitutions. \n- \"Permission 3\" Non-admins can't create/edit or delete substitutions, and they cannot use any commands.")	
				elif msg == "help":
					self.client.send_chat_message(chat_message.group_jid,self.help_msg)
				elif msg.startswith("gif"):
					self.send_gif(chat_message, chat_message.group_jid);
				elif msg == "trigger":
					self.list_trigger(chat_message)
				elif msg == "blacklist":
					self.list_black(chat_message)
				elif msg=="greeting":
					if chat_message.group_jid in self.groups_greeting_messeges:
						self.client.send_chat_message(chat_message.group_jid,self.groups_greeting_messeges[chat_message.group_jid] )
					else:
						self.client.send_chat_message(chat_message.group_jid,'No greeting set, admins can set a greeting through \"set greeting Hi\"')
				elif msg=="rules":
					if chat_message.group_jid in self.rules:
						self.client.send_chat_message(chat_message.group_jid,self.rules[chat_message.group_jid] )
					else:
						self.client.send_chat_message(chat_message.group_jid,'No rules set, admins can set rules through \"set the rules Hi\"')
				elif trigger_sympol in msg :
					self.set_trigger(chat_message)
				elif permission_pattern.match(msg)is not None:
					self.client.send_chat_message(chat_message.group_jid,"Only admins can do this.")
				
				elif msg.startswith("delete"):
					if chat_message.group_jid in self.groups_triggers:
						if msg[len("delete"):].strip() in self.groups_triggers[chat_message.group_jid]:
							self.delete_trigger(chat_message)
						else:
							self.client.send_chat_message(chat_message.group_jid,"Trigger doesn't exist.")
					else:
						self.client.send_chat_message(chat_message.group_jid,"No triggers to delete yet.")
				elif chat_message.group_jid in self.groups_triggers:
					if msg in self.groups_triggers[chat_message.group_jid]:
						if re.match(regex,self.groups_triggers[chat_message.group_jid][msg]) is not None:
							self.client.send_link(chat_message.group_jid,self.groups_triggers[chat_message.group_jid][msg], self.groups_triggers[chat_message.group_jid][msg], text='', app_name='Webpage')
						else:
							self.client.send_chat_message(chat_message.group_jid,self.groups_triggers[chat_message.group_jid][msg])
if __name__ == '__main__':
	main()
