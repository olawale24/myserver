#!/usr/bin/python

#Copyright (c) 2014 SSH Communications Security Corporation.
#
#This software is protected by international copyright laws.
#
#                    All rights reserved.

import sys
import socket
import ldap

class Blackboard ():
  """
  Parses and keeps all the parameters sent to the script from server.
  """
  cert_subject_name = None
  cert_issuer_name = None
  cert_serial_no = None
  user_group = None
  user_name_no_domain = None
  user_name = None
  user_id = None

  def __init__ (self):
    # Creating a pair blackboard item - method to handle the item
    self.parameters_dictionary = {
      "certificate-subject-name" : self.set_subject_name,
      "certificate-issuer-name": self.set_cert_issuer_name,
      "certificate-serial-number" : self.set_cret_serial_number,
      "user": self.set_user_name,
      "user-group" : self.set_user_group,
      "user-name-no-domain" : self.set_user_name_no_domain
    }
    
  def set_subject_name(self, value):
    self.cert_subject_name = value
    #dbg.print_msg("subject name --- %s" % self.cert_subject_name)

  def set_cert_issuer_name(self, value):
    self.cert_issuer_name = value

  def set_user_group(self, value):
    self.user_group = value

  def set_user_name_no_domain(self, value):
    self.user_name_no_domain = value

  def set_cret_serial_number(self, value):
    self.cert_serial_no = value

  def set_user_name(self, value):
    if value.find(":") :
      (user_id, user_name) = value.split(':', 1)
      self.user_id = user_id
      self.user_name = user_name
    else :
      self.user_name = value

  def parse_parameter(self, received_string):
      dbg.print_msg(received_string + "\n")
      (parameter, value) = received_string.split('=', 1)
      for item in self.parameters_dictionary.items() :
        if (parameter == item[0]):
          #dbg.print_msg(received_string + "\n")
          item[1](value)
          break


class BlackboardCertificate ():
  """
  Parses and keeps certificate related information.
  """
  class SubjectName ():
    common_name = None
    organization = None
    country = None

  subj_name = SubjectName()

  def __init__ (self, blackboard):
    self.parse_subj_name(blackboard.cert_subject_name)

  def parse_subj_name(self, subj):
    #dbg.print_msg("Subj:"+ subj + "\n")
    fields = ldap.dn.explode_dn(subj)
    for field in fields :
      #dbg.print_msg("Field:"+ field + "\n")
      (field_type, value) = field.split('=', 1)
      if field_type == "CN" :
        self.subj_name.common_name = value
      elif field_type == "O" :
        self.subj_name.organization = value
      elif field_type == "C" :
        self.subj_name.country = value
      else :
        # unknown filed
        pass
    return

class UserMatcher():
  """
  Check if user passed from server matches the user stored in the certificate.
  """
  def produce_user_name(self, blackboard):
    """
    Shuffles user name given in the certificate.
    Out of Last.First.Middle.id it produces First.Last
    blackboard - the object where information from the server is stored
    returns    - composed user name or None if fails
    """
    user_name = None
    cert = BlackboardCertificate(blackboard)

    cert_cn = cert.subj_name.common_name
    #dbg.print_msg("cn:" + cert_cn + "\n")
    try :
      (last_name, first_name, middle_name, cac_id) = cert_cn.split(".")
      user_name = first_name + "." + last_name
    except :
      # wrong format
      user_name = None

    return user_name

  def match_given_and_cn_names(self, blackboard):
    """
    Checks if user name script got from server matches the name
    produced from certificate's CN.

    returns  True if names are the same
             False otherwise
    """
    ret_val = False
    cn_user_name = self.produce_user_name(blackboard)
    dbg.print_msg("user name: %s\n" % cn_user_name)
    dbg.print_msg("blackboard user name: %s\n" % blackboard.user_name)
    if cn_user_name and cn_user_name == blackboard.user_name :
      ret_val = True
    else :
      ret_val = False

    return ret_val

class DebugOutput():
  """
  !!! DO NOT USE IT IN RELEASE VERSION
  EVERYBODY LOGGED IN CAN LISTEN THE SOCKET !!!

  For debugging.
  Send strings to a socket. Something like netcat can listen on the other side.
  """
  pf_type = socket.AF_INET
  port = 10022
  host = "127.0.0.1"
  socket = None
  def __init__ (self):
    self.socket = socket.socket(self.pf_type, socket.SOCK_STREAM)
    server_address = (self.host, self.port)
    try:
      self.socket.connect(server_address)
    except:
      self.socket = None

  def __del__ (self):
    try:
      self.socket.close()
    except:
      pass

  def print_msg(self, message):
    if self.socket != None:
      self.socket.sendall(message)


# ==== Main starts here ====

# !!! Comment dbg out on the release version !!!
dbg = DebugOutput()

blackboard = Blackboard()

# First ssh-server-g3 expects protocol version
# Currently only version 1 is supported
sys.stdout.write("version:1\n")
sys.stdout.flush()

# Read version string sent by server.
version = sys.stdin.readline()
(ver, num) = version.split(':')
if (ver == "version") :
  if (int(num) != 1):
    sys.exit(1)
else:
  sys.exit(1)

# Version is OK, let's wait for request.
request = sys.stdin.readline()
(request_str, num) = request.split(':')
if (request_str == "request") :
  request_no = int(num)
else:
  sys.exit(2)

# Request started, let's read request's data.
while 1:
    received_string = sys.stdin.readline()
    if not received_string:
      # failed to read stdin
      sys.exit(4)

    # remove end of line
    received_string = received_string.rstrip('\n')

    if received_string.find("end-of-request",0,14) == 0 :
      # no more parameters to receive left
      (end_of_request_str, num) = received_string.split(':')
      end_of_request_no = int(num)
      if (end_of_request_no == request_no):
        break
      else :
        # that's end of another request
        sys.exit(3)
    else:
      # handle parameters
      blackboard.parse_parameter(received_string)

# Let's match user names.
matcher = UserMatcher()

# Request finished, let's send response.
sys.stdout.write("%s"%request)

if matcher.match_given_and_cn_names(blackboard) == True:
  #sys.stdout.write("mapped-user=first.last\n")
  sys.stdout.write("success:\n")
else:
  sys.stdout.write("fail:cannot map user name\n")

sys.stdout.flush()

sys.exit(0) 
