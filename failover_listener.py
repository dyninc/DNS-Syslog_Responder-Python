#!/usr/bin/env python
"""
Script to catch, parse and react to probe states from DynECT syslog notifications
"""
from socket import *
import thread
from optparse import OptionParser
import sys, traceback
import time
import csv
from dynect.DynectDNS import DynectRest
import ConfigParser


BUFF = 4096
MSG_COMPLETE_DELAY = 1

def parse_options():
        """
        Parses command line arguments
        """

        usage = """%prog [options]

        Server for responding to DynECT syslog errors for multiple failovers"""
        parser = OptionParser(usage = usage)

        parser.add_option(
                '--port', '-p',
                action = 'store',
                type = 'int',
                dest = 'port',
                default = '514',
                help = 'Port to server on [default %default]',
        )

        parser.add_option(
                '--address', '-a',
                action = 'store',
                type = 'str',
                dest = 'address',
                default = '0.0.0.0',
                help = 'Local NIC address to bind to [default %default]',
        )

        parser.add_option(
                '--rules', '-r',
                action = 'store',
                type = 'str',
                dest = 'rules',
                default = 'rules.csv',
                help = 'CSV of failover rules [default %default]',
        )

        parser.add_option(
                '--sensitivity', '-s',
                action = 'store',
                type = 'str',
                dest = 'sensitivity',
                default = 'all',
                help = 'How many probes must be down to kick into failover. Valid options are \'all\', \'majority\' and \'any\' [default %default]',
        )


        options = parser.parse_args()[0]

        #in cse some one entered and invalid option, set it to the default
        if options.sensitivity != 'majority' and options.sensitivity != 'any':
                options.sensitivity = 'all'

        return options

def parse_data(data):
        """
        Parse out how many failures are in the returned DynECT probe data... if the data is not he rigtht format just return a -1
        """
        up = -1
        down = -1
        ip = "0.0.0.0"
        try:
                lines = data.split("\r\n")
                for line in lines:
                        if len(line) > 1:
                                words = line.split(" ")
                                probe = words[7]
                                fqdn = words[4]
                                ip = words[len(words) - 1]
                                state = words[8]

                                # we initialized to -1 so we could tell a failed parse from no ups or no downs, as such, set them to 0 when parse succeeds
                                if (state == "down" or state == "up") and (up == -1 or down == -1):
                                        down = 0
                                        up = 0

                                if state == "down":
                                        down = down + 1
                                elif state == "up":
                                        up = up + 1
        except Exception:
                print Exception
                traceback.print_exc()
                down = -1
                up = -1
                ip = "0.0.0.0"

        return down, up, ip

def majority(total):
        """
        Quick helper function to return a number representing one more than half or half rounded up to the nearest integer
        """
        half = float(total) / 2.0
        if ((half % 1) == 0):
                if half < total:
                        return half + 1
                return total
        else:
                return math.ceil(half)

def parse_rules(rules_file):
        """
        Read the rules file in and pull out the rule sets. Each line in the file is:

        Zone, FQDN, Primary IP, Secondary IP

        Returns an associative array which is an IP address as the key and an array of the other information as the values

        """
        try:
                rules = {}
                with open(rules_file, 'rb') as csvfile:
                        reader = csv.reader(csvfile, delimiter=',', quotechar='|')
                        for row in reader:
                                if row[2].strip() in rules:
                                        rules[row[2].strip()].append({"zone" : row[0].strip(), "fqdn" : row[1].strip(), "secondary" : row[3].strip()})
                                else:
                                        rules[row[2].strip()] = [{"zone" : row[0].strip(), "fqdn" : row[1].strip(), "secondary" : row[3].strip()}]
        except Exception:
                print Exception
                traceback.print_exc()
                rules = {}

        return rules

def login(cust, user, pwd, dynect):
        '''
        Do the DynECT login
        '''
        try:
                arguments = {
                        'customer_name':  cust,
                        'user_name':  user,
                        'password':  pwd,
                }
                response = dynect.execute('/Session/', 'POST', arguments)

                if response['status'] != 'success':
                        raise("Incorrect DynECT Credentials")
        except:
                print "Warning.... unable to parse status return for login"
def get_records(zone, fqdn, dynect):
        """
        Return all the A records from the fqdn
        """
        response = dynect.execute('/REST/ARecord/' + zone + '/' + fqdn + '/', 'GET')

        if response['status'] != 'success':
                print "Failed to retrieve record list"
                print response
                return None

        return response['data']

def get_address_from_record(url, dynect):
        """
        Get the record data for a record and return the ip address for it
        """
        response = dynect.execute(url, 'GET')

        if response['status'] != 'success':
                print "Failed to retrieve record data"
                print response
                return None

        return response['data']['rdata']['address']

def put_record(url, ip, dynect):
        """
        Do the update of the record to the new ip
        """
        arguments = {
                'rdata':  {"address" : ip},
        }

        response = dynect.execute(url, 'PUT', arguments)

        if response['status'] != 'success':
                print "Failed to update record data"
                print response
                return False

        return True

def publish(zone, dynect):
        """
        Publish the zone after updating the records
        """
        arguments = {
                'publish' : True,
        }

        response = dynect.execute('/REST/Zone/' + zone + '/', 'PUT', arguments)

        if response['status'] != 'success':
                print "Failed to publish zone"
                print response
                return False

        return True

def update_record(zone, fqdn, current_ip, new_ip, dynect):
        """
        Take advantage of the DynECT Python Rest Library to quickly find and update the needed records
        """
        records = get_records(zone, fqdn, dynect)
        for record in records:
                ip = get_address_from_record(record, dynect)
                if ip == current_ip:
                        if put_record(record, new_ip, dynect):
                                if publish(zone, dynect):
                                        return True
        return False

def update_dynect(rules, ip, customername, username, password, recover = False):
        """
        Check id there needs to be updates made and if so call update record for each one
        """
        if ip in rules:
                dynect = DynectRest()
                login(customername, username, password, dynect)
                try:
                        for match in rules[ip]:
                                if recover:
                                        if update_record(match["zone"], match["fqdn"], match["secondary"], ip, dynect):
                                                print match["fqdn"] + " has recoverd to IP address " + ip
                                else:
                                        if update_record(match["zone"], match["fqdn"], ip, match["secondary"], dynect):
                                                print match["fqdn"] + " has failed over to IP address " + match["secondary"]
                except  Exception:
                        print Exception
                        traceback.print_exc()
                        rules = {}

                finally:
                        # Log out, to be polite
                        dynect.execute('/Session/', 'DELETE')

def handler(sock, sensitivity, rules_file, customername, username, password):
        """
        Thread handler function, read the data from the connection which just came in then take appropriate action based on data
        """
        try:
                # lets give it 1 second to make sure the full message has been pushed by DynECT
                time.sleep(MSG_COMPLETE_DELAY)
                while 1:
                        data = sock.recv(BUFF)
                        down, up, ip = parse_data(data)
                        # if there are valid probe values only, take action based on the values... if not, ignore them
                        if up > -1 and down > -1:
                                print "Dynect Syslog message received and being processed"
                                total = down + up
                                # first let's check if any of the kick into failover conditions are met
                                if (sensitivity == "all" and down == total) or (sensitivity == "majority" and down >= majority(total)) or (sensitivity == "any" and down > 0):
                                        rules = parse_rules(rules_file)
                                        update_dynect(rules, ip, customername, username, password)

                                # now lets check if any of the recovery conditions are met
                                if (sensitivity == "all" and up > 0) or (sensitivity == "majority" and up >= majority(total)) or (sensitivity == "any" and  up == total):
                                        rules = parse_rules(rules_file)
                                        update_dynect(rules, ip, customername, username, password, True)

                        if not data:
                                break
        finally:
                sock.close()

def main():
        """
        Main Routine
        """

        username = ''
        password = ''
        customername = ''

        # now read in the DynECT user credentials
        config = ConfigParser.ConfigParser()
        try:
                config.read('credentials.cfg')
                customername = config.get('Dynect', 'customer', 'none')
                username = config.get('Dynect', 'user', 'none')
                password = config.get('Dynect', 'password', 'none')
        except:
                sys.exit("Error Reading crednetials.cfg file")

        options = parse_options()

        #set up the address
        ADDR = (options.address, options.port)

        # use tcp
        sock = socket(AF_INET, SOCK_STREAM)

        # reuse the socket
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        # bind and listen
        sock.bind(ADDR)
        sock.listen(1)
        print "Starting DynECT Syslog Message Handler"
        try:
                while 1:
                        connected_sock, addr = sock.accept()
                        thread.start_new_thread(handler, (connected_sock, options.sensitivity, options.rules, customername, username, password))
        except KeyboardInterrupt:
                sock.close()
                sys.exit("Closing DynECT Syslog Message Handler")
        finally:
                sock.close()


if __name__ == '__main__':
        main()