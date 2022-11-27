from distutils.log import log
from multiprocessing import process
import socket
from app import app, logout, mysql, MySQLdb, render_template, request, redirect, url_for, session, loggedin, hashlib, os, flash, g, helper_functions, jsonify
from collections import namedtuple
from datetime import datetime
from flask import Flask, Response, render_template, request, abort, make_response
import filehelpers as fh
import subprocess
import time
from pygtail import Pygtail
import json
from collections import defaultdict
import sys

modifiedTime = {}

def browse(path):
       
    File = namedtuple("File", "path_url name")
    dirs = []
    files = []
    parent, _ = os.path.split(path)

    for name in os.listdir(make_filepath(path)):
        path_url = "/gnueditor/" + os.path.join(path, name)
        f = File(path_url, name)
        if os.path.isdir(make_filepath(f.path_url[1:])):
            dirs.append(f)
        else:
            files.append(f)

    return render_template("browse.html",
                            path=path,
                            parent=parent,
                            dirs=sorted(dirs),
                            files=sorted(files),username=session['username'], role=session['role'])

def edit(path):
    with open(make_filepath(path), 'r') as f:
        content = f.read()
    return render_template("edit.html",
                            content=content,
                            path=path,username=session['username'], role=session['role'])


def find_extension(path):
    i = path.rfind(".")
    return path[i:]

# Path /
def make_filepath(path):
    return os.path.join("/", path)


def view(path):
       if loggedin():
         if find_extension(path) == ".md":
            content = fh.get_html_from_md(make_filepath(path))
         else:
            with open(make_filepath(path), 'r') as f:
                  content = "<pre><code>{}</code></pre>".format(f.read())
         parent_url, filename = os.path.split(path)
         parent_url = "/gnueditor/" + parent_url
         file_url = "/gnueditor/" + path
         return render_template("view.html",
                                 content=content,
                                 parent_url=parent_url,
                                 file_url=file_url, username=session['username'], role=session['role'])
       return redirect(url_for('login'))


# http://localhost:5000/home - this will be the home page, only accessible for loggedin users
@app.route('/home')
def home():
    # Check if user is loggedin
    if loggedin():
       app.logger.info('User ' + session['username'] + " accessed home (Dashboard) page.")
       osquery=helper_functions.helpers()
       
       hostname = request.headers.get('Host')
       
       return render_template('home.html', username=session['username'], role=session['role'], data=osquery.get_sysinfo(), ram=osquery.get_memory(),hostname=hostname)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))
 
 
@app.route("/gnueditor/", methods = ["GET", "POST"])
@app.route("/gnueditor/<path:path>", methods = ["GET", "POST"])
def gnueditor(path=""):
   print(session['role'])
   if (loggedin()) and (session['role'] == 'Admin'):

            filepath = make_filepath(path)
            app.logger.info("User " + session['username'] + " accessed gnueditor page." )
            # parse POST request, used for simple file commands
            if request.method == "POST":
               if request.form['command'] == "make_file":
                     fh.make_file(filepath, request.form['name'])

               elif request.form['command'] == "make_dir":
                     fh.make_dir(filepath, request.form['name'])

               elif request.form['command'] == "rename":
                     fh.rename(filepath, request.form['new_name'])

               elif request.form['command'] == "save":
                     fh.save(filepath, request.form['text'])

               elif request.form['command'] == "delete_dir":
                     fh.delete_dir(filepath)

               elif request.form['command'] == "delete_file":
                     fh.delete_file(filepath)

               else:
                     return "could not understand POST request"
               return "done"

            # if directory then browse
            if os.path.isdir(filepath):
               return browse(path)

            # if not a directory and not a file then 404
            if not os.path.isfile(filepath):
               abort(404)

            # edit
            if "edit" in request.args:
               return edit(path)

            # view
            
            return view(path)
   return redirect(url_for('login'))

# http://localhost:5000/about - this will be the home page, only accessible for loggedin users
@app.route('/about')
def about():
    # Check if user is loggedin
    if loggedin():
       app.logger.info('User ' + session['username'] + " accessed about page.")

       
       return render_template('about.html', username=session['username'], role=session['role'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))
 

def create_hashes():
    try:
        command1 = ['/usr/bin/sudo','/usr/sbin/postmap', '/etc/postfix/check_client_fqdn'];
        command2 = ['/usr/bin/sudo','/usr/sbin/postmap', '/etc/postfix/cidr_greylist_network_exceptions'];
        command3 = ['/usr/bin/sudo','/usr/sbin/postmap', '/etc/postfix/greylist_sender_exceptions'];
        command4 = ['/usr/bin/sudo','/usr/sbin/postmap', '/etc/postfix/transport'];
        command5 = ['/usr/bin/sudo','/usr/sbin/postmap', '/etc/postfix/tls_policy'];
        command6 = ['/usr/bin/sudo','/usr/sbin/postmap', '/etc/postfix/virtual'];
        command7 = ['/usr/bin/sudo','/usr/bin/newaliases'];
        command8 = ['/usr/bin/sudo','/usr/sbin/postmap','/etc/postfix/sender_canonical'];
        command9 = ['/usr/bin/sudo','/usr/sbin/postmap','/etc/postfix/sasl/sasl_password'];
        
        #shell=FALSE for sudo to work.
        app.logger.info("User " + session['username'] +" rebuilding all postfix database hashes ")
        file1='/etc/postfix/check_client_fqdn'
        isExistFile1 = os.path.exists(file1)
        if(isExistFile1):
            subprocess.call(command1, shell=False)
        file2='/etc/postfix/cidr_greylist_network_exceptions'
        isExistFile2 = os.path.exists(file2)
        if(isExistFile2):
            subprocess.call(command2, shell=False)
        
        file3='/etc/postfix/greylist_sender_exceptions'
        isExistFile3 = os.path.exists(file3)
        if(isExistFile3):     
            subprocess.call(command3, shell=False)
        
        file4='/etc/postfix/transport'
        isExistFile4 = os.path.exists(file4)
        if(isExistFile4):     
            subprocess.call(command4, shell=False)
         
        file5='/etc/postfix/tls_policy'
        isExistFile5 = os.path.exists(file5)
        if(isExistFile5): 
            subprocess.call(command5, shell=False)
        file6='/etc/postfix/virtual'
        isExistFile6 = os.path.exists(file6)
        if(isExistFile6): 
            subprocess.call(command6, shell=False)
        file7='/etc/aliases'
        isExistFile7 = os.path.exists(file7)
        if(isExistFile7): 
            subprocess.call(command7, shell=False)
        time.sleep(2.5)
        file8='/etc/postfix/sender_canonical'
        isExistFile8 = os.path.exists(file8)
        if(isExistFile8): 
            subprocess.call(command8, shell=False)
        time.sleep(2.5)
        file9='/etc/postfix/sasl/sasl_password'
        isExistFile9 = os.path.exists(file9)
        if(isExistFile9): 
            subprocess.call(command9, shell=False)
        time.sleep(2.5)
    except subprocess.CalledProcessError as e:
            app.logger.error(e)
            flash('An error occured. Please inspect application logs.','info')
            return "An error occurred ."

 
def restart_service(name):
    try:
        command = ['/usr/bin/sudo','/bin/systemctl', 'restart', name];
        #shell=FALSE for sudo to work.
        app.logger.info("User " + session['username'] +" restarting service " + name)
        flash(name + ' restarted successfully.','success')
        subprocess.call(command, shell=False)
        time.sleep(2.5)
  
    except subprocess.CalledProcessError as e:
            app.logger.error(e)
            flash('An error occured. Please inspect application logs.','info')
            return "An error occurred ."
    
def stop_service(name):
    try:
        command = ['/usr/bin/sudo','/bin/systemctl', 'stop', name];
        #shell=FALSE for sudo to work.
        app.logger.info("User " + session['username'] +" stopping service " + name)
        flash(name + ' stopped successfully.','success')
        subprocess.call(command, shell=False)
        time.sleep(2.5) 

    except subprocess.CalledProcessError as e:
            app.logger.error(e)
            flash('An error occured. Please inspect application logs.','info')
            return "An error occurred ."
    
def start_service(name):
    try:
        command = ['/usr/bin/sudo','/bin/systemctl', 'start', name];
        #shell=FALSE for sudo to work.
        app.logger.info("User " + session['username'] +" starting service "+ name)
        flash(name + ' started successfully.','success')
        subprocess.call(command, shell=False)
        time.sleep(2.5)

     
    except subprocess.CalledProcessError as e:
            app.logger.error(e)
            flash('An error occured. Please inspect application logs.','info')
            return "An error occurred ."
 
 
def check_status():
        p0 =  subprocess.Popen(['/usr/bin/sudo','/bin/systemctl', "is-active",  'postfix'], stdout=subprocess.PIPE)
        (output0, err) = p0.communicate()
        output0 = output0.decode('utf-8')
        #app.logger.info(output0)
        
        p1 =  subprocess.Popen(['/usr/bin/sudo','/bin/systemctl', "is-active",  'postgrey'], stdout=subprocess.PIPE)
        (output1, err) = p1.communicate()
        output1 = output1.decode('utf-8')
        #app.logger.info(output1)
        
        p2 =  subprocess.Popen(['/usr/bin/sudo','/bin/systemctl', "is-active",  'amavis'], stdout=subprocess.PIPE)
        (output2, err) = p2.communicate()
        output2 = output2.decode('utf-8')
        #app.logger.info(output2)
        
        p3 =  subprocess.Popen(['/usr/bin/sudo','/bin/systemctl', "is-active",  'clamav-daemon'], stdout=subprocess.PIPE)
        (output3, err) = p3.communicate()
        output3 = output3.decode('utf-8')
        #app.logger.info(output3)
        
        p4 =  subprocess.Popen(['/usr/bin/sudo','/bin/systemctl', "is-active",  'bind9'], stdout=subprocess.PIPE)
        (output4, err) = p4.communicate()
        output4 = output4.decode('utf-8')
        #app.logger.info(output4)
        
        p5 =  subprocess.Popen(['/usr/bin/sudo','/bin/systemctl', "is-active",  'spamassassin'], stdout=subprocess.PIPE)
        (output5, err) = p5.communicate()
        output5 = output5.decode('utf-8')
        #app.logger.info(output5)
        
        p6 =  subprocess.Popen(['/usr/bin/sudo','/bin/systemctl', "is-active",  'clamav-freshclam'], stdout=subprocess.PIPE)
        (output6, err) = p6.communicate()
        output6 = output6.decode('utf-8')
        #app.logger.info(output6)
        
        statuses = {'postfix': output0.strip(), 'postgrey': output1.strip(),'amavis': output2.strip(),'clamav-daemon':output3.strip(),'bind9': output4.strip(),'spamassassin': output5.strip(),'clamav-freshclam': output6.strip()}
        
        #app.logger.info(statuses)
        app.logger.info("User " + session['username'] + " requested service status." )
        #app.logger.info(statuses)
        
        
        return statuses
    

 #Delete contact    
@app.route("/action/<string:cmd>/<string:action>",methods=['GET'])
def action(cmd,action):
    if(loggedin):
        #actions: str=start stp=stop res=restart
        if request.method == 'GET':
            
            app.logger.info("Command: "+ cmd +" "+ "Action: " + action)    
               
            service = cmd;    
                
            #Postfix
            if(cmd == "0") and (action == "str"):
                service = "postfix"

                create_hashes()
                start_service(service)
            elif (cmd == "0") and (action == "stp"):
                service = "postfix"

                stop_service(service)
            elif (cmd == "0") and (action == "res"):
                service = "postfix"
                create_hashes()
                restart_service(service)
                
            #Postgrey
            if(cmd == "1") and (action == "str"):
                service = "postgrey"

                start_service(service)
            elif (cmd == "1") and (action == "stp"):
                service = "postgrey"

                stop_service(service)
            elif (cmd == "1") and (action == "res"):
                service = "postgrey"

                restart_service(service)
                
            
            #Amavis-new
            if(cmd == "2") and (action == "str"):
                service = "amavis"

                start_service(service)
            elif (cmd == "2") and (action == "stp"):
                service = "amavis"

                stop_service(service)
            elif (cmd == "2") and (action == "res"):
                service = "amavis"

                restart_service(service)
            
            #Clamav
            if(cmd == "3") and (action == "str"):
                service = "clamav-daemon"

                start_service(service)
            elif (cmd == "3") and (action == "stp"):
                service = "clamav-daemon"

                stop_service(service)
            elif (cmd == "3") and (action == "res"):
                service = "clamav-daemon"

                restart_service(service)
                
            #Clamav-freshclam
            if(cmd == "4") and (action == "str"):
                service = "clamav-freshclam"

                start_service(service)
            elif (cmd == "4") and (action == "stp"):
                service = "clamav-freshclam"

                stop_service(service)
            elif (cmd == "4") and (action == "res"):
                service = "clamav-freshclam"

                restart_service(service)
            
            
            #bind
            if(cmd == "5") and (action == "str"):
                service = "bind9"

                start_service(service)
            elif (cmd == "5") and (action == "stp"):
                service = "bind9"

                stop_service(service)
            elif (cmd == "5") and (action == "res"):
                service = "bind9"

                restart_service(service)
            
            #spamassassin
            if(cmd == "6") and (action == "str"):
                service = "spamassassin"

                start_service(service)
            elif (cmd == "6") and (action == "stp"):
                service = "spamassassin"

                stop_service(service)
            elif (cmd == "6") and (action == "res"):
                service = "spamassassin"

                restart_service(service)
                
            
        statuses = check_status()
        
        return redirect(url_for("shellcmd", statuses=statuses))
    return redirect(url_for('login'))

 
 # http://localhost:5000/shellcmd - this will be the home page, only accessible for loggedin users
@app.route('/shellcmd')
def shellcmd():
    # Check if user is loggedin
    if loggedin():
        app.logger.info("User " + session['username'] + " accessed shellcmd page." )
        statuses = check_status()

        return render_template('control_panel.html', username=session['username'], role=session['role'],statuses=statuses)
    # User is not loggedin redirect to login page
    



def parse_log(f): 
            # Get the last line from the file
            p = subprocess.Popen(['/usr/bin/tail','-1000',f],shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            res,err = p.communicate()
            if err:
                print (err.decode())
            else:
                # Use split to get the part of the line that you require
                res = res.decode()
                return (res)
                
def mail_report(): 
            # Get the last line from the file
            p = subprocess.Popen(['/usr/sbin/pflogsumm','/var/log/mail.log'],shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            res,err = p.communicate()
            if err:
                print (err.decode())
            else:
                # Use split to get the part of the line that you require
                res = res.decode()
                return (res)                
 
################## FIREWALL START ##############

def ufw_rules(): 
            # Get the last line from the file
            p = subprocess.Popen(['/usr/bin/sudo','/usr/sbin/ufw','status', 'numbered'],shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            res,err = p.communicate()
            if err:
                print (err.decode())
            else:
                # Use split to get the part of the line that you require
                res = res.decode()
                return (res)   

@app.route('/firewall', methods=['GET'])
def firewall():
    if(loggedin):
        
        fwcontent1 = ufw_rules()
    
        app.logger.info("User " + session['username'] + " accessed logs page." )
        return render_template('firewall.html', fwcontent1=fwcontent1, username=session['username'], role=session['role'])
    return redirect(url_for('login'))

#Delete rule
@app.route('/fwdelrule', methods=['GET','POST'])
def fwdelrule():
    # Check if user is loggedin
    if loggedin():

        fwcontent1 = ufw_rules()

        if request.method == 'POST' and 'rulenumber' in request.form :
            
            number = request.form['rulenumber']

            command = ['/usr/bin/yes| /usr/bin/sudo /usr/sbin/ufw delete '+ number];
            #shell=FALSE for sudo to work.
            app.logger.info("User " + session['username'] +" deleted firewall rule "+ number)
            flash("Rule with " + number + ' deleted successfully.','success')
            subprocess.call(command, shell=True)
            
            return redirect(url_for('firewall'))
            #return render_template('home.html', fwcontent1=fwcontent1,username=session['username'], role=session['role'])
        else:
            app.logger.info('Firewall rule cannot be deleted.')

    return redirect(url_for('login'))

#Allow port rule
@app.route('/fwallowport', methods=['GET','POST'])
def fwallowport():
    # Check if user is loggedin
    if loggedin():

        if request.method == 'POST' and 'port' in request.form and  'comment' in request.form :
            
            port_number = request.form['port']
            
            comment = request.form['comment']

            command = ['/usr/bin/sudo /usr/sbin/ufw allow '+ port_number + ' comment ' + "'"+comment +"'"];
            #shell=FALSE for sudo to work.
            app.logger.info("User " + session['username'] +" added a  firewall rule from any to port "+ port_number)
            flash("Access to port " + port_number + ' added successfully.','success')
            subprocess.call(command, shell=True)
            
            return redirect(url_for('firewall'))
            #return render_template('home.html', fwcontent1=fwcontent1,username=session['username'], role=session['role'])
        else:
            app.logger.info('Firewall rule cannot be deleted.')

    return redirect(url_for('login'))



#Deny from host or net
@app.route('/fwdenyhostnet', methods=['GET','POST'])
def fwdenyhostnet():
    # Check if user is loggedin
    if loggedin():

        if request.method == 'POST' and 'ipaddress' in request.form and 'linenumber' in request.form and 'comment' in request.form :
            
            ip_or_net = request.form['ipaddress']
            
            line_number = request.form['linenumber']
            
            comment = request.form['comment']

            command = ['/usr/bin/sudo /usr/sbin/ufw insert ' +line_number+ ' deny from '+ ip_or_net + ' comment ' + "'"+comment +"'"];
            #shell=FALSE for sudo to work.
            app.logger.info("User " + session['username'] +" added a  firewall DENY rule from "+ip_or_net+" to any port ")
            flash("Deny access to IP or NET " + ip_or_net + ' added successfully.','success')
            subprocess.call(command, shell=True)
            
            return redirect(url_for('firewall'))
            #return render_template('home.html', fwcontent1=fwcontent1,username=session['username'], role=session['role'])
        else:
            flash('Missing arguments','warning')
            app.logger.info('Firewall rule cannot be deleted.')

    return redirect(url_for('login'))


#Allow from host or net
@app.route('/fwallowhostnet', methods=['GET','POST'])
def fwallowhostnet():
    # Check if user is loggedin
    if loggedin():

        if request.method == 'POST' and 'ipaddress' in request.form and 'linenumber' in request.form and 'port' in request.form  and 'comment' in request.form :
            
            ip_or_net = request.form['ipaddress']
            
            line_number = request.form['linenumber']
            
            port_number = request.form['port']
            
            comment = request.form['comment']

            command = ['/usr/bin/sudo /usr/sbin/ufw insert ' +line_number+ ' allow from '+ ip_or_net + ' to any port ' +port_number+ ' comment ' + "'"+comment +"'"];
            #shell=FALSE for sudo to work.
            app.logger.info("User " + session['username'] +" added a  firewall ALLOW rule from "+ip_or_net+" to any port ")
            flash("Allow access to IP or NET " + ip_or_net + ' added successfully.','success')
            subprocess.call(command, shell=True)
            
            return redirect(url_for('firewall'))
            #return render_template('home.html', fwcontent1=fwcontent1,username=session['username'], role=session['role'])
        else:
            flash('Missing arguments','warning')
            app.logger.info('Firewall rule cannot be deleted.')

    return redirect(url_for('login'))

################## FIREWALL STOP ##############
                
################## LOGS START ##############

@app.route('/logs', methods=['GET'])
def logs():
    if(loggedin):
        
        
        mailreport = mail_report()
        
         
        file1='/var/log/mail.log'
        isExistFile1 = os.path.exists(file1)
        if(isExistFile1):    
           
                content1 = parse_log(file1)  
                
        else:
            content1="No logs available"
            app.logger.warning('File mail.log not found')
            flash('No logs available. Please check your system','warning')
        
        file2='/opt/gnuproxy/logs/gnuproxy.log'
        isExistFile2 = os.path.exists(file2)
        if(isExistFile2):        

                content2 = parse_log(file2)    

        else:
            content2="No logs available"
            app.logger.warning('File gnuproxy.log not found')
            flash('No logs available. Please check your system','warning')
        
        file3='/var/log/syslog'
        isExistFile3 = os.path.exists(file3)
        if(isExistFile3):        
           
                content3 = parse_log(file3)     
               
                
        else:
            content3="No logs available"
            app.logger.warning('File syslog not found')
            flash('No logs available. Please check your system','warning')
        
        file4='/var/log/nginx/gnuproxy.access.log'
        isExistFile4 = os.path.exists(file4)
        if(isExistFile4):    
            
                content4 = parse_log(file4)    
             
        else:
            content4="No logs available"
            app.logger.warning('File nginx gnuproxy-access.log not found')
            flash('No logs available. Please check your system','warning')
            
        
        file5='/var/log/auth.log'
        isExistFile5 = os.path.exists(file5)
        if(isExistFile5):    
                
                content5 = parse_log(file5)
                  
        else:
            content5="No logs available"
            app.logger.warning('File auth.log not found')
            flash('No logs available. Please check your system','warning')
        
            
        app.logger.info("User " + session['username'] + " accessed logs page." )
        return render_template('logs.html', content1=content1, content2=content2,content3=content3,content4=content4,content5=content5,mailreport=mailreport, username=session['username'], role=session['role'])
    return redirect(url_for('login'))


def generate_queue():
    try:
        if(os.path.exists("queue/queue.log")):
            f = open("queue/queue.log", "w")
            proc = subprocess.Popen(['/usr/bin/mailq'],shell=True,stdout=f)
            proc.communicate()
            f.close

    except subprocess.CalledProcessError as e:
            app.logger.error(e)
            flash('An error occured. Please inspect application logs.','info')
            return "An error occurred ."



@app.route('/queue', methods=['GET'])
def queue():
    if(loggedin):
        
        #generate and show mail queue
        generate_queue()
        
        with open("queue/queue.log", "r") as f:
            content = f.read()
          

        #app.logger.info("User " + session['username'] + " accessed mail queue page." )
        return render_template('queue.html', data=content,mimetype = 'text/plain', username=session['username'], role=session['role'])
    return redirect(url_for('login'))


        
 # http://localhost:5000/pause - this will be the home page, only accessible for loggedin users
@app.route('/pause')
def pause():
    # Check if user is loggedin
    if loggedin():
        statuses=check_status()
        app.logger.info("User " + session['username'] + " accessed shellcmd page." )
        
        #sudo postconf -e defer_transports=smtp; sudo postfix reload
        
        try:
            command = ['/usr/bin/sudo','/usr/sbin/postsuper', '-h', 'ALL','deferred'];
            #shell=FALSE for sudo to work.
            app.logger.info("User " + session['username'] +" pausing SMTP queue.")
            flash('Deffered messages in Queue holded.','info')
            subprocess.call(command, shell=False)
            time.sleep(1.5)
            
        except subprocess.CalledProcessError as e:
                app.logger.error(e)
                flash('An error occured. Please inspect application logs.','info')
                return "An error occurred ."

        return render_template('control_panel.html', username=session['username'], role=session['role'],statuses=statuses)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/release - this will be the home page, only accessible for loggedin users
@app.route('/release')
def release():
    # Check if user is loggedin
    if loggedin():
        statuses=check_status()
        app.logger.info("User " + session['username'] + " accessed shellcmd page." )
        #sudo postconf -e defer_transports=; sudo postfix reload; sudo postfix flush
        try:
            command = ['/usr/bin/sudo','/usr/sbin/postsuper', '-d','ALL','hold'];
            #shell=FALSE for sudo to work.
            app.logger.info("User " + session['username'] +" released SMTP queue.")
            flash('Messages on hold in Queue deleted.','info')
            subprocess.call(command, shell=False)
            time.sleep(1.5)
            
        except subprocess.CalledProcessError as e:
                app.logger.error(e)
                flash('An error occured. Please inspect application logs.','info')
                return "An error occurred ."

        return render_template('control_panel.html', username=session['username'], role=session['role'],statuses=statuses)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/reload - this will be the home page, only accessible for loggedin users
@app.route('/reload')
def reload():
    # Check if user is loggedin
    if loggedin():
        statuses=check_status()
        app.logger.info("User " + session['username'] + " accessed shellcmd page." )
        #sudo postconf -e defer_transports=; sudo postfix reload; sudo postfix flush
        try:
            command = ['/usr/bin/sudo','/usr/sbin/postsuper', '-f', 'ALL'];
            #shell=FALSE for sudo to work.
            app.logger.info("User " + session['username'] +" reload SMTP queue.")
            flash('Messages in Queue flashed.','info')
            subprocess.call(command, shell=False)
            time.sleep(1.5)
            
        except subprocess.CalledProcessError as e:
                app.logger.error(e)
                flash('Cannot reload queue. Please inspect application logs.','warning')
                return "An error occurred ."

        return render_template('control_panel.html', username=session['username'], role=session['role'],statuses=statuses)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


# http://localhost:5000/shellcmd - this will be the home page, only accessible for loggedin users
@app.route('/network')
def network():
    # Check if user is loggedin
    if loggedin():
        app.logger.info("User " + session['username'] + " accessed network page." )
        statuses = check_status()

        return render_template('network.html', username=session['username'], role=session['role'],statuses=statuses)
    # User is not loggedin redirect to login page
              
              
              
@app.route("/restart")
def restart():
    if loggedin():
        app.logger.warning("User " + session['username'] + " is rebooting the system.")

        subprocess.run("/usr/sbin/shutdown -r 0", shell=True, check=True)
    return render_template('restart.html') 

@app.route("/shutdown")
def shutdown():
    if loggedin():
       app.logger.warning("User " + session['username'] + " shuting down the system.")

       subprocess.run("/usr/sbin/shutdown -h 0", shell=True, check=True)
    return redirect(url_for('logout')) 

#shell in a box
@app.route("/terminal")
def terminal():
    if loggedin():
       app.logger.warning("User " + session['username'] + " openning terminal.")
       return render_template('terminal.html', username=session['username'], role=session['role'])
      
    return redirect(url_for('logout'))
