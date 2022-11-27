import logging
import random
from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, g, jsonify, flash
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
import MySQLdb.cursors
from flask_gravatar import Gravatar
import re
import uuid 
import hashlib
import datetime
import os

app = Flask(__name__,static_folder='static')

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = '321F14ED9A47669368FEB8EC372B9'

# App Settings
app.config['threaded'] = True

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'gnuproxy'
app.config['MYSQL_PASSWORD'] = 'P@ssw0rd1'
app.config['MYSQL_DB'] = 'gnuproxydb'

# Enter your email server details below, the following details uses the gmail smtp server (requires gmail account)
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USERNAME'] = 'ioannis.bouhras@gmail.com'
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Enter your domain name below
app.config['DOMAIN'] = 'http://yourdomain.com'

app.config["TEMPLATES_AUTO_RELOAD"] = True

# Intialize MySQL
mysql = MySQL(app)

# Intialize Mail
mail = Mail(app)

# Enable account activation?
account_activation_required = True

# Enable CSRF Protection?
csrf_protection = True

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    use_ssl=False,
                    base_url=None)



@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.before_first_request
def before_first_request():
    log_level = logging.INFO

    for handler in app.logger.handlers:
        app.logger.removeHandler(handler)

    root = os.path.dirname(os.path.abspath(__file__))
    logdir = os.path.join(root, 'logs')
    if not os.path.exists(logdir):
        os.mkdir(logdir)
    log_file = os.path.join(logdir, 'gnuproxy.log')
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)
    app.logger.addHandler(handler)

    app.logger.setLevel(log_level)
    
    defaultFormatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    handler.setFormatter(defaultFormatter)



# http://localhost:5000/ - this will be the login page, we need to use both GET and POST requests
@app.route('/', methods=['GET', 'POST'])
def login():
	# Redirect user to home page if logged-in
	if loggedin():
		return redirect(url_for('home'))
	# Output message if something goes wrong...
	msg = ''
	# Check if "username" and "password" POST requests exist (user submitted form)
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'token' in request.form:
		# Create variables for easy access
		username = request.form['username']
		password = request.form['password']
		token = request.form['token']
		# Retrieve the hashed password
		hash = password + app.secret_key
		hash = hashlib.sha1(hash.encode())
		password = hash.hexdigest();
		# Check if account exists using MySQL
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute(
		    'SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
		# Fetch one record and return result
		account = cursor.fetchone()
		# If account exists in accounts table in out database
		if account:
			if account_activation_required and account['activation_code'] != 'activated' and account['activation_code'] != '':
				return 'Please activate your account to login!'
			if csrf_protection and str(token) != str(session['token']):
				return 'Invalid token!'
			# Create session data, we can access this data in other routes
			session['loggedin'] = True
			session['id'] = account['id']
			session['username'] = account['username']
			session['role'] = account['role']
			if 'rememberme' in request.form:
				# Create hash to store as cookie
				hash = account['username'] + request.form['password'] + app.secret_key
				hash = hashlib.sha1(hash.encode())
				hash = hash.hexdigest();
				# the cookie expires in 90 days
				expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
				resp = make_response('Success', 200)
				resp.set_cookie('rememberme', hash, expires=expire_date)
				# Update rememberme in accounts table to the cookie hash
				cursor.execute(
				    'UPDATE accounts SET rememberme = %s WHERE id = %s', (hash, account['id'],))
				mysql.connection.commit()
				return resp
			app.logger.info("User " + session['username'] + " logged-in successfully.")
   
			return 'Success'
		else:
			# Account doesnt exist or username/password incorrect
			return 'Incorrect username/password!'
	# Generate random token that will prevent CSRF attacks
	token = uuid.uuid4()
	session['token'] = token
	# Show the login form with message (if any)
	return render_template('index.html', msg=msg, token=token)

# http://localhost:5000/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register', methods=['GET', 'POST'])
def register():
	# Redirect user to home page if logged-in
	if loggedin():
		return redirect(url_for('home'))
	# Output message if something goes wrong...
	msg = ''
	# Check if "username", "password" and "email" POST requests exist (user submitted form)
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'cpassword' in request.form and 'email' in request.form:
		# Create variables for easy access
		username = request.form['username']
		password = request.form['password']
		cpassword = request.form['cpassword']
		email = request.form['email']
		# Hash the password
		hash = password + app.secret_key
		hash = hashlib.sha1(hash.encode())
		hashed_password = hash.hexdigest();
		# Check if account exists using MySQL
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
		account = cursor.fetchone()
		# If account exists show error and validation checks
		if account:
			return 'Account already exists!'
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			return 'Invalid email address!'
		elif not re.match(r'[A-Za-z0-9]+', username):
			return 'Username must contain only characters and numbers!'
		elif not username or not password or not cpassword or not email:
			return 'Please fill out the form!'
		elif password != cpassword:
			return 'Passwords do not match!'
		elif len(username) < 5 or len(username) > 20:
			return 'Username must be between 5 and 20 characters long!'
		elif len(password) < 5 or len(password) > 20:
			return 'Password must be between 5 and 20 characters long!'
		elif account_activation_required:
			# Account activation enabled
			# Generate a random unique id for activation code
			activation_code = uuid.uuid4()
			cursor.execute('INSERT INTO accounts (username, password, email, activation_code) VALUES (%s, %s, %s, %s)',
			               (username, hashed_password, email, activation_code,))
			mysql.connection.commit()
			# Create new message
			email_info = Message('Account Activation Required',
			                     sender=app.config['MAIL_USERNAME'], recipients=[email])
			# Activate Link URL
			activate_link = app.config['DOMAIN'] + \
			    url_for('activate', email=email, code=str(activation_code))
			# Define and render the activation email template
			email_info.body = render_template(
			    'activation-email-template.html', link=activate_link)
			email_info.html = render_template(
			    'activation-email-template.html', link=activate_link)
			# send activation email to user
			mail.send(email_info)
			return 'Please check your email to activate your account!'
		else:
			# Account doesnt exists and the form data is valid, now insert new account into accounts table
			cursor.execute('INSERT INTO accounts (username, password, email, activation_code) VALUES (%s, %s, %s, "activated")',
			               (username, hashed_password, email,))
			mysql.connection.commit()
			return 'You have successfully registered!'
	elif request.method == 'POST':
		# Form is empty... (no POST data)
		return 'Please fill out the form!'
	# Show registration form with message (if any)
	return render_template('register.html', msg=msg)

# http://localhost:5000/activate/<email>/<code> - this page will activate a users account if the correct activation code and email are provided
@app.route('/activate/<string:email>/<string:code>', methods=['GET'])
def activate(email, code):
	msg = 'Account doesn\'t exist with that email or the activation code is incorrect!'
	# Check if the email and code provided exist in the accounts table
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
	    'SELECT * FROM accounts WHERE email = %s AND activation_code = %s', (email, code,))
	account = cursor.fetchone()
	if account:
		# account exists, update the activation code to "activated"
		cursor.execute(
		    'UPDATE accounts SET activation_code = "activated" WHERE email = %s AND activation_code = %s', (email, code,))
		mysql.connection.commit()
		# automatically log the user in and redirect to the home page
		session['loggedin'] = True
		session['id'] = account['id']
		session['username'] = account['username']
		session['role'] = account['role']
		return redirect(url_for('home'))
	return render_template('activate.html', msg=msg)
		




# http://localhost:5000/profile - this will be the profile page, only accessible for loggedin users
@app.route('/profile')
def profile():
	# Check if user is loggedin
	if loggedin():
		# We need all the account info for the user so we can display it on the profile page
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
		account = cursor.fetchone()
		# Show the profile page with account info
		return render_template('profile.html', account=account, role=session['role'])
	# User is not loggedin redirect to login page
	return redirect(url_for('login'))

# http://localhost:5000/profile/edit - user can edit their existing details
@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
	# Check if user is loggedin
	if loggedin():
		# We need all the account info for the user so we can display it on the profile page
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		# Output message
		msg = ''
		# Check if "username", "password" and "email" POST requests exist (user submitted form)
		if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
			# Create variables for easy access
			username = request.form['username']
			password = request.form['password']
			email = request.form['email']
			# Retrieve account by the username
			cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
			account = cursor.fetchone()
			# validation check
			if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
				msg = 'Invalid email address!'
			elif not re.match(r'[A-Za-z0-9]+', username):
				msg = 'Username must contain only characters and numbers!'
			elif not username or not email:
				msg = 'Please fill out the form!'
			elif session['username'] != username and account:
				msg = 'Username already exists!'
			elif len(username) < 5 or len(username) > 20:
				flash('Password must be between 5 and 20 characters long.','warning')
				#return 'Username must be between 5 and 20 characters long!'
			elif len(password) < 5 or len(password) > 20:
				flash('Password must be between 5 and 20 characters long','warning')
				#return 'Password must be between 5 and 20 characters long!'
			else:
				cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
				account = cursor.fetchone()
				current_password = account['password']
				if password:
					# Hash the password
					hash = password + app.secret_key
					hash = hashlib.sha1(hash.encode())
					current_password = hash.hexdigest();
				# update account with the new details
				cursor.execute('UPDATE accounts SET username = %s, password = %s, email = %s WHERE id = %s',
				               (username, current_password, email, session['id'],))
				mysql.connection.commit()
				msg = 'Updated!'
		cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
		account = cursor.fetchone()
		# Show the profile page with account info
		app.logger.info("User " + session['username'] + " edited profile page." )
		return render_template('profile-edit.html', account=account, role=session['role'], msg=msg)
	return redirect(url_for('login'))

# http://localhost:5000/forgotpassword - user can use this page if they have forgotten their password
@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
	msg = ''
	if request.method == 'POST' and 'email' in request.form:
		email = request.form['email']
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
		account = cursor.fetchone()
		if account:
			# Generate unique ID
			reset_code = uuid.uuid4()
			# Update the reset column in the accounts table to reflect the generated ID
			cursor.execute(
			    'UPDATE accounts SET reset = %s WHERE email = %s', (reset_code, email,))
			mysql.connection.commit()
			# Change your_email@gmail.com
			email_info = Message(
			    'Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[email])
			# Generate reset password link
			reset_link = app.config['DOMAIN'] + \
			    url_for('resetpassword', email=email, code=str(reset_code))
			# change the email body below
			email_info.body = 'Please click the following link to reset your password: ' + \
			    str(reset_link)
			email_info.html = '<p>Please click the following link to reset your password: <a href="' + \
			    str(reset_link) + '">' + str(reset_link) + '</a></p>'
			mail.send(email_info)
			msg = 'Reset password link has been sent to your email!'
		else:
			msg = 'An account with that email does not exist!'
	return render_template('forgotpassword.html', msg=msg)

# http://localhost:5000/resetpassword/EMAIL/CODE - proceed to reset the user's password
@app.route('/resetpassword/<string:email>/<string:code>', methods=['GET', 'POST'])
def resetpassword(email, code):
	msg = ''
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Retrieve the account with the email and reset code provided from the GET request
	cursor.execute(
	    'SELECT * FROM accounts WHERE email = %s AND reset = %s', (email, code,))
	account = cursor.fetchone()
	# If account exists
	if account:
		# Check if the new password fields were submitted
		if request.method == 'POST' and 'npassword' in request.form and 'cpassword' in request.form:
			npassword = request.form['npassword']
			cpassword = request.form['cpassword']
			# Password fields must match
			if npassword == cpassword and npassword != "":
				# Hash new password
				hash = npassword + app.secret_key
				hash = hashlib.sha1(hash.encode())
				npassword = hash.hexdigest();
				# Update the user's password
				cursor.execute(
				    'UPDATE accounts SET password = %s, reset = "" WHERE email = %s', (npassword, email,))
				mysql.connection.commit()
				msg = 'Your password has been reset, you can now <a href="' + \
				    url_for('login') + '">login</a>!'
			else:
				msg = 'Passwords must match and must not be empty!'
		return render_template('resetpassword.html', msg=msg, email=email, code=code)
	return 'Invalid email and/or code!'

# http://localhost:5000/logout - this will be the logout page
@app.route('/logout')
def logout():
	# Remove session data, this will log the user out
	app.logger.info("User " + session['username'] + " logged-out." )
	session.pop('loggedin', None)
	session.pop('id', None)
	session.pop('username', None)
	session.pop('role', None)
	# Remove cookie data "remember me"
	resp = make_response(redirect(url_for('login')))
	resp.set_cookie('rememberme', expires=0)
	return resp

# Check if logged in function, update session if cookie for "remember me" exists


def loggedin():
	if 'loggedin' in session:
		return True
	elif 'rememberme' in request.cookies:
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		# check if remembered, cookie has to match the "rememberme" field
		cursor.execute('SELECT * FROM accounts WHERE rememberme = %s',
		               (request.cookies['rememberme'],))
		account = cursor.fetchone()
		if account:
			# update session variables
			session['loggedin'] = True
			session['id'] = account['id']
			session['username'] = account['username']
			session['role'] = account['role']
			return True
	# account not logged in return false
	return False



# Import the admin file
import admin
import helper_functions
import gnuproxy

if __name__ == '__main__':
	app.run()
	
