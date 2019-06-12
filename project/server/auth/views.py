# project/server/auth/views.py

from flask import Blueprint, request, redirect, session, url_for, render_template, make_response, jsonify
from flask.views import MethodView
from project.server import bcrypt, db
from project.server.models import User, BlacklistToken

auth_blueprint = Blueprint('auth', __name__)

class HomePage(MethodView):
	"""
	Application Home Page
	"""
	def get(self):
		return render_template('home.html')

class LandingPage(MethodView):
	"""
	Application Landing Page
	"""
	def get(self):
		return render_template('landing.html')

class LoginPage(MethodView):
	"""
	Application Login Page
	"""
	def get(self):
		return render_template('login.html')

class RegistrationPage(MethodView):
	"""
	Application Registration Page
	"""
	def get(self):
		return render_template('register.html')

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        if request.form:
        	post_data = {
				'email': request.form['email'],
				'password' : request.form['password']
			}
        else:
        	post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )

                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202

class LoginAPI(MethodView):
	"""
	User Login Resource
	"""
	def post(self):
		# get post data
		if request.form:
			post_data = {
				'email': request.form['email'],
				'password' : request.form['password']
			}
		else:
			post_data = request.get_json()
		try:
			# fetch the user data
			user = User.query.filter_by(
				email=post_data.get('email')
			).first()
			if user:
				if bcrypt.check_password_hash(user.password, post_data.get('password')):
					auth_token = user.encode_auth_token(user.id)
					if auth_token:
						responseObject = {
							'status' : 'success',
							'message' : 'Successfully logged in.',
							'auth_token' : auth_token.decode()
						}
						session['auth_token'] = responseObject['auth_token']
						session['headers'] = {"Authorization": "Bearer " + session['auth_token'], "Accept" : "application/json"}
						return render_template('home.html', data = responseObject)
				else:
					responseObject = {
						'status' : 'fail',
						'message' : 'Invalid password.'
					}
					return make_response(jsonify(responseObject)), 401
			else:
				responseObject = {
					'status' : 'fail',
					'message' : 'User does not exist.'
				}
				return make_response(jsonify(responseObject)), 404
		except Exception as e:
			print(e)
			responseObject = {
				'status' : 'fail',
				'message' : 'Try again'
			}
			return make_response(jsonify(responseObject)), 500

class UserAPI(MethodView):
	"""
	User Resource
	"""
	def get(self):
		#auth_header = request.headers.get('Authorization')
		auth_header = session['headers']['Authorization']
		if auth_header:
			try:
				auth_token = auth_header.split(" ")[1]
			except IndexError:
				responseObject = {
					'status': 'fail',
					'message': 'Bearer token malformed.'
				}
				return make_response(jsonify(responseObject)), 401
		else:
			auth_token = ''
		if auth_token:
			resp = User.decode_auth_token(auth_token)
			if not isinstance(resp, str):
				user = User.query.filter_by(id=resp).first()
				responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
				return render_template('home.html', data = responseObject)
			responseObject = {
				'status': 'fail',
				'message': resp
			}
			return make_response(jsonify(responseObject)), 401
		else:
			responseObject = {
				'status': 'fail',
				'message': 'Provide a valid auth token.'
			}
			return make_response(jsonify(responseObject)), 401

class LogoutAPI(MethodView):
	"""
	Logout Resource
	"""
	def post(self):
		# get auth token
		#auth_header = request.headers.get('Authorization')
		auth_header = session['headers']['Authorization']
		if auth_header:
			auth_token = auth_header.split(" ")[1]
		else:
			auth_token = ''
		if auth_token:
			resp = User.decode_auth_token(auth_token)
			if not isinstance(resp, str):
				# mark the token as blacklisted
				blacklist_token = BlacklistToken(token=auth_token)
				try:
					# insert the token
					db.session.add(blacklist_token)
					db.session.commit()
					responseObject = {
						'status': 'success',
						'message': 'Successfully logged out.'
					}
					return make_response(jsonify(responseObject)), 200
				except Exception as e:
					responseObject = {
						'status' : 'fail',
						'message': e
					}
					return make_response(jsonify(responseObject)), 200
			else:
				responseObject = {
					'status': 'fail',
					'message': resp
				}
				return make_response(jsonify(responseObject)), 401
		else:
			responseObject = {
				'status': 'fail',
				'message': 'Provide a valid auth token.'
			}
			return make_response(jsonify(responseObject)), 403

# define the API resources
landing_page_view = LandingPage.as_view('landing_page_view')
home_page_view = HomePage.as_view('home_page_view')
login_page_view = LoginPage.as_view('login_page_view')
registration_page_view = RegistrationPage.as_view('registration_page_view')

registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/',
    view_func=landing_page_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/home',
    view_func=home_page_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/login',
    view_func=login_page_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/register',
    view_func=registration_page_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
	'/auth/logout',
	view_func=logout_view,
	methods=['POST']
)