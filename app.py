from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import paramiko
import os
from datetime import datetime
import json
import logging
from logging.handlers import RotatingFileHandler
from config import config

def create_app(config_name='default'):
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    # Setup logging
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/web_terminal.log',
                                         maxBytes=10240,
                                         backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            app.config['LOG_FORMAT']))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Web Terminal startup')

    # Initialize extensions
    mongo = PyMongo(app)
    socketio = SocketIO(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # User class for Flask-Login
    class User(UserMixin):
        def __init__(self, user_data):
            self.id = str(user_data['_id'])
            self.username = user_data['username']
            self.password_hash = user_data['password_hash']
            self.is_admin = user_data.get('is_admin', False)
            self.servers = user_data.get('servers', [])

        @staticmethod
        def get(user_id):
            user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            return User(user_data) if user_data else None

        @staticmethod
        def get_by_username(username):
            user_data = mongo.db.users.find_one({'username': username})
            return User(user_data) if user_data else None

    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)

    # Routes
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('terminal'))
        return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.get_by_username(username)
            
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                app.logger.info(f'User {username} logged in successfully')
                return redirect(url_for('terminal'))
            app.logger.warning(f'Failed login attempt for user {username}')
            flash('Invalid username or password')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        app.logger.info(f'User {current_user.username} logged out')
        logout_user()
        return redirect(url_for('index'))

    @app.route('/terminal')
    @login_required
    def terminal():
        user_servers = mongo.db.servers.find({'_id': {'$in': [ObjectId(sid) for sid in current_user.servers]}})
        servers = list(user_servers)
        return render_template('terminal.html', servers=servers)

    # WebSocket handlers
    @socketio.on('connect')
    def handle_connect():
        if not current_user.is_authenticated:
            return False

    @socketio.on('execute_command')
    def handle_command(data):
        if not current_user.is_authenticated:
            return
        
        server_id = data.get('server_id')
        command = data.get('command')
        
        server = mongo.db.servers.find_one({'_id': ObjectId(server_id)})
        if not server or str(server['_id']) not in current_user.servers:
            app.logger.warning(f'Unauthorized server access attempt by {current_user.username}')
            emit('error', {'message': 'Unauthorized access to server'})
            return
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if server.get('ssh_key'):
                key = paramiko.RSAKey(data=server['ssh_key'].encode())
                ssh.connect(server['ip'], 
                          port=server['port'], 
                          username=server['username'], 
                          pkey=key,
                          timeout=app.config['SSH_TIMEOUT'])
            else:
                ssh.connect(server['ip'], 
                          port=server['port'], 
                          username=server['username'], 
                          password=server['password'],
                          timeout=app.config['SSH_TIMEOUT'])
            
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            # Log the activity
            log = {
                'user_id': ObjectId(current_user.id),
                'server_id': ObjectId(server_id),
                'command': command,
                'output': output + error,
                'ip_address': request.remote_addr,
                'timestamp': datetime.utcnow()
            }
            mongo.db.activity_logs.insert_one(log)
            
            app.logger.info(f'Command executed by {current_user.username} on server {server["name"]}')
            
            emit('command_output', {
                'output': output,
                'error': error
            })
            
        except Exception as e:
            app.logger.error(f'Error executing command: {str(e)}')
            emit('error', {'message': str(e)})
        finally:
            ssh.close()

    def init_db():
        # Create indexes
        mongo.db.users.create_index('username', unique=True)
        mongo.db.servers.create_index('ip')
        mongo.db.activity_logs.create_index([('user_id', 1), ('timestamp', -1)])
        
        # Create admin user if not exists
        if not mongo.db.users.find_one({'username': 'admin'}):
            admin = {
                'username': 'admin',
                'password_hash': generate_password_hash('admin'),
                'is_admin': True,
                'servers': []
            }
            mongo.db.users.insert_one(admin)
            app.logger.info('Admin user created')

    # Initialize database
    with app.app_context():
        init_db()

    return app

if __name__ == '__main__':
    app = create_app(os.getenv('FLASK_ENV', 'development'))
    socketio.run(app, debug=app.config['DEBUG']) 