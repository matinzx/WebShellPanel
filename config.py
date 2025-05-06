import os
from datetime import timedelta

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    DEBUG = False
    TESTING = False
    
    # MongoDB Configuration
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb://localhost:27017/web_terminal'
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # SSH Configuration
    SSH_TIMEOUT = 30  # seconds
    SSH_RETRY_COUNT = 3
    
    # Terminal Configuration
    TERMINAL_ROWS = 24
    TERMINAL_COLS = 80
    
    # Logging Configuration
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Security Configuration
    PASSWORD_MIN_LENGTH = 8
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True

class DevelopmentConfig(Config):
    DEBUG = True
    MONGO_URI = 'mongodb://localhost:27017/web_terminal_dev'
    LOG_LEVEL = 'DEBUG'

class TestingConfig(Config):
    TESTING = True
    MONGO_URI = 'mongodb://localhost:27017/web_terminal_test'
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    MONGO_URI = os.environ.get('MONGO_URI')
    LOG_LEVEL = 'WARNING'
    
    @classmethod
    def init_app(cls, app):
        # Production specific initialization
        pass

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 