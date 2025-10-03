import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DATABASE = os.getenv("DB_DATABASE")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM","HS512")
ENV = os.getenv("ENV", "dev")

# Cookie settings
ACCESS_COOKIE_NAME = "jwt_cookie"
COOKIE_HTTP_ONLY = True  
COOKIE_SECURE = True if ENV == "prod" else False
COOKIE_SAMESITE = "strict" if ENV == "prod" else "lax"

# Database URL
if ENV == "prod":
    DATABASE_URL = (
        f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_DATABASE}"
        f"?ssl_ca=/etc/ssl/certs/ca-cert.pem"
    )
else:
    DATABASE_URL = (
        f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_DATABASE}"
        "?ssl_verify_cert=false&ssl_verify_identity=false"
    )
