from sqlalchemy import create_engine, text
import os

db_connection_string = os.environ['DB_CONNECTION_STRING']
engine = create_engine(db_connection_string)

"""
engine = create_engine(db_connection_string,
                       connect_args={"ssl": {
                         "ssl_ca": "/etc/ssl/cert.pem"
                       }})
"""
def login_from_db(username):
  with engine.connect() as conn:
    query = "SELECT * FROM info WHERE username = '" + username + "'"
    result = conn.execute(text(query))
    rows = result.all()
    info = []
    for row in rows:
      info.append(row._mapping)
    if len(rows) == 0:
      return None
    else:
      return info
