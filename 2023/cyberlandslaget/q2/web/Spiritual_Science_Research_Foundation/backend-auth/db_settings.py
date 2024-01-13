import os
def get_db_url():
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", 5432)
    db = "db"
    url = f"postgresql://{user}:{password}@{host}:{port}/{db}"
    if not (user or password or host or port):
        raise Exception
    return url