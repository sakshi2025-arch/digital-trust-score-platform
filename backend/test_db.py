import os
from pathlib import Path

import pymysql
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

try:
    connection = pymysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3307")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "digital_trust_score"),
        connect_timeout=5,
    )

    print("SUCCESS: MySQL connection established!")

    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE()")
        print("Connected database:", cursor.fetchone()[0])

    connection.close()

except Exception as error:
    print("MySQL connection failed.")
    print("Error:", error)