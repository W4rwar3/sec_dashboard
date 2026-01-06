
import sqlite3

def migrate_security():
    try:
        conn = sqlite3.connect('d:/vapt-security-dashboard-main/bran/vapt_dashboard.db')
        cursor = conn.cursor()
        
        # Check columns
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        
        updates = [
            ("failed_login_attempts", "INTEGER DEFAULT 0"),
            ("lockout_until", "DATETIME"),
            ("must_change_password", "BOOLEAN DEFAULT 1")
        ]
        
        for col, type_def in updates:
            if col not in columns:
                print(f"Adding {col}...")
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {type_def}")
            else:
                print(f"{col} already exists.")
                
        conn.commit()
        conn.close()
        print("Security migration successful.")
    except Exception as e:
        print(f"Migration error: {e}")

if __name__ == "__main__":
    migrate_security()
