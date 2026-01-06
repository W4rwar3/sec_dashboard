
import sqlite3

def migrate():
    try:
        conn = sqlite3.connect('d:/vapt-security-dashboard-main/bran/vapt_dashboard.db')
        cursor = conn.cursor()
        
        # Check if column exists
        cursor.execute("PRAGMA table_info(projects)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'is_draft' not in columns:
            print("Adding is_draft column...")
            cursor.execute("ALTER TABLE projects ADD COLUMN is_draft BOOLEAN DEFAULT 0")
            conn.commit()
            print("Migration successful.")
        else:
            print("Column header already exists.")
            
        conn.close()
    except Exception as e:
        print(f"Migration error: {e}")

if __name__ == "__main__":
    migrate()
