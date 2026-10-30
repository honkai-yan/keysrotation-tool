use crate::crypto::Res;
use rusqlite::{Connection, params};
use std::io::Cursor;

#[derive(Clone)]
pub struct Entry {
    pub id: i64,
    pub desc: String,
    /// base64(nonce || ciphertext)
    pub content: String,
}

/// 内存中的 sqlite 数据库，从不落盘
pub struct Db {
    conn: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    desc TEXT NOT NULL,
    content TEXT NOT NULL
);";

impl Db {
    pub fn new_empty() -> Res<Db> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn })
    }

    pub fn from_bytes(bytes: &[u8]) -> Res<Db> {
        let mut conn = Connection::open_in_memory()?;
        conn.deserialize_read_exact("main", Cursor::new(bytes), bytes.len(), false)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn })
    }

    pub fn to_bytes(&mut self) -> Res<Vec<u8>> {
        Ok(self.conn.serialize("main")?.to_vec())
    }

    pub fn meta(&self, key: &str) -> Res<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Res<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn entries(&self) -> Res<Vec<Entry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, desc, content FROM entries ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(Entry {
                id: r.get(0)?,
                desc: r.get(1)?,
                content: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn insert(&self, desc: &str, content: &str) -> Res<i64> {
        self.conn.execute(
            "INSERT INTO entries (desc, content) VALUES (?1, ?2)",
            params![desc, content],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn update_desc(&self, id: i64, desc: &str) -> Res<()> {
        self.conn
            .execute("UPDATE entries SET desc = ?1 WHERE id = ?2", params![desc, id])?;
        Ok(())
    }

    pub fn update_content(&self, id: i64, content: &str) -> Res<()> {
        self.conn.execute(
            "UPDATE entries SET content = ?1 WHERE id = ?2",
            params![content, id],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: i64) -> Res<()> {
        self.conn
            .execute("DELETE FROM entries WHERE id = ?1", params![id])?;
        Ok(())
    }
}
