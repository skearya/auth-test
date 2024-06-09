import Database from "better-sqlite3";

export const db = new Database("./db.sqlite");

db.exec(
    `CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )`
);

db.exec(
    `CREATE TABLE IF NOT EXISTS sessions(
        id INTEGER PRIMARY KEY,
        expires INTEGER NOT NULL,
        username TEXT NOT NULL,
        FOREIGN KEY (username)
            REFERENCES users (username)
    )`
);

export const getSession = db.prepare<
    { id: number },
    {
        id: number;
        expires: number;
        username: string;
    }
>(`SELECT * FROM sessions WHERE id IS :id`);

export const insertSession = db.prepare<{
    id: number;
    expires: number;
    username: string;
}>(
    `INSERT INTO sessions (id, expires, username) VALUES (:id, :expires, :username)`
);

export const deleteSession = db.prepare<{ id: number }>(
    `DELETE from sessions WHERE id = :id`
);

export const getPasswordHash = db.prepare<
    { username: string },
    { password_hash: string }
>(`SELECT password_hash FROM users WHERE username IS :username`);

export const insertUser = db.prepare<{
    username: string;
    passwordHash: string;
}>(
    `INSERT INTO users (username, password_hash) VALUES (:username, :passwordHash)`
);
