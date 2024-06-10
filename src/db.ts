import Database from "better-sqlite3";

export const db = new Database("./db.sqlite");

db.exec(
    `CREATE TABLE IF NOT EXISTS users(
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        avatar_url TEXT
    )`
);

db.exec(
    `CREATE TABLE IF NOT EXISTS oauth_accounts(
        provider_name TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (provider_name, provider_user_id),
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )`
);

db.exec(
    `CREATE TABLE IF NOT EXISTS sessions(
        session_id TEXT PRIMARY KEY,
        expires INTEGER NOT NULL,
        user_id TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (user_id)
    )`
);

type User = {
    user_id: string;
    username: string;
    password_hash: string | undefined;
    avatar_url: string | undefined;
};

type OauthAccount = {
    provider_name: string;
    provider_user_id: string;
    user_id: string;
};

type Session = {
    session_id: string;
    expires: number;
    user_id: string;
};

// users

export const getUser = db.prepare<Pick<User, "user_id">, User>(
    `SELECT * FROM users WHERE user_id IS :user_id`
);

export const getUserByUsername = db.prepare<Pick<User, "username">, User>(
    `SELECT * FROM users WHERE username IS :username`
);

export const insertUser = db.prepare<User>(
    `INSERT INTO users (user_id, username, password_hash, avatar_url) VALUES (:user_id, :username, :password_hash, :avatar_url)`
);

// oauth accounts

export const getOauthAccount = db.prepare<
    Pick<OauthAccount, "provider_user_id">,
    OauthAccount
>(`
    SELECT * from oauth_accounts WHERE provider_user_id IS :provider_user_id
`);

export const insertOauthAccount = db.prepare<OauthAccount>(
    `INSERT INTO oauth_accounts (provider_name, provider_user_id, user_id) VALUES (:provider_name, :provider_user_id, :user_id)`
);

// sessions

export const getSession = db.prepare<Pick<Session, "session_id">, Session>(
    `SELECT * FROM sessions WHERE session_id IS :session_id`
);

export const insertSession = db.prepare<Session>(
    `INSERT INTO sessions (session_id, expires, user_id) VALUES (:session_id, :expires, :user_id)`
);

export const deleteSession = db.prepare<Pick<Session, "session_id">>(
    `DELETE from sessions WHERE session_id = :session_id`
);
