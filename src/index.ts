import Database, { SqliteError } from "better-sqlite3";
import { readFile } from "fs/promises";
import {
    createApp,
    createRouter,
    defineEventHandler,
    deleteCookie,
    getCookie,
    readBody,
    sendRedirect,
    setCookie,
    toNodeListener,
} from "h3";
import { createServer } from "http";
import { hashPassword } from "./hash.js";

const db = new Database("./db.sqlite");

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

const insertSession = db.prepare(
    `INSERT INTO sessions (id, expires, username) VALUES (:id, :expires, :username)`
);
const getSession = db.prepare(`SELECT * FROM sessions WHERE id IS :id`);

const insertUser = db.prepare(
    `INSERT INTO users (username, password_hash) VALUES (:username, :passwordHash)`
);
const getPasswordHash = db.prepare(
    `SELECT password_hash FROM users WHERE username IS :username`
);

const app = createApp();
const router = createRouter();
app.use(router);

const html = (name: string) => {
    return readFile(`./src/templates/${name}.html`, {
        encoding: "utf8",
    });
};

router.get(
    "/",
    defineEventHandler(async (event) => {
        const sessionId = getCookie(event, "session");
        const session = sessionId && (getSession.get({ id: sessionId }) as any);
        let message: string;

        if (session && new Date().getTime() < session.expires) {
            message = `you are logged in as ${session.username}`;
        } else {
            deleteCookie(event, "session");
            message = "you are not logged in";
        }

        const page = await html("root");
        return page.replace("<!-- message -->", `<h2>${message}</h2>`);
    })
);

router.get(
    "/sign-up",
    defineEventHandler(() => html("sign-up"))
);

router.post(
    "/sign-up",
    defineEventHandler(async (event) => {
        const { username, password } = await readBody(event);

        let message: string;

        if (!username || !password) {
            message = "missing username or password";
        } else {
            try {
                insertUser.run({
                    username,
                    passwordHash: await hashPassword(password),
                });

                const sessionId = crypto.getRandomValues(new Uint32Array(1))[0];
                const expires = new Date();
                expires.setDate(expires.getDate() + 30);

                insertSession.run({
                    id: sessionId,
                    expires: expires.getTime(),
                    username,
                });

                setCookie(event, "session", sessionId.toString(), {
                    httpOnly: true,
                    maxAge: 60 * 60 * 24 * 30,
                    sameSite: "lax",
                    path: "/",
                });

                return sendRedirect(event, "/");
            } catch (error: unknown) {
                if (
                    error instanceof SqliteError &&
                    error.code === "SQLITE_CONSTRAINT_PRIMARYKEY"
                ) {
                    message = "there's already someone with that username";
                } else {
                    message = "something went wrong";
                }
            }
        }

        const page = await html("sign-up");
        return page.replace("<!-- error message -->", `<h1>${message}</h1>`);
    })
);

createServer(toNodeListener(app)).listen(3021);
console.log("listening on http://localhost:3021");
