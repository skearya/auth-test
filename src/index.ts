import "dotenv/config";
import { createServer } from "http";
import { readFile, stat } from "fs/promises";
import {
    createApp,
    createError,
    createRouter,
    defineEventHandler,
    getCookie,
    getQuery,
    readBody,
    sendRedirect,
    serveStatic,
    setCookie,
    toNodeListener,
} from "h3";
import { hashPassword, verifyHash } from "./hash.js";
import {
    Session,
    deleteOauthSignupSession,
    getOauthAccount,
    getOauthSignupSession,
    getUser,
    getUserByUsername,
    insertOauthAccount,
    insertOauthSignupSession,
    insertUser,
} from "./db.js";
import { createAndSetSession, removeSession, useSession } from "./sessions.js";
import { join } from "path";

const html = async (session: Session | undefined, name: string) => {
    const layout = await readFile(`./src/templates/layout.html`, {
        encoding: "utf8",
    });

    return layout
        .replace(
            `<!-- title -->`,
            name === "index" ? "auth test" : name.replaceAll("-", " ")
        )
        .replace(
            `<!-- sign in/up -->`,
            session
                ? `<form action="/logout" method="post" class="inline"><button>logout</button></form>`
                : `<a href="/sign-in">sign in</a><a href="/sign-up">sign up</a>`
        )
        .replace(
            `<!-- slot -->`,
            await readFile(`./src/templates/${name}.html`, {
                encoding: "utf8",
            })
        );
};

const app = createApp();
const router = createRouter();

app.use(
    defineEventHandler((event) => {
        event.context.session = useSession(event);
    })
);

app.use(router);

app.use(
    defineEventHandler((event) => {
        return serveStatic(event, {
            getContents: (id) => readFile(join("public", id)),
            getMeta: async (id) => {
                const stats = await stat(join("public", id)).catch(() => {});

                if (!stats || !stats.isFile()) {
                    return;
                }

                return {
                    size: stats.size,
                    mtime: stats.mtimeMs,
                };
            },
        });
    })
);

router.get(
    "/",
    defineEventHandler(async (event) => {
        const session: Session | undefined = event.context.session;

        const username =
            session && getUser.get({ user_id: session.user_id })?.username;

        const page = await html(session, "index");
        return page.replace(
            "<!-- message -->",
            `<h2>${
                username
                    ? `you are logged in as "${username}"`
                    : "you are not logged in"
            }</h2>`
        );
    })
);

router.get(
    "/sign-in",
    defineEventHandler((event) => {
        const session: Session | undefined = event.context.session;

        if (session) {
            return sendRedirect(event, "/");
        }

        return html(session, "sign-in");
    })
);

router.post(
    "/sign-in",
    defineEventHandler(async (event) => {
        const session: Session | undefined = event.context.session;

        if (session) {
            return sendRedirect(event, "/");
        }

        const { username, password } = await readBody(event);

        if (!username || !password) {
            throw createError({
                status: 404,
                statusMessage: "Bad request",
            });
        }

        const user = getUserByUsername.get({
            username,
        });

        if (user) {
            const valid =
                user.password_hash &&
                (await verifyHash(user.password_hash, password));

            if (valid) {
                createAndSetSession(event, user.user_id);
                return sendRedirect(event, "/");
            }
        }

        const page = await html(session, "sign-in");
        return page.replace(
            "<!-- error message -->",
            `<h1>invalid username/password</h1>`
        );
    })
);

router.get(
    "/sign-up",
    defineEventHandler((event) => {
        const session: Session | undefined = event.context.session;

        if (session) {
            return sendRedirect(event, "/");
        }

        return html(session, "sign-up");
    })
);

router.post(
    "/sign-up",
    defineEventHandler(async (event) => {
        const session: Session | undefined = event.context.session;

        if (session) {
            return sendRedirect(event, "/");
        }

        const { username, password } = await readBody(event);

        if (!username || !password) {
            throw createError({
                status: 404,
                statusMessage: "Bad request",
            });
        }

        try {
            const userId = crypto.randomUUID();

            insertUser.run({
                user_id: userId,
                username,
                password_hash: await hashPassword(password),
                avatar_url: undefined,
            });

            createAndSetSession(event, userId);
            return sendRedirect(event, "/");
        } catch (error: any) {
            const page = await html(session, "sign-up");
            return page.replace(
                "<!-- error message -->",
                `<h1>${
                    error?.code === "SQLITE_CONSTRAINT_UNIQUE"
                        ? "there's already someone with that username"
                        : "something went wrong"
                }</h1>`
            );
        }
    })
);

router.get(
    "/github-sign-in",
    defineEventHandler((event) => {
        const session: Session | undefined = event.context.session;

        if (session) {
            return sendRedirect(event, "/");
        }

        const state = crypto.randomUUID();

        setCookie(event, "state", state, {
            path: "/",
            maxAge: 60 * 10,
        });

        return sendRedirect(
            event,
            `https://github.com/login/oauth/authorize?` +
                new URLSearchParams({
                    client_id: process.env.GITHUB_CLIENT_ID!,
                    state,
                })
        );
    })
);

router.get(
    "/github-callback",
    defineEventHandler(async (event) => {
        const { code, state } = getQuery(event);

        const storedState = getCookie(event, "state");

        if (!code || !state || !storedState || state !== storedState) {
            return html(event.context.session, "oauth-error");
        }

        try {
            const accessToken = await fetch(
                "https://github.com/login/oauth/access_token?" +
                    new URLSearchParams({
                        client_id: process.env.GITHUB_CLIENT_ID!,
                        client_secret: process.env.GITHUB_CLIENT_SECRET!,
                        code: code as string,
                    }),
                {
                    headers: {
                        Accept: "application/json",
                    },
                }
            )
                .then((res) => res.json())
                .then((json) => json.access_token);

            const githubUser = await fetch("https://api.github.com/user", {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            }).then((res) => res.json());

            const existingAccount = getOauthAccount.get({
                provider_user_id: githubUser.id,
            });

            if (existingAccount) {
                createAndSetSession(event, existingAccount.user_id);
                return sendRedirect(event, "/");
            } else {
                const signupSessionId = crypto.randomUUID();

                insertOauthSignupSession.run({
                    session_id: signupSessionId,
                    expires: new Date(Date.now() + 60 * 60 * 1000).getTime(), // 1 hour from now
                    provider_name: "github",
                    access_token: accessToken,
                });

                setCookie(event, "signup_session", signupSessionId, {
                    path: "/",
                    maxAge: 60 * 60,
                });

                return sendRedirect(event, "/choose-username");
            }
        } catch {
            return html(event.context.session, "oauth-error");
        }
    })
);

router.get(
    "/choose-username",
    defineEventHandler((event) =>
        html(event.context.session, "choose-username")
    )
);

router.post(
    "/choose-username",
    defineEventHandler(async (event) => {
        const { username } = await readBody(event);

        const signupSessionId = getCookie(event, "signup_session");

        if (!username || !signupSessionId) {
            throw createError({
                status: 404,
                statusMessage: "Bad request",
            });
        }

        try {
            const signupSession = getOauthSignupSession.get({
                session_id: signupSessionId,
            });

            if (
                !signupSession ||
                new Date().getTime() > signupSession.expires
            ) {
                throw new Error("No signup session");
            }

            const githubUser = await fetch("https://api.github.com/user", {
                headers: {
                    Authorization: `Bearer ${signupSession.access_token}`,
                },
            }).then((res) => res.json());

            const userId = crypto.randomUUID();

            insertUser.run({
                user_id: userId,
                username,
                avatar_url: githubUser.avatar_url,
                password_hash: undefined,
            });
            insertOauthAccount.run({
                provider_name: "github",
                provider_user_id: githubUser.id,
                user_id: userId,
            });
            deleteOauthSignupSession.run({
                session_id: signupSessionId,
            });

            createAndSetSession(event, userId);
            return sendRedirect(event, "/");
        } catch (error: any) {
            const page = await html(event.context.session, "choose-username");
            return page.replace(
                "<!-- error message -->",
                `<h1>${
                    error?.code === "SQLITE_CONSTRAINT_UNIQUE"
                        ? "there's already someone with that username"
                        : "something went wrong, please try signing in again"
                }</h1>`
            );
        }
    })
);

router.post(
    "/logout",
    defineEventHandler((event) => {
        const session: Session | undefined = event.context.session;

        if (session) {
            removeSession(event, session.session_id);
        }

        return sendRedirect(event, "/");
    })
);

createServer(toNodeListener(app)).listen(3021);
console.log("listening on http://localhost:3021");
