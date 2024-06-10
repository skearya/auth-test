import "dotenv/config";
import { createServer } from "http";
import { readFile } from "fs/promises";
import {
    createApp,
    createError,
    createRouter,
    defineEventHandler,
    getCookie,
    getQuery,
    readBody,
    sendRedirect,
    setCookie,
    toNodeListener,
} from "h3";
import { hashPassword, verifyHash } from "./hash.js";
import {
    getOauthAccount,
    getUser,
    getUserByUsername,
    insertOauthAccount,
    insertUser,
} from "./db.js";
import { createAndSetSession, removeSession, useSession } from "./sessions.js";

const app = createApp();
const router = createRouter();
app.use(router);

const html = async (name: string) => {
    const layout = await readFile(`./src/templates/layout.html`, {
        encoding: "utf8",
    });

    return layout
        .replace(
            `<!-- title -->`,
            name === "index" ? "auth test" : name.replaceAll("-", " ")
        )
        .replace(
            `<!-- slot -->`,
            await readFile(`./src/templates/${name}.html`, {
                encoding: "utf8",
            })
        );
};

router.get(
    "/",
    defineEventHandler(async (event) => {
        const session = useSession(event);

        let message: string;

        if (session) {
            const user = getUser.get({ user_id: session.user_id });
            message = `you are logged in as ${user?.username}`;
        } else {
            message = "you are not logged in";
        }

        const page = await html("index");
        return page.replace("<!-- message -->", `<h2>${message}</h2>`);
    })
);

router.get(
    "/sign-in",
    defineEventHandler((event) => {
        const session = useSession(event);

        if (session) {
            return sendRedirect(event, "/");
        }

        return html("sign-in");
    })
);

router.post(
    "/sign-in",
    defineEventHandler(async (event) => {
        const session = useSession(event);

        if (session) {
            return sendRedirect(event, "/");
        }

        const { username, password } = await readBody(event);

        let message: string;

        if (!username || !password) {
            message = "missing username or password";
        } else {
            const user = getUserByUsername.get({
                username,
            });

            if (!user) {
                message = "invalid username/password";
            } else {
                const valid =
                    user?.password_hash &&
                    (await verifyHash(user.password_hash, password));

                if (valid) {
                    createAndSetSession(event, user.user_id);
                    return sendRedirect(event, "/");
                } else {
                    message = "invalid username/password";
                }
            }
        }

        const page = await html("sign-in");
        return page.replace("<!-- error message -->", `<h1>${message}</h1>`);
    })
);

router.get(
    "/sign-up",
    defineEventHandler((event) => {
        const session = useSession(event);

        if (session) {
            return sendRedirect(event, "/");
        }

        return html("sign-up");
    })
);

router.post(
    "/sign-up",
    defineEventHandler(async (event) => {
        const session = useSession(event);

        if (session) {
            return sendRedirect(event, "/");
        }

        const { username, password } = await readBody(event);

        let message: string;

        if (!username || !password) {
            message = "missing username or password";
        } else {
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
                if (error?.code === "SQLITE_CONSTRAINT_UNIQUE") {
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

router.get(
    "/github-sign-in",
    defineEventHandler((event) => {
        const session = useSession(event);

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
            throw createError({
                status: 404,
                statusMessage: "Bad request",
            });
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
            ).then((res) => res.json());

            const githubUser = await fetch("https://api.github.com/user", {
                headers: {
                    Authorization: `Bearer ${accessToken.access_token}`,
                },
            }).then((res) => res.json());

            const existingAccount = getOauthAccount.get({
                provider_user_id: githubUser.id,
            });

            if (existingAccount) {
                createAndSetSession(event, existingAccount.user_id);
                return sendRedirect(event, "/");
            } else {
                const userId = crypto.randomUUID();

                insertUser.run({
                    user_id: userId,
                    username: githubUser.login,
                    avatar_url: githubUser.avatar_url,
                    password_hash: undefined,
                });

                insertOauthAccount.run({
                    provider_name: "github",
                    provider_user_id: githubUser.id,
                    user_id: userId,
                });

                createAndSetSession(event, userId);
                return sendRedirect(event, "/");
            }
        } catch (error) {
            console.error(error);
            throw createError({
                status: 500,
                statusMessage: "Something went wrong",
            });
        }
    })
);

router.post(
    "/logout",
    defineEventHandler((event) => {
        const session = useSession(event);

        if (session) {
            removeSession(event, session.session_id);
        }

        return sendRedirect(event, "/");
    })
);

createServer(toNodeListener(app)).listen(3021);
console.log("listening on http://localhost:3021");
