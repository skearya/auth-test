import { createServer } from "http";
import { readFile } from "fs/promises";
import {
    createApp,
    createRouter,
    defineEventHandler,
    readBody,
    sendRedirect,
    toNodeListener,
} from "h3";
import { hashPassword, verifyHash } from "./hash.js";
import { getPasswordHash, insertUser } from "./db.js";
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

        if (session && new Date().getTime() < session.expires) {
            message = `you are logged in as ${session.username}`;
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
            const passwordHash = getPasswordHash.get({
                username,
            })?.password_hash;

            const valid =
                passwordHash && (await verifyHash(passwordHash, password));

            if (valid) {
                createAndSetSession(event, username);
                return sendRedirect(event, "/");
            } else {
                message = "invalid username/password";
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
                insertUser.run({
                    username,
                    passwordHash: await hashPassword(password),
                });

                createAndSetSession(event, username);
                return sendRedirect(event, "/");
            } catch (error: any) {
                if (error?.code === "SQLITE_CONSTRAINT_PRIMARYKEY") {
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

router.post(
    "/logout",
    defineEventHandler((event) => {
        const session = useSession(event);

        if (session) {
            removeSession(event, session.id);
        }

        return sendRedirect(event, "/");
    })
);

createServer(toNodeListener(app)).listen(3021);
console.log("listening on http://localhost:3021");
