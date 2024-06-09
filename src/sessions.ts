import {
    H3Event,
    EventHandlerRequest,
    setCookie,
    getCookie,
    deleteCookie,
} from "h3";
import { deleteSession, getSession, insertSession } from "./db.js";

export function createAndSetSession(
    event: H3Event<EventHandlerRequest>,
    username: string
) {
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
}

export function removeSession(event: H3Event<EventHandlerRequest>, id: number) {
    deleteSession.run({ id });
    deleteCookie(event, "session");
}

export function useSession(event: H3Event<EventHandlerRequest>) {
    const sessionId = getCookie(event, "session");
    const session = sessionId && getSession.get({ id: parseInt(sessionId) });

    if (session) {
        if (new Date().getTime() < session.expires) {
            return session;
        } else {
            deleteCookie(event, "session");
        }
    }

    return undefined;
}
