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
    userId: string
) {
    const sessionId = crypto.randomUUID();
    const expires = new Date();
    expires.setDate(expires.getDate() + 30);

    insertSession.run({
        session_id: sessionId,
        expires: expires.getTime(),
        user_id: userId,
    });

    setCookie(event, "session", sessionId, {
        httpOnly: true,
        maxAge: 60 * 60 * 24 * 30,
        sameSite: "lax",
        path: "/",
    });
}

export function removeSession(
    event: H3Event<EventHandlerRequest>,
    sessionId: string
) {
    deleteSession.run({ session_id: sessionId });
    deleteCookie(event, "session");
}

export function useSession(event: H3Event<EventHandlerRequest>) {
    const sessionId = getCookie(event, "session");

    if (sessionId) {
        const session = getSession.get({ session_id: sessionId });

        if (session && new Date().getTime() < session.expires) {
            return session;
        }

        deleteCookie(event, "session");
    }

    return undefined;
}
