import argon2 from "argon2";

const secret = Buffer.from(process.env.HASH_SECRET!);

export function hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
        type: argon2.argon2d,
        secret,
        parallelism: 1,
        memoryCost: 19456,
        timeCost: 2,
    });
}

export function verifyHash(hash: string, password: string): Promise<boolean> {
    return argon2.verify(hash, password, {
        secret,
    });
}
