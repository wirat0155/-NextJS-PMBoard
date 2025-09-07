import type { NextApiRequest, NextApiResponse } from "next";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from "zod";
import { prisma } from "../../../lib/prisma";
import { PrismaClient } from "@prisma/client/extension";
import { RateLimiterRes } from "rate-limiter-flexible";
import { loginLimiter } from "../../../lib/rateLimiter";
import { logger } from "../../../lib/logger";
import { v4 as uuidv4 } from "uuid";
import type { ApiErrorResponse } from "@/types/api";
import { allowCors } from "@/lib/cors";
import { cookies } from "next/headers";
import cookie from "cookie";

// Schema validation
const loginSchema = z.object({
    email: z.string().email("Invalid email"),
    password: z.string().min(1, "Password is required"),
});

type LoginRequest = z.infer<typeof loginSchema>;

const SECRET_KEY = process.env.JWT_SECRET || 'supersecret';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    if (allowCors(req, res)) {
        return;
    }

    // Preflight
    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        res.setHeader("Allow", ["POST"]);
        return res.status(405)
                .json({ message: 'Method not allowed' });
    }
    
    const requestId = uuidv4();
    const forwarded = req.headers["x-forwarded-for"];
    const ip = Array.isArray(forwarded) ? forwarded[0] : forwarded?.split(",")[0] || req.socket.remoteAddress || "";


    try {
        // Rate limiting
        await loginLimiter.consume(String(ip));

        // Validate input
        const parsed: LoginRequest = loginSchema.parse(req.body);
        const { email, password } = parsed;

        // Find user
        const user = await prisma.users.findUnique({ where : { email } });
        if (!user || !user.is_active) {
            return res.status(401)
                .json({ message: 'Invalid credentials' })
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401)
                    .json({ message: 'Invalid credentials' })
        }

        // Generate JWT
        const token = jwt.sign({ userId: user.user_id, email: user.email, role: user.role }
            , SECRET_KEY, { expiresIn: '1h' }
        );

        // Set token in HttpOnly cookie
        res.setHeader("Set-Cookie", cookie.serialize("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 60 * 60,
            path: "/",
        }));

        return res.status(200)
                .json({
                    message: "Login successful",
                    user: {
                        id: user.user_id,
                        fullName: user.full_name,
                        email: user.email,
                        role: user.role
                    },
                });
    } catch (err: unknown) {
        if (err instanceof z.ZodError) {
            const response: ApiErrorResponse = {
                message: "Invalid input",
                errors: err.issues,
                statusCode: 400
            };
            return res.status(400)
                    .json(response);
        }

        if (err instanceof RateLimiterRes) {
            const retryAfter = Math.ceil(err.msBeforeNext / 1000);
            res.setHeader("Retry-After", retryAfter.toString());
            const response: ApiErrorResponse = {
                message: "Too many requests",
                retryAfter,
                statusCode: 429,
            };
            return res.status(429).json(response);
        }

        // Unexpected error
        const logContext = {
        requestId,
        ip,
        route: "/api/login",
        method: req.method,
        statusCode: 500,
        request: { email: req.body?.email },
        err,
        };
        logger.error(logContext, "Login error");

        const response: ApiErrorResponse = {
        message: "Internal server error",
        statusCode: 500,
        };
        return res.status(500).json({ ...response, requestId });
    } finally {
        if (process.env.NODE_ENV !== "production") {
            await prisma.$disconnect();
        }
    }
}