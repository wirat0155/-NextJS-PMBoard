import type { NextApiRequest, NextApiResponse } from "next";
import bcrypt from 'bcrypt';
import { z } from "zod";
import { prisma } from "../../../lib/prisma";
import { registerLimiter } from '../../../lib/rateLimiter';
import { Prisma } from "@prisma/client";
import { RateLimiterRes } from "rate-limiter-flexible";
import { logger } from "../../../lib/logger";
import type { ApiErrorResponse } from "@/types/api";
import { v4 as uuidv4 } from "uuid";

const registerSchema = z.object({
    fullName: z.string().min(1, "Full name is required"),
    email: z.string().email("Invalid email"),
    password: z.string().min(8, "Password must be at least 8 characters"),
});

type RegisterRequest = z.infer<typeof registerSchema>;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
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
        await registerLimiter.consume(String(ip));

        // Validate input
        const parsed: RegisterRequest = registerSchema.parse(req.body);
        const { fullName, email, password } = parsed;

        // Hash password
        const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS) || 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Create user (atomic)
        const user = await prisma.users.create({
            data: {
                full_name: fullName,
                email,
                password_hash: passwordHash,
            },
        });
        
        // Return response
        return res.status(201)
                .json({
                    message: "User registered successfully",
                    user: {
                        id: user.user_id,
                        fullName: user.full_name,
                        email: user.email,
                        createdAt: user.created_at,
                    },
                });
    } catch (err: unknown){
        if (err instanceof z.ZodError) {
            const response: ApiErrorResponse = {
                message: "Invalid input",
                errors: err.issues,
                statusCode: 400
            };
            return res.status(400)
                    .json(response);
        }

        // Prisma error (unique constraint violation)
        if (err instanceof Prisma.PrismaClientKnownRequestError){
            if (err.code === "P2002") {
                const response: ApiErrorResponse = {
                    message: "Email already exists",
                    statusCode: 400
                };
                return res.status(400)
                    .json(response);
            }
        }

        if (err instanceof RateLimiterRes) {
            const retryAfter = Math.ceil(err.msBeforeNext / 1000); // in seconds
            res.setHeader("Retry-After", retryAfter.toString());
           
            const response: ApiErrorResponse = {
                message: "Too many requests",
                retryAfter,
                statusCode: 429
            };
            return res.status(429)
                    .json(response);
        }

        const logContext = {
            requestId,
            ip,
            route: "/api/register",
            method: req.method,
            statusCode: 500,
            request: {
                fullName: req.body?.fullName,
                email: req.body?.email,
            },
            err,
        };
        logger.error(logContext, "Registration error");
        const response: ApiErrorResponse = {
            message: "Internal server error",
            statusCode: 500
        }
        return res.status(500)
                    .json({ ...response, requestId });
    } finally {
        // Clean up Prisma connection in long-lived app if needs
        if (process.env.NODE_ENV !== "production") {
            await prisma.$disconnect();
        }
    }
}