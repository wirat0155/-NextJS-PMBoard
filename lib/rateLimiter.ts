import { RateLimiterMemory } from "rate-limiter-flexible";

const createLimiter = (points: number, duration: number) => 
    new RateLimiterMemory({points, duration});

export const registerLimiter = createLimiter(10, 60);
export const loginLimiter = createLimiter(10, 60)