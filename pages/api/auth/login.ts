import type { NextApiRequest, NextApiResponse } from "next";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { PrismaClient } from "@prisma/client/extension";

const prisma = new PrismaClient();
const SECRET_KEY = process.env.JWT_SECRET || 'supersecre';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    if (req.method !== 'POST') {
        return res.status(405)
                .json({ message: 'Method not allowed' });
    }

    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400)
                .json({ message: 'Missing fields' });
    }

    const user  = await prisma.users.findUnique({ where: { email } });
    if (!user || !user.is_active) {
        return res.status(401)
                .json({ message: 'Invalid credentials' })
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
        return res.status(401)
                .json({ message: 'Invalid credentials' })
    }

    const token = jwt.sign({ userId: user.user_id, email: user.email, role: user.role }
        , SECRET_KEY, { expiresIn: '1h' }
    );

    res.status(200)
        .json({ token })
}