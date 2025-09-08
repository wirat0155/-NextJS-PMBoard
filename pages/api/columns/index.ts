import { allowCors } from "@/lib/cors";
import type { NextApiRequest, NextApiResponse } from "next";
import { describe } from "node:test";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { prisma } from "../../../lib/prisma";
import { create } from "domain";


const boardSchema = z.object({
    title: z.string().min(1, "Board title is required"),
    description: z.string().optional(),
    workspaceId: z.string().uuid(),
    ownerId: z.string().uuid(),
});

type BoardRequest = z.infer<typeof boardSchema>

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    if (allowCors(req, res)) {
        return;
    }

    if (req.method === "OPTIONS") {
        return res.status(200).end();
    }

    const { boardId } = req.query; // GET/PUT/DELETE: /pages/api/boards?boardId=xxx
    const requestId = uuidv4();

    try {
        switch (req.method) {
            // CREATE
            case "POST": {
                const parsed: BoardRequest = boardSchema.parse(req.body);
                const { title, description, workspaceId, ownerId } = parsed;
                
                const board = await prisma.boards.create({
                    data: {
                        board_id: uuidv4(),
                        workspace_id: workspaceId,
                        title,
                        description,
                        owner_id: ownerId,
                        is_active: true,
                        created_at: new Date(),
                    },
                });

                return res.status(201)
                    .json({
                        message: "Board created successfully",
                        board: {
                            id: board.board_id,
                            title: board.title,
                            description: board.description,
                            workspaceId: board.workspace_id,
                            ownerId: board.owner_id,
                            createdAt: board.created_at
                        }
                    });
            }
        }
    }
}