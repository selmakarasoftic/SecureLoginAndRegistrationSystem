import { Request } from "express";
import { db } from "../config/database";

export interface AuditLogInput {
  action: string;
  actorId?: number | null;
  actorRole?: string | null;
  object?: string | null;
  objectId?: string | number | null;
  originalObject?: unknown;
  requestData?: unknown;
  req?: Request;
  ipAddress?: string | null;
  userAgent?: string | null;
}

export async function auditLog(input: AuditLogInput): Promise<void> {
  const ipAddress = input.ipAddress ?? input.req?.ip ?? null;
  const userAgent =
    input.userAgent ?? input.req?.headers["user-agent"] ?? null;

  const originalObject =
    input.originalObject == null ? null : JSON.stringify(input.originalObject);

  const requestData =
    input.requestData == null ? null : JSON.stringify(input.requestData);

  try {
    await db.execute(
      `INSERT INTO audit_logs
       (actor_id, actor_role, action, object, object_id, original_object,
        request_data, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        input.actorId ?? null,
        input.actorRole ?? null,
        input.action,
        input.object ?? null,
        input.objectId == null ? null : String(input.objectId),
        originalObject,
        requestData,
        ipAddress,
        userAgent,
      ]
    );
  } catch (err) {
    console.error("auditLog: failed to write audit log", {
      action: input.action,
      error: err,
    });
  }
}