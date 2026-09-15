import { InboundPolicy, type ZuploContext, type ZuploRequest } from "@zuplo/runtime";

/**
 * Base64url-decodes a JWT's payload segment without verifying its signature.
 * The gateway does not enforce auth on this route, so claims are read
 * on a best-effort basis purely for logging/attribution.
 */
function decodeJwtClaims(token: string): Record<string, unknown> | undefined {
  const payload = token.split(".")[1];
  if (!payload) {
    return undefined;
  }
  try {
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return undefined;
  }
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

interface JsonRpcMessage {
  method?: string;
  params?: { name?: string; arguments?: unknown };
}

/** MCP batches can send an array of JSON-RPC messages in one request body. */
function extractToolCalls(
  body: unknown
): { tool: string; arguments: unknown }[] {
  const messages = Array.isArray(body) ? body : [body];
  const calls: { tool: string; arguments: unknown }[] = [];
  for (const message of messages) {
    const rpc = message as JsonRpcMessage;
    const toolName = stringClaim(rpc?.params?.name);
    if (rpc?.method === "tools/call" && toolName) {
      calls.push({ tool: toolName, arguments: rpc.params?.arguments });
    }
  }
  return calls;
}

/**
 * Logs the calling app/user/email (from an unverified bearer JWT, since this
 * route runs with no auth enforcement) plus, for `tools/call` messages, the
 * tool name and arguments. Always passes the request through unchanged.
 */
export class LogMcpCallInboundPolicy extends InboundPolicy {
  async handler(request: ZuploRequest, context: ZuploContext) {
    const bearer = request.headers.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
    const claims = bearer ? decodeJwtClaims(bearer) : undefined;

    const appClientId = stringClaim(claims?.client_id) ?? stringClaim(claims?.azp) ?? stringClaim(claims?.cid);
    const userSub = stringClaim(claims?.sub);
    const userEmail = stringClaim(claims?.email);

    context.log.setLogProperties?.({
      mcpAppClientId: appClientId ?? "unknown",
      mcpUserSub: userSub ?? "unknown",
      mcpUserEmail: userEmail ?? "unknown",
    });

    const body = await request
      .clone()
      .json()
      .catch(() => undefined);
    const toolCalls = body === undefined ? [] : extractToolCalls(body);

    if (toolCalls.length > 0) {
      for (const call of toolCalls) {
        context.log.info(
          {
            event: "mcp_tool_call",
            tool: call.tool,
            arguments: call.arguments,
            appClientId,
            userSub,
            userEmail,
          },
          `MCP tool call: ${call.tool}`
        );
      }
    } else {
      context.log.info(
        {
          event: "mcp_request",
          method: request.method,
          rpcMethod: (body as JsonRpcMessage | undefined)?.method,
          appClientId,
          userSub,
          userEmail,
        },
        `MCP request: ${request.method}`
      );
    }

    return request;
  }
}
