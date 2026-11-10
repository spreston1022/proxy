import { InboundPolicy, type ZuploContext, type ZuploRequest } from "@zuplo/runtime";

/**
 * Logs the client address the platform reports for the request, plus its ASN
 * and AS owner. Always passes the request through unchanged.
 */
export class LogClientIpInboundPolicy extends InboundPolicy {
  async handler(request: ZuploRequest, context: ZuploContext) {
    const { ip, asn, asOrganization } = context.incomingRequestProperties;
    context.log.info(
      {
        event: "client_ip",
        method: request.method,
        path: new URL(request.url).pathname,
        clientIp: ip,
        asn,
        asOrganization,
      },
      `Client IP ${ip ?? "unidentified"} (AS${asn ?? "?"} ${asOrganization ?? ""})`
    );
    return request;
  }
}
