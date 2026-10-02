import { eveChannel } from "eve/channels/eve";
import {
  localDev,
  type AuthFn,
  vercelOidc,
  extractBearerToken,
  withAuthChallenges,
} from "eve/channels/auth";
import { auth } from "@/lib/auth";

const betterAuthSession: AuthFn<Request> = async (request) => {
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session) return null;

  const attributes: Record<string, string> = {
    email: session.user.email,
    name: session.user.name,
  };
  if (session.user.image) {
    attributes.picture = session.user.image;
  }

  return {
    attributes,
    authenticator: "better-auth:vercel",
    principalId: session.user.id,
    principalType: "user",
  };
};

const apiKeyAuth: AuthFn<Request> = withAuthChallenges(
  (request) => {
    const expectedKey = process.env.BOT_API_KEY;
    if (!expectedKey) return null;

    const token = extractBearerToken(request.headers.get("authorization"));
    if (token && token === expectedKey) {
      return {
        attributes: {},
        authenticator: "api-key",
        principalId: "discord-bot",
        principalType: "service",
      };
    }
    return null;
  },
  [{ scheme: "Bearer" }]
);

export default eveChannel({
  auth: [betterAuthSession, apiKeyAuth, vercelOidc(), localDev()],
});
