import { createContext, type ReactNode, useContext, useEffect, useState } from "react";
import { ApiError, api, type MeResponse, type SessionResponse } from "./api";
import { signOutIdentity } from "./identity";

type SessionStatus = "loading" | "ready" | "error";

interface SessionContextValue {
  status: SessionStatus;
  me: MeResponse | null;
  error: string;
  refresh: () => Promise<MeResponse>;
  accept: (session: SessionResponse | MeResponse) => void;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue | null>(null);
const anonymous: MeResponse = { authenticated: false, session_kind: "ANONYMOUS", user_id: null, role: null, role_request: null };

function normalizedSession(session: SessionResponse | MeResponse): MeResponse {
  const authenticated = Boolean(session.authenticated || session.user_id);
  return {
    ...session,
    authenticated,
    session_kind: session.session_kind ?? (authenticated ? "USER" : "ANONYMOUS"),
    role: authenticated ? session.role : null,
  };
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SessionStatus>("loading");
  const [me, setMe] = useState<MeResponse | null>(null);
  const [error, setError] = useState("");

  async function refresh() {
    setStatus("loading");
    setError("");
    try {
      const next = await api.me();
      setMe(normalizedSession(next));
      setStatus("ready");
      return next;
    } catch (reason) {
      setMe(null);
      setStatus("error");
      setError(reason instanceof ApiError ? reason.message : "Your session could not be checked.");
      throw reason;
    }
  }

  useEffect(() => {
    refresh().catch(() => undefined);
  }, []);

  function accept(session: SessionResponse | MeResponse) {
    setMe(normalizedSession({ ...session, authenticated: true, session_kind: "USER" }));
    setStatus("ready");
    setError("");
  }

  async function signOut() {
    try {
      await signOutIdentity();
    } finally {
      setMe(anonymous);
      setStatus("ready");
      setError("");
    }
  }

  return <SessionContext.Provider value={{ status, me, error, refresh, accept, signOut }}>{children}</SessionContext.Provider>;
}

export function useSession() {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}
