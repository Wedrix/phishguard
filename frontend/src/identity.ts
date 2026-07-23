import type { MultiFactorResolver, TotpSecret } from "firebase/auth";
import { api, type RequestedRole } from "./api";

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
};

let pendingResolver: MultiFactorResolver | null = null;
let pendingRequestedRole: RequestedRole | undefined;
let pendingReauthResolver: MultiFactorResolver | null = null;
let pendingSecret: TotpSecret | null = null;

export class IdentityError extends Error {
  constructor(message: string, public code = "identity_failed") {
    super(message);
  }
}

export function identityConfigured() {
  return Boolean(firebaseConfig.apiKey && firebaseConfig.authDomain && firebaseConfig.projectId);
}

async function configuredAuth() {
  if (!identityConfigured()) {
    throw new IdentityError("Identity Platform is not configured for this build.", "identity_not_configured");
  }
  const [{ getApp, getApps, initializeApp }, { getAuth }] = await Promise.all([
    import("firebase/app"),
    import("firebase/auth"),
  ]);
  const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
  return getAuth(app);
}

async function exchangeCredential(
  user: { getIdToken(forceRefresh?: boolean): Promise<string> },
  requestedRole?: RequestedRole,
) {
  return api.exchangeSession(await user.getIdToken(true), requestedRole);
}

export async function beginPasswordSignIn(email: string, password: string, requestedRole?: RequestedRole) {
  const auth = await configuredAuth();
  const { getMultiFactorResolver, signInWithEmailAndPassword, TotpMultiFactorGenerator } = await import("firebase/auth");
  try {
    const credential = await signInWithEmailAndPassword(auth, email, password);
    const session = await exchangeCredential(credential.user, requestedRole);
    pendingRequestedRole = undefined;
    return { mfaRequired: false as const, factorName: "", session };
  } catch (error) {
    if (firebaseCode(error) === "auth/multi-factor-auth-required") {
      pendingResolver = getMultiFactorResolver(auth, error as Parameters<typeof getMultiFactorResolver>[1]);
      pendingRequestedRole = requestedRole;
      const hint = pendingResolver.hints.find((item) => item.factorId === TotpMultiFactorGenerator.FACTOR_ID);
      if (!hint) throw new IdentityError("This account requires an unsupported second factor.", "unsupported_mfa");
      return { mfaRequired: true as const, factorName: hint.displayName || "Authenticator app" };
    }
    throw friendlyIdentityError(error);
  }
}

export async function completeTotpSignIn(code: string) {
  if (!pendingResolver) throw new IdentityError("Start sign-in again before entering a verification code.", "mfa_expired");
  const { TotpMultiFactorGenerator } = await import("firebase/auth");
  const hint = pendingResolver.hints.find((item) => item.factorId === TotpMultiFactorGenerator.FACTOR_ID);
  if (!hint) throw new IdentityError("No TOTP factor is available for this account.", "unsupported_mfa");
  try {
    const assertion = TotpMultiFactorGenerator.assertionForSignIn(hint.uid, code);
    const credential = await pendingResolver.resolveSignIn(assertion);
    const session = await exchangeCredential(credential.user, pendingRequestedRole);
    pendingResolver = null;
    pendingRequestedRole = undefined;
    return session;
  } catch (error) {
    throw friendlyIdentityError(error);
  }
}

export async function beginSessionReauthentication(password: string) {
  const auth = await configuredAuth();
  await auth.authStateReady();
  const user = auth.currentUser;
  if (!user?.email) throw new IdentityError("Sign in again before changing protected settings.", "authentication_required");
  const { EmailAuthProvider, getMultiFactorResolver, reauthenticateWithCredential, TotpMultiFactorGenerator } = await import("firebase/auth");
  try {
    await reauthenticateWithCredential(user, EmailAuthProvider.credential(user.email, password));
    await api.reauthenticate(await user.getIdToken(true));
    return { mfaRequired: false, factorName: "" };
  } catch (error) {
    if (firebaseCode(error) === "auth/multi-factor-auth-required") {
      pendingReauthResolver = getMultiFactorResolver(auth, error as Parameters<typeof getMultiFactorResolver>[1]);
      const hint = pendingReauthResolver.hints.find((item) => item.factorId === TotpMultiFactorGenerator.FACTOR_ID);
      if (!hint) throw new IdentityError("This account requires an unsupported second factor.", "unsupported_mfa");
      return { mfaRequired: true, factorName: hint.displayName || "Authenticator app" };
    }
    throw friendlyIdentityError(error);
  }
}

export async function completeSessionReauthentication(code: string) {
  if (!pendingReauthResolver) throw new IdentityError("Restart verification before entering a code.", "mfa_expired");
  const { TotpMultiFactorGenerator } = await import("firebase/auth");
  const hint = pendingReauthResolver.hints.find((item) => item.factorId === TotpMultiFactorGenerator.FACTOR_ID);
  if (!hint) throw new IdentityError("No TOTP factor is available for this account.", "unsupported_mfa");
  try {
    const credential = await pendingReauthResolver.resolveSignIn(
      TotpMultiFactorGenerator.assertionForSignIn(hint.uid, code),
    );
    pendingReauthResolver = null;
    await api.reauthenticate(await credential.user.getIdToken(true));
  } catch (error) {
    throw friendlyIdentityError(error);
  }
}

export async function createPasswordAccount(email: string, password: string) {
  const auth = await configuredAuth();
  const { createUserWithEmailAndPassword, sendEmailVerification, signOut } = await import("firebase/auth");
  try {
    const credential = await createUserWithEmailAndPassword(auth, email, password);
    await sendEmailVerification(credential.user);
    await signOut(auth);
  } catch (error) {
    throw friendlyIdentityError(error);
  }
}

export async function requestPasswordReset(email: string) {
  const auth = await configuredAuth();
  const { sendPasswordResetEmail } = await import("firebase/auth");
  try {
    await sendPasswordResetEmail(auth, email);
  } catch (error) {
    throw friendlyIdentityError(error);
  }
}

export async function beginTotpEnrollment() {
  const auth = await configuredAuth();
  const { multiFactor, TotpMultiFactorGenerator } = await import("firebase/auth");
  const user = auth.currentUser;
  if (!user) throw new IdentityError("Sign in before setting up two-step verification.", "authentication_required");
  if (!user.emailVerified) throw new IdentityError("Verify your email address before enabling two-step verification.", "email_not_verified");
  try {
    pendingSecret = await TotpMultiFactorGenerator.generateSecret(await multiFactor(user).getSession());
    return {
      secretKey: pendingSecret.secretKey,
      qrCodeUrl: pendingSecret.generateQrCodeUrl(user.email ?? user.uid, "PhishGuard"),
    };
  } catch (error) {
    throw friendlyIdentityError(error);
  }
}

export async function completeTotpEnrollment(code: string) {
  const auth = await configuredAuth();
  const { multiFactor, TotpMultiFactorGenerator } = await import("firebase/auth");
  const user = auth.currentUser;
  if (!user || !pendingSecret) throw new IdentityError("Restart TOTP setup before entering a code.", "enrollment_expired");
  try {
    await multiFactor(user).enroll(
      TotpMultiFactorGenerator.assertionForEnrollment(pendingSecret, code),
      "Authenticator app",
    );
    pendingSecret = null;
    await exchangeCredential(user);
  } catch (error) {
    throw friendlyIdentityError(error);
  }
}

export async function signOutIdentity() {
  try {
    await api.endSession();
  } finally {
    if (identityConfigured()) {
      const auth = await configuredAuth();
      const { signOut } = await import("firebase/auth");
      await signOut(auth);
    }
  }
}

function firebaseCode(error: unknown) {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") return error.code;
  return "identity_failed";
}

function friendlyIdentityError(error: unknown) {
  const code = firebaseCode(error);
  const messages: Record<string, string> = {
    "auth/invalid-credential": "The email address or password is incorrect.",
    "auth/invalid-verification-code": "The verification code is invalid or expired.",
    "auth/email-already-in-use": "An account already uses this email address.",
    "auth/invalid-email": "Enter a valid email address.",
    "auth/weak-password": "Choose a stronger password that meets the Identity Platform policy.",
    "auth/too-many-requests": "Too many attempts were made. Wait before trying again.",
    "auth/network-request-failed": "Identity Platform could not be reached. Check your connection.",
    "auth/requires-recent-login": "Sign in again before changing two-step verification.",
  };
  return new IdentityError(messages[code] ?? "Authentication could not be completed.", code);
}
