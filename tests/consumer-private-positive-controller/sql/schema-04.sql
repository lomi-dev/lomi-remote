CREATE TABLE "desktop_login" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "clientId" TEXT NOT NULL,
    "redirectUri" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "codeChallenge" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "codeHash" TEXT,
    "codeExpiresAt" TIMESTAMP(3),
    "userId" TEXT REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE,
    "sourceSessionId" TEXT REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "desktop_login_codeHash_key" ON "desktop_login"("codeHash");
CREATE INDEX "desktop_login_expiresAt_idx" ON "desktop_login"("expiresAt");
CREATE INDEX "desktop_login_userId_idx" ON "desktop_login"("userId");
CREATE INDEX "desktop_login_sourceSessionId_idx" ON "desktop_login"("sourceSessionId");
