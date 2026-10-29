-- CreateTable
CREATE TABLE "remote_login_attempt" (
    "id" TEXT NOT NULL,
    "cookieHash" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "verifier" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "redirectUri" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "remote_login_attempt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_identity_code" (
    "id" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "attemptId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sourceSessionId" TEXT NOT NULL,
    "codeChallenge" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "remote_identity_code_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_service_authorization" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sourceSessionId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "scope" TEXT NOT NULL DEFAULT 'remote:account:read',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "remote_service_authorization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_web_session" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sourceSessionId" TEXT NOT NULL,
    "authorizationId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "idleExpiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "remote_web_session_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "remote_login_attempt_cookieHash_key" ON "remote_login_attempt"("cookieHash");

-- CreateIndex
CREATE INDEX "remote_login_attempt_expiresAt_idx" ON "remote_login_attempt"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "remote_identity_code_codeHash_key" ON "remote_identity_code"("codeHash");

-- CreateIndex
CREATE UNIQUE INDEX "remote_identity_code_attemptId_key" ON "remote_identity_code"("attemptId");

-- CreateIndex
CREATE INDEX "remote_identity_code_expiresAt_idx" ON "remote_identity_code"("expiresAt");

-- CreateIndex
CREATE INDEX "remote_identity_code_sourceSessionId_idx" ON "remote_identity_code"("sourceSessionId");

-- CreateIndex
CREATE INDEX "remote_identity_code_userId_idx" ON "remote_identity_code"("userId");

-- CreateIndex
CREATE INDEX "remote_service_authorization_expiresAt_idx" ON "remote_service_authorization"("expiresAt");

-- CreateIndex
CREATE INDEX "remote_service_authorization_sourceSessionId_idx" ON "remote_service_authorization"("sourceSessionId");

-- CreateIndex
CREATE INDEX "remote_service_authorization_userId_idx" ON "remote_service_authorization"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "remote_web_session_tokenHash_key" ON "remote_web_session"("tokenHash");

-- CreateIndex
CREATE INDEX "remote_web_session_expiresAt_idx" ON "remote_web_session"("expiresAt");

-- CreateIndex
CREATE INDEX "remote_web_session_idleExpiresAt_idx" ON "remote_web_session"("idleExpiresAt");

-- CreateIndex
CREATE INDEX "remote_web_session_sourceSessionId_idx" ON "remote_web_session"("sourceSessionId");

-- CreateIndex
CREATE INDEX "remote_web_session_userId_idx" ON "remote_web_session"("userId");

-- AddForeignKey
ALTER TABLE "remote_identity_code" ADD CONSTRAINT "remote_identity_code_attemptId_fkey" FOREIGN KEY ("attemptId") REFERENCES "remote_login_attempt"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_identity_code" ADD CONSTRAINT "remote_identity_code_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_identity_code" ADD CONSTRAINT "remote_identity_code_sourceSessionId_fkey" FOREIGN KEY ("sourceSessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_service_authorization" ADD CONSTRAINT "remote_service_authorization_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_service_authorization" ADD CONSTRAINT "remote_service_authorization_sourceSessionId_fkey" FOREIGN KEY ("sourceSessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_web_session" ADD CONSTRAINT "remote_web_session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_web_session" ADD CONSTRAINT "remote_web_session_sourceSessionId_fkey" FOREIGN KEY ("sourceSessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remote_web_session" ADD CONSTRAINT "remote_web_session_authorizationId_fkey" FOREIGN KEY ("authorizationId") REFERENCES "remote_service_authorization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

