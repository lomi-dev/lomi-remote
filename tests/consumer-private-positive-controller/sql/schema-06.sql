-- CreateTable
CREATE TABLE "remote_host" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sourceSessionId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "bundle" JSONB NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "accessEpoch" INTEGER NOT NULL DEFAULT 1,
    "lastSeen" TIMESTAMP(3) NOT NULL,
    "shares" JSONB NOT NULL,

    CONSTRAINT "remote_host_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_pairing" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "webSessionId" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "deviceBundle" JSONB NOT NULL,
    "deviceFingerprint" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "signedApproval" JSONB,

    CONSTRAINT "remote_pairing_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_grant" (
    "id" TEXT NOT NULL,
    "pairingId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "webSessionId" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "sessionIds" TEXT[],
    "shareEpochs" JSONB NOT NULL,
    "permissions" TEXT NOT NULL,
    "signedApproval" JSONB NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "remote_grant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_channel" (
    "id" TEXT NOT NULL,
    "grantId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "shareEpoch" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "remote_channel_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_relay_ticket" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "channelId" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "remote_relay_ticket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remote_relay_owner" (
    "id" TEXT NOT NULL,
    "epoch" INTEGER NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "remote_relay_owner_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "remote_host_userId_idx" ON "remote_host"("userId");

-- CreateIndex
CREATE INDEX "remote_pairing_hostId_status_idx" ON "remote_pairing"("hostId", "status");

-- CreateIndex
CREATE INDEX "remote_pairing_webSessionId_idx" ON "remote_pairing"("webSessionId");

-- CreateIndex
CREATE UNIQUE INDEX "remote_grant_pairingId_key" ON "remote_grant"("pairingId");

-- CreateIndex
CREATE INDEX "remote_grant_hostId_idx" ON "remote_grant"("hostId");

-- CreateIndex
CREATE INDEX "remote_grant_webSessionId_idx" ON "remote_grant"("webSessionId");

-- CreateIndex
CREATE INDEX "remote_channel_grantId_idx" ON "remote_channel"("grantId");

-- CreateIndex
CREATE UNIQUE INDEX "remote_relay_ticket_tokenHash_key" ON "remote_relay_ticket"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "remote_relay_ticket_channelId_role_key" ON "remote_relay_ticket"("channelId", "role");

ALTER TABLE remote_host ADD CONSTRAINT remote_host_user_fk FOREIGN KEY ("userId") REFERENCES "user"(id) ON DELETE CASCADE;
ALTER TABLE remote_host ADD CONSTRAINT remote_host_parent_fk FOREIGN KEY ("sourceSessionId") REFERENCES "session"(id) ON DELETE CASCADE;
ALTER TABLE remote_pairing ADD CONSTRAINT remote_pairing_web_fk FOREIGN KEY ("webSessionId") REFERENCES remote_web_session(id) ON DELETE CASCADE;
ALTER TABLE remote_pairing ADD CONSTRAINT remote_pairing_host_fk FOREIGN KEY ("hostId") REFERENCES remote_host(id) ON DELETE CASCADE;
ALTER TABLE remote_grant ADD CONSTRAINT remote_grant_web_fk FOREIGN KEY ("webSessionId") REFERENCES remote_web_session(id) ON DELETE CASCADE;
ALTER TABLE remote_grant ADD CONSTRAINT remote_grant_host_fk FOREIGN KEY ("hostId") REFERENCES remote_host(id) ON DELETE CASCADE;
ALTER TABLE remote_grant ADD CONSTRAINT remote_grant_pair_fk FOREIGN KEY ("pairingId") REFERENCES remote_pairing(id) ON DELETE CASCADE;
ALTER TABLE remote_channel ADD CONSTRAINT remote_channel_grant_fk FOREIGN KEY ("grantId") REFERENCES remote_grant(id) ON DELETE CASCADE;
ALTER TABLE remote_relay_ticket ADD CONSTRAINT remote_ticket_channel_fk FOREIGN KEY ("channelId") REFERENCES remote_channel(id) ON DELETE CASCADE;
