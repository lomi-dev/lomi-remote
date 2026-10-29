-- CreateIndex
CREATE INDEX "remote_channel_expiresAt_idx" ON "remote_channel"("expiresAt");

-- CreateIndex
CREATE INDEX "remote_grant_expiresAt_idx" ON "remote_grant"("expiresAt");

-- CreateIndex
CREATE INDEX "remote_pairing_expiresAt_idx" ON "remote_pairing"("expiresAt");

-- CreateIndex
CREATE INDEX "remote_relay_ticket_expiresAt_idx" ON "remote_relay_ticket"("expiresAt");

