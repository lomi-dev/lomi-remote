-- CreateTable
CREATE TABLE "notification_preference" (
    "userId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "consentEpoch" INTEGER NOT NULL DEFAULT 1,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "lastOperationId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "notification_preference_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "push_source" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sourceSessionId" TEXT NOT NULL,
    "desktopInstallationId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "sourceEpoch" INTEGER NOT NULL DEFAULT 1,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "lastOperationId" TEXT,
    "label" TEXT NOT NULL,
    "remoteHostId" TEXT,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "push_source_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "push_installation" (
    "id" TEXT NOT NULL,
    "bindingSecretHash" TEXT NOT NULL,
    "bindingId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "mobileSessionId" TEXT,
    "environment" TEXT NOT NULL,
    "expoProjectId" TEXT NOT NULL,
    "appIdentifier" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "receiveEpoch" INTEGER NOT NULL DEFAULT 1,
    "bindingGeneration" INTEGER NOT NULL DEFAULT 1,
    "tokenGeneration" INTEGER NOT NULL DEFAULT 1,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "lastOperationId" TEXT,
    "expoTokenCiphertext" TEXT,
    "expoTokenHash" TEXT,
    "permissionState" TEXT NOT NULL,
    "disabledReason" TEXT,
    "retiredAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastRegisteredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "push_installation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "push_event" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sourceId" TEXT,
    "testOwnerMobileSessionId" TEXT,
    "testOwnerDesktopSessionId" TEXT,
    "eventKey" TEXT NOT NULL,
    "schemaVersion" INTEGER NOT NULL,
    "type" TEXT NOT NULL,
    "sourceKind" TEXT,
    "logicalTaskId" TEXT,
    "turnId" TEXT,
    "consentEpoch" INTEGER NOT NULL,
    "sourceEpoch" INTEGER NOT NULL,
    "completedAt" TIMESTAMP(3) NOT NULL,
    "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "optionalTargetJson" JSONB,
    "outcome" TEXT NOT NULL,
    "suppressionReason" TEXT,

    CONSTRAINT "push_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "push_delivery" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "installationId" TEXT NOT NULL,
    "bindingIdSnapshot" TEXT NOT NULL,
    "bindingGenerationSnapshot" INTEGER NOT NULL,
    "receiveEpochSnapshot" INTEGER NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'queued',
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "leaseOwner" TEXT,
    "leaseUntil" TIMESTAMP(3),
    "terminalReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "push_delivery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "push_attempt" (
    "id" TEXT NOT NULL,
    "deliveryId" TEXT NOT NULL,
    "sequence" INTEGER NOT NULL,
    "bindingIdSnapshot" TEXT NOT NULL,
    "bindingGenerationSnapshot" INTEGER NOT NULL,
    "tokenGenerationSnapshot" INTEGER NOT NULL,
    "tokenHashSnapshot" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "expoTicketId" TEXT,
    "httpStatus" INTEGER,
    "errorCode" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "receiptDueAt" TIMESTAMP(3),
    "receiptCheckedAt" TIMESTAMP(3),

    CONSTRAINT "push_attempt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "push_project_circuit" (
    "id" TEXT NOT NULL,
    "pausedAt" TIMESTAMP(3),
    "reason" TEXT,

    CONSTRAINT "push_project_circuit_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "push_source_userId_enabled_idx" ON "push_source"("userId", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "push_source_userId_sourceSessionId_desktopInstallationId_key" ON "push_source"("userId", "sourceSessionId", "desktopInstallationId");

-- CreateIndex
CREATE UNIQUE INDEX "push_installation_bindingId_key" ON "push_installation"("bindingId");

-- CreateIndex
CREATE INDEX "push_installation_userId_enabled_idx" ON "push_installation"("userId", "enabled");

-- CreateIndex
CREATE INDEX "push_installation_mobileSessionId_idx" ON "push_installation"("mobileSessionId");

-- CreateIndex
CREATE UNIQUE INDEX "push_installation_environment_expoProjectId_expoTokenHash_key" ON "push_installation"("environment", "expoProjectId", "expoTokenHash");

-- CreateIndex
CREATE INDEX "push_event_acceptedAt_idx" ON "push_event"("acceptedAt");

-- CreateIndex
CREATE UNIQUE INDEX "push_event_userId_eventKey_key" ON "push_event"("userId", "eventKey");

-- CreateIndex
CREATE INDEX "push_delivery_state_nextAttemptAt_idx" ON "push_delivery"("state", "nextAttemptAt");

-- CreateIndex
CREATE UNIQUE INDEX "push_delivery_eventId_installationId_key" ON "push_delivery"("eventId", "installationId");

-- CreateIndex
CREATE UNIQUE INDEX "push_attempt_expoTicketId_key" ON "push_attempt"("expoTicketId");

-- CreateIndex
CREATE INDEX "push_attempt_state_receiptDueAt_idx" ON "push_attempt"("state", "receiptDueAt");

-- CreateIndex
CREATE UNIQUE INDEX "push_attempt_deliveryId_sequence_key" ON "push_attempt"("deliveryId", "sequence");

-- AddForeignKey
ALTER TABLE "notification_preference" ADD CONSTRAINT "notification_preference_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_source" ADD CONSTRAINT "push_source_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_source" ADD CONSTRAINT "push_source_sourceSessionId_fkey" FOREIGN KEY ("sourceSessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_source" ADD CONSTRAINT "push_source_remoteHostId_fkey" FOREIGN KEY ("remoteHostId") REFERENCES "remote_host"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_installation" ADD CONSTRAINT "push_installation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_installation" ADD CONSTRAINT "push_installation_mobileSessionId_fkey" FOREIGN KEY ("mobileSessionId") REFERENCES "mobile_session"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_event" ADD CONSTRAINT "push_event_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_event" ADD CONSTRAINT "push_event_sourceId_fkey" FOREIGN KEY ("sourceId") REFERENCES "push_source"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_event" ADD CONSTRAINT "push_event_testOwnerMobileSessionId_fkey" FOREIGN KEY ("testOwnerMobileSessionId") REFERENCES "mobile_session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_event" ADD CONSTRAINT "push_event_testOwnerDesktopSessionId_fkey" FOREIGN KEY ("testOwnerDesktopSessionId") REFERENCES "session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_delivery" ADD CONSTRAINT "push_delivery_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "push_event"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_delivery" ADD CONSTRAINT "push_delivery_installationId_fkey" FOREIGN KEY ("installationId") REFERENCES "push_installation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_attempt" ADD CONSTRAINT "push_attempt_deliveryId_fkey" FOREIGN KEY ("deliveryId") REFERENCES "push_delivery"("id") ON DELETE CASCADE ON UPDATE CASCADE;


ALTER TABLE push_event ADD CONSTRAINT push_event_producer_shape CHECK (
 (type = 'agent.task.completed.v1' AND "sourceId" IS NOT NULL AND "testOwnerMobileSessionId" IS NULL AND "testOwnerDesktopSessionId" IS NULL AND "sourceKind" IN ('managed-task', 'chat')) OR
 (type = 'push.test.v1' AND "sourceId" IS NULL AND (("testOwnerMobileSessionId" IS NOT NULL)::int + ("testOwnerDesktopSessionId" IS NOT NULL)::int) = 1 AND "sourceKind" IS NULL)
);
ALTER TABLE push_delivery ADD CONSTRAINT push_delivery_state CHECK (state IN ('queued','leased','expo_accepted','provider_handoff_confirmed','failed','suppressed','expired','unknown'));
ALTER TABLE push_installation ADD CONSTRAINT push_installation_generations CHECK ("bindingGeneration" > 0 AND "receiveEpoch" > 0 AND "tokenGeneration" > 0 AND revision > 0);
-- Lifecycle changes remain serialized by the existing application authorization
-- lock. These triggers also cover existing revoke/delete paths without widening
-- their credential projections. They never resurrect terminal deliveries.
CREATE FUNCTION push_revoke_mobile() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
 IF TG_OP = 'DELETE' OR NEW."revokedAt" IS NOT NULL THEN
  UPDATE public.push_delivery SET state='suppressed', "terminalReason"='SESSION_REVOKED', "leaseOwner"=NULL, "leaseUntil"=NULL, "updatedAt"=now()
   WHERE state IN ('queued','leased') AND "installationId" IN (SELECT id FROM public.push_installation WHERE "mobileSessionId"=OLD.id);
  UPDATE public.push_installation SET enabled=false, "receiveEpoch"="receiveEpoch"+1, revision=revision+1, "disabledReason"='SESSION_REVOKED', "updatedAt"=now()
   WHERE "mobileSessionId"=OLD.id AND enabled=true;
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER push_mobile_revoke BEFORE DELETE OR UPDATE OF "revokedAt" ON mobile_session FOR EACH ROW EXECUTE FUNCTION push_revoke_mobile();
CREATE FUNCTION push_revoke_authorization() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
 IF NEW."revokedAt" IS NOT NULL THEN
  UPDATE public.push_delivery SET state='suppressed', "terminalReason"='AUTHORIZATION_REVOKED', "leaseOwner"=NULL, "leaseUntil"=NULL, "updatedAt"=now()
   WHERE state IN ('queued','leased') AND "installationId" IN (SELECT i.id FROM public.push_installation i JOIN public.mobile_session m ON m.id=i."mobileSessionId" WHERE m."authorizationId"=NEW.id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER push_authorization_revoke AFTER UPDATE OF "revokedAt" ON remote_service_authorization FOR EACH ROW EXECUTE FUNCTION push_revoke_authorization();
CREATE FUNCTION push_revoke_user() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
 IF NEW.status <> 'active' THEN
  UPDATE public.push_delivery SET state='suppressed', "terminalReason"='ACCOUNT_UNAVAILABLE', "leaseOwner"=NULL, "leaseUntil"=NULL, "updatedAt"=now()
   WHERE state IN ('queued','leased') AND "eventId" IN (SELECT id FROM public.push_event WHERE "userId"=NEW.id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER push_user_status AFTER UPDATE OF status ON "user" FOR EACH ROW EXECUTE FUNCTION push_revoke_user();
CREATE FUNCTION push_revoke_desktop() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
 UPDATE public.push_delivery SET state='suppressed', "terminalReason"='SOURCE_SESSION_REVOKED', "leaseOwner"=NULL, "leaseUntil"=NULL, "updatedAt"=now()
  WHERE state IN ('queued','leased') AND "eventId" IN (SELECT e.id FROM public.push_event e LEFT JOIN public.push_source s ON s.id=e."sourceId" WHERE s."sourceSessionId"=OLD.id OR e."testOwnerDesktopSessionId"=OLD.id);
 RETURN OLD;
END $$;
CREATE TRIGGER push_desktop_revoke BEFORE DELETE ON "session" FOR EACH ROW EXECUTE FUNCTION push_revoke_desktop();
REVOKE ALL ON FUNCTION push_revoke_mobile(), push_revoke_authorization(), push_revoke_user(), push_revoke_desktop() FROM PUBLIC;
