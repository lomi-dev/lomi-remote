-- Terminal signals mean attention, not verified task completion.
-- Keep producer and explicit test owner shapes mutually exclusive.
ALTER TABLE push_event DROP CONSTRAINT push_event_producer_shape;
ALTER TABLE push_event ADD CONSTRAINT push_event_producer_shape CHECK (COALESCE(
 (type = 'agent.task.completed.v1' AND "sourceId" IS NOT NULL AND "testOwnerMobileSessionId" IS NULL AND "testOwnerDesktopSessionId" IS NULL AND "sourceKind" IN ('managed-task', 'chat')) OR
 (type = 'agent.terminal.notification.v1' AND "sourceId" IS NOT NULL AND "testOwnerMobileSessionId" IS NULL AND "testOwnerDesktopSessionId" IS NULL AND "sourceKind" = 'terminal-notification') OR
 (type = 'push.test.v1' AND "sourceId" IS NULL AND (("testOwnerMobileSessionId" IS NOT NULL)::int + ("testOwnerDesktopSessionId" IS NOT NULL)::int) = 1 AND "sourceKind" IS NULL),
 false
));
