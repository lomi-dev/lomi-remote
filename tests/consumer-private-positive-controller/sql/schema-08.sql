-- AlterTable
ALTER TABLE "remote_channel" ADD COLUMN     "purpose" TEXT NOT NULL DEFAULT 'terminal';

-- AlterTable
ALTER TABLE "remote_grant" ADD COLUMN     "workspaceEpoch" TEXT,
ADD COLUMN     "workspaceId" TEXT;

-- AlterTable
ALTER TABLE "remote_host" ADD COLUMN     "workspaces" JSONB NOT NULL DEFAULT '[]';

-- AlterTable
ALTER TABLE "remote_pairing" ADD COLUMN     "workspaceEpoch" TEXT,
ADD COLUMN     "workspaceId" TEXT,
ADD COLUMN     "workspaceRevision" BIGINT;
