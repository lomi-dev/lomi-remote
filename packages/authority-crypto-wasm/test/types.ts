import { BrowserChannel, BrowserHandshakeV3, BrowserIdentity, initializeAuthorityCrypto, verifyHostKeyInitiation, verifyHostEnrollmentProof, prepareHostEnrollmentChallenge, verifyHostRefreshProof, verifyRegisteredHostIdentity, verifyConsumerWindowIdentity, prepareConsumerWindowChallenge, verifyConsumerWindowProof, prepareGrantProposalV3, verifyGrantProposalV3, prepareChannelContextV3, verifyChannelAdmissionV3 } from '@lomi/authority-crypto-wasm';
initializeAuthorityCrypto(new Uint8Array());
const identity = new BrowserIdentity({ accountId: new Uint8Array(16), subjectId: new Uint8Array(16), host: false, keyVersion: 1 });
const restored = BrowserIdentity.restore({ accountId: new Uint8Array(16), subjectId: new Uint8Array(16),
  seedBlob: new Uint8Array(97), expectedBundleJson: "{}" });
const seedBlob: Uint8Array = identity.seedBlobForEncryption();
const fingerprint: Uint8Array = identity.fingerprint();
const publicBundle: string = identity.publicBundle();
const publicIdentityWire: string = identity.publicIdentityWire();
const consumerProof: string = identity.signConsumerWindowProof(new Uint8Array());
const handshake = new BrowserHandshakeV3({ initiator: true, identity, signedJson: '{}', expectedJson: '{}', authorityJson: '{}', hostPin: new Uint8Array(32), consumerPin: new Uint8Array(32), now: 1n });
const message: Uint8Array = handshake.write();
handshake.read(message);
const channel: BrowserChannel = handshake.finish();
const frame: Uint8Array = channel.sealBinary(new Uint8Array(16), new Uint8Array());
const plaintext: Uint8Array = channel.openBinary(new Uint8Array(16), frame);
const transcriptHash: Uint8Array = channel.transcriptHash();
identity.dispose(); identity.free(); restored.dispose(); restored.free(); channel.dispose(); channel.free();
void seedBlob;
void fingerprint; void publicBundle; void publicIdentityWire; void consumerProof; void plaintext; void transcriptHash;
// @ts-expect-error identities use named, validated options
new BrowserIdentity(new Uint8Array(16), new Uint8Array(16), false, 1);
// @ts-expect-error V3 time must be an unsigned BigInt
new BrowserHandshakeV3({ initiator: true, identity, signedJson: '{}', expectedJson: '{}', authorityJson: '{}', hostPin: new Uint8Array(32), consumerPin: new Uint8Array(32), now: 1 });
const publicCommitment: string = verifyHostKeyInitiation('{}');
const prepared: string = prepareHostEnrollmentChallenge(publicCommitment, new Uint8Array(32), new Uint8Array(16), '{}');
void prepared;
verifyHostEnrollmentProof('{}', '{}', publicCommitment, new Uint8Array(32), new Uint8Array(16), 1n);
// @ts-expect-error time must be an exact unsigned BigInt
verifyHostEnrollmentProof('{}', '{}', publicCommitment, new Uint8Array(32), new Uint8Array(16), 1);

verifyHostRefreshProof('{}', publicCommitment, new Uint8Array(32), new Uint8Array(16), '{}');
// @ts-expect-error account must be fixed Uint8Array data
verifyHostRefreshProof('{}', publicCommitment, new Uint8Array(32), [], '{}');

const registered: string = verifyRegisteredHostIdentity('{}', publicCommitment, new Uint8Array(32), new Uint8Array(16));
const consumer: string = verifyConsumerWindowIdentity('{}', new Uint8Array(16), new Uint8Array(16));
const windowChallenge: string = prepareConsumerWindowChallenge('{}', new Uint8Array(16), '{}');
verifyConsumerWindowProof('{}', windowChallenge, '{}', new Uint8Array(16), 1n);
// @ts-expect-error time must be an exact unsigned BigInt
verifyConsumerWindowProof('{}', windowChallenge, '{}', new Uint8Array(16), 1);
void registered; void consumer;

const v3Proposal: string = prepareGrantProposalV3('{}', '{}', '{}', new Uint8Array(16), new Uint8Array(32), new Uint8Array(32));
const v3Grant: string = verifyGrantProposalV3('{}', '00', '{}', '{}', new Uint8Array(32), new Uint8Array(32), '{}', 1n);
const v3Context: string = prepareChannelContextV3('{}', '{}', '{}', '{}', new Uint8Array(32), new Uint8Array(32), '{}', 1n);
const v3Admission: string = verifyChannelAdmissionV3('{}', '00', '{}', '{}', '{}', new Uint8Array(32), new Uint8Array(32), '{}', 1n);
// @ts-expect-error exact BigInt required
verifyGrantProposalV3('{}', '00', '{}', '{}', new Uint8Array(32), new Uint8Array(32), '{}', 1);
// @ts-expect-error exact BigInt required
prepareChannelContextV3('{}', '{}', '{}', '{}', new Uint8Array(32), new Uint8Array(32), '{}', '1');
// @ts-expect-error fixed public bytes required
verifyChannelAdmissionV3('{}', '00', '{}', '{}', '{}', [], new Uint8Array(32), '{}', 1n);
void v3Proposal; void v3Grant; void v3Context; void v3Admission;
