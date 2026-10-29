import { decode, validate, checkResponse, OrderedSequence } from '@lomi/remote-contracts';
import type { ContractMap } from '@lomi/remote-contracts';
const unknownValue: unknown = {};
if (validate('rpc-request', unknownValue)) {
  const method: string = unknownValue.call.method;
  const request: ContractMap['rpc-request'] = unknownValue;
  checkResponse(request, {});
  void method;
}
const frame = decode('workspace-stream-frame','{}');
const kind: string = frame.type;
new OrderedSequence().accept('1');
void kind;
// @ts-expect-error unknown schema names must be rejected
validate('not-a-contract', {});

if (validate('HostRuntimeGetResult', unknownValue)) {
  const generation: string = unknownValue.runtimeGeneration;
  const epoch: string = unknownValue.hostAccessEpoch;
  const runtime: ContractMap['HostRuntimeGetResult']['runtime'] = unknownValue.runtime;
  void generation;
  void epoch;
  void runtime;
}
// @ts-expect-error GET lookup has no request DTO
validate('RuntimeGetParams', {});

if (validate('HostRevocationAckParams', unknownValue)) {
  const family: string = unknownValue.hostAuthorizationId;
  const epoch: string = unknownValue.expectedHostAccessEpoch;
  const refresh: string = unknownValue.refresh;
  const request: ContractMap['HostRevocationAckParams'] = unknownValue;
  void family;
  void epoch;
  void refresh;
  void request;
}

if (validate('local-request', unknownValue) && unknownValue.call.method === 'auth.configure') {
  const relay: string | null | undefined = unknownValue.call.params.configuration.relayEndpoint;
  const api: string | null | undefined = unknownValue.call.params.configuration.remoteApiOrigin;
  void relay;
  void api;
  // @ts-expect-error a relay endpoint is optional validated text, never a number
  const invalidRelay: number = unknownValue.call.params.configuration.relayEndpoint;
  void invalidRelay;
}
