import { CrateService as pkiclient } from './gen/clients/pki';
import { CrateService as dsclient } from './gen/clients/ds';

void (async () => {
  const module = await import('ssf');
  await module.mls_example();
  const uid = new Uint8Array([1, 2, 3, 4, 5]);
  const group_id = new Uint8Array([1, 2, 3, 4, 5]);
  await module.mlsInitClient(uid);
  await module.mlsCgkaInit(uid, group_id);
  const otherUid = new Uint8Array([5, 4, 3, 2, 1]);
  await module.mlsInitClient(otherUid);
  const keyPackage = await module.mlsGenerateKeyPackage(otherUid); 
  const proposal = await module.mlsCgkaAddProposal(uid, group_id, keyPackage);
  console.log(proposal.welcomeMsg, proposal.controlMsg);
  await module.mlsCgkaApplyPendingCommit(uid, group_id);
  await module.mlsCgkaJoinGroup(otherUid, proposal.welcomeMsg);
  console.log("Group with two members");
  await module.mlsCgkaUpdateKeys(uid, group_id);
  await module.mlsCgkaApplyPendingCommit(uid, group_id);
  await module.mlsCgkaUpdateKeys(otherUid, group_id);
  await module.mlsCgkaApplyPendingCommit(otherUid, group_id);
  console.log("Group with updated keys");
  //const caCredential = await pkiclient.getCaCredential();
  //console.log(caCredential);
})();
