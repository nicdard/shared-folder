// Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
import { string2Uint8Array } from '../../../protocol/commonCrypto';
import { GRaPPA } from '../grappa';
import { InMemoryMiddleware } from '../inMemoryMiddleware';
import {
  AddAdmControlCommand,
  AddControlCommand,
  RemAdmControlCommand,
  RemControlCommand,
} from '../gkp';
import { join } from 'path';

function generateClientRandomIdentity() {
  return crypto.randomUUID() + '@test.com';
}

it('GRaPPA: adding second client as member and as admin, then removing it.', async () => {
  const middleware = new InMemoryMiddleware();
  const client1 = generateClientRandomIdentity();
  const grappa1 = await GRaPPA.initUser(client1, middleware);
  expect(grappa1).toBeDefined();
  expect(grappa1.getRole()).toBeUndefined();
  const uid1 = GRaPPA.getUidFromUserId(client1);
  await GRaPPA.publishKeyPackage(client1, middleware);
  const client2 = generateClientRandomIdentity();
  let grappa2 = await GRaPPA.initUser(client2, middleware);
  const uid2 = GRaPPA.getUidFromUserId(client2);
  await GRaPPA.publishKeyPackage(client2, middleware);
  const folderId = crypto.randomUUID();
  const folderUint8 = string2Uint8Array(folderId);
  await grappa1.createGroup(folderId);
  expect(grappa1.getRole()).toEqual('admin');
  expect(grappa1.getCurrentEpoch()).toEqual(0);
  // Add client 2.
  await grappa1.execCtrl({ type: 'ADD', uid: uid2 });
  expect(middleware.getProposalQueueLength(client2, folderUint8)).toBe(1);
  expect(grappa1.getCurrentEpoch()).toEqual(1);
  expect(grappa1.getEpochInterval()).toBeDefined();
  expect(grappa1.getEpochInterval()).toEqual({ left: 0, right: 1 });
  // Client 2 fetches the proposal and process join.
  const proposal = await middleware.fetchPendingProposal(client2, folderUint8);
  expect(proposal.proposal.cmd.type).toEqual('ADD');
  expect((proposal.proposal.cmd as AddControlCommand).uid).toStrictEqual(uid2);
  expect(proposal.applicationMsg).toBeDefined();
  expect((proposal.applicationMsg.cmd as AddControlCommand).uid).toStrictEqual(
    uid2
  );
  expect(proposal.proposal.messageId).toBeDefined();
  expect(proposal.proposal.messageId).toEqual(0);
  grappa2 = await GRaPPA.joinCtrl(client2, middleware, proposal);
  expect(grappa2.getRole()).toEqual('member');
  expect(grappa2.getCurrentEpoch()).toEqual(1);
  expect(grappa2.getEpochInterval()).toBeDefined();
  expect(grappa2.getEpochInterval()).toEqual({ left: 1, right: 1 });
  // Check that the proposal has been acked and deleted.
  expect(middleware.getProposalQueueLength(client2, folderUint8)).toEqual(0);
  // Add client2 as a member the second time should fail.
  await grappa1.execCtrl({ type: 'ADD', uid: uid2 });
  expect(middleware.getProposalQueueLength(client2, folderUint8)).toEqual(0);
  // Add client2 as an admin.
  await grappa1.execCtrl({ type: 'ADD_ADM', uid: uid2 });
  expect(middleware.getProposalQueueLength(client2, folderUint8)).toEqual(1);
  const addAdminProposal = await middleware.fetchPendingProposal(
    client2,
    folderUint8
  );
  expect(addAdminProposal.proposal.cmd.type).toEqual('ADD_ADM');
  expect(
    (addAdminProposal.proposal.cmd as AddAdmControlCommand).uid
  ).toStrictEqual(uid2);
  expect(addAdminProposal.applicationMsg).toBeDefined();
  expect(
    (addAdminProposal.applicationMsg.cmd as AddAdmControlCommand).uid
  ).toStrictEqual(uid2);
  expect(addAdminProposal.proposal.messageId).toBeDefined();
  expect(addAdminProposal.proposal.messageId).toEqual(1);
  await grappa2.procCtrl(addAdminProposal);
  expect(grappa2.getRole()).toEqual('admin');
  expect(grappa2.getCurrentEpoch()).toEqual(2);
  expect(grappa2.getEpochInterval()).toBeDefined();
  // When the member becomes an admin it gets the full history.
  expect(grappa2.getEpochInterval()).toEqual({ left: 0, right: 2 });
  // Remove the admin privileges.
  await grappa1.execCtrl({ type: 'REM_ADM', uid: uid2 });
  expect(middleware.getProposalQueueLength(client2, folderUint8)).toEqual(1);
  const remAdminProposal = await middleware.fetchPendingProposal(
    client2,
    folderUint8
  );
  expect(remAdminProposal.proposal.cmd.type).toEqual('REM_ADM');
  expect(
    (remAdminProposal.proposal.cmd as RemAdmControlCommand).uid
  ).toStrictEqual(uid2);
  expect(remAdminProposal.applicationMsg).toBeDefined();
  expect(
    (remAdminProposal.applicationMsg.cmd as RemAdmControlCommand).uid
  ).toStrictEqual(uid2);
  expect(remAdminProposal.proposal.messageId).toBeDefined();
  expect(remAdminProposal.proposal.messageId).toEqual(2);
  await grappa2.procCtrl(remAdminProposal);
  expect(grappa2.getRole()).toEqual('member');
  expect(grappa2.getCurrentEpoch()).toEqual(3);
  expect(grappa2.getEpochInterval()).toBeDefined();
  // It will maintain the full history and process an extension as any other member.
  expect(grappa2.getEpochInterval()).toEqual({ left: 0, right: 3 });
  // Remove the member.
  await grappa1.execCtrl({ type: 'REM', uid: uid2 });
  expect(grappa1.getCurrentEpoch()).toEqual(4);
  expect(grappa1.getEpochInterval()).toBeDefined();
  expect(grappa1.getEpochInterval()).toEqual({ left: 0, right: 4 });
  expect(middleware.getProposalQueueLength(client2, folderUint8)).toEqual(1);
  const remProposal = await middleware.fetchPendingProposal(
    client2,
    folderUint8
  );
  expect(remProposal.proposal.cmd.type).toEqual('REM');
  expect((remProposal.proposal.cmd as RemControlCommand).uid).toStrictEqual(
    uid2
  );
  expect(remProposal.applicationMsg).toBeDefined();
  expect(
    (remProposal.applicationMsg.cmd as RemControlCommand).uid
  ).toStrictEqual(uid2);
  expect(remProposal.proposal.messageId).toBeDefined();
  expect(remProposal.proposal.messageId).toEqual(3);
  const grappa2Reset = await grappa2.procCtrl(remProposal);
  expect(grappa2Reset).toBeDefined();
  expect(grappa2Reset.getRole()).toBeUndefined();
  expect(
    middleware.getProposalQueueLength(client2, folderUint8)
  ).toBeUndefined();
});

it('GRaPPA: adding 2 clients, removing one, adding it again.', async () => {
  let execCtrlCounter = 0;
  const middleware = new InMemoryMiddleware();
  const client1 = generateClientRandomIdentity();
  const grappa1 = await GRaPPA.initUser(client1, middleware);
  expect(grappa1).toBeDefined();
  expect(grappa1.getRole()).toBeUndefined();
  await GRaPPA.publishKeyPackage(client1, middleware);
  const others = [
    generateClientRandomIdentity(),
    generateClientRandomIdentity(),
  ];
  const otherGrappas = [];
  for (const other of others) {
    await GRaPPA.initUser(other, middleware);
    await GRaPPA.publishKeyPackage(other, middleware);
  }
  const otherAdmin = others[0];
  const folderId = crypto.randomUUID();
  const folderUint8 = string2Uint8Array(folderId);
  await grappa1.createGroup(folderId);
  expect(grappa1.getRole()).toEqual('admin');
  expect(grappa1.getCurrentEpoch()).toEqual(0);
  // Add the other clients as members.
  for (const other of others) {
    await grappa1.execCtrl({
      type: 'ADD',
      uid: GRaPPA.getUidFromUserId(other),
    });
    execCtrlCounter++;
    expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
    expect(grappa1.getEpochInterval()).toBeDefined();
    expect(grappa1.getEpochInterval()).toEqual({
      left: 0,
      right: execCtrlCounter,
    });
    const proposal = await middleware.fetchPendingProposal(other, folderUint8);
    expect(proposal.proposal.cmd.type).toEqual('ADD');
    expect((proposal.proposal.cmd as AddControlCommand).uid).toStrictEqual(
      GRaPPA.getUidFromUserId(other)
    );
    expect(proposal.applicationMsg).toBeDefined();
    expect(
      (proposal.applicationMsg.cmd as AddControlCommand).uid
    ).toStrictEqual(GRaPPA.getUidFromUserId(other));
    const pendingMessages = middleware.getProposalQueueLength(
      other,
      folderUint8
    );
    expect(pendingMessages).toBeGreaterThan(0);
    const joinedGrappa = await GRaPPA.joinCtrl(other, middleware, proposal);
    expect(joinedGrappa.getRole()).toBeDefined();
    expect(joinedGrappa.getRole()).toEqual('member');
    expect(joinedGrappa.getCurrentEpoch()).toEqual(execCtrlCounter);
    expect(joinedGrappa.getEpochInterval()).toBeDefined();
    expect(joinedGrappa.getEpochInterval()).toEqual({
      left: execCtrlCounter,
      right: execCtrlCounter,
    });
    otherGrappas.push(joinedGrappa);
  }
  const otherAdminGrappa = otherGrappas[0];
  // Drain the queue of the other admin.
  expect(
    middleware.getProposalQueueLength(otherAdmin, folderUint8)
  ).toBeGreaterThan(0);
  while (middleware.getProposalQueueLength(otherAdmin, folderUint8) > 0) {
    const proposal = await middleware.fetchPendingProposal(
      otherAdmin,
      folderUint8
    );
    await otherAdminGrappa.procCtrl(proposal);
  }
  // Verify that all the extensions have been computed.
  expect(otherAdminGrappa.getCurrentEpoch()).toEqual(execCtrlCounter);
  // Add admin privileges.
  await grappa1.execCtrl({
    type: 'ADD_ADM',
    uid: GRaPPA.getUidFromUserId(otherAdmin),
  });
  execCtrlCounter++;
  expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
  expect(grappa1.getEpochInterval()).toBeDefined();
  expect(grappa1.getEpochInterval()).toEqual({
    left: 0,
    right: execCtrlCounter,
  });
  const proposal = await middleware.fetchPendingProposal(
    otherAdmin,
    folderUint8
  );
  expect(proposal.proposal.cmd.type).toEqual('ADD_ADM');
  expect((proposal.proposal.cmd as AddAdmControlCommand).uid).toStrictEqual(
    GRaPPA.getUidFromUserId(otherAdmin)
  );
  expect(proposal.applicationMsg).toBeDefined();
  expect(
    (proposal.applicationMsg.cmd as AddAdmControlCommand).uid
  ).toStrictEqual(GRaPPA.getUidFromUserId(otherAdmin));
  let pendingMessages = middleware.getProposalQueueLength(
    otherAdmin,
    folderUint8
  );
  expect(pendingMessages).toBeGreaterThan(0);
  const result = await otherAdminGrappa.procCtrl(proposal);
  expect(result).toBeUndefined();
  expect(otherAdminGrappa.getRole()).toEqual('admin');
  expect(otherAdminGrappa.getEpochInterval()).toBeDefined();
  expect(otherAdminGrappa.getEpochInterval()).toEqual({
    left: 0,
    right: execCtrlCounter,
  });
  expect(middleware.getProposalQueueLength(otherAdmin, folderUint8)).toBe(0);
  for (const other of otherGrappas) {
    if (other.getUserId() != otherAdmin) {
      expect(
        middleware.getProposalQueueLength(other.getUserId(), folderUint8)
      ).toBeGreaterThan(0);
      // Drain the queue and check for the extension to be processed.
      while (
        middleware.getProposalQueueLength(other.getUserId(), folderUint8) > 0
      ) {
        const proposal = await middleware.fetchPendingProposal(
          other.getUserId(),
          folderUint8
        );
        const result = await other.procCtrl(proposal);
        expect(result).toBeUndefined();
      }
      expect(other.getRole()).toEqual('member');
      expect(other.getEpochInterval()).toBeDefined();
      expect(other.getCurrentEpoch()).toEqual(execCtrlCounter);
      // They are not admins and should not get access to the full history.
      expect(other.getEpochInterval().left).toBeGreaterThan(0);
    }
  }
  // Remove admin.
  expect(
    await grappa1.execCtrl({
      type: 'REM_ADM',
      uid: GRaPPA.getUidFromUserId(otherAdmin),
    })
  ).toBeUndefined();
  execCtrlCounter++;
  expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
  expect(grappa1.getEpochInterval()).toBeDefined();
  expect(grappa1.getEpochInterval()).toEqual({
    left: 0,
    right: execCtrlCounter,
  });
  const removeAdminProposal = await middleware.fetchPendingProposal(
    otherAdmin,
    folderUint8
  );
  expect(removeAdminProposal.proposal.cmd.type).toEqual('REM_ADM');
  expect(
    (removeAdminProposal.proposal.cmd as RemAdmControlCommand).uid
  ).toStrictEqual(GRaPPA.getUidFromUserId(otherAdmin));
  expect(removeAdminProposal.applicationMsg).toBeDefined();
  expect(
    (removeAdminProposal.applicationMsg.cmd as RemAdmControlCommand).uid
  ).toStrictEqual(GRaPPA.getUidFromUserId(otherAdmin));
  pendingMessages = middleware.getProposalQueueLength(otherAdmin, folderUint8);
  expect(pendingMessages).toEqual(1);
  // Process the removal
  expect(await otherAdminGrappa.procCtrl(removeAdminProposal)).toBeUndefined();
  expect(otherAdminGrappa.getRole()).toEqual('member');
  expect(otherAdminGrappa.getEpochInterval()).toBeDefined();
  expect(otherAdminGrappa.getEpochInterval()).toEqual({
    left: 0,
    right: execCtrlCounter,
  });
  expect(middleware.getProposalQueueLength(otherAdmin, folderUint8)).toBe(0);
  // Rotate keys.
  expect(await grappa1.execCtrl({ type: 'ROT_KEYS' })).toBeUndefined();
  execCtrlCounter++;
  expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
  expect(grappa1.getEpochInterval()).toBeDefined();
  expect(grappa1.getEpochInterval()).toEqual({
    left: 0,
    right: execCtrlCounter,
  });
  // This should fail for the admin.
  await expect(grappa1.execCtrl({ type: 'UPD_USER' })).resolves.toBeUndefined();
  expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
  expect(grappa1.getEpochInterval()).toBeDefined();
  expect(grappa1.getEpochInterval()).toEqual({
    left: 0,
    right: execCtrlCounter,
  });
  // Sync also the other members.
  for (const other of otherGrappas) {
    if (other.getUserId() != otherAdmin) {
      expect(
        middleware.getProposalQueueLength(other.getUserId(), folderUint8)
      ).toBeGreaterThan(0);
      // Drain the queue and check for the extension to be processed.
      while (
        middleware.getProposalQueueLength(other.getUserId(), folderUint8) > 0
      ) {
        const proposal = await middleware.fetchPendingProposal(
          other.getUserId(),
          folderUint8
        );
        const result = await other.procCtrl(proposal);
        expect(result).toBeUndefined();
      }
      expect(other.getRole()).toEqual('member');
      expect(other.getEpochInterval()).toBeDefined();
      expect(other.getCurrentEpoch()).toEqual(execCtrlCounter);
      // They are not admins and should not get access to the full history.
      expect(other.getEpochInterval().left).toBeGreaterThan(0);
    }
  }
});

it('GRaPPA: regression test on REM_ADM', async () => {
  let execCtrlCounter = 0;
  const middleware = new InMemoryMiddleware();
  const client1 = generateClientRandomIdentity();
  const grappa1 = await GRaPPA.initUser(client1, middleware);
  expect(grappa1).toBeDefined();
  expect(grappa1.getRole()).toBeUndefined();
  await GRaPPA.publishKeyPackage(client1, middleware);
  const others = [
    generateClientRandomIdentity(),
    generateClientRandomIdentity(),
  ];
  const otherGrappas = [];
  for (const other of others) {
    await GRaPPA.initUser(other, middleware);
    await GRaPPA.publishKeyPackage(other, middleware);
  }
  const folderId = crypto.randomUUID();
  const folderUint8 = string2Uint8Array(folderId);
  // Create a folder where current is admin.
  await grappa1.createGroup(folderId);
  expect(grappa1.getRole()).toEqual('admin');
  expect(grappa1.getCurrentEpoch()).toEqual(0);
  // Share the folder with all other clients.
  for (const other of others) {
    await grappa1.execCtrl({
      type: 'ADD',
      uid: GRaPPA.getUidFromUserId(other),
    });
    execCtrlCounter++;
    expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
  }
  // Sync them.
  for (const other of others) {
    const proposal = await middleware.fetchPendingProposal(other, folderUint8);
    const joinedGrappa = await GRaPPA.joinCtrl(other, middleware, proposal);
    expect(joinedGrappa.getRole()).toBeDefined();
    expect(joinedGrappa.getRole()).toEqual('member');
    while (
      middleware.getProposalQueueLength(joinedGrappa.getUserId(), folderUint8) >
      0
    ) {
      const proposal = await middleware.fetchPendingProposal(
        joinedGrappa.getUserId(),
        folderUint8
      );
      const result = await joinedGrappa.procCtrl(proposal);
      expect(result).toBeUndefined();
    }
    expect(joinedGrappa.getCurrentEpoch()).toEqual(execCtrlCounter);
    otherGrappas.push(joinedGrappa);
  }
  // Verify that the creator is still an admin.
  while (
    middleware.getProposalQueueLength(grappa1.getUserId(), folderUint8) > 0
  ) {
    const proposal = await middleware.fetchPendingProposal(
      grappa1.getUserId(),
      folderUint8
    );
    const result = await grappa1.procCtrl(proposal);
    expect(result).toBeUndefined();
  }
  expect(grappa1.getRole()).toEqual('admin');
  // Perform key rotation.
  expect(await grappa1.execCtrl({ type: 'ROT_KEYS' })).toBeUndefined();
  execCtrlCounter++;
  expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
  expect(grappa1.getRole()).toEqual('admin');
  // Sync all other clients. make all of them admins
  for (const other of otherGrappas) {
    while (
      middleware.getProposalQueueLength(other.getUserId(), folderUint8) > 0
    ) {
      const proposal = await middleware.fetchPendingProposal(
        other.getUserId(),
        folderUint8
      );
      const result = await other.procCtrl(proposal);
      expect(result).toBeUndefined();
      expect(other.getRole()).toEqual('member');
    }
    // Add client as admins.
    expect(
      await grappa1.execCtrl({
        type: 'ADD_ADM',
        uid: GRaPPA.getUidFromUserId(other.getUserId()),
      })
    ).toBeUndefined();
    execCtrlCounter++;
    expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
    expect(grappa1.getRole()).toEqual('admin');
    // And sync each of them.
    while (
      middleware.getProposalQueueLength(other.getUserId(), folderUint8) > 0
    ) {
      const proposal = await middleware.fetchPendingProposal(
        other.getUserId(),
        folderUint8
      );
      const result = await other.procCtrl(proposal);
      expect(result).toBeUndefined();
      expect(other.getRole()).toEqual('admin');
      expect(other.getCurrentEpoch()).toEqual(execCtrlCounter);
    }
  }
  // Cleanup: remove admin privileges.
  // sync admin
  // Verify that the creator is still an admin.
  while (
    middleware.getProposalQueueLength(grappa1.getUserId(), folderUint8) > 0
  ) {
    const proposal = await middleware.fetchPendingProposal(
      grappa1.getUserId(),
      folderUint8
    );
    const result = await grappa1.procCtrl(proposal);
    expect(result).toBeUndefined();
  }
  expect(grappa1.getRole()).toEqual('admin');
  for (const other of otherGrappas) {
    // Remove admin privileges.
    expect(
      await grappa1.execCtrl({
        type: 'REM_ADM',
        uid: GRaPPA.getUidFromUserId(other.getUserId()),
      })
    ).toBeUndefined();
    execCtrlCounter++;
    expect(grappa1.getCurrentEpoch()).toEqual(execCtrlCounter);
    expect(grappa1.getRole()).toEqual('admin');
    // And sync each of them.
    while (
      middleware.getProposalQueueLength(other.getUserId(), folderUint8) > 0
    ) {
      const proposal = await middleware.fetchPendingProposal(
        other.getUserId(),
        folderUint8
      );
      const result = await other.procCtrl(proposal);
      expect(result).toBeUndefined();
    }
    expect(other.getRole()).toEqual('member');
  }
});
