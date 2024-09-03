import { CrateService as pkiclient } from './gen/clients/pki';
import { CrateService as dsclient } from './gen/clients/ds';

void (async () => {
  const module = await import('ssf');
  await module.mls_example();
  //const caCredential = await pkiclient.getCaCredential();
  //console.log(caCredential);
})();
