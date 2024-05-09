import { CrateService as pkiclient } from "./gen/clients/pki";
import { CrateService as dsclient } from "./gen/clients/ds";

void (async () => {
  const module = await import('ssf');
  module.greet('CIAO');
  const caCredential = await pkiclient.getCaCredential();
  console.log(caCredential);
})();
