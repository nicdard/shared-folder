import { WebSocket } from "isomorphic-ws";
import { CLIENTS_CERT_DIR, loadCaTLSCredentials, loadDefaultCaTLSCredentialsInterceptor, loadDsTLSInterceptor, loadTLSCredentials, } from "../../../src/authentication";
import { OpenAPI as pkiOpenAPI } from '../../gen/clients/pki';
import { OpenAPI as dsOpenAPI } from '../../gen/clients/ds';
import { register } from "../../../src/ds";
import { createIdentity, switchIdentity } from "../../../src/cli";


/**
 * This test requires both the pki and the ds servers to be up and running.
 */
it('can connect to the websocket, also multiple clients', async () => {
    pkiOpenAPI.interceptors.request.use(loadDefaultCaTLSCredentialsInterceptor);
    dsOpenAPI.interceptors.request.use(loadDsTLSInterceptor);
    const email = crypto.randomUUID() + "@test.com";
    await createIdentity(email, { clientsDir: CLIENTS_CERT_DIR, reThrow: true });
    await switchIdentity(email, { clientsDir: CLIENTS_CERT_DIR });
    const [key, cert] = loadTLSCredentials();
    await register(email);
    const ws = new WebSocket("wss://127.0.0.1:8001/groups/ws", {
        ca: loadCaTLSCredentials(),
        key,
        cert
    });
    ws.onmessage = (e) => { console.log(e.data); };
    const p1 = new Promise((resolve, reject) => {
        ws.addEventListener("open", () => { ws.send("ciao1"); setTimeout(() => {
            if (ws.readyState == 1) {
                ws.close();
                resolve("ciao"); 
            } else {
                console.error("The server detected an authentiation problem, check the DS logs.");
                reject();
            }
        }, 10000)} );
    });
    const email2 = crypto.randomUUID() + "@test2.com";
    await createIdentity(email2, { clientsDir: CLIENTS_CERT_DIR, reThrow: true });
    await switchIdentity(email2, { clientsDir: CLIENTS_CERT_DIR });
    const [key2, cert2] = loadTLSCredentials();
    await register(email2);
    const ws2 = new WebSocket("wss://127.0.0.1:8001/echo", {
        ca: loadCaTLSCredentials(),
        key: key2,
        cert: cert2
    });
    ws2.onmessage = (e) => console.log(e.data);
    const p2 = await new Promise((resolve, reject) => {
        ws2.addEventListener("open", () => { ws2.send("ciao2"); setTimeout(() => {
            if (ws2.readyState == 1) {
                ws2.close();
                resolve("ciao"); 
            } else {
                console.error("The server detected an authentiation problem, check the DS logs.");
                reject();
            }
        }, 10000)} );
    });
    await Promise.all([p1, p2]);
});