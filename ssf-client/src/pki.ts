import { mkClientCertificateRequestParams } from "common";
import { CrateService as pkiclient } from "./gen/clients/pki";

export async function createClientCertificate(email: string): Promise<[string, string]> {
    const {keyPair, signingRequest} = mkClientCertificateRequestParams(email);
    const { certificate } = await pkiclient.register({
        requestBody: {
            email,
            certificate_request: signingRequest,
        }
    });
    return [certificate, keyPair];
}