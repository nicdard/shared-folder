import { mkClientCertificateRequestParams } from "common";
import { CrateService as pkiclient } from "./gen/clients/pki";

/**
 * @param email The email of the client.
 * @returns The client certificate and the private key.
 */
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

/**
 * @returns the CA certificate.
 */
export async function downloadCACertificate(): Promise<string> {
    const { certificate } = await pkiclient.getCaCredential();
    return certificate;
}

/**
 * @param certificate The certificate to validate.
 * @returns true if the certificate is valid, false otherwise.
 */
export async function isValid(certificate: string): Promise<boolean> {
    const { valid } = await pkiclient.verify({
        requestBody: {
            certificate
        }
    });
    return valid;
}