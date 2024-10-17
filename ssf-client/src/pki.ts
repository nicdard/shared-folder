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
import { mkClientCertificateRequestParams, verifyCertificate } from 'common';
import { CrateService as pkiclient } from './gen/clients/pki';
import { loadCaTLSCredentials } from './protocol/authentication';

/**
 * @param email The email of the client.
 * @returns The client certificate and the private key.
 */
export async function createClientCertificate(
  email: string
): Promise<[string, string]> {
  const { keyPair, signingRequest } = mkClientCertificateRequestParams(email);
  const { certificate } = await pkiclient.register({
    requestBody: {
      email,
      certificate_request: signingRequest,
    },
  });
  return [certificate, keyPair];
}

/**
 * @param email The email of the client to get the certificate for.
 * @returns The client certificate.
 */
export async function getClientCertificate(email: string): Promise<string> {
  const { certificate } = await pkiclient.getCredential({
    requestBody: {
      email,
    },
  });
  return certificate;
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
      certificate,
    },
  });
  return valid;
}

/**
 * Performs a local validation using the CA certificate stored locally and retrieved by {@link loadCaTLSCredentials}.
 * @param certificate The certificate to validate.
 * @returns true if the certificate is valid, false otherwise.
 */
export function localIsValid(certificate: string): boolean {
  const issuer = loadCaTLSCredentials().toString();
  return verifyCertificate(certificate, issuer);
}
