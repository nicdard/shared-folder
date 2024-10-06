import { AxiosRequestConfig } from 'axios';
import fs from 'fs';
import { Agent, AgentOptions } from 'https';
import path from 'path';

/**
 * The default clients credentials directory.
 * This is relative to the project installation directory.
 */
export const CLIENTS_CERT_DIR = path.join(
  __dirname,
  '..',
  'dist',
  'private',
  'clients'
);
/**
 * The client PEM-encoded key file path.
 * This is relative to the project installation directory.
 */
export const CLIENT_KEY_PATH = path.join(CLIENTS_CERT_DIR, 'key.pem');
/**
 * The client Certificate PEM-encoded file path.
 * This is relative to the project installation directory.
 */
export const CLIENT_CERT_PATH = path.join(CLIENTS_CERT_DIR, 'cert.pem');

/**
 * The CA PEM-encoded certificate file path.
 */
const CA_CERT_PATH = path.join(
  __dirname,
  '..',
  'dist',
  'private',
  'ca',
  'ca_cert.pem'
);

/**
 * @returns the CA TLS credentials from the project installation directory.
 */
export function loadCaTLSCredentials(): Buffer {
  return fs.readFileSync(CA_CERT_PATH);
}

/**
 * @param caCert the CA certificate to save.
 */
export function saveCaTLSCredentials(caCert: string): void {
  fs.writeFileSync(CA_CERT_PATH, caCert);
}

/**
 * @returns the client TLS credentials as a tuple [key, cert] from the `/clients` folder.
 */
export function loadTLSCredentials(): [Buffer, Buffer] {
  const key = fs.readFileSync(CLIENT_KEY_PATH);
  const cert = fs.readFileSync(CLIENT_CERT_PATH);
  return [key, cert];
}

/**
 * @param request the request to add the https agent to.
 * @param agentOptions the agent options to add to the request.
 * @returns the request with the https agent added (or extended).
 */
function addHttpsUserAgent(
  request: AxiosRequestConfig,
  agentOptions: AgentOptions
): AxiosRequestConfig {
  request.httpsAgent =
    request.httpsAgent != null && typeof request.httpsAgent === 'object'
      ? new Agent({ ...(request.httpsAgent as AgentOptions), ...agentOptions })
      : new Agent({ ...agentOptions });
  return request;
}

/**
 * @param request the request to add the CA TLS credentials to.
 * @param loader a function which returns the Buffer containing the PEM-encoded certificate.
 * @returns the request with the CA TLS credentials added.
 */
export function loadCaTLSCredentialsInterceptor(
  request: AxiosRequestConfig,
  loader: () => Buffer
): AxiosRequestConfig {
  const agentOptions = {
    rejectUnauthorized: true,
    ca: loader(),
  };
  return addHttpsUserAgent(request, agentOptions);
}

/**
 *
 * @param request the request to add the CA TLS credentials to.
 * @returns the request with the CA TLS credentials added.
 */
export function loadDefaultCaTLSCredentialsInterceptor(
  request: AxiosRequestConfig
): AxiosRequestConfig {
  return loadCaTLSCredentialsInterceptor(request, loadCaTLSCredentials);
}

/**
 * @param request the request to add the client and CA TLS credentials to.
 * @returns the request with the client and CA TLS credentials added.
 */
export function loadDsTLSInterceptor(
  request: AxiosRequestConfig
): AxiosRequestConfig {
  const [key, cert] = loadTLSCredentials();
  const agentOptions = {
    rejectUnauthorized: true,
    ca: loadCaTLSCredentials(),
    key: key,
    cert: cert,
  };
  return addHttpsUserAgent(request, agentOptions);
}
