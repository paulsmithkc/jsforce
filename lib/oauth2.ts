import * as querystring from 'node:querystring';
import { Transport } from './transport';

export interface OAuthOptions {
  loginUrl?: string; // Salesforce login server URL.
  authzServiceUrl?: string; // OAuth2 authorization service URL. If not specified, it generates from default by adding to login server URL.
  tokenServiceUrl?: string; // OAuth2 token service URL. If not specified it generates from default by adding to login server URL.
  clientId?: string; // OAuth2 client ID.
  clientSecret?: string; // OAuth2 client secret (This is optional for public client).
  redirectUri?: string; // URI to be callbacked from Salesforce OAuth2 authorization service.
  revokeServiceUrl?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
}

export class OAuth2 {
  private loginUrl: string;
  private authzServiceUrl: string;
  private tokenServiceUrl: string;
  private revokeServiceUrl?: string;
  private clientId?: string;
  private clientSecret?: string;
  private redirectUri?: string;

  private _transport: Transport;

  constructor(options: OAuthOptions) {
    if (options.authzServiceUrl && options.tokenServiceUrl) {
      this.loginUrl = options.authzServiceUrl.split('/').slice(0, 3).join('/');
      this.authzServiceUrl = options.authzServiceUrl;
      this.tokenServiceUrl = options.tokenServiceUrl;
      this.revokeServiceUrl = options.revokeServiceUrl;
    } else {
      this.loginUrl = options.loginUrl || 'https://login.salesforce.com';
      this.authzServiceUrl = this.loginUrl + '/services/oauth2/authorize';
      this.tokenServiceUrl = this.loginUrl + '/services/oauth2/token';
      this.revokeServiceUrl = this.loginUrl + '/services/oauth2/revoke';
    }

    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.redirectUri = options.redirectUri;

    this._transport = new Transport();
  }

  /** Get Salesforce OAuth2 authorization page URL. */
  getAuthorizationUrl(params: {scope?: string, state?: string, code_challenge?: string}): string {
    const paramsEx: any = {
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      ...(params || {})
    };
    return (
      this.authzServiceUrl +
      (this.authzServiceUrl.indexOf('?') >= 0 ? '&' : '?') +
      querystring.stringify(paramsEx)
    );
  }

  /** OAuth2 Refresh Token Flow */
  refreshToken(refreshToken: string): Promise<TokenResponse> {
    return this._postParams({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: refreshToken,
    });
  }

  /** OAuth2 Web Server Authentication Flow (Authorization Code) Access Token Request */
  requestToken(code: string, params: { code_verifier?: string}): Promise<TokenResponse> {
    return this._postParams({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      redirect_uri: this.redirectUri,
      code: code,
      ...(params || {})
    });
  }

  /** OAuth2 Username-Password Flow (Resource Owner Password Credentials) */
  authenticate(username: string, password: string) {
    return this._postParams(
      {
        grant_type: 'password',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        redirect_uri: this.redirectUri,
        username: username,
        password: password,
      }
    );
  }

  /** OAuth2 Revoke Session or API Token */
  revokeToken(token: string): Promise<void> {
    return this._transport
      .httpRequest({
        method: 'POST',
        url: this.revokeServiceUrl,
        body: querystring.stringify({ token: token }),
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      })
      .then((response) => {
        if (response.statusCode >= 400) {
          let res: { error?: string, error_description?: string, [key: string]: unknown }; 
          res = querystring.parse(response.body);
          if (!res || !res.error) {
            res = {
              error: 'ERROR_HTTP_' + response.statusCode,
              error_description: response.body,
            };
          }
          const err = new Error(res.error_description);
          err.name = res.error || 'Error';
          throw err;
        }
      })
  }

  private _postParams(params: Record<string, string | undefined>) {
    return this._transport
      .httpRequest({
        method: 'POST',
        url: this.tokenServiceUrl,
        body: querystring.stringify(params),
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
      })
      .then((response) => {
        let res: any;
        try {
          res = JSON.parse(response.body);
        } catch (e) {}
        if (response.statusCode >= 400) {
          res = res || {
            error: 'ERROR_HTTP_' + response.statusCode,
            error_description: response.body,
          };
          var err = new Error(res.error_description);
          err.name = res.error;
          throw err;
        }
        return res;
      });
  }
}
