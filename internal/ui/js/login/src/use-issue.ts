import { useCallback } from "react"

type SAMLStep1 = {
  redirectURL: string;
  noAuthRedirect: boolean;
}

type SAMLStep2 = {
  SAMLResponse: string;
  relayState: string
}

interface IssueParams {
  sourceNamespace: string
  sourceName: string
  cookie: boolean
  cloak?: string[]
}

interface IssueLdapParams extends IssueParams {
  username: string
  password: string
}

interface UseIssueOptions {
  /**
   * The base URL for the a3s backend. Shouldn't include the `/` in the end.
   * Example: `https://127.0.0.1:44443`
   */
  apiUrl: string
  /**
   * The audience for the JWT.
   */
  audience: string[]
}

/**
 * TODO: Support custom fetch function.
 * TODO: Add error handling
 */
export function useIssue({ apiUrl, audience }: UseIssueOptions) {
  const issueUrl = `${apiUrl}/issue`

  const issueWithLdap = useCallback(
    ({
      sourceNamespace,
      sourceName,
      username,
      password,
      cookie,
      cloak,
    }: IssueLdapParams) =>
      fetch(issueUrl, {
        method: "POST",
        body: JSON.stringify({
          sourceType: "LDAP",
          sourceNamespace,
          sourceName,
          inputLDAP: {
            username,
            password,
          },
          cookie,
          cookieDomain: window.location.hostname,
          audience,
          cloak,
        }),
        headers: {
          "Content-Type": "application/json",
        },
      }),
    [issueUrl, audience]
  )

  const issueWithMtls = useCallback(
    ({ sourceNamespace, sourceName, cookie, cloak }: IssueParams) =>
      fetch(issueUrl, {
        method: "POST",
        body: JSON.stringify({
          sourceType: "MTLS",
          sourceNamespace,
          sourceName,
          cookie,
          cookieDomain: window.location.hostname,
          audience,
          cloak,
        }),
        headers: {
          "Content-Type": "application/json",
        },
      }),
    [issueUrl, audience]
  )

  const issueWithOidc = useCallback(
    ({
      sourceNamespace,
      sourceName,
      redirectUrl,
      cloak,
    }: Omit<IssueParams, "cookie"> & { redirectUrl: string }) => {
      // Remove the trailing slash
      const currentUrl = (
        window.location.origin + window.location.pathname
      ).replace(/\/$/, "")
      return fetch(issueUrl, {
        method: "POST",
        body: JSON.stringify({
          sourceType: "OIDC",
          sourceNamespace,
          sourceName,
          inputOIDC: {
            redirectURL: currentUrl,
            redirectErrorURL: currentUrl,
            noAuthRedirect: true,
          },
          cloak
        }),
        headers: {
          "Content-Type": "application/json",
        },
      })
        .then(res => res.json())
        .then(obj => {
          redirectUrl && localStorage.setItem("redirectUrl", redirectUrl)
          window.location.href = obj.inputOIDC.authURL
        })
    },
    [issueUrl]
  )

  // Cloak an existing token
  const issueWithA3s = useCallback(
    ({
      cloak,
      token,
      cookie,
    }: {
      cloak: string[]
      token: string
      cookie: boolean
    }) =>
      fetch(issueUrl, {
        method: "POST",
        body: JSON.stringify({
          sourceType: "A3S",
          inputA3S: {
            token,
          },
          cloak,
          cookie,
          cookieDomain: window.location.hostname,
          audience,
        }),
        headers: {
          "Content-Type": "application/json",
        },
      }),
    [audience, issueUrl]
  )

  const issueWithSaml = useCallback(
    async ({ sourceNamespace, sourceName }: { sourceNamespace: string; sourceName: string }) => {
      const fetchIssue = async (step: SAMLStep1 | SAMLStep2) => (
        await fetch(issueUrl, {
          method: "POST",
          body: JSON.stringify({
            sourceType: "SAML",
            sourceName,
            sourceNamespace,
            inputSAML: 'SAMLResponse' in step ?
              { SAMLResponse: step.SAMLResponse, relayState: step.relayState } : 
              { redirectURL: step.redirectURL, noAuthRedirect: step.noAuthRedirect },
            cookie: true,
          }),
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
        })
      );
      const response = await fetchIssue({ redirectURL: `${location.origin}/saml/callback`, noAuthRedirect: true });
      const responseBody = await response.json();
      const samlWindow = window.open(responseBody.inputSAML.authURL, 'saml', 'width=640,height=640,left=300,top=200');

      return new Promise((resolve, reject) => {
        window.onmessage = async ({ data }) => {
          if (!data.SAMLResponse || !data.relayState) {
            return;
          }

          try {
            const issueResponse = await fetchIssue({
              SAMLResponse: data.SAMLResponse,
              relayState: data.relayState
            });
            samlWindow?.close();
            resolve(issueResponse);
          } catch (error) {
            reject(error);
          }
        };  
      });
    },
    [issueUrl]
  );

  return {
    issueWithLdap,
    issueWithOidc,
    issueWithMtls,
    issueWithA3s,
    issueWithSaml,
  }
}
